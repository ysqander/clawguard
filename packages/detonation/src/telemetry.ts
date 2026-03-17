import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import type {
  ArtifactRef,
  DetonationReport,
  DetonationTelemetryEvent,
  ThreatIntelSubject,
  ThreatIntelVerdict,
} from "@clawguard/contracts";

import type { PromptRunnerResult } from "./prompt-runner.js";

export interface DetonationTelemetryVirusTotalClient {
  getUrlVerdict?(url: string): Promise<ThreatIntelVerdict | null>;
  getDomainVerdict?(domain: string): Promise<ThreatIntelVerdict | null>;
  searchIndicators?(query: string): Promise<{ verdicts: ThreatIntelVerdict[] } | null>;
}

export interface BuildDetonationReportOptions {
  generatedAt?: string;
  artifactsRoot?: string;
  virustotalClient?: DetonationTelemetryVirusTotalClient;
}

export interface BuildDetonationReportResult {
  report: DetonationReport;
  telemetry: DetonationTelemetryEvent[];
  intelligence: ThreatIntelVerdict[];
  artifacts: ArtifactRef[];
}

export async function buildDetonationReportFromPromptRunner(
  result: PromptRunnerResult,
  options: BuildDetonationReportOptions = {},
): Promise<BuildDetonationReportResult> {
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const telemetry = collectTelemetry(result, generatedAt);
  const intelligence = await enrichTelemetryIndicators(telemetry, options.virustotalClient);
  const artifacts = options.artifactsRoot
    ? await persistTelemetryArtifacts(result, telemetry, intelligence, options.artifactsRoot, generatedAt)
    : [];

  const triggeredActions = telemetry
    .filter((event) => event.type === "process")
    .map((event) => event.detail);

  const report: DetonationReport = {
    request: result.request,
    summary: summarizeTelemetry(telemetry, intelligence),
    triggeredActions,
    artifacts,
    telemetry,
    intelligence,
    generatedAt,
  };

  return {
    report,
    telemetry,
    intelligence,
    artifacts,
  };
}

function collectTelemetry(result: PromptRunnerResult, observedAt: string): DetonationTelemetryEvent[] {
  const events: DetonationTelemetryEvent[] = [];

  for (const [index, step] of result.execution.entries()) {
    const command = [step.command ?? "", ...(step.args ?? [])].join(" ").trim();
    if (command.length > 0) {
      events.push({
        eventId: `evt-${index + 1}-process`,
        type: "process",
        detail: command,
        observedAt,
        stepId: step.stepId,
      });
    }

    const output = `${step.result?.stdout ?? ""}\n${step.result?.stderr ?? ""}\n${step.value}\n${step.boundCommand ?? ""}`;

    for (const indicator of extractIndicators(output)) {
      events.push({
        eventId: `evt-${index + 1}-${indicator.subjectType}-${events.length + 1}`,
        type: "network",
        detail: `Observed ${indicator.subjectType}: ${indicator.subject}`,
        observedAt,
        stepId: step.stepId,
        indicator,
      });
    }

    const fileMatches = output.match(/(?:\.{0,2}\/)?[\w.-]+\/[\w./-]+|\/[\w./-]+/gu) ?? [];
    for (const filePath of fileMatches.slice(0, 5)) {
      events.push({
        eventId: `evt-${index + 1}-file-${events.length + 1}`,
        type: "file",
        detail: `Touched path ${filePath}`,
        observedAt,
        stepId: step.stepId,
      });
    }
  }

  for (const diff of result.memoryDiffs) {
    if (!diff.changed) {
      continue;
    }

    events.push({
      eventId: `evt-memory-${diff.name}`,
      type: "memory",
      detail: `Memory file changed: ${diff.name}`,
      observedAt,
    });
  }

  return dedupeTelemetry(events);
}

async function enrichTelemetryIndicators(
  telemetry: DetonationTelemetryEvent[],
  virustotalClient: DetonationTelemetryVirusTotalClient | undefined,
): Promise<ThreatIntelVerdict[]> {
  if (!virustotalClient) {
    return [];
  }

  const verdicts: ThreatIntelVerdict[] = [];
  const seen = new Set<string>();

  for (const event of telemetry) {
    const indicator = event.indicator;
    if (!indicator) {
      continue;
    }

    const key = `${indicator.subjectType}:${indicator.subject}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);

    try {
      if (indicator.subjectType === "url") {
        const verdict = await virustotalClient.getUrlVerdict?.(indicator.subject);
        if (verdict) {
          verdicts.push(verdict);
        }
        continue;
      }

      if (indicator.subjectType === "domain") {
        const verdict = await virustotalClient.getDomainVerdict?.(indicator.subject);
        if (verdict) {
          verdicts.push(verdict);
        }
        continue;
      }

      if (indicator.subjectType === "ip") {
        const search = await virustotalClient.searchIndicators?.(`ip:${indicator.subject}`);
        if (search) {
          verdicts.push(...search.verdicts.filter((item) => item.subjectType === "ip"));
        }
      }
    } catch {
      // non-blocking enrichment by design
    }
  }

  return dedupeVerdicts(verdicts);
}

async function persistTelemetryArtifacts(
  result: PromptRunnerResult,
  telemetry: DetonationTelemetryEvent[],
  intelligence: ThreatIntelVerdict[],
  artifactsRoot: string,
  generatedAt: string,
): Promise<ArtifactRef[]> {
  const requestRoot = path.join(artifactsRoot, result.request.requestId);
  await mkdir(path.join(requestRoot, "steps"), { recursive: true });

  const telemetryPath = path.join(requestRoot, "telemetry.json");
  await writeFile(telemetryPath, JSON.stringify({ generatedAt, telemetry, intelligence }, null, 2), "utf8");

  const artifacts: ArtifactRef[] = [
    {
      scanId: result.request.requestId,
      type: "report-json",
      path: telemetryPath,
      mimeType: "application/json",
    },
  ];

  for (const [index, step] of result.execution.entries()) {
    if (!step.result) {
      continue;
    }

    const stdoutPath = path.join(requestRoot, "steps", `${index + 1}-${step.stepId}.stdout.log`);
    const stderrPath = path.join(requestRoot, "steps", `${index + 1}-${step.stepId}.stderr.log`);
    await Promise.all([
      writeFile(stdoutPath, step.result.stdout, "utf8"),
      writeFile(stderrPath, step.result.stderr, "utf8"),
    ]);

    artifacts.push(
      {
        scanId: result.request.requestId,
        type: "detonation-stdout",
        path: stdoutPath,
        mimeType: "text/plain",
      },
      {
        scanId: result.request.requestId,
        type: "detonation-stderr",
        path: stderrPath,
        mimeType: "text/plain",
      },
    );
  }

  return artifacts;
}

function summarizeTelemetry(telemetry: DetonationTelemetryEvent[], intelligence: ThreatIntelVerdict[]): string {
  const processCount = telemetry.filter((event) => event.type === "process").length;
  const networkCount = telemetry.filter((event) => event.type === "network").length;
  const fileCount = telemetry.filter((event) => event.type === "file").length;
  const memoryCount = telemetry.filter((event) => event.type === "memory").length;

  return [
    `Captured ${processCount} process events, ${networkCount} network indicators, ${fileCount} file touches, and ${memoryCount} memory diffs.`,
    `VirusTotal enrichment returned ${intelligence.length} indicator verdicts.`,
  ].join(" ");
}

function extractIndicators(text: string): Array<{ subjectType: ThreatIntelSubject; subject: string }> {
  const indicators: Array<{ subjectType: ThreatIntelSubject; subject: string }> = [];

  const urlMatches = text.match(/https?:\/\/[^\s"'`<>]+/gu) ?? [];
  for (const url of urlMatches) {
    indicators.push({ subjectType: "url", subject: url });
    const domain = toDomain(url);
    if (domain) {
      indicators.push({ subjectType: "domain", subject: domain });
    }
  }

  const ipMatches = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/gu) ?? [];
  for (const ip of ipMatches) {
    indicators.push({ subjectType: "ip", subject: ip });
  }

  return indicators;
}

function toDomain(url: string): string | undefined {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch {
    return undefined;
  }
}

function dedupeTelemetry(events: DetonationTelemetryEvent[]): DetonationTelemetryEvent[] {
  const seen = new Set<string>();
  const deduped: DetonationTelemetryEvent[] = [];
  for (const event of events) {
    const key = `${event.type}:${event.detail}:${event.stepId ?? ""}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    deduped.push(event);
  }
  return deduped;
}

function dedupeVerdicts(verdicts: ThreatIntelVerdict[]): ThreatIntelVerdict[] {
  const seen = new Set<string>();
  return verdicts.filter((verdict) => {
    const key = `${verdict.provider}:${verdict.subjectType}:${verdict.subject}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}
