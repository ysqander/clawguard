import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import type {
  ArtifactRef,
  DetonationFileObservation,
  DetonationFileOperation,
  DetonationReport,
  DetonationTelemetryEvent,
  ThreatIntelVerdict,
} from "@clawguard/contracts";

import type {
  PromptRunnerFileChange,
  PromptRunnerResult,
  PromptRunnerStepTrace,
} from "./prompt-runner.js";

const SANDBOX_PATH_PREFIXES = ["/workspace/openclaw", "/home/clawguard"] as const;
const INTERNAL_SANDBOX_PREFIXES = [
  "/workspace/openclaw/.clawguard/",
  "/home/clawguard/.clawguard/",
] as const;

export interface DetonationTelemetryVirusTotalClient {
  getFileVerdict?(contentHash: string): Promise<ThreatIntelVerdict | null>;
  getUrlVerdict?(url: string): Promise<ThreatIntelVerdict | null>;
  getDomainVerdict?(domain: string): Promise<ThreatIntelVerdict | null>;
  searchIndicators?(query: string): Promise<{ verdicts: ThreatIntelVerdict[] } | null>;
}

export interface BuildDetonationReportOptions {
  generatedAt?: string;
  artifactsRoot?: string;
}

export interface BuildDetonationReportResult {
  report: DetonationReport;
  telemetry: DetonationTelemetryEvent[];
  artifacts: ArtifactRef[];
}

export async function buildDetonationReportFromPromptRunner(
  result: PromptRunnerResult,
  options: BuildDetonationReportOptions = {},
): Promise<BuildDetonationReportResult> {
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const telemetry = collectTelemetry(result, generatedAt);
  const artifacts = options.artifactsRoot
    ? await persistTelemetryArtifacts(result, telemetry, options.artifactsRoot, generatedAt)
    : [];

  const triggeredActions = telemetry.flatMap((event) =>
    event.type === "process" && event.process
      ? [formatCommandLine(event.process.command, event.process.args)]
      : [],
  );

  const report: DetonationReport = {
    request: result.request,
    summary: summarizeTelemetry(telemetry),
    triggeredActions,
    artifacts,
    telemetry,
    generatedAt,
  };

  return {
    report,
    telemetry,
    artifacts,
  };
}

/**
 * Enriches telemetry indicators by querying a VirusTotal-compatible client for
 * verdicts on files, URLs, domains, and IPs extracted from the telemetry events.
 *
 * The returned verdicts are not automatically attached to the report. Callers
 * should set `report.intelligence = verdicts` after enrichment to persist the
 * results in the {@link DetonationReport}.
 */
export async function enrichDetonationTelemetryIndicators(
  telemetry: DetonationTelemetryEvent[],
  virustotalClient: DetonationTelemetryVirusTotalClient | undefined,
): Promise<ThreatIntelVerdict[]> {
  if (!virustotalClient) {
    return [];
  }

  const verdicts: ThreatIntelVerdict[] = [];
  const seen = new Set<string>();

  for (const indicator of collectThreatIntelIndicators(telemetry)) {
    const key = `${indicator.subjectType}:${indicator.subject}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);

    try {
      if (indicator.subjectType === "file") {
        const verdict = await virustotalClient.getFileVerdict?.(indicator.subject);
        if (verdict) {
          verdicts.push(verdict);
        }
        continue;
      }

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
          verdicts.push(...search.verdicts.filter((entry) => entry.subjectType === "ip"));
        }
      }
    } catch {
      // enrichment failures must not break behavioral completion
    }
  }

  return dedupeVerdicts(verdicts);
}

function collectTelemetry(
  result: PromptRunnerResult,
  generatedAt: string,
): DetonationTelemetryEvent[] {
  const events: DetonationTelemetryEvent[] = [];
  const stepsById = new Map(result.execution.map((entry) => [entry.stepId, entry]));
  let nextEventId = 1;

  const pushEvent = (event: Omit<DetonationTelemetryEvent, "eventId">): void => {
    events.push({
      eventId: `evt-${String(nextEventId).padStart(4, "0")}`,
      ...event,
    });
    nextEventId += 1;
  };

  const tracedStepIds = new Set(result.stepTraces.map((t) => t.stepId));

  for (const stepTrace of result.stepTraces) {
    const execution = stepsById.get(stepTrace.stepId);
    const observedAt = execution?.completedAt ?? generatedAt;
    appendTraceEvents(stepTrace, observedAt, pushEvent);
  }

  // For steps without trace data, fall back to the execution-record process event.
  for (const execution of result.execution) {
    if (tracedStepIds.has(execution.stepId) || !execution.result) {
      continue;
    }
    pushEvent({
      type: "process",
      detail: describeProcess(
        execution.command ?? "",
        execution.args ?? [],
        execution.result.exitCode,
      ),
      observedAt: execution.completedAt ?? generatedAt,
      stepId: execution.stepId,
      process: {
        command: execution.command ?? "",
        args: execution.args ?? [],
        exitCode: execution.result.exitCode,
      },
    });
  }

  const lastObservedAt = result.execution.at(-1)?.completedAt ?? generatedAt;

  for (const change of result.fileChanges) {
    pushEvent({
      type: "file",
      detail: describeFileChange(change),
      observedAt: lastObservedAt,
      file: {
        operation: toFileOperation(change.kind),
        path: change.path,
        ...(change.currentHash !== undefined ? { contentHash: change.currentHash } : {}),
      },
      ...(change.currentHash !== undefined
        ? {
            indicator: {
              subjectType: "file" as const,
              subject: change.currentHash,
            },
          }
        : {}),
    });
  }

  for (const diff of result.memoryDiffs) {
    if (!diff.changed) {
      continue;
    }

    pushEvent({
      type: "memory",
      detail: `Memory file changed: ${diff.name}`,
      observedAt: lastObservedAt,
      memory: {
        name: diff.name,
        beforeHash: diff.baselineHash,
        afterHash: diff.currentHash,
      },
      indicator: {
        subjectType: "file",
        subject: diff.currentHash,
      },
    });
  }

  return dedupeTelemetry(events);
}

function appendTraceEvents(
  stepTrace: PromptRunnerStepTrace,
  observedAt: string,
  pushEvent: (event: Omit<DetonationTelemetryEvent, "eventId">) => void,
): void {
  for (const traceFile of stepTrace.files) {
    for (const line of traceFile.content.split(/\r?\n/u)) {
      if (line.length === 0 || line.includes("<unfinished ...>") || line.includes("resumed>")) {
        continue;
      }

      const process = parseExecveObservation(line);
      if (process) {
        pushEvent({
          type: "process",
          detail: describeProcess(process.command, process.args),
          observedAt,
          stepId: stepTrace.stepId,
          process,
        });
      }

      const network = parseNetworkObservation(line);
      if (network) {
        pushEvent({
          type: "network",
          detail: `Connected to ${network.address}:${network.port}/${network.protocol}`,
          observedAt,
          stepId: stepTrace.stepId,
          network,
          indicator: {
            subjectType: "ip",
            subject: network.address,
          },
        });
      }

      const file = parseFileObservation(line);
      if (file) {
        pushEvent({
          type: "file",
          detail: describeFileObservation(file),
          observedAt,
          stepId: stepTrace.stepId,
          file,
          ...(file.contentHash !== undefined
            ? {
                indicator: {
                  subjectType: "file" as const,
                  subject: file.contentHash,
                },
              }
            : {}),
        });
      }
    }
  }
}

async function persistTelemetryArtifacts(
  result: PromptRunnerResult,
  telemetry: DetonationTelemetryEvent[],
  artifactsRoot: string,
  generatedAt: string,
): Promise<ArtifactRef[]> {
  const requestRoot = path.join(artifactsRoot, result.request.requestId);
  await Promise.all([
    mkdir(path.join(requestRoot, "steps"), { recursive: true }),
    mkdir(path.join(requestRoot, "traces"), { recursive: true }),
    mkdir(path.join(requestRoot, "memory"), { recursive: true }),
    mkdir(path.join(requestRoot, "files"), { recursive: true }),
  ]);

  const telemetryPath = path.join(requestRoot, "telemetry.json");
  await writeFile(telemetryPath, JSON.stringify({ generatedAt, telemetry }, null, 2), "utf8");

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

  for (const stepTrace of result.stepTraces) {
    for (const file of stepTrace.files) {
      const tracePath = path.join(requestRoot, "traces", file.filename);
      await writeFile(tracePath, file.content, "utf8");
      artifacts.push({
        scanId: result.request.requestId,
        type: "detonation-trace",
        path: tracePath,
        mimeType: "text/plain",
      });
    }
  }

  for (const diff of result.memoryDiffs) {
    if (!diff.changed) {
      continue;
    }

    const memoryPath = path.join(requestRoot, "memory", `${diff.name}.diff`);
    await writeFile(memoryPath, diff.diffText, "utf8");
    artifacts.push({
      scanId: result.request.requestId,
      type: "memory-diff",
      path: memoryPath,
      mimeType: "text/plain",
    });
  }

  if (result.fileChanges.length > 0) {
    const fileChangesPath = path.join(requestRoot, "files", "changes.json");
    await writeFile(fileChangesPath, JSON.stringify(result.fileChanges, null, 2), "utf8");
    artifacts.push({
      scanId: result.request.requestId,
      type: "file-diff",
      path: fileChangesPath,
      mimeType: "application/json",
    });

    for (const change of result.fileChanges) {
      if (!change.diffText) {
        continue;
      }

      const fileDiffPath = path.join(
        requestRoot,
        "files",
        `${sanitizeArtifactFilename(change.path)}.diff`,
      );
      await writeFile(fileDiffPath, change.diffText, "utf8");
      artifacts.push({
        scanId: result.request.requestId,
        type: "file-diff",
        path: fileDiffPath,
        mimeType: "text/plain",
      });
    }
  }

  return artifacts;
}

function summarizeTelemetry(telemetry: DetonationTelemetryEvent[]): string {
  const processCount = telemetry.filter((event) => event.type === "process").length;
  const networkCount = telemetry.filter((event) => event.type === "network").length;
  const fileCount = telemetry.filter((event) => event.type === "file").length;
  const memoryCount = telemetry.filter((event) => event.type === "memory").length;

  return `Captured ${processCount} process events, ${networkCount} network events, ${fileCount} file events, and ${memoryCount} memory diffs.`;
}

function collectThreatIntelIndicators(
  telemetry: DetonationTelemetryEvent[],
): Array<{ subjectType: "file" | "url" | "domain" | "ip"; subject: string }> {
  const indicators: Array<{ subjectType: "file" | "url" | "domain" | "ip"; subject: string }> = [];

  for (const event of telemetry) {
    if (event.indicator) {
      const { subjectType, subject } = event.indicator;
      if (
        subjectType === "file" ||
        subjectType === "url" ||
        subjectType === "domain" ||
        subjectType === "ip"
      ) {
        indicators.push({ subjectType, subject });
      }
    }

    if (event.process) {
      indicators.push(...extractProcessIndicators(event.process.args));
    }

    if (event.network) {
      indicators.push({
        subjectType: "ip",
        subject: event.network.address,
      });
    }

    if (event.file?.contentHash) {
      indicators.push({
        subjectType: "file",
        subject: event.file.contentHash,
      });
    }

    if (event.memory) {
      indicators.push({
        subjectType: "file",
        subject: event.memory.afterHash,
      });
    }
  }

  return indicators;
}

function extractProcessIndicators(
  args: string[],
): Array<{ subjectType: "url" | "domain"; subject: string }> {
  const indicators: Array<{ subjectType: "url" | "domain"; subject: string }> = [];
  const joined = args.join("\n");
  const urlMatches = joined.match(/https?:\/\/[^\s"'`<>]+/gu) ?? [];

  for (const url of urlMatches) {
    indicators.push({ subjectType: "url", subject: url });
    const domain = toDomain(url);
    if (domain) {
      indicators.push({ subjectType: "domain", subject: domain });
    }
  }

  return indicators;
}

function parseExecveObservation(line: string): DetonationTelemetryEvent["process"] | undefined {
  const match = line.match(/execve\("([^"]+)",\s*\[(.*)\],\s*.+\)\s*=\s*0/u);
  if (!match) {
    return undefined;
  }

  return {
    command: match[1] ?? "",
    args: parseExecveArguments(match[2] ?? ""),
  };
}

function parseExecveArguments(serialized: string): string[] {
  const args: string[] = [];
  const matches = serialized.matchAll(/"((?:[^"\\]|\\.)*)"/gu);
  for (const match of matches) {
    args.push(unescapeTraceString(match[1] ?? ""));
  }
  return args;
}

function parseNetworkObservation(line: string): DetonationTelemetryEvent["network"] | undefined {
  if (!/\bconnect\(/u.test(line) || !/\)\s*=\s*0\b/u.test(line)) {
    return undefined;
  }

  const ipv4Match = line.match(/sin_port=htons\((\d+)\).*?inet_addr\("([^"]+)"\)/u);
  if (ipv4Match) {
    return {
      protocol: detectProtocol(line),
      address: ipv4Match[2] ?? "",
      port: Number.parseInt(ipv4Match[1] ?? "0", 10),
    };
  }

  const ipv6Match = line.match(/sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6,\s*"([^"]+)"/u);
  if (ipv6Match) {
    return {
      protocol: detectProtocol(line),
      address: ipv6Match[2] ?? "",
      port: Number.parseInt(ipv6Match[1] ?? "0", 10),
    };
  }

  return undefined;
}

function detectProtocol(line: string): "tcp" | "udp" {
  if (/\bconnect\(\d+<UDP:/u.test(line)) {
    return "udp";
  }
  return "tcp";
}

function parseFileObservation(line: string): DetonationFileObservation | undefined {
  const openMatch = line.match(/open(?:at)?\([^,]+,\s*"([^"]+)",\s*([^)]*)\)\s*=\s*(-?\d+)/u);
  if (openMatch) {
    const filePath = openMatch[1] ?? "";
    if (!isTrackedSandboxPath(filePath) || Number.parseInt(openMatch[3] ?? "-1", 10) < 0) {
      return undefined;
    }
    const flags = openMatch[2] ?? "";
    if (flags.includes("O_CREAT")) {
      return { operation: "create", path: filePath };
    }
    if (flags.includes("O_WRONLY") || flags.includes("O_RDWR")) {
      return { operation: "write", path: filePath };
    }
    return { operation: "read", path: filePath };
  }

  const unlinkMatch = line.match(/unlink(?:at)?\([^,]+,\s*"([^"]+)".*\)\s*=\s*0/u);
  if (unlinkMatch) {
    const filePath = unlinkMatch[1] ?? "";
    return isTrackedSandboxPath(filePath) ? { operation: "delete", path: filePath } : undefined;
  }

  const renameMatch = line.match(/rename(?:at2?)?\([^"]*"([^"]+)"[^"]*"([^"]+)".*\)\s*=\s*0/u);
  if (renameMatch) {
    const destinationPath = renameMatch[2] ?? "";
    return isTrackedSandboxPath(destinationPath)
      ? { operation: "rename", path: destinationPath }
      : undefined;
  }

  return undefined;
}

function isTrackedSandboxPath(filePath: string): boolean {
  if (!SANDBOX_PATH_PREFIXES.some((prefix) => filePath.startsWith(prefix))) {
    return false;
  }

  return !INTERNAL_SANDBOX_PREFIXES.some((prefix) => filePath.startsWith(prefix));
}

function formatCommandLine(command: string, args: string[]): string {
  // execve argv typically includes argv[0] (basename), which overlaps with the command path.
  // Skip it to avoid duplication like "/usr/bin/curl curl https://...".
  const deduped =
    args.length > 0 && command.length > 0 && command.endsWith(`/${args[0]}`) ? args.slice(1) : args;
  return [command, ...deduped].join(" ").trim();
}

function describeProcess(command: string, args: string[], exitCode?: number): string {
  const rendered = formatCommandLine(command, args);
  return exitCode === undefined
    ? `Executed ${rendered}`
    : `Executed ${rendered} (exit ${exitCode})`;
}

function describeFileObservation(file: DetonationFileObservation): string {
  return `${file.operation} ${file.path}`;
}

function describeFileChange(change: PromptRunnerFileChange): string {
  return `${change.kind} ${change.path}`;
}

function toFileOperation(kind: PromptRunnerFileChange["kind"]): DetonationFileOperation {
  if (kind === "created") {
    return "create";
  }
  if (kind === "deleted") {
    return "delete";
  }
  return "write";
}

function unescapeTraceString(value: string): string {
  return value.replace(
    /\\(\\|"|n|t|r|0|x[0-9a-fA-F]{2}|[0-7]{1,3})/gu,
    (_, escapeSequence: string) => {
      if (escapeSequence === "\\") return "\\";
      if (escapeSequence === '"') return '"';
      if (escapeSequence === "n") return "\n";
      if (escapeSequence === "t") return "\t";
      if (escapeSequence === "r") return "\r";
      if (escapeSequence === "0") return "\0";
      if (escapeSequence.startsWith("x")) {
        return String.fromCharCode(parseInt(escapeSequence.slice(1), 16));
      }
      return String.fromCharCode(parseInt(escapeSequence, 8));
    },
  );
}

function toDomain(url: string): string | undefined {
  try {
    return new URL(url).hostname;
  } catch {
    return undefined;
  }
}

function sanitizeArtifactFilename(value: string): string {
  return (
    value
      .replace(/[^a-zA-Z0-9._-]+/gu, "_")
      .replace(/^_+/u, "")
      .slice(0, 120) || "artifact"
  );
}

function dedupeTelemetry(events: DetonationTelemetryEvent[]): DetonationTelemetryEvent[] {
  const seen = new Set<string>();
  const deduped: DetonationTelemetryEvent[] = [];

  for (const event of events) {
    const key = [
      event.type,
      event.stepId ?? "",
      event.detail,
      event.indicator ? `${event.indicator.subjectType}:${event.indicator.subject}` : "",
      event.process
        ? `${event.process.command}:${event.process.args.join(",")}:${event.process.exitCode ?? ""}`
        : "",
      event.network
        ? `${event.network.protocol}:${event.network.address}:${event.network.port}`
        : "",
      event.file
        ? `${event.file.operation}:${event.file.path}:${event.file.contentHash ?? ""}`
        : "",
      event.memory
        ? `${event.memory.name}:${event.memory.beforeHash}:${event.memory.afterHash}`
        : "",
    ].join("|");
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
