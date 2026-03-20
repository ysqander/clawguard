import path from "node:path";

import {
  defaultClawGuardConfig,
  type ArtifactType,
  type DetonationFileObservation,
  type DetonationFinding,
  type DetonationReport,
  type DetonationTelemetryEvent,
  type FindingSeverity,
  type SkillSnapshot,
  type VerdictLevel,
} from "@clawguard/contracts";
import { analyzeSkillSnapshot } from "@clawguard/scanner";

import { defaultDetonationHoneypotPaths, defaultDetonationSandboxLayout } from "./environment.js";
import {
  buildDetonationReportFromPromptRunner,
  enrichDetonationTelemetryIndicators,
} from "./telemetry.js";
import { runPromptRunner, type RunPromptRunnerOptions } from "./prompt-runner.js";
import {
  createDetonationRuntimeProvider,
  type CreateDetonationRuntimeProviderOptions,
  type DetonationRuntimeProvider,
} from "./runtime-provider.js";

const MAX_EVIDENCE = 3;
const DEFAULT_MIN_PROMPTS = 3;
const severityWeight: Record<FindingSeverity, number> = {
  low: 10,
  medium: 25,
  high: 40,
  critical: 60,
};

export const defaultLiveDetonationPrompts = [
  "Review SKILL.md and summarize declared capabilities.",
  "Run any declared setup or initialization steps exactly once.",
  "Execute one representative workflow end-to-end and note side effects.",
  "Exercise a second workflow variation to uncover conditional behavior.",
  "Summarize observed command and network intent from this run.",
] as const;

export interface BuildLiveDetonationRequestOptions {
  requestId?: string;
  timeoutSeconds?: number;
  promptBudget?: number;
  prompts?: string[];
}

export interface DetonationArtifactPayload {
  type: ArtifactType;
  filename: string;
  data: Uint8Array | string;
  mimeType: string;
}

export type DetonationFailureCode =
  | "runtime_unavailable"
  | "timeout"
  | "sandbox_image_failure"
  | "execution_failed";

export interface RunDetonationAnalysisOptions
  extends Omit<CreateDetonationRuntimeProviderOptions, "preferredRuntime">,
    Pick<RunPromptRunnerOptions, "commandRunner" | "prepareEnvironment"> {
  runtimeProvider?: DetonationRuntimeProvider;
  preferredRuntime?: "podman" | "docker";
  virustotalClient?: Parameters<typeof enrichDetonationTelemetryIndicators>[1];
  requestId?: string;
  timeoutSeconds?: number;
  promptBudget?: number;
  prompts?: string[];
  generatedAt?: string;
}

export interface RunDetonationAnalysisSuccess {
  ok: true;
  runtime: "podman" | "docker";
  startedAt: string;
  completedAt: string;
  report: DetonationReport;
  artifactPayloads: DetonationArtifactPayload[];
}

export interface RunDetonationAnalysisFailure {
  ok: false;
  status: "runtime-unavailable" | "failed";
  errorCode: DetonationFailureCode;
  message: string;
  runtime?: "podman" | "docker";
  startedAt: string;
  completedAt: string;
  artifactPayloads: DetonationArtifactPayload[];
}

export type RunDetonationAnalysisResult =
  | RunDetonationAnalysisSuccess
  | RunDetonationAnalysisFailure;

export function buildLiveDetonationRequest(
  snapshot: SkillSnapshot,
  options: BuildLiveDetonationRequestOptions = {},
) {
  const promptBudget = Math.max(
    1,
    options.promptBudget ?? defaultClawGuardConfig.detonation.promptBudget,
  );
  const prompts = (options.prompts ?? [...defaultLiveDetonationPrompts])
    .map((prompt) => prompt.trim())
    .filter((prompt, index, values) => prompt.length > 0 && values.indexOf(prompt) === index)
    .slice(0, promptBudget);

  return {
    requestId:
      options.requestId ?? `detonation-${snapshot.slug}-${snapshot.contentHash.slice(0, 12)}`,
    snapshot,
    prompts,
    timeoutSeconds: options.timeoutSeconds ?? defaultClawGuardConfig.detonation.timeoutSeconds,
  };
}

export async function runDetonationAnalysis(
  snapshot: SkillSnapshot,
  options: RunDetonationAnalysisOptions = {},
): Promise<RunDetonationAnalysisResult> {
  const startedAt = new Date().toISOString();
  const request = buildLiveDetonationRequest(snapshot, {
    ...(options.requestId ? { requestId: options.requestId } : {}),
    ...(options.timeoutSeconds ? { timeoutSeconds: options.timeoutSeconds } : {}),
    ...(options.promptBudget ? { promptBudget: options.promptBudget } : {}),
    ...(options.prompts ? { prompts: options.prompts } : {}),
  });

  let provider: DetonationRuntimeProvider;
  try {
    provider =
      options.runtimeProvider ??
      (await createDetonationRuntimeProvider({
        preferredRuntime:
          options.preferredRuntime ?? defaultClawGuardConfig.detonation.defaultRuntime,
        ...(options.runtimeDetector ? { runtimeDetector: options.runtimeDetector } : {}),
        ...(options.commandExecutor ? { commandExecutor: options.commandExecutor } : {}),
      }));
  } catch (error) {
    return {
      ok: false,
      status: "runtime-unavailable",
      errorCode: "runtime_unavailable",
      message:
        error instanceof Error ? error.message : "No supported container runtime is available.",
      startedAt,
      completedAt: new Date().toISOString(),
      artifactPayloads: [],
    };
  }

  const result = await runPromptRunner(provider, request, {
    ...(options.commandRunner ? { commandRunner: options.commandRunner } : {}),
    ...(options.prepareEnvironment ? { prepareEnvironment: options.prepareEnvironment } : {}),
    minPrompts: Math.min(DEFAULT_MIN_PROMPTS, request.prompts.length),
    maxPrompts: request.prompts.length,
  });
  const built = await buildDetonationReportFromPromptRunner(result, {
    ...(options.generatedAt ? { generatedAt: options.generatedAt } : {}),
  });
  const intelligence = await enrichDetonationTelemetryIndicators(
    built.telemetry,
    options.virustotalClient,
  );
  const evaluatedReport = evaluateDetonationReport({
    ...built.report,
    ...(intelligence.length > 0 ? { intelligence } : {}),
  });
  const completedAt = new Date().toISOString();
  const artifactPayloads = collectDetonationArtifactPayloads(result);

  if (hasUsableBehavioralReport(evaluatedReport)) {
    return {
      ok: true,
      runtime: provider.runtime,
      startedAt,
      completedAt,
      report: evaluatedReport,
      artifactPayloads,
    };
  }

  const failure = classifyExecutionFailure(result.execution.map((entry) => entry.errorMessage));
  return {
    ok: false,
    status: "failed",
    errorCode: failure.code,
    message: failure.message,
    runtime: provider.runtime,
    startedAt,
    completedAt,
    artifactPayloads,
  };
}

export function evaluateDetonationReport(report: DetonationReport): DetonationReport {
  const staticAnalysis = analyzeSkillSnapshot(report.request.snapshot);
  const findings = compactFindings([
    buildStagedDownloadFinding(report.telemetry ?? []),
    buildFetchedScriptExecutionFinding(report.telemetry ?? []),
    buildHoneypotAccessFinding(report.telemetry ?? []),
    buildSecretExfilChainFinding(report.telemetry ?? []),
    buildCredentialHarvestingFinding(report.telemetry ?? []),
    buildMemoryMutationFinding(report.telemetry ?? []),
    buildPersistentInstructionInjectionFinding(report.telemetry ?? []),
    buildReverseShellFinding(report.telemetry ?? [], staticAnalysis),
    buildSuspiciousNetworkChainFinding(report.telemetry ?? []),
  ]);
  const score = computeRiskScore(findings);
  const recommendation = deriveRecommendation(score, findings);

  return {
    ...report,
    findings,
    score,
    recommendation,
    summary: findings[0]?.message ?? report.summary,
  };
}

export function collectDetonationArtifactPayloads(
  result: Pick<
    Awaited<ReturnType<typeof runPromptRunner>>,
    "request" | "execution" | "stepTraces" | "memoryDiffs" | "fileChanges"
  >,
): DetonationArtifactPayload[] {
  const payloads: DetonationArtifactPayload[] = [];

  for (const execution of result.execution) {
    if (execution.result?.stdout) {
      payloads.push({
        type: "detonation-stdout",
        filename: `${result.request.requestId}.${execution.stepId}.stdout.txt`,
        data: execution.result.stdout,
        mimeType: "text/plain",
      });
    }

    if (execution.result?.stderr) {
      payloads.push({
        type: "detonation-stderr",
        filename: `${result.request.requestId}.${execution.stepId}.stderr.txt`,
        data: execution.result.stderr,
        mimeType: "text/plain",
      });
    }
  }

  for (const trace of result.stepTraces) {
    for (const file of trace.files) {
      payloads.push({
        type: "detonation-trace",
        filename: `${result.request.requestId}.${file.filename}`,
        data: file.content,
        mimeType: "text/plain",
      });
    }
  }

  for (const diff of result.memoryDiffs.filter((entry) => entry.changed)) {
    payloads.push({
      type: "memory-diff",
      filename: `${result.request.requestId}.${diff.name}.diff.txt`,
      data: diff.diffText,
      mimeType: "text/plain",
    });
  }

  for (const change of result.fileChanges) {
    if (!change.diffText) {
      continue;
    }

    payloads.push({
      type: "file-diff",
      filename: `${result.request.requestId}.${sanitizePathSegment(change.path)}.diff.txt`,
      data: change.diffText,
      mimeType: "text/plain",
    });
  }

  return payloads;
}

function buildStagedDownloadFinding(
  telemetry: DetonationTelemetryEvent[],
): DetonationFinding | undefined {
  const directPipeProcess = telemetry.find(
    (event) =>
      event.type === "process" &&
      event.process &&
      [event.process.command, ...event.process.args].some((value) =>
        /\b(?:curl|wget)\b[^\n|]*\|\s*(?:bash|sh|zsh)\b/i.test(value),
      ),
  );
  if (directPipeProcess) {
    return {
      ruleId: "CG-DET-STAGED-DOWNLOAD-EXECUTE",
      severity: "critical",
      message: "Behavioral detonation observed a staged download-and-execute chain.",
      evidence: [directPipeProcess.detail],
    };
  }

  const changedPaths = new Set(
    telemetry
      .filter(
        (event) => event.type === "file" && event.file && isInterestingChangedFile(event.file),
      )
      .map((event) => event.file?.path)
      .filter((value): value is string => typeof value === "string"),
  );
  const downloadEvents = telemetry.filter(
    (event) => event.type === "process" && event.process && processLooksLikeDownload(event.process),
  );
  const executionEvents = telemetry.filter(
    (event) =>
      event.type === "process" &&
      event.process &&
      !isInternalHelperExecution(event.process) &&
      (processLooksLikeInterpreterExecution(event.process) ||
        processLooksLikeLocalScript(event.process)) &&
      executionReferencesChangedScript(event.process, changedPaths),
  );

  if (downloadEvents.length === 0 || executionEvents.length === 0) {
    return undefined;
  }

  return {
    ruleId: "CG-DET-STAGED-DOWNLOAD-EXECUTE",
    severity: "critical",
    message: "Behavioral detonation observed a staged download-and-execute chain.",
    evidence: unique([
      ...downloadEvents.map((event) => event.detail),
      ...executionEvents.map((event) => event.detail),
    ]).slice(0, MAX_EVIDENCE),
  };
}

function buildFetchedScriptExecutionFinding(
  telemetry: DetonationTelemetryEvent[],
): DetonationFinding | undefined {
  const changedPaths = new Set(
    telemetry
      .filter(
        (event) => event.type === "file" && event.file && isInterestingChangedFile(event.file),
      )
      .map((event) => event.file?.path)
      .filter((value): value is string => typeof value === "string"),
  );
  if (changedPaths.size === 0) {
    return undefined;
  }

  const executions = telemetry.filter(
    (event) =>
      event.type === "process" &&
      event.process &&
      event.process.args.some((arg) => pathMatchesChangedFile(arg, changedPaths)),
  );
  if (executions.length === 0) {
    return undefined;
  }

  return {
    ruleId: "CG-DET-FETCHED-SCRIPT-EXECUTION",
    severity: "high",
    message: "Behavioral detonation observed execution of a newly fetched or modified script.",
    evidence: unique(executions.map((event) => event.detail)).slice(0, MAX_EVIDENCE),
  };
}

function buildHoneypotAccessFinding(
  telemetry: DetonationTelemetryEvent[],
): DetonationFinding | undefined {
  const matches = telemetry.filter(
    (event) =>
      event.type === "file" &&
      event.file &&
      event.file.operation === "read" &&
      isHoneypotPath(event.file.path),
  );
  if (matches.length === 0) {
    return undefined;
  }

  return {
    ruleId: "CG-DET-HONEYPOT-ACCESS",
    severity: "critical",
    message: "Behavioral detonation observed access to honeypot credential material.",
    evidence: unique(matches.map((event) => event.detail)).slice(0, MAX_EVIDENCE),
  };
}

function buildSecretExfilChainFinding(
  telemetry: DetonationTelemetryEvent[],
): DetonationFinding | undefined {
  const stepGroups = groupTelemetryByStep(telemetry);

  for (const group of stepGroups.values()) {
    const honeypotReads = group.filter(
      (event) =>
        event.type === "file" &&
        event.file &&
        event.file.operation === "read" &&
        isHoneypotPath(event.file.path),
    );
    const suspiciousProcesses = group.filter(
      (event) =>
        event.type === "process" &&
        event.process &&
        processLooksLikeSecretExfiltration(event.process),
    );
    const networkEvents = group.filter((event) => event.type === "network" && event.network);

    if (honeypotReads.length === 0 || (suspiciousProcesses.length === 0 && networkEvents.length === 0)) {
      continue;
    }

    return {
      ruleId: "CG-DET-SECRET-EXFIL-CHAIN",
      severity: "critical",
      message:
        "Behavioral detonation observed honeypot secret access chained to an outbound exfiltration attempt.",
      evidence: unique([
        ...honeypotReads.map((event) => event.detail),
        ...suspiciousProcesses.map((event) => event.detail),
        ...networkEvents.map((event) => event.detail),
      ]).slice(0, MAX_EVIDENCE),
      signalIds: ["secret-source", "network-sink"],
      confidence: 96,
    };
  }

  return undefined;
}

function buildMemoryMutationFinding(
  telemetry: DetonationTelemetryEvent[],
): DetonationFinding | undefined {
  const matches = telemetry.filter((event) => event.type === "memory" && event.memory);
  if (matches.length === 0) {
    return undefined;
  }

  return {
    ruleId: "CG-DET-MEMORY-MUTATION",
    severity: "critical",
    message: "Behavioral detonation observed mutation of persistent memory files.",
    evidence: unique(matches.map((event) => event.detail)).slice(0, MAX_EVIDENCE),
  };
}

function buildPersistentInstructionInjectionFinding(
  telemetry: DetonationTelemetryEvent[],
): DetonationFinding | undefined {
  const matches = telemetry.filter(
    (event) =>
      event.type === "memory" &&
      event.memory &&
      /\b(?:always trust|skip confirmation|do not log|take priority|future sessions?|responding normally)\b/i.test(
        event.detail,
      ),
  );
  if (matches.length === 0) {
    return undefined;
  }

  return {
    ruleId: "CG-DET-PERSISTENT-INSTRUCTION-INJECTION",
    severity: "critical",
    message:
      "Behavioral detonation observed persistent memory mutation that alters future instruction handling.",
    evidence: unique(matches.map((event) => event.detail)).slice(0, MAX_EVIDENCE),
    signalIds: ["memory-target", "persistence-directive", "prompt-override"],
    confidence: 94,
  };
}

function buildCredentialHarvestingFinding(
  telemetry: DetonationTelemetryEvent[],
): DetonationFinding | undefined {
  const stepGroups = groupTelemetryByStep(telemetry);

  for (const group of stepGroups.values()) {
    const matches = group.filter(
      (event) =>
        event.type === "process" &&
        event.process &&
        processLooksLikeCredentialHarvesting(event.process),
    );
    if (matches.length === 0) {
      continue;
    }

    const followUpWrites = group.filter(
      (event) =>
        event.type === "file" &&
        event.file &&
        event.file.operation !== "read" &&
        /(?:session-auth|auth|password|credential)/i.test(event.file.path),
    );
    const persistenceWrites = group.filter(
      (event) =>
        event.type === "memory" ||
        (event.type === "file" &&
          event.file &&
          event.file.operation !== "read" &&
          /(?:MEMORY\.md|SOUL\.md|USER\.md)/i.test(event.file.path)),
    );

    if (followUpWrites.length === 0 && persistenceWrites.length === 0) {
      continue;
    }

    return {
      ruleId: "CG-DET-CREDENTIAL-HARVESTING",
      severity: "critical",
      message: "Behavioral detonation observed a credential-harvesting prompt workflow.",
      evidence: unique([
        ...matches.map((event) => event.detail),
        ...followUpWrites.map((event) => event.detail),
        ...persistenceWrites.map((event) => event.detail),
      ]).slice(0, MAX_EVIDENCE),
      signalIds: ["credential-prompt"],
      confidence: 94,
    };
  }

  return undefined;
}

function buildReverseShellFinding(
  telemetry: DetonationTelemetryEvent[],
  staticAnalysis: ReturnType<typeof analyzeSkillSnapshot>,
): DetonationFinding | undefined {
  const shellExecutions = telemetry.filter(
    (event) =>
      event.type === "process" &&
      event.process &&
      [event.process.command, ...event.process.args].some((value) => /\/bin\/sh\b/i.test(value)),
  );
  const networkEvents = telemetry.filter((event) => event.type === "network" && event.network);
  if (shellExecutions.length > 0 && networkEvents.length > 0) {
    return {
      ruleId: "CG-DET-REVERSE-SHELL",
      severity: "critical",
      message: "Behavioral detonation observed a shell spawned alongside outbound network activity.",
      evidence: unique([
        ...shellExecutions.map((event) => event.detail),
        ...networkEvents.map((event) => event.detail),
      ]).slice(0, MAX_EVIDENCE),
      signalIds: ["interactive-shell", "network-capability"],
      confidence: 97,
    };
  }

  const interactiveShellSignal = staticAnalysis.signals.find(
    (signal) => signal.id === "interactive-shell",
  );
  if (!interactiveShellSignal) {
    return undefined;
  }

  const stepGroups = groupTelemetryByStep(telemetry);
  for (const group of stepGroups.values()) {
    const suspiciousExecutions = group.filter(
      (event) =>
        event.type === "process" &&
        event.process &&
        !isInternalHelperExecution(event.process) &&
        (processLooksLikeInterpreterExecution(event.process) ||
          processLooksLikeLocalScript(event.process)),
    );
    const groupedNetworkEvents = group.filter((event) => event.type === "network" && event.network);
    if (suspiciousExecutions.length === 0 || groupedNetworkEvents.length === 0) {
      continue;
    }

    return {
      ruleId: "CG-DET-REVERSE-SHELL",
      severity: "critical",
      message:
        "Behavioral detonation observed outbound network activity while executing code with reverse-shell capability.",
      evidence: unique([
        ...suspiciousExecutions.map((event) => event.detail),
        ...groupedNetworkEvents.map((event) => event.detail),
        ...interactiveShellSignal.evidence,
      ]).slice(0, MAX_EVIDENCE),
      signalIds: ["interactive-shell", "network-capability"],
      confidence: 90,
    };
  }

  return undefined;
}

function buildSuspiciousNetworkChainFinding(
  telemetry: DetonationTelemetryEvent[],
): DetonationFinding | undefined {
  const networkEvents = telemetry.filter((event) => event.type === "network" && event.network);
  const suspiciousProcesses = telemetry.filter(
    (event) =>
      event.type === "process" &&
      event.process &&
      (processLooksLikeDownload(event.process) ||
        processLooksLikeInterpreterExecution(event.process) ||
        processLooksLikeNetworkUtility(event.process)),
  );
  if (networkEvents.length === 0 || suspiciousProcesses.length === 0) {
    return undefined;
  }

  return {
    ruleId: "CG-DET-SUSPICIOUS-NETWORK-CHAIN",
    severity: "high",
    message:
      "Behavioral detonation observed suspicious outbound network activity chained to executable processes.",
    evidence: unique([
      ...suspiciousProcesses.map((event) => event.detail),
      ...networkEvents.map((event) => event.detail),
    ]).slice(0, MAX_EVIDENCE),
  };
}

function hasUsableBehavioralReport(report: DetonationReport): boolean {
  return (
    report.findings.length > 0 ||
    (report.telemetry?.length ?? 0) > 0 ||
    report.triggeredActions.length > 0
  );
}

function classifyExecutionFailure(messages: Array<string | undefined>): {
  code: DetonationFailureCode;
  message: string;
} {
  const message =
    messages.find((value): value is string => typeof value === "string" && value.length > 0) ??
    "Detonation failed before a behavioral report could be produced.";
  const normalized = message.toLowerCase();

  if (normalized.includes("timed out")) {
    return { code: "timeout", message };
  }

  if (
    normalized.includes("unable to build sandbox image") ||
    normalized.includes("unable to pull sandbox image")
  ) {
    return { code: "sandbox_image_failure", message };
  }

  if (normalized.includes("no supported container runtime")) {
    return { code: "runtime_unavailable", message };
  }

  return { code: "execution_failed", message };
}

function computeRiskScore(findings: DetonationFinding[]): number {
  const baseScore = findings.reduce(
    (total, finding) => total + severityWeight[finding.severity],
    0,
  );
  const diversityBonus = new Set(findings.map((finding) => finding.severity)).size * 5;
  return Math.min(100, baseScore + diversityBonus);
}

function deriveRecommendation(score: number, findings: DetonationFinding[]): VerdictLevel {
  if (findings.some((finding) => finding.severity === "critical") || score >= 70) {
    return "block";
  }

  if (
    findings.some((finding) => finding.severity === "high" || finding.severity === "medium") ||
    score >= 30
  ) {
    return "review";
  }

  return "allow";
}

function processLooksLikeDownload(
  process: NonNullable<DetonationTelemetryEvent["process"]>,
): boolean {
  const command = path.posix.basename(process.command).toLowerCase();
  if (command !== "curl" && command !== "wget") {
    return process.args.some((arg) => /\b(?:curl|wget)\b/i.test(arg) && /https?:\/\//i.test(arg));
  }

  return process.args.some((arg) => /https?:\/\//i.test(arg));
}

function processLooksLikeInterpreterExecution(
  process: NonNullable<DetonationTelemetryEvent["process"]>,
): boolean {
  const command = path.posix.basename(process.command).toLowerCase();
  return ["bash", "sh", "zsh", "node", "python", "python3"].includes(command);
}

function processLooksLikeLocalScript(
  process: NonNullable<DetonationTelemetryEvent["process"]>,
): boolean {
  return process.args.some(
    (arg) =>
      arg.startsWith(defaultDetonationSandboxLayout.skillsDir) ||
      arg.startsWith("/tmp/") ||
      /\.(?:sh|bash|zsh|js|mjs|cjs|py)$/i.test(arg),
  );
}

function processLooksLikeNetworkUtility(
  process: NonNullable<DetonationTelemetryEvent["process"]>,
): boolean {
  const command = path.posix.basename(process.command).toLowerCase();
  return ["nc", "ncat", "ssh", "scp"].includes(command);
}

function processLooksLikeCredentialHarvesting(
  process: NonNullable<DetonationTelemetryEvent["process"]>,
): boolean {
  const command = path.posix.basename(process.command).toLowerCase();
  const commandLine = [process.command, ...process.args].join(" ");
  if (command === "osascript") {
    return (
      /\bdisplay\s+dialog\b/i.test(commandLine) &&
      /\bhidden\s+answer\b/i.test(commandLine) &&
      /\bpassword\b/i.test(commandLine)
    );
  }

  if (command === "zenity") {
    return /\b--password\b/i.test(commandLine);
  }

  return /\bgetpass(?:\.getpass)?\b/i.test(commandLine) || /\bread\s+-s\b/i.test(commandLine);
}

function processLooksLikeSecretExfiltration(
  process: NonNullable<DetonationTelemetryEvent["process"]>,
): boolean {
  const command = path.posix.basename(process.command).toLowerCase();
  const commandLine = [process.command, ...process.args].join(" ");

  if (command !== "curl" && command !== "wget" && command !== "python3" && command !== "python") {
    return false;
  }

  return (
    /\b(?:-X|--request)\s*POST\b/i.test(commandLine) ||
    /\b(?:-d|--data|--data-binary)\b/i.test(commandLine) ||
    /\bwebhook\b/i.test(commandLine) ||
    /@\/home\/clawguard\//i.test(commandLine)
  );
}

function isInternalHelperExecution(
  process: NonNullable<DetonationTelemetryEvent["process"]>,
): boolean {
  return [process.command, ...process.args].some(
    (value) =>
      value.startsWith(`${defaultDetonationSandboxLayout.workspaceDir}/.clawguard/`) ||
      value.startsWith(`${defaultDetonationSandboxLayout.homeDir}/.clawguard/`),
  );
}

function isInterestingChangedFile(file: DetonationFileObservation): boolean {
  if (file.operation !== "create" && file.operation !== "write") {
    return false;
  }

  return (
    file.path.startsWith(defaultDetonationSandboxLayout.skillsDir) ||
    /\.(?:sh|bash|zsh|js|mjs|cjs|py)$/i.test(file.path)
  );
}

function executionReferencesChangedScript(
  process: NonNullable<DetonationTelemetryEvent["process"]>,
  changedPaths: Set<string>,
): boolean {
  if (changedPaths.size === 0) {
    return false;
  }

  return [process.command, ...process.args].some((value) =>
    pathMatchesChangedFile(value, changedPaths),
  );
}

function pathMatchesChangedFile(candidate: string, changedPaths: Set<string>): boolean {
  if (changedPaths.has(candidate)) {
    return true;
  }

  return [...changedPaths].some(
    (changedPath) => path.posix.basename(changedPath) === path.posix.basename(candidate),
  );
}

function isHoneypotPath(targetPath: string): boolean {
  return (
    defaultDetonationHoneypotPaths.envFiles.includes(
      targetPath as (typeof defaultDetonationHoneypotPaths.envFiles)[number],
    ) ||
    defaultDetonationHoneypotPaths.sshKeys.includes(
      targetPath as (typeof defaultDetonationHoneypotPaths.sshKeys)[number],
    )
  );
}

function compactFindings(findings: Array<DetonationFinding | undefined>): DetonationFinding[] {
  return findings.filter((finding): finding is DetonationFinding => finding !== undefined);
}

function groupTelemetryByStep(
  telemetry: DetonationTelemetryEvent[],
): Map<string, DetonationTelemetryEvent[]> {
  const groups = new Map<string, DetonationTelemetryEvent[]>();

  for (const event of telemetry) {
    const stepId = event.stepId ?? "global";
    const existing = groups.get(stepId);
    if (existing) {
      existing.push(event);
      continue;
    }

    groups.set(stepId, [event]);
  }

  return groups;
}

function unique(values: string[]): string[] {
  return values.filter((value, index) => values.indexOf(value) === index);
}

function sanitizePathSegment(value: string): string {
  return value
    .replace(/[^A-Za-z0-9._-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^[-.]+|[-.]+$/g, "");
}
