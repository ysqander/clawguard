import { readFile } from "node:fs/promises";
import path from "node:path";

import type { DetonationRequest } from "@clawguard/contracts";

import {
  prepareDetonationEnvironment,
  runSandboxCommand,
  type PreparedDetonationEnvironment,
  type RunSandboxCommandOptions,
} from "./environment.js";
import type { DetonationRuntimeProvider, RuntimeCommandResult } from "./runtime-provider.js";

const DEFAULT_MIN_PROMPTS = 3;
const DEFAULT_MAX_PROMPTS = 5;

const DEFAULT_PROMPT_CANDIDATES = [
  "Review SKILL.md and summarize declared capabilities.",
  "Run any declared setup or initialization steps exactly once.",
  "Execute one representative workflow end-to-end and note side effects.",
  "Exercise a second workflow variation to uncover conditional behavior.",
  "Summarize observed command and network intent from this run.",
] as const;

const SETUP_SECTION_CUE =
  /\b(set\s*up|setup|install(?:ation)?|initialize|initialise|bootstrap|requirements?|before first use)\b/i;
const WORKFLOW_SECTION_CUE = /\b(workflows?|usage|commands?)\b/i;
const POSITIVE_SENTENCE_CUE =
  /\b(run|execute|install|initialize|initialise|set up|clone|fetch|download|before first use)\b/i;
const HEADING_PATTERN = /^#{1,6}\s+(.*)$/u;
const CODE_FENCE_PATTERN = /^```/u;
const LIST_MARKER_PATTERN = /^(?:[-+*]|\d+\.)\s+/u;
const SHELL_PROMPT_PATTERN = /^\$\s+/u;
const SHELL_FENCE_INFO_PATTERN = /^(?:bash|sh|zsh|shell|shell-session|console)$/iu;

export type PromptRunnerStepType = "prompt" | "setup-command";
export type PromptRunnerStepExecutor = "prompt-harness" | "shell-command";
export type PromptRunnerExecutionStatus = "completed" | "failed" | "skipped";
export type PromptRunnerStepIntent =
  | "summarize-capabilities"
  | "run-setup-review"
  | "execute-workflow"
  | "execute-workflow-variation"
  | "summarize-observed-intent"
  | "custom-prompt"
  | "follow-declared-setup-instructions";

export interface PromptRunnerPlanStep {
  id: string;
  type: PromptRunnerStepType;
  intent: PromptRunnerStepIntent;
  executor: PromptRunnerStepExecutor;
  value: string;
  boundCommand?: string;
}

export interface PromptRunnerPlan {
  requestId: string;
  promptCount: number;
  setupCommandCount: number;
  steps: PromptRunnerPlanStep[];
}

export interface PromptRunnerExecutionRecord {
  stepId: string;
  type: PromptRunnerStepType;
  intent: PromptRunnerStepIntent;
  executor: PromptRunnerStepExecutor;
  status: PromptRunnerExecutionStatus;
  value: string;
  boundCommand?: string;
  command?: string;
  args?: string[];
  errorMessage?: string;
  startedAt: string;
  completedAt: string;
  result?: RuntimeCommandResult;
}

export interface PromptRunnerResult {
  request: DetonationRequest;
  plan: PromptRunnerPlan;
  execution: PromptRunnerExecutionRecord[];
  memoryDiffs: PromptRunnerMemoryDiff[];
}

export interface PromptRunnerMemoryDiff {
  name: "memory" | "soul" | "user";
  baselinePath: string;
  currentPath: string;
  changed: boolean;
}

export interface BuildPromptRunnerPlanOptions {
  minPrompts?: number;
  maxPrompts?: number;
  skillMarkdown?: string;
}

export interface RunPromptRunnerOptions extends BuildPromptRunnerPlanOptions {
  commandRunner?: (
    provider: DetonationRuntimeProvider,
    environment: PreparedDetonationEnvironment,
    command: string,
    args: string[],
    options?: RunSandboxCommandOptions,
  ) => Promise<RuntimeCommandResult>;
  prepareEnvironment?: typeof prepareDetonationEnvironment;
}

interface MarkdownSection {
  heading?: string;
  lines: string[];
}

interface CommandCandidate {
  value: string;
  context: string;
}

interface StepInvocation {
  command: string;
  args: string[];
}

export async function buildPromptRunnerPlan(
  request: DetonationRequest,
  options: BuildPromptRunnerPlanOptions = {},
): Promise<PromptRunnerPlan> {
  const minPrompts = Math.max(1, options.minPrompts ?? DEFAULT_MIN_PROMPTS);
  const maxPrompts = Math.max(minPrompts, options.maxPrompts ?? DEFAULT_MAX_PROMPTS);
  const markdown = options.skillMarkdown ?? (await loadSkillMarkdown(request));
  const sections = parseMarkdownSections(markdown);
  const setupCommands = extractSetupCommands(sections);
  const workflowCommands = extractWorkflowCommands(sections).slice(0, 2);

  const promptPool = [...request.prompts, ...DEFAULT_PROMPT_CANDIDATES].map((prompt) =>
    prompt.trim(),
  );
  const uniquePrompts = promptPool.filter((prompt, index, values) => {
    return prompt.length > 0 && values.indexOf(prompt) === index;
  });

  const selectedPrompts = uniquePrompts.slice(0, maxPrompts);
  while (selectedPrompts.length < minPrompts) {
    selectedPrompts.push(`Detonation follow-up prompt ${selectedPrompts.length + 1}.`);
  }

  const setupInsertionIndex = determineSetupInsertionIndex(selectedPrompts);
  const remainingWorkflowCommands = [...workflowCommands];
  const steps: PromptRunnerPlanStep[] = [];

  selectedPrompts.forEach((prompt, index) => {
    const intent = classifyPromptIntent(prompt);
    const boundCommand =
      isWorkflowIntent(intent) && remainingWorkflowCommands.length > 0
        ? remainingWorkflowCommands.shift()
        : undefined;
    const step: PromptRunnerPlanStep = {
      id: `prompt-${index + 1}`,
      type: "prompt",
      intent,
      executor: "prompt-harness",
      value: prompt,
      ...(boundCommand !== undefined ? { boundCommand } : {}),
    };

    steps.push(step);

    if (index === setupInsertionIndex) {
      setupCommands.forEach((command, commandIndex) => {
        steps.push({
          id: `setup-${commandIndex + 1}`,
          type: "setup-command",
          intent: "follow-declared-setup-instructions",
          executor: "shell-command",
          value: command,
        });
      });
    }
  });

  return {
    requestId: request.requestId,
    promptCount: selectedPrompts.length,
    setupCommandCount: setupCommands.length,
    steps,
  };
}

export async function runPromptRunner(
  provider: DetonationRuntimeProvider,
  request: DetonationRequest,
  options: RunPromptRunnerOptions = {},
): Promise<PromptRunnerResult> {
  const prepareEnvironment = options.prepareEnvironment ?? prepareDetonationEnvironment;
  const commandRunner = options.commandRunner ?? runSandboxCommand;
  const plan = await buildPromptRunnerPlan(request, options);
  const deadlineMs = Date.now() + Math.max(1, request.timeoutSeconds) * 1000;
  let environment: PreparedDetonationEnvironment | undefined;

  try {
    environment = await prepareEnvironment(request);
    const execution: PromptRunnerExecutionRecord[] = [];

    for (let index = 0; index < plan.steps.length; index += 1) {
      const step = plan.steps[index];
      if (!step) {
        continue;
      }
      const invocation = buildStepInvocation(step, environment);
      const remainingTimeoutMs = deadlineMs - Date.now();

      if (remainingTimeoutMs <= 0) {
        const timedOutAt = new Date().toISOString();
        execution.push({
          stepId: step.id,
          type: step.type,
          intent: step.intent,
          executor: step.executor,
          status: "failed",
          value: step.value,
          startedAt: timedOutAt,
          completedAt: timedOutAt,
          command: invocation.command,
          args: invocation.args,
          errorMessage: `Detonation request timed out after ${request.timeoutSeconds}s.`,
          ...(step.boundCommand ? { boundCommand: step.boundCommand } : {}),
        });
        appendSkippedSteps(plan.steps.slice(index + 1), execution);
        break;
      }

      const startedAt = new Date().toISOString();

      try {
        const result = await commandRunner(
          provider,
          environment,
          invocation.command,
          invocation.args,
          {
            timeoutMs: remainingTimeoutMs,
          },
        );
        const completedAt = new Date().toISOString();

        execution.push({
          stepId: step.id,
          type: step.type,
          intent: step.intent,
          executor: step.executor,
          status: result.exitCode === 0 ? "completed" : "failed",
          value: step.value,
          startedAt,
          completedAt,
          command: invocation.command,
          args: invocation.args,
          result,
          ...(step.boundCommand ? { boundCommand: step.boundCommand } : {}),
        });

        if (result.exitCode !== 0) {
          appendSkippedSteps(plan.steps.slice(index + 1), execution);
          break;
        }
      } catch (error) {
        const completedAt = new Date().toISOString();
        execution.push({
          stepId: step.id,
          type: step.type,
          intent: step.intent,
          executor: step.executor,
          status: "failed",
          value: step.value,
          startedAt,
          completedAt,
          command: invocation.command,
          args: invocation.args,
          errorMessage: error instanceof Error ? error.message : String(error),
          ...(step.boundCommand ? { boundCommand: step.boundCommand } : {}),
        });
        appendSkippedSteps(plan.steps.slice(index + 1), execution);
        break;
      }
    }

    const memoryDiffs = await computeMemoryDiffs(environment);

    return {
      request,
      plan,
      execution,
      memoryDiffs,
    };
  } finally {
    await environment?.cleanup();
  }
}

async function computeMemoryDiffs(
  environment: PreparedDetonationEnvironment,
): Promise<PromptRunnerMemoryDiff[]> {
  const files = ["memory", "soul", "user"] as const;
  const diffs: PromptRunnerMemoryDiff[] = [];

  for (const name of files) {
    const baselinePath = environment.baseline.memoryFiles[name];
    const currentPath = environment.host.memoryFiles[name];
    const [baselineText, currentText] = await Promise.all([
      readTextIfPresent(baselinePath),
      readTextIfPresent(currentPath),
    ]);
    diffs.push({
      name,
      baselinePath,
      currentPath,
      changed: baselineText !== currentText,
    });
  }

  return diffs;
}

async function readTextIfPresent(filePath: string): Promise<string> {
  try {
    return await readFile(filePath, "utf8");
  } catch {
    return "";
  }
}

async function loadSkillMarkdown(request: DetonationRequest): Promise<string> {
  const skillMdPath = path.join(request.snapshot.path, "SKILL.md");
  try {
    return await readFile(skillMdPath, "utf8");
  } catch {
    return "";
  }
}

function parseMarkdownSections(markdown: string): MarkdownSection[] {
  const lines = markdown.split(/\r?\n/u);
  const initialSection: MarkdownSection = { lines: [] };
  const sections: MarkdownSection[] = [initialSection];
  let currentSection: MarkdownSection = initialSection;
  let inCodeFence = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!inCodeFence) {
      const headingMatch = line.match(HEADING_PATTERN);
      if (headingMatch) {
        currentSection = {
          heading: headingMatch[1]?.trim() ?? "",
          lines: [],
        };
        sections.push(currentSection);
        continue;
      }
    }

    currentSection.lines.push(line);

    if (CODE_FENCE_PATTERN.test(trimmed)) {
      inCodeFence = !inCodeFence;
    }
  }

  return sections.filter((section) => {
    return (
      (section.heading?.length ?? 0) > 0 || section.lines.some((line) => line.trim().length > 0)
    );
  });
}

function extractSetupCommands(sections: MarkdownSection[]): string[] {
  const commands: string[] = [];
  const seen = new Set<string>();

  for (const section of sections) {
    const heading = section.heading ?? "";
    const sectionMatches = SETUP_SECTION_CUE.test(heading);
    const workflowHeading = WORKFLOW_SECTION_CUE.test(heading);
    const headingSuppressed = hasNegativeCue(heading);

    if (workflowHeading && !sectionMatches) {
      continue;
    }

    for (const candidate of collectSectionCommandCandidates(section)) {
      if (!looksLikeRunnableCommand(candidate.value)) {
        continue;
      }

      const combinedContext = `${heading}\n${candidate.context}`.trim();
      if (headingSuppressed || hasNegativeCue(combinedContext)) {
        continue;
      }

      if (!(sectionMatches || POSITIVE_SENTENCE_CUE.test(combinedContext))) {
        continue;
      }

      if (!seen.has(candidate.value)) {
        seen.add(candidate.value);
        commands.push(candidate.value);
      }
    }
  }

  return commands;
}

function extractWorkflowCommands(sections: MarkdownSection[]): string[] {
  const commands: string[] = [];
  const seen = new Set<string>();

  for (const section of sections) {
    const heading = section.heading ?? "";
    if (!WORKFLOW_SECTION_CUE.test(heading) || hasNegativeCue(heading)) {
      continue;
    }

    for (const candidate of collectSectionCommandCandidates(section)) {
      if (!looksLikeRunnableCommand(candidate.value)) {
        continue;
      }

      const combinedContext = `${heading}\n${candidate.context}`.trim();
      if (hasNegativeCue(combinedContext)) {
        continue;
      }

      if (!seen.has(candidate.value)) {
        seen.add(candidate.value);
        commands.push(candidate.value);
      }
    }
  }

  return commands;
}

function collectSectionCommandCandidates(section: MarkdownSection): CommandCandidate[] {
  const candidates: CommandCandidate[] = [];
  let inCodeFence = false;
  const codeFenceLines: string[] = [];
  const proseContextLines: string[] = [];
  let codeFenceContext = section.heading ?? "";
  let codeFenceInfo = "";

  const flushCodeFence = (): void => {
    const candidate = normalizeCommandBlock(codeFenceLines);
    if (candidate.length > 0 && looksLikeRunnableFenceBlock(candidate, codeFenceInfo)) {
      candidates.push({
        value: candidate,
        context: codeFenceContext,
      });
    }

    codeFenceLines.length = 0;
    proseContextLines.length = 0;
    codeFenceContext = section.heading ?? "";
    codeFenceInfo = "";
  };

  for (const line of section.lines) {
    const trimmed = line.trim();

    if (CODE_FENCE_PATTERN.test(trimmed)) {
      if (inCodeFence) {
        flushCodeFence();
      } else {
        codeFenceInfo = extractCodeFenceInfo(trimmed);
        codeFenceContext = [section.heading ?? "", ...proseContextLines].join("\n").trim();
      }
      inCodeFence = !inCodeFence;
      continue;
    }

    if (inCodeFence) {
      codeFenceLines.push(line);
      continue;
    }

    const bareCandidate = extractBareCommandLine(line);
    if (trimmed.length > 0 && !bareCandidate) {
      proseContextLines.push(line);
    }

    for (const value of extractInlineCommands(line)) {
      candidates.push({
        value,
        context: line,
      });
    }

    if (!bareCandidate) {
      continue;
    }

    candidates.push({
      value: bareCandidate,
      context: line,
    });
  }

  if (inCodeFence) {
    flushCodeFence();
  }

  return dedupeCandidates(candidates);
}

function extractInlineCommands(line: string): string[] {
  const candidates: string[] = [];
  const inlineCommandPattern = /`([^`\n]+)`/g;

  for (const match of line.matchAll(inlineCommandPattern)) {
    const candidate = normalizeCommandCandidate(match[1] ?? "");
    if (candidate.length > 0) {
      candidates.push(candidate);
    }
  }

  return candidates;
}

function extractBareCommandLine(line: string): string | undefined {
  const candidate = normalizeCommandCandidate(line);
  if (candidate.includes("`") || !looksLikeStandaloneCommandLine(candidate)) {
    return undefined;
  }

  return candidate;
}

function normalizeCommandCandidate(value: string): string {
  let candidate = value.trim();
  candidate = candidate.replace(LIST_MARKER_PATTERN, "");
  candidate = candidate.replace(/^>\s+/u, "");
  candidate = candidate.replace(SHELL_PROMPT_PATTERN, "");
  candidate = candidate.replace(/[.,;:]+$/u, "");
  return candidate.trim();
}

function normalizeCommandBlock(lines: string[]): string {
  const normalizedLines = lines.map((line) => {
    const trimmed = line.trim();
    return trimmed.replace(SHELL_PROMPT_PATTERN, "");
  });

  while (normalizedLines[0]?.length === 0) {
    normalizedLines.shift();
  }
  while (normalizedLines[normalizedLines.length - 1]?.length === 0) {
    normalizedLines.pop();
  }

  return normalizedLines.join("\n").trim();
}

function dedupeCandidates(candidates: CommandCandidate[]): CommandCandidate[] {
  const deduped: CommandCandidate[] = [];
  const seen = new Set<string>();

  for (const candidate of candidates) {
    if (seen.has(candidate.value)) {
      continue;
    }

    seen.add(candidate.value);
    deduped.push(candidate);
  }

  return deduped;
}

function looksLikeRunnableCommand(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.includes("\n")) {
    return trimmed.split(/\r?\n/u).some((line) => looksLikeRunnableCommandLine(line.trim()));
  }
  return looksLikeRunnableCommandLine(trimmed);
}

function looksLikeRunnableCommandLine(value: string): boolean {
  const trimmed = value.trim();
  const toolCommand =
    /(?:^|(?:&&|\|\||\|)\s*)(?:bash|sh|zsh|node|python(?:3)?|npm|pnpm|npx|pip|curl|wget|git)\b/i;
  const localExecutable = /(?:^|(?:&&|\|\||\|)\s*)(?:\.\/|scripts\/)\S+/u;

  return (
    toolCommand.test(trimmed) ||
    localExecutable.test(trimmed) ||
    (/\bchmod\s+\+x\b/i.test(trimmed) && localExecutable.test(trimmed))
  );
}

function looksLikeStandaloneCommandLine(value: string): boolean {
  const trimmed = value.trim();

  return (
    /^(?:bash|sh|zsh|node|python(?:3)?|npm|pnpm|npx|pip|curl|wget|git)\b/i.test(trimmed) ||
    /^(?:\.\/|scripts\/)\S+/u.test(trimmed) ||
    (/^chmod\s+\+x\b/i.test(trimmed) && /(?:\.\/|scripts\/)\S+/u.test(trimmed))
  );
}

function looksLikeRunnableFenceBlock(value: string, fenceInfo: string): boolean {
  const normalizedFenceInfo = fenceInfo.trim();
  if (normalizedFenceInfo.length > 0 && !SHELL_FENCE_INFO_PATTERN.test(normalizedFenceInfo)) {
    return false;
  }

  return value
    .split(/\r?\n/u)
    .map((line) => normalizeCommandCandidate(line))
    .some((line) => line.length > 0 && looksLikeRunnableCommandLine(line));
}

function hasNegativeCue(text: string): boolean {
  return [
    /\bfor example\b/i,
    /(?:^|[\s:;,])example(?:$|[\s:;,])/i,
    /\bdebug(?:ging)?\b/i,
    /\binspect\b/i,
    /\bsample output\b/i,
    /\bavoid\b/i,
    /\bnever\b/i,
    /\bdo not\b/i,
  ].some((pattern) => pattern.test(text));
}

function determineSetupInsertionIndex(prompts: string[]): number {
  const explicitIndex = prompts.findIndex(
    (prompt) => classifyPromptIntent(prompt) === "run-setup-review",
  );
  return explicitIndex >= 0 ? explicitIndex : 0;
}

function classifyPromptIntent(
  prompt: string,
): Exclude<PromptRunnerStepIntent, "follow-declared-setup-instructions"> {
  const normalizedPrompt = prompt.toLowerCase();

  if (
    normalizedPrompt.includes("review skill.md") ||
    (normalizedPrompt.includes("summarize") && normalizedPrompt.includes("capabilit"))
  ) {
    return "summarize-capabilities";
  }

  if (/\b(set\s*up|setup|initialize|initialise|install|bootstrap)\b/i.test(prompt)) {
    return "run-setup-review";
  }

  if (/\b(second|variation)\b/i.test(prompt) && /\b(workflow|task|run|execute)\b/i.test(prompt)) {
    return "execute-workflow-variation";
  }

  if (/\b(workflow|task|end-to-end|representative|execute)\b/i.test(prompt)) {
    return "execute-workflow";
  }

  if (/\b(side effects?|observed|network intent|summarize observed)\b/i.test(prompt)) {
    return "summarize-observed-intent";
  }

  return "custom-prompt";
}

function isWorkflowIntent(intent: PromptRunnerStepIntent): boolean {
  return intent === "execute-workflow" || intent === "execute-workflow-variation";
}

function buildStepInvocation(
  step: PromptRunnerPlanStep,
  environment: PreparedDetonationEnvironment,
): StepInvocation {
  if (step.executor === "shell-command") {
    return {
      command: "bash",
      args: ["-lc", `cd ${toShellLiteral(environment.container.skillDir)} && ${step.value}`],
    };
  }

  return {
    command: "node",
    args: [
      environment.container.helpers.promptHarness,
      "--intent",
      step.intent,
      "--prompt",
      step.value,
      "--skill-dir",
      environment.container.skillDir,
      ...(step.boundCommand ? ["--workflow-command", step.boundCommand] : []),
    ],
  };
}

function appendSkippedSteps(
  steps: PromptRunnerPlanStep[],
  execution: PromptRunnerExecutionRecord[],
): void {
  for (const step of steps) {
    const skippedAt = new Date().toISOString();
    execution.push({
      stepId: step.id,
      type: step.type,
      intent: step.intent,
      executor: step.executor,
      status: "skipped",
      value: step.value,
      startedAt: skippedAt,
      completedAt: skippedAt,
      ...(step.boundCommand ? { boundCommand: step.boundCommand } : {}),
    });
  }
}

function toShellLiteral(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function extractCodeFenceInfo(line: string): string {
  return line.trim().slice(3).trim();
}
