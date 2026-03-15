import { readFile } from "node:fs/promises";
import path from "node:path";

import type { DetonationRequest } from "@clawguard/contracts";

import {
  prepareDetonationEnvironment,
  runSandboxCommand,
  type PreparedDetonationEnvironment,
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

export interface PromptRunnerPlanStep {
  id: string;
  type: "prompt" | "setup-command";
  intent: string;
  value: string;
}

export interface PromptRunnerPlan {
  requestId: string;
  promptCount: number;
  setupCommandCount: number;
  steps: PromptRunnerPlanStep[];
}

export interface PromptRunnerExecutionRecord {
  stepId: string;
  type: PromptRunnerPlanStep["type"];
  intent: string;
  value: string;
  startedAt: string;
  completedAt: string;
  result?: RuntimeCommandResult;
}

export interface PromptRunnerResult {
  request: DetonationRequest;
  plan: PromptRunnerPlan;
  execution: PromptRunnerExecutionRecord[];
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
  ) => Promise<RuntimeCommandResult>;
  prepareEnvironment?: typeof prepareDetonationEnvironment;
}

export async function buildPromptRunnerPlan(
  request: DetonationRequest,
  options: BuildPromptRunnerPlanOptions = {},
): Promise<PromptRunnerPlan> {
  const minPrompts = Math.max(1, options.minPrompts ?? DEFAULT_MIN_PROMPTS);
  const maxPrompts = Math.max(minPrompts, options.maxPrompts ?? DEFAULT_MAX_PROMPTS);
  const markdown = options.skillMarkdown ?? (await loadSkillMarkdown(request));
  const setupCommands = extractSetupCommands(markdown);

  const promptPool = [...request.prompts, ...DEFAULT_PROMPT_CANDIDATES].map((prompt) => prompt.trim());
  const uniquePrompts = promptPool.filter((prompt, index, values) => {
    return prompt.length > 0 && values.indexOf(prompt) === index;
  });

  const selectedPrompts = uniquePrompts.slice(0, maxPrompts);
  while (selectedPrompts.length < minPrompts) {
    selectedPrompts.push(`Detonation follow-up prompt ${selectedPrompts.length + 1}.`);
  }

  const steps: PromptRunnerPlanStep[] = [];

  selectedPrompts.forEach((prompt, index) => {
    steps.push({
      id: `prompt-${index + 1}`,
      type: "prompt",
      intent: "exercise-skill-capability",
      value: prompt,
    });

    if (index === 0) {
      setupCommands.forEach((command, commandIndex) => {
        steps.push({
          id: `setup-${commandIndex + 1}`,
          type: "setup-command",
          intent: "follow-declared-setup-instructions",
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
  const environment = await prepareEnvironment(request);
  const plan = await buildPromptRunnerPlan(request, options);

  try {
    const execution: PromptRunnerExecutionRecord[] = [];

    for (const step of plan.steps) {
      const startedAt = new Date().toISOString();

      if (step.type === "setup-command") {
        const result = await commandRunner(provider, environment, "bash", [
          "-lc",
          `cd ${toShellLiteral(environment.container.skillDir)} && ${step.value}`,
        ]);
        const completedAt = new Date().toISOString();

        execution.push({
          stepId: step.id,
          type: step.type,
          intent: step.intent,
          value: step.value,
          startedAt,
          completedAt,
          result,
        });
        continue;
      }

      const completedAt = new Date().toISOString();
      execution.push({
        stepId: step.id,
        type: step.type,
        intent: step.intent,
        value: step.value,
        startedAt,
        completedAt,
      });
    }

    return {
      request,
      plan,
      execution,
    };
  } finally {
    await environment.cleanup();
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

function extractSetupCommands(markdown: string): string[] {
  const inlineCommandPattern = /`([^`\n]+)`/g;
  const commands: string[] = [];

  for (const match of markdown.matchAll(inlineCommandPattern)) {
    const candidate = match[1]?.trim();
    if (!candidate || !looksLikeSetupCommand(candidate)) {
      continue;
    }

    if (!commands.includes(candidate)) {
      commands.push(candidate);
    }
  }

  return commands;
}

function looksLikeSetupCommand(value: string): boolean {
  return /(?:^|\s)(?:bash|sh|curl|wget|python|node|npm|pnpm|pip)\b/.test(value);
}

function toShellLiteral(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

