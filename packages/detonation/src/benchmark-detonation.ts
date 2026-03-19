import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath, pathToFileURL } from "node:url";

import type { DetonationRequest } from "@clawguard/contracts";
import {
  listSkillFixtures,
  loadFixtureSnapshot,
  type SkillFixtureDefinition,
} from "@clawguard/fixtures";
import { createPlatformAdapter, type ContainerRuntimeDetector } from "@clawguard/platform";

import {
  createDetonationRuntimeProvider,
  type CreateDetonationRuntimeProviderOptions,
  type DetonationRuntimeProvider,
} from "./runtime-provider.js";
import { runPromptRunner } from "./prompt-runner.js";
import { buildDetonationReportFromPromptRunner } from "./telemetry.js";

const DEFAULT_TIMEOUT_SECONDS = 90;
const DEFAULT_BUDGET_MS = 90_000;
const DETONATION_BENCHMARK_PROMPTS = [
  "Initialize the skill and perform any required setup.",
  "Exercise one representative task end-to-end.",
] as const;

export interface DetonationBenchmarkExecutionResult {
  setupCommandCount: number;
  failedStepCount: number;
  telemetryCount: number;
  artifactCount: number;
  memoryChangeCount: number;
  fileChangeCount: number;
  triggeredActionCount: number;
  errorMessage?: string;
}

export interface DetonationBenchmarkRow {
  fixtureId: string;
  intent: SkillFixtureDefinition["intent"];
  runtime: string;
  runtimeAvailable: boolean;
  requestId: string;
  promptCount: number;
  timeoutSeconds: number;
  status: "completed" | "runtime-unavailable" | "failed";
  durationMs?: number;
  setupCommandCount?: number;
  failedStepCount?: number;
  telemetryCount?: number;
  artifactCount?: number;
  memoryChangeCount?: number;
  fileChangeCount?: number;
  triggeredActionCount?: number;
  errorMessage?: string;
}

export interface DetonationBenchmarkFailure {
  fixtureId: string;
  reason: "execution-failed" | "budget-exceeded";
  durationMs?: number;
  budgetMs?: number;
  errorMessage?: string;
}

export interface DetonationBenchmarkSummary {
  fixtureCount: number;
  generatedAt: string;
  passed: boolean;
  failures: DetonationBenchmarkFailure[];
  budgetMs?: number;
  rows: DetonationBenchmarkRow[];
}

export interface DetonationBenchmarkOptions {
  timeoutSeconds?: number;
  budgetMs?: number;
  runtimeDetector?: ContainerRuntimeDetector;
  createRuntimeProvider?: (
    options: CreateDetonationRuntimeProviderOptions,
  ) => Promise<DetonationRuntimeProvider>;
  runFixture?: (
    provider: DetonationRuntimeProvider,
    request: DetonationRequest,
    fixture: SkillFixtureDefinition,
  ) => Promise<DetonationBenchmarkExecutionResult>;
}

export interface DetonationBenchmarkCliResult {
  summary: DetonationBenchmarkSummary;
  exitCode: number;
}

export async function runDetonationBenchmark(
  options: DetonationBenchmarkOptions = {},
): Promise<DetonationBenchmarkSummary> {
  const fixtures = listSkillFixtures({ benchmarkTag: "detonation-target" });
  if (fixtures.length === 0) {
    throw new Error("No detonation benchmark fixtures were found.");
  }

  const runtimeDetector = options.runtimeDetector ?? createPlatformAdapter().containerRuntimes;
  const timeoutSeconds = options.timeoutSeconds ?? DEFAULT_TIMEOUT_SECONDS;
  const preferredRuntime = await runtimeDetector.getPreferredRuntime("podman");

  if (!preferredRuntime) {
    const rows = fixtures.map<DetonationBenchmarkRow>((fixture) => {
      const request = buildBenchmarkRequest(fixture, timeoutSeconds);
      return {
        fixtureId: fixture.id,
        intent: fixture.intent,
        runtime: "unavailable",
        runtimeAvailable: false,
        requestId: request.requestId,
        promptCount: request.prompts.length,
        timeoutSeconds: request.timeoutSeconds,
        status: "runtime-unavailable",
      };
    });

    return {
      fixtureCount: rows.length,
      generatedAt: new Date().toISOString(),
      passed: true,
      failures: [],
      ...(options.budgetMs !== undefined ? { budgetMs: options.budgetMs } : {}),
      rows,
    };
  }

  const providerFactory = options.createRuntimeProvider ?? createDetonationRuntimeProvider;
  const runFixture = options.runFixture ?? executeBenchmarkFixture;

  let provider: DetonationRuntimeProvider;
  try {
    provider = await providerFactory({
      preferredRuntime: "podman",
      runtimeDetector,
    });
  } catch (error) {
    const rows = fixtures.map<DetonationBenchmarkRow>((fixture) => {
      const request = buildBenchmarkRequest(fixture, timeoutSeconds);
      return {
        fixtureId: fixture.id,
        intent: fixture.intent,
        runtime: preferredRuntime.runtime,
        runtimeAvailable: true,
        requestId: request.requestId,
        promptCount: request.prompts.length,
        timeoutSeconds: request.timeoutSeconds,
        status: "failed",
        errorMessage: error instanceof Error ? error.message : String(error),
      };
    });

    return {
      fixtureCount: rows.length,
      generatedAt: new Date().toISOString(),
      passed: false,
      failures: collectFailures(rows, options.budgetMs),
      ...(options.budgetMs !== undefined ? { budgetMs: options.budgetMs } : {}),
      rows,
    };
  }

  const rows: DetonationBenchmarkRow[] = [];

  for (const fixture of fixtures) {
    const request = buildBenchmarkRequest(fixture, timeoutSeconds);
    const startedAt = performance.now();

    try {
      const execution = await runFixture(provider, request, fixture);
      const durationMs = performance.now() - startedAt;
      const status = execution.failedStepCount > 0 ? "failed" : "completed";

      rows.push({
        fixtureId: fixture.id,
        intent: fixture.intent,
        runtime: provider.runtime,
        runtimeAvailable: true,
        requestId: request.requestId,
        promptCount: request.prompts.length,
        timeoutSeconds: request.timeoutSeconds,
        durationMs,
        setupCommandCount: execution.setupCommandCount,
        failedStepCount: execution.failedStepCount,
        telemetryCount: execution.telemetryCount,
        artifactCount: execution.artifactCount,
        memoryChangeCount: execution.memoryChangeCount,
        fileChangeCount: execution.fileChangeCount,
        triggeredActionCount: execution.triggeredActionCount,
        status,
        ...(status === "failed" && execution.errorMessage
          ? { errorMessage: execution.errorMessage }
          : {}),
      });
    } catch (error) {
      const durationMs = performance.now() - startedAt;

      rows.push({
        fixtureId: fixture.id,
        intent: fixture.intent,
        runtime: provider.runtime,
        runtimeAvailable: true,
        requestId: request.requestId,
        promptCount: request.prompts.length,
        timeoutSeconds: request.timeoutSeconds,
        durationMs,
        status: "failed",
        errorMessage: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const failures = collectFailures(rows, options.budgetMs);

  return {
    fixtureCount: rows.length,
    generatedAt: new Date().toISOString(),
    passed: failures.length === 0,
    failures,
    ...(options.budgetMs !== undefined ? { budgetMs: options.budgetMs } : {}),
    rows,
  };
}

export async function runDetonationBenchmarkCli(
  env: NodeJS.ProcessEnv = process.env,
  runtimeDetector?: ContainerRuntimeDetector,
  overrides: Pick<DetonationBenchmarkOptions, "createRuntimeProvider" | "runFixture"> = {},
): Promise<DetonationBenchmarkCliResult> {
  const summary = await runDetonationBenchmark({
    ...resolveCliOptions(env),
    ...(runtimeDetector ? { runtimeDetector } : {}),
    ...overrides,
  });

  return {
    summary,
    exitCode: summary.passed ? 0 : 1,
  };
}

function resolveCliOptions(
  env: NodeJS.ProcessEnv,
): Pick<DetonationBenchmarkOptions, "timeoutSeconds" | "budgetMs"> {
  const timeoutSeconds =
    parsePositiveInt(env.CLAWGUARD_BENCH_DETONATION_TIMEOUT_SECONDS) ?? DEFAULT_TIMEOUT_SECONDS;
  const shouldEnforceBudget =
    env.CLAWGUARD_BENCH_DETONATION_ENFORCE === "1" ||
    env.CLAWGUARD_BENCH_DETONATION_BUDGET_MS !== undefined;
  const budgetMs = shouldEnforceBudget
    ? (parseNonNegativeInt(env.CLAWGUARD_BENCH_DETONATION_BUDGET_MS) ?? DEFAULT_BUDGET_MS)
    : undefined;

  return {
    timeoutSeconds,
    ...(budgetMs !== undefined ? { budgetMs } : {}),
  };
}

function collectFailures(
  rows: DetonationBenchmarkRow[],
  budgetMs: number | undefined,
): DetonationBenchmarkFailure[] {
  const failures: DetonationBenchmarkFailure[] = rows
    .filter((row) => row.status === "failed")
    .map((row) => ({
      fixtureId: row.fixtureId,
      reason: "execution-failed" as const,
      ...(row.durationMs !== undefined ? { durationMs: row.durationMs } : {}),
      ...(row.errorMessage ? { errorMessage: row.errorMessage } : {}),
    }));

  if (budgetMs === undefined) {
    return failures;
  }

  return [
    ...failures,
    ...rows
      .filter((row) => row.status === "completed" && (row.durationMs ?? 0) > budgetMs)
      .map((row) => ({
        fixtureId: row.fixtureId,
        reason: "budget-exceeded" as const,
        ...(row.durationMs !== undefined ? { durationMs: row.durationMs } : {}),
        budgetMs,
      })),
  ];
}

function buildBenchmarkRequest(
  fixture: SkillFixtureDefinition,
  timeoutSeconds: number,
): DetonationRequest {
  return {
    requestId: `bench-${fixture.id}`,
    snapshot: loadFixtureSnapshot(fixture),
    prompts: [...DETONATION_BENCHMARK_PROMPTS],
    timeoutSeconds,
  };
}

async function executeBenchmarkFixture(
  provider: DetonationRuntimeProvider,
  request: DetonationRequest,
  _fixture: SkillFixtureDefinition,
): Promise<DetonationBenchmarkExecutionResult> {
  const artifactsRoot = await mkdtemp(path.join(tmpdir(), "clawguard-detonation-bench-"));

  try {
    const result = await runPromptRunner(provider, request, {
      minPrompts: request.prompts.length,
      maxPrompts: request.prompts.length,
    });
    const built = await buildDetonationReportFromPromptRunner(result, {
      artifactsRoot,
    });
    const failedExecution = result.execution.find((entry) => entry.status === "failed");
    const failedStepCount = result.execution.filter((entry) => entry.status === "failed").length;

    return {
      setupCommandCount: result.plan.setupCommandCount,
      failedStepCount,
      telemetryCount: built.telemetry.length,
      artifactCount: built.artifacts.length,
      memoryChangeCount: result.memoryDiffs.filter((entry) => entry.changed).length,
      fileChangeCount: result.fileChanges.length,
      triggeredActionCount: built.report.triggeredActions.length,
      ...(failedStepCount > 0
        ? { errorMessage: formatExecutionFailureMessage(failedExecution, failedStepCount) }
        : {}),
    };
  } finally {
    await rm(artifactsRoot, { recursive: true, force: true });
  }
}

function formatExecutionFailureMessage(
  failedExecution: Awaited<ReturnType<typeof runPromptRunner>>["execution"][number] | undefined,
  failedStepCount: number,
): string {
  const directMessage = failedExecution?.errorMessage?.trim();
  if (directMessage) {
    return directMessage;
  }

  const stderrMessage = failedExecution?.result?.stderr?.trim();
  if (stderrMessage) {
    return stderrMessage;
  }

  if (failedExecution?.stepId && failedExecution.result?.exitCode !== undefined) {
    return `Step ${failedExecution.stepId} failed with exit code ${failedExecution.result.exitCode}`;
  }

  return `Detonation fixture recorded ${failedStepCount} failed step(s).`;
}

function parsePositiveInt(value: string | undefined): number | undefined {
  if (!value) {
    return undefined;
  }

  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return undefined;
  }

  return parsed;
}

function parseNonNegativeInt(value: string | undefined): number | undefined {
  if (!value) {
    return undefined;
  }

  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return undefined;
  }

  return parsed;
}

async function main(): Promise<void> {
  const { summary, exitCode } = await runDetonationBenchmarkCli();
  console.log(JSON.stringify(summary, null, 2));
  if (exitCode !== 0) {
    process.exitCode = exitCode;
  }
}

if (
  process.argv[1] &&
  path.basename(fileURLToPath(import.meta.url)).startsWith("benchmark-detonation") &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  await main();
}
