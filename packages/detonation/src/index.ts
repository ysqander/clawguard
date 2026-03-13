import { performance } from "node:perf_hooks";

import type { DetonationRequest } from "@clawguard/contracts";
import {
  getSkillFixtureById,
  listSkillFixtures,
  loadFixtureSnapshot,
  type SkillFixtureDefinition,
} from "@clawguard/fixtures";
import { createPlatformAdapter, type ContainerRuntimeDetector } from "@clawguard/platform";

export {
  createChildProcessRuntimeCommandExecutor,
  createDetonationRuntimeProvider,
  defaultDetonationRuntime,
  defaultSandboxImageTag,
  type CreateDetonationRuntimeProviderOptions,
  type DetonationRuntime,
  type DetonationRuntimeProvider,
  type EnsureSandboxImageOptions,
  type EnsureSandboxImageResult,
  type RuntimeCommandExecutor,
  type RuntimeCommandResult,
} from "./runtime-provider.js";

const DEFAULT_TIMEOUT_SECONDS = 90;
const DETONATION_BENCHMARK_PROMPTS = [
  "Initialize the skill and perform any required setup.",
  "Exercise one representative task end-to-end.",
] as const;

export interface DetonationPreflightBenchmarkOptions {
  timeoutSeconds?: number;
  runtimeDetector?: ContainerRuntimeDetector;
}

export interface DetonationPreflightBenchmarkRow {
  fixtureId: string;
  intent: SkillFixtureDefinition["intent"];
  runtime: string;
  runtimeAvailable: boolean;
  requestId: string;
  promptCount: number;
  timeoutSeconds: number;
  runtimeDetectionMs: number;
  requestBuildMs: number;
  status: "ready" | "runtime-unavailable";
}

export interface DetonationPreflightBenchmarkSummary {
  fixtureCount: number;
  generatedAt: string;
  rows: DetonationPreflightBenchmarkRow[];
}

export interface DetonationPreflightBenchmarkCliResult {
  summary: DetonationPreflightBenchmarkSummary;
  exitCode: number;
}

export function buildDetonationBenchmarkRequest(
  fixture: SkillFixtureDefinition | string,
  timeoutSeconds = DEFAULT_TIMEOUT_SECONDS,
): DetonationRequest {
  const definition = typeof fixture === "string" ? getSkillFixtureById(fixture) : fixture;

  return {
    requestId: `bench-${definition.id}`,
    snapshot: loadFixtureSnapshot(definition),
    prompts: [...DETONATION_BENCHMARK_PROMPTS],
    timeoutSeconds,
  };
}

export async function runDetonationPreflightBenchmark(
  options: DetonationPreflightBenchmarkOptions = {},
): Promise<DetonationPreflightBenchmarkSummary> {
  const timeoutSeconds = options.timeoutSeconds ?? DEFAULT_TIMEOUT_SECONDS;
  const runtimeDetector = options.runtimeDetector ?? createPlatformAdapter().containerRuntimes;
  const fixtures = listSkillFixtures({ benchmarkTag: "detonation-target" });

  if (fixtures.length === 0) {
    throw new Error("No detonation benchmark fixtures were found.");
  }

  const runtimeStart = performance.now();
  const runtime = await runtimeDetector.getPreferredRuntime("podman");
  const runtimeDetectionMs = performance.now() - runtimeStart;

  const rows: DetonationPreflightBenchmarkRow[] = fixtures.map((fixture) => {
    const requestStart = performance.now();
    const request = buildDetonationBenchmarkRequest(fixture, timeoutSeconds);
    const requestBuildMs = performance.now() - requestStart;

    return {
      fixtureId: fixture.id,
      intent: fixture.intent,
      runtime: runtime?.runtime ?? "unavailable",
      runtimeAvailable: runtime !== undefined,
      requestId: request.requestId,
      promptCount: request.prompts.length,
      timeoutSeconds: request.timeoutSeconds,
      runtimeDetectionMs,
      requestBuildMs,
      status: runtime ? "ready" : "runtime-unavailable",
    };
  });

  return {
    fixtureCount: rows.length,
    generatedAt: new Date().toISOString(),
    rows,
  };
}

export async function runDetonationPreflightBenchmarkCli(
  env: NodeJS.ProcessEnv = process.env,
  runtimeDetector?: ContainerRuntimeDetector,
): Promise<DetonationPreflightBenchmarkCliResult> {
  const timeoutSeconds = parsePositiveInt(env.CLAWGUARD_BENCH_DETONATION_TIMEOUT_SECONDS);
  const summary = await runDetonationPreflightBenchmark({
    ...(timeoutSeconds !== undefined ? { timeoutSeconds } : {}),
    ...(runtimeDetector ? { runtimeDetector } : {}),
  });

  return {
    summary,
    exitCode: 0,
  };
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
