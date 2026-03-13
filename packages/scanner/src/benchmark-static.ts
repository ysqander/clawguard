import path from "node:path";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";

import { listSkillFixtures, loadFixtureSnapshot } from "@clawguard/fixtures";

import { scanSkillSnapshot } from "./index.js";

const DEFAULT_ITERATIONS = 100;
const DEFAULT_P95_BUDGET_MS = 2000;

export interface StaticBenchmarkRow {
  fixtureId: string;
  intent: string;
  expectedRuleIds: string[];
  p50Ms: number;
  p95Ms: number;
  maxMs: number;
  avgMs: number;
}

export interface StaticBenchmarkFailure {
  fixtureId: string;
  p95Ms: number;
  budgetMs: number;
}

export interface StaticBenchmarkSummary {
  iterations: number;
  fixtureCount: number;
  generatedAt: string;
  passed: boolean;
  failures: StaticBenchmarkFailure[];
  budgetMs?: number;
  rows: StaticBenchmarkRow[];
}

export interface StaticBenchmarkOptions {
  iterations?: number;
  budgetMs?: number;
}

export interface StaticBenchmarkCliResult {
  summary: StaticBenchmarkSummary;
  exitCode: number;
}

export function runStaticBenchmark(options: StaticBenchmarkOptions = {}): StaticBenchmarkSummary {
  const iterations = options.iterations ?? DEFAULT_ITERATIONS;
  const fixtures = listSkillFixtures({ benchmarkTag: "static" });

  if (fixtures.length === 0) {
    throw new Error("No static benchmark fixtures were found.");
  }

  const rows: StaticBenchmarkRow[] = [];
  for (const fixture of fixtures) {
    const snapshot = loadFixtureSnapshot(fixture);
    const samples: number[] = [];

    for (let iteration = 0; iteration < iterations; iteration += 1) {
      const start = performance.now();
      scanSkillSnapshot(snapshot);
      samples.push(performance.now() - start);
    }

    samples.sort((left, right) => left - right);

    rows.push({
      fixtureId: fixture.id,
      intent: fixture.intent,
      expectedRuleIds: fixture.expectedRuleIds,
      p50Ms: percentile(samples, 0.5),
      p95Ms: percentile(samples, 0.95),
      maxMs: samples.at(-1) ?? 0,
      avgMs: samples.reduce((accumulator, value) => accumulator + value, 0) / samples.length,
    });
  }

  const failures = collectFailures(rows, options.budgetMs);

  return {
    iterations,
    fixtureCount: rows.length,
    generatedAt: new Date().toISOString(),
    passed: failures.length === 0,
    failures,
    ...(options.budgetMs !== undefined ? { budgetMs: options.budgetMs } : {}),
    rows,
  };
}

export function runStaticBenchmarkCli(
  env: NodeJS.ProcessEnv = process.env,
): StaticBenchmarkCliResult {
  const summary = runStaticBenchmark(resolveCliOptions(env));

  return {
    summary,
    exitCode: summary.passed ? 0 : 1,
  };
}

function resolveCliOptions(env: NodeJS.ProcessEnv): StaticBenchmarkOptions {
  const iterations = parsePositiveInt(env.CLAWGUARD_BENCH_ITERATIONS) ?? DEFAULT_ITERATIONS;
  const shouldEnforceBudget =
    env.CLAWGUARD_BENCH_STATIC_ENFORCE === "1" ||
    env.CLAWGUARD_BENCH_STATIC_P95_BUDGET_MS !== undefined;
  const budgetMs = shouldEnforceBudget
    ? (parseNonNegativeInt(env.CLAWGUARD_BENCH_STATIC_P95_BUDGET_MS) ?? DEFAULT_P95_BUDGET_MS)
    : undefined;

  return {
    iterations,
    ...(budgetMs !== undefined ? { budgetMs } : {}),
  };
}

function collectFailures(
  rows: StaticBenchmarkRow[],
  budgetMs: number | undefined,
): StaticBenchmarkFailure[] {
  if (budgetMs === undefined) {
    return [];
  }

  return rows
    .filter((row) => row.p95Ms > budgetMs)
    .map((row) => ({
      fixtureId: row.fixtureId,
      p95Ms: row.p95Ms,
      budgetMs,
    }));
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

function percentile(sortedSamples: number[], quantile: number): number {
  if (sortedSamples.length === 0) {
    return 0;
  }

  const index = Math.min(sortedSamples.length - 1, Math.floor(sortedSamples.length * quantile));
  return sortedSamples[index] ?? 0;
}

function main(): void {
  const { summary, exitCode } = runStaticBenchmarkCli();
  console.log(JSON.stringify(summary, null, 2));
  if (exitCode !== 0) {
    process.exitCode = exitCode;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}
