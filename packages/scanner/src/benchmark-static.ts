import { performance } from "node:perf_hooks";

import { listSkillFixtures, loadFixtureSnapshot } from "@clawguard/fixtures";

import { scanSkillSnapshot } from "./index.js";

const DEFAULT_ITERATIONS = 100;

interface BenchmarkRow {
  fixtureId: string;
  intent: string;
  expectedRuleIds: string[];
  p50Ms: number;
  p95Ms: number;
  maxMs: number;
  avgMs: number;
}

async function main(): Promise<void> {
  const iterations = parsePositiveInt(process.env.CLAWGUARD_BENCH_ITERATIONS) ?? DEFAULT_ITERATIONS;
  const fixtures = listSkillFixtures({ benchmarkTag: "static" });

  if (fixtures.length === 0) {
    throw new Error("No static benchmark fixtures were found.");
  }

  const rows: BenchmarkRow[] = [];
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

  const summary = {
    iterations,
    fixtureCount: rows.length,
    generatedAt: new Date().toISOString(),
    rows,
  };

  console.log(JSON.stringify(summary, null, 2));
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

function percentile(sortedSamples: number[], quantile: number): number {
  if (sortedSamples.length === 0) {
    return 0;
  }

  const index = Math.min(sortedSamples.length - 1, Math.floor(sortedSamples.length * quantile));
  return sortedSamples[index] ?? 0;
}

await main();
