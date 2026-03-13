import assert from "node:assert/strict";
import { test } from "node:test";

import { listSkillFixtures } from "@clawguard/fixtures";

import { runStaticBenchmark, runStaticBenchmarkCli } from "./benchmark-static.js";

test("runStaticBenchmark covers every static fixture in the corpus", () => {
  const summary = runStaticBenchmark({ iterations: 2 });
  const staticFixtures = listSkillFixtures({ benchmarkTag: "static" });

  assert.equal(summary.fixtureCount, staticFixtures.length);
  assert.deepEqual(
    summary.rows.map((row) => row.fixtureId).sort((left, right) => left.localeCompare(right)),
    staticFixtures.map((fixture) => fixture.id).sort((left, right) => left.localeCompare(right)),
  );
  assert.equal(summary.passed, true);
  assert.deepEqual(summary.failures, []);
});

test("runStaticBenchmark records failures when the p95 budget is exceeded", () => {
  const summary = runStaticBenchmark({ iterations: 2, budgetMs: 0 });

  assert.equal(summary.passed, false);
  assert.equal(summary.budgetMs, 0);
  assert.equal(summary.failures.length, summary.fixtureCount);
});

test("runStaticBenchmarkCli returns a non-zero exit code when enforcement fails", () => {
  const result = runStaticBenchmarkCli({
    CLAWGUARD_BENCH_ITERATIONS: "2",
    CLAWGUARD_BENCH_STATIC_ENFORCE: "1",
    CLAWGUARD_BENCH_STATIC_P95_BUDGET_MS: "0",
  });

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.passed, false);
});
