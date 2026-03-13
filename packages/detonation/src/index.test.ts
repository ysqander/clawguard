import assert from "node:assert/strict";
import { test } from "node:test";

import { getSkillFixtureById, listSkillFixtures } from "@clawguard/fixtures";
import type { ContainerRuntimeDetector, DetectedContainerRuntime } from "@clawguard/platform";

import {
  buildDetonationBenchmarkRequest,
  runDetonationPreflightBenchmark,
  runDetonationPreflightBenchmarkCli,
} from "./index.js";

function createRuntimeDetector(runtime?: DetectedContainerRuntime): ContainerRuntimeDetector {
  return {
    async detectAvailableRuntimes() {
      return runtime ? [runtime] : [];
    },
    async getPreferredRuntime() {
      return runtime;
    },
  };
}

test("buildDetonationBenchmarkRequest is deterministic", () => {
  const fixture = getSkillFixtureById("malicious-staged-download");
  const request = buildDetonationBenchmarkRequest(fixture);

  assert.equal(request.requestId, `bench-${fixture.id}`);
  assert.equal(request.snapshot.slug, fixture.slug);
  assert.equal(request.timeoutSeconds, 90);
  assert.deepEqual(request.prompts, [
    "Initialize the skill and perform any required setup.",
    "Exercise one representative task end-to-end.",
  ]);
});

test("runDetonationPreflightBenchmark consumes every detonation-target fixture", async () => {
  const fixtures = listSkillFixtures({ benchmarkTag: "detonation-target" });
  const runtime = {
    runtime: "podman",
    command: "podman",
  } satisfies DetectedContainerRuntime;

  const summary = await runDetonationPreflightBenchmark({
    runtimeDetector: createRuntimeDetector(runtime),
  });

  assert.equal(summary.fixtureCount, fixtures.length);
  assert.deepEqual(
    summary.rows.map((row) => row.fixtureId),
    fixtures.map((fixture) => fixture.id),
  );
  assert.ok(summary.rows.every((row) => row.runtimeAvailable));
  assert.ok(summary.rows.every((row) => row.runtime === "podman"));
  assert.ok(summary.rows.every((row) => row.status === "ready"));
  assert.ok(summary.rows.every((row) => row.promptCount === 2));
  assert.ok(summary.rows.every((row) => row.timeoutSeconds === 90));
});

test("runDetonationPreflightBenchmarkCli reports runtime-unavailable without failing", async () => {
  const result = await runDetonationPreflightBenchmarkCli(
    {
      CLAWGUARD_BENCH_DETONATION_TIMEOUT_SECONDS: "120",
    },
    createRuntimeDetector(),
  );

  assert.equal(result.exitCode, 0);
  assert.ok(result.summary.rows.every((row) => row.requestId === `bench-${row.fixtureId}`));
  assert.ok(result.summary.rows.every((row) => row.runtime === "unavailable"));
  assert.ok(result.summary.rows.every((row) => row.runtimeAvailable === false));
  assert.ok(result.summary.rows.every((row) => row.status === "runtime-unavailable"));
  assert.ok(result.summary.rows.every((row) => row.timeoutSeconds === 120));
});
