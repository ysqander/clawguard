import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";

import { listSkillFixtures } from "@clawguard/fixtures";
import type { ContainerRuntimeDetector, DetectedContainerRuntime } from "@clawguard/platform";

import {
  runDetonationBenchmark,
  runDetonationBenchmarkCli,
  type DetonationBenchmarkExecutionResult,
} from "./benchmark-detonation.js";
import type {
  CreateDetonationRuntimeProviderOptions,
  DetonationRuntimeProvider,
} from "./runtime-provider.js";

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

function createStubProvider(): DetonationRuntimeProvider {
  return {
    runtime: "podman",
    command: "podman",
    async ensureSandboxImage() {
      return {
        runtime: "podman",
        runtimeCommand: "podman",
        imageTag: "ghcr.io/clawguard/detonation-sandbox:test",
        source: "cache",
      };
    },
    async runRuntimeCommand() {
      return {
        exitCode: 0,
        stdout: "",
        stderr: "",
      };
    },
  };
}

test("runDetonationBenchmark reports runtime-unavailable without failing", async () => {
  const result = await runDetonationBenchmark({
    runtimeDetector: createRuntimeDetector(),
  });

  assert.equal(result.passed, true);
  assert.ok(result.rows.every((row) => row.runtime === "unavailable"));
  assert.ok(result.rows.every((row) => row.runtimeAvailable === false));
  assert.ok(result.rows.every((row) => row.status === "runtime-unavailable"));
});

test("runDetonationBenchmark covers every detonation fixture with execution metrics", async () => {
  const fixtures = listSkillFixtures({ benchmarkTag: "detonation-target" });
  const runtime = {
    runtime: "podman",
    command: "podman",
  } satisfies DetectedContainerRuntime;

  const summary = await runDetonationBenchmark({
    runtimeDetector: createRuntimeDetector(runtime),
    async createRuntimeProvider(_options: CreateDetonationRuntimeProviderOptions) {
      return createStubProvider();
    },
    async runFixture(_provider, _request, fixture): Promise<DetonationBenchmarkExecutionResult> {
      return {
        setupCommandCount: fixture.intent === "malicious" ? 1 : 0,
        failedStepCount: 0,
        telemetryCount: fixture.intent === "malicious" ? 4 : 1,
        artifactCount: 3,
        memoryChangeCount: fixture.intent === "malicious" ? 1 : 0,
        fileChangeCount: fixture.intent === "malicious" ? 1 : 0,
        triggeredActionCount: fixture.intent === "malicious" ? 2 : 1,
      };
    },
  });

  assert.equal(summary.fixtureCount, fixtures.length);
  assert.equal(summary.passed, true);
  assert.deepEqual(
    summary.rows.map((row) => row.fixtureId).sort((left, right) => left.localeCompare(right)),
    fixtures.map((fixture) => fixture.id).sort((left, right) => left.localeCompare(right)),
  );
  assert.ok(summary.rows.every((row) => row.status === "completed"));
  assert.ok(
    summary.rows.some((row) => row.intent === "malicious" && (row.fileChangeCount ?? 0) > 0),
  );
  assert.ok(summary.rows.some((row) => row.intent === "benign" && row.fileChangeCount === 0));
});

test("runDetonationBenchmark treats non-throwing failed steps as execution failures", async () => {
  const runtime = {
    runtime: "podman",
    command: "podman",
  } satisfies DetectedContainerRuntime;

  const summary = await runDetonationBenchmark({
    runtimeDetector: createRuntimeDetector(runtime),
    async createRuntimeProvider() {
      return createStubProvider();
    },
    async runFixture(_provider, _request, fixture) {
      return {
        setupCommandCount: 0,
        failedStepCount: fixture.id === "malicious-staged-download" ? 1 : 0,
        telemetryCount: 1,
        artifactCount: 1,
        memoryChangeCount: 0,
        fileChangeCount: 0,
        triggeredActionCount: 1,
        ...(fixture.id === "malicious-staged-download" ? { errorMessage: "workflow failed" } : {}),
      };
    },
  });

  const failedRow = summary.rows.find((row) => row.fixtureId === "malicious-staged-download");

  assert.equal(summary.passed, false);
  assert.equal(failedRow?.status, "failed");
  assert.equal(failedRow?.errorMessage, "workflow failed");
  assert.ok(
    summary.failures.some((failure) => {
      return (
        failure.fixtureId === "malicious-staged-download" &&
        failure.reason === "execution-failed" &&
        failure.errorMessage === "workflow failed"
      );
    }),
  );
});

test("runDetonationBenchmark records execution and budget regressions", async () => {
  const runtime = {
    runtime: "podman",
    command: "podman",
  } satisfies DetectedContainerRuntime;

  const summary = await runDetonationBenchmark({
    runtimeDetector: createRuntimeDetector(runtime),
    budgetMs: 0,
    async createRuntimeProvider() {
      return createStubProvider();
    },
    async runFixture(_provider, _request, fixture) {
      if (fixture.id === "malicious-staged-download") {
        throw new Error("synthetic detonation failure");
      }

      await delay(2);
      return {
        setupCommandCount: 0,
        failedStepCount: 0,
        telemetryCount: 1,
        artifactCount: 1,
        memoryChangeCount: 0,
        fileChangeCount: 0,
        triggeredActionCount: 1,
      };
    },
  });

  assert.equal(summary.passed, false);
  assert.ok(summary.failures.some((failure) => failure.reason === "execution-failed"));
  assert.ok(summary.failures.some((failure) => failure.reason === "budget-exceeded"));
  assert.equal(
    summary.failures.filter((failure) => failure.fixtureId === "malicious-staged-download").length,
    1,
  );
});

test("runDetonationBenchmarkCli returns a non-zero exit code when enforcement fails", async () => {
  const runtime = {
    runtime: "podman",
    command: "podman",
  } satisfies DetectedContainerRuntime;

  const result = await runDetonationBenchmarkCli(
    {
      CLAWGUARD_BENCH_DETONATION_ENFORCE: "1",
      CLAWGUARD_BENCH_DETONATION_BUDGET_MS: "0",
    },
    createRuntimeDetector(runtime),
    {
      async createRuntimeProvider() {
        return createStubProvider();
      },
      async runFixture() {
        await delay(2);
        return {
          setupCommandCount: 0,
          failedStepCount: 0,
          telemetryCount: 1,
          artifactCount: 1,
          memoryChangeCount: 0,
          fileChangeCount: 0,
          triggeredActionCount: 1,
        };
      },
    },
  );

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.passed, false);
});

test("runDetonationBenchmarkCli returns a non-zero exit code for non-throwing execution failures", async () => {
  const runtime = {
    runtime: "podman",
    command: "podman",
  } satisfies DetectedContainerRuntime;

  const result = await runDetonationBenchmarkCli({}, createRuntimeDetector(runtime), {
    async createRuntimeProvider() {
      return createStubProvider();
    },
    async runFixture() {
      return {
        setupCommandCount: 0,
        failedStepCount: 1,
        telemetryCount: 1,
        artifactCount: 1,
        memoryChangeCount: 0,
        fileChangeCount: 0,
        triggeredActionCount: 1,
        errorMessage: "workflow failed",
      };
    },
  });

  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.passed, false);
  assert.ok(result.summary.failures.some((failure) => failure.reason === "execution-failed"));
});
