import assert from "node:assert/strict";
import { test } from "node:test";

import { getSkillFixtureById, listSkillFixtures } from "@clawguard/fixtures";
import type { ContainerRuntimeDetector, DetectedContainerRuntime } from "@clawguard/platform";

import {
  buildDetonationBenchmarkRequest,
  createDetonationRuntimeProvider,
  runDetonationPreflightBenchmark,
  runDetonationPreflightBenchmarkCli,
} from "./index.js";

function createRuntimeDetector(
  runtime?: DetectedContainerRuntime,
  available: DetectedContainerRuntime[] = runtime ? [runtime] : [],
): ContainerRuntimeDetector {
  return {
    async detectAvailableRuntimes() {
      return available;
    },
    async getPreferredRuntime(preferredRuntime) {
      if (preferredRuntime !== undefined) {
        const preferredMatch = available.find(
          (candidate) => candidate.runtime === preferredRuntime,
        );
        if (preferredMatch !== undefined) {
          return preferredMatch;
        }
      }

      return available[0];
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

test("createDetonationRuntimeProvider prefers Podman when both runtimes are available", async () => {
  const runtimeDetector = createRuntimeDetector(undefined, [
    {
      runtime: "docker",
      command: "docker",
    },
    {
      runtime: "podman",
      command: "podman",
    },
  ]);

  const commandLog: string[] = [];
  const provider = await createDetonationRuntimeProvider({
    runtimeDetector,
    commandExecutor: {
      async run(command, args) {
        commandLog.push(`${command} ${args.join(" ")}`);
        return {
          exitCode: 1,
          stdout: "",
          stderr: "missing",
        };
      },
    },
  });

  assert.equal(provider.runtime, "podman");
  assert.equal(provider.command, "podman");
  assert.deepEqual(commandLog, []);
});

test("runtime providers share image-cache semantics across podman and docker", async () => {
  for (const runtime of ["podman", "docker"] as const) {
    const commandCalls: Array<{ command: string; args: string[] }> = [];
    const runtimeDetector = createRuntimeDetector({ runtime, command: runtime });

    const provider = await createDetonationRuntimeProvider({
      runtimeDetector,
      commandExecutor: {
        async run(command, args) {
          commandCalls.push({ command, args });

          const isImageCheck =
            runtime === "podman"
              ? args.join(" ") === "image exists ghcr.io/clawguard/detonation-sandbox:0.1.0"
              : args.join(" ") === "image inspect ghcr.io/clawguard/detonation-sandbox:0.1.0";

          if (isImageCheck) {
            return {
              exitCode: 1,
              stdout: "",
              stderr: "not found",
            };
          }

          return {
            exitCode: 0,
            stdout: "ok",
            stderr: "",
          };
        },
      },
    });

    const result = await provider.ensureSandboxImage();

    assert.equal(result.runtime, runtime);
    assert.equal(result.runtimeCommand, runtime);
    assert.equal(result.source, "built");
    assert.equal(commandCalls[0]?.command, runtime);
    assert.ok(commandCalls[1]?.args.includes("build"));
  }
});
