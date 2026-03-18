import assert from "node:assert/strict";
import { test } from "node:test";

import { buildCommand, buildPayload, formatSuccess } from "./index.js";

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
});

test("buildPayload keeps detonate command on CLI surface", () => {
  assert.deepEqual(buildPayload("detonate", ["calendar-helper"]), {
    command: "detonate",
    slug: "calendar-helper",
  });
});

test("buildCommand parses direct service-management commands", () => {
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
