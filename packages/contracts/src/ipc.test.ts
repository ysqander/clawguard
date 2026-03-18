import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import { daemonResponseEnvelopeValidator, resolveDaemonSocketPath } from "./index.js";

test("resolveDaemonSocketPath uses the env override and falls back to os.tmpdir()", () => {
  const original = process.env.CLAWGUARD_DAEMON_SOCKET;

  try {
    process.env.CLAWGUARD_DAEMON_SOCKET = "/tmp/custom-clawguard.sock";
    assert.equal(resolveDaemonSocketPath(), "/tmp/custom-clawguard.sock");

    delete process.env.CLAWGUARD_DAEMON_SOCKET;
    assert.equal(resolveDaemonSocketPath(), path.join(tmpdir(), "clawguard-daemon.sock"));
  } finally {
    if (original === undefined) {
      delete process.env.CLAWGUARD_DAEMON_SOCKET;
    } else {
      process.env.CLAWGUARD_DAEMON_SOCKET = original;
    }
  }
});

test("daemonResponseEnvelopeValidator accepts status payloads with watcher health details", () => {
  const response = daemonResponseEnvelopeValidator.parse({
    version: 1,
    requestId: "request-123",
    ok: true,
    data: {
      state: "degraded",
      jobs: 2,
      watcher: "degraded",
      issues: ["Watcher startup failed: permission denied"],
    },
  });

  assert.equal(response.ok, true);
  if (!response.ok) {
    throw new Error("Expected a successful status response");
  }

  assert.deepEqual(response.data, {
    state: "degraded",
    jobs: 2,
    watcher: "degraded",
    issues: ["Watcher startup failed: permission denied"],
  });
});

test("daemonResponseEnvelopeValidator accepts legacy status payloads without watcher health details", () => {
  const response = daemonResponseEnvelopeValidator.parse({
    version: 1,
    requestId: "request-legacy",
    ok: true,
    data: {
      state: "idle",
      jobs: 0,
    },
  });

  assert.equal(response.ok, true);
  if (!response.ok) {
    throw new Error("Expected a successful status response");
  }

  assert.deepEqual(response.data, {
    state: "idle",
    jobs: 0,
  });
});
