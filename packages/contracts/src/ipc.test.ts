import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import { resolveDaemonSocketPath } from "./index.js";

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
