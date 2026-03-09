import test from "node:test";
import assert from "node:assert/strict";

import { UnsupportedFeatureError, createPlatformAdapter } from "./index.js";
import { buildDisplayNotificationScript } from "./macos/notifications.js";
import { parseLaunchctlPrintOutput, renderLaunchAgentPlist } from "./macos/service-manager.js";
import { normalizeWatchEventType } from "./macos/watcher.js";

test("createPlatformAdapter returns a macOS adapter for darwin", () => {
  const adapter = createPlatformAdapter({
    platform: "darwin",
    userId: 501,
    homeDir: "/Users/tester",
  });

  assert.equal(adapter.capabilities.platform, "macos");
  assert.equal(adapter.capabilities.supportsWatcher, true);
  assert.equal(adapter.capabilities.supportsNotifications, true);
  assert.equal(adapter.capabilities.supportsServiceInstall, true);
});

test("linux adapter exposes placeholders for unsupported features", async () => {
  const adapter = createPlatformAdapter({ platform: "linux" });

  assert.equal(adapter.capabilities.platform, "linux");
  assert.equal(adapter.capabilities.supportsWatcher, false);
  assert.equal(adapter.capabilities.supportsNotifications, false);
  assert.equal(adapter.capabilities.supportsServiceInstall, false);

  await assert.rejects(
    adapter.notifications.send({ title: "ClawGuard", body: "Blocked" }),
    UnsupportedFeatureError,
  );
  await assert.rejects(
    adapter.services.getServiceStatus("com.clawguard.daemon"),
    UnsupportedFeatureError,
  );
  await assert.rejects(
    adapter.watcher.watchDirectory("/tmp", {
      onEvent() {},
    }),
    UnsupportedFeatureError,
  );
});

test("container runtime detection prefers available runtimes", async () => {
  const adapter = createPlatformAdapter({
    platform: "linux",
    commandRunner: {
      async run(command) {
        if (command === "podman") {
          return {
            command,
            args: ["--version"],
            exitCode: 0,
            stdout: "podman version 5.6.0\n",
            stderr: "",
          };
        }

        throw new Error("not installed");
      },
    },
  });

  const available = await adapter.containerRuntimes.detectAvailableRuntimes();
  const preferred = await adapter.containerRuntimes.getPreferredRuntime("docker");

  assert.deepEqual(available, [
    {
      runtime: "podman",
      command: "podman",
      version: "podman version 5.6.0",
    },
  ]);
  assert.deepEqual(preferred, {
    runtime: "podman",
    command: "podman",
    version: "podman version 5.6.0",
  });
});

test("macOS helpers render stable scripts and plist content", () => {
  assert.equal(normalizeWatchEventType("change"), "updated");
  assert.equal(normalizeWatchEventType("rename"), "renamed");
  assert.equal(normalizeWatchEventType("other"), "unknown");

  assert.equal(
    buildDisplayNotificationScript({
      title: 'ClawGuard "Alert"',
      body: "Skill quarantined",
      subtitle: "review needed",
    }),
    'display notification "Skill quarantined" with title "ClawGuard \\"Alert\\"" subtitle "review needed"',
  );

  const plist = renderLaunchAgentPlist({
    label: "com.clawguard.daemon",
    program: "/usr/local/bin/node",
    args: ["apps/daemon/dist/index.js"],
    workingDirectory: "/workspace",
    runAtLoad: true,
    keepAlive: true,
  });

  assert.match(plist, /<key>Label<\/key>\s*<string>com\.clawguard\.daemon<\/string>/u);
  assert.match(plist, /<key>ProgramArguments<\/key>/u);
  assert.match(plist, /<key>KeepAlive<\/key>\s*<true\/>/u);

  assert.deepEqual(
    parseLaunchctlPrintOutput(
      "com.clawguard.daemon",
      "/Users/tester/Library/LaunchAgents/com.clawguard.daemon.plist",
      [
        "gui/501/com.clawguard.daemon = {",
        "\tstate = running",
        "\tpid = 9901",
        "\tlast exit code = 0",
        "}",
      ].join("\n"),
    ),
    {
      label: "com.clawguard.daemon",
      plistPath: "/Users/tester/Library/LaunchAgents/com.clawguard.daemon.plist",
      installed: true,
      loaded: true,
      running: true,
      pid: 9901,
      lastExitCode: 0,
    },
  );
});
