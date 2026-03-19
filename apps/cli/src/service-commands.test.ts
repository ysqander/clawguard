import assert from "node:assert/strict";
import test from "node:test";

import {
  DEFAULT_DAEMON_SERVICE_LABEL,
  buildDaemonLaunchCommand,
  buildDaemonServiceDefinition,
  formatServiceCommandResult,
  getDaemonServiceStatus,
  installDaemonService,
  uninstallDaemonService,
  type ServiceCommandsClient,
  type ServiceDefinitionLike,
  type ServiceStatusLike,
} from "./service-commands.js";
import { resolveDefaultServiceWorkingDirectory } from "./install-layout.js";

function createServiceStatus(
  overrides: {
    label?: string;
    plistPath?: string;
    installed?: boolean;
    loaded?: boolean;
    running?: boolean;
    pid?: number;
    lastExitCode?: number;
  } = {},
): ServiceStatusLike {
  return {
    label: overrides.label ?? DEFAULT_DAEMON_SERVICE_LABEL,
    plistPath:
      overrides.plistPath ?? "/Users/tester/Library/LaunchAgents/com.clawguard.daemon.plist",
    installed: overrides.installed ?? true,
    loaded: overrides.loaded ?? true,
    running: overrides.running ?? true,
    ...(overrides.pid !== undefined ? { pid: overrides.pid } : {}),
    ...(overrides.lastExitCode !== undefined ? { lastExitCode: overrides.lastExitCode } : {}),
  };
}

function createClient(handlers: {
  installService?(
    definition: ServiceDefinitionLike,
  ): Promise<ServiceStatusLike> | ServiceStatusLike;
  uninstallService?(label: string): Promise<void> | void;
  getServiceStatus?(label: string): Promise<ServiceStatusLike> | ServiceStatusLike;
}): ServiceCommandsClient {
  return {
    services: {
      async installService(definition) {
        if (!handlers.installService) {
          throw new Error("installService not expected");
        }
        return handlers.installService(definition);
      },
      async uninstallService(label) {
        if (!handlers.uninstallService) {
          throw new Error("uninstallService not expected");
        }
        await handlers.uninstallService(label);
      },
      async getServiceStatus(label) {
        if (!handlers.getServiceStatus) {
          throw new Error("getServiceStatus not expected");
        }
        return handlers.getServiceStatus(label);
      },
    },
  };
}

test("buildDaemonServiceDefinition resolves the daemon entrypoint relative to the CLI package", () => {
  const definition = buildDaemonServiceDefinition({
    nodeExecutable: "/usr/local/bin/node",
    workingDirectory: "/Users/tester/clawguard",
  });

  assert.equal(definition.label, DEFAULT_DAEMON_SERVICE_LABEL);
  assert.equal(definition.program, "/usr/local/bin/node");
  assert.deepEqual(definition.args, ["--enable-source-maps", definition.args?.[1]]);
  assert.equal(definition.workingDirectory, "/Users/tester/clawguard");
  assert.equal(definition.runAtLoad, true);
  assert.equal(definition.keepAlive, true);
  assert.match(definition.args?.[1] ?? "", /(apps\/daemon\/dist\/index|dist\/daemon)\.js$/u);
});

test("buildDaemonLaunchCommand defaults to the current node executable and stable working directory", () => {
  const launch = buildDaemonLaunchCommand();

  assert.equal(launch.program, process.execPath);
  assert.deepEqual(launch.args, ["--enable-source-maps", launch.args[1]]);
  assert.equal(launch.workingDirectory, resolveDefaultServiceWorkingDirectory());
});

test("buildDaemonServiceDefinition defaults the working directory to HOME", () => {
  const definition = buildDaemonServiceDefinition();

  assert.equal(definition.workingDirectory, resolveDefaultServiceWorkingDirectory());
  assert.equal(definition.runAtLoad, true);
  assert.equal(definition.keepAlive, true);
});

test("installDaemonService returns the installed service status and definition", async () => {
  const client = createClient({
    installService: (definition) => {
      assert.equal(definition.label, DEFAULT_DAEMON_SERVICE_LABEL);
      assert.equal(definition.program, "/usr/local/bin/node");
      assert.deepEqual(definition.args, [
        "--enable-source-maps",
        "/repo/apps/daemon/dist/index.js",
      ]);
      assert.equal(definition.workingDirectory, resolveDefaultServiceWorkingDirectory());
      assert.equal(definition.runAtLoad, true);
      assert.equal(definition.keepAlive, true);
      return createServiceStatus({ plistPath: "/tmp/com.clawguard.daemon.plist" });
    },
  });

  const result = await installDaemonService(client, {
    nodeExecutable: "/usr/local/bin/node",
    daemonEntrypointPath: "/repo/apps/daemon/dist/index.js",
  });

  assert.equal(result.command, "install");
  assert.equal(result.service.program, "/usr/local/bin/node");
  assert.equal(result.status.plistPath, "/tmp/com.clawguard.daemon.plist");
  assert.match(formatServiceCommandResult(result), /ClawGuard daemon service installed/u);
  assert.match(formatServiceCommandResult(result), /- Status: running/u);
});

test("getDaemonServiceStatus formats the current launchd state", async () => {
  const client = createClient({
    getServiceStatus: (label) =>
      createServiceStatus({
        label,
        installed: true,
        loaded: true,
        running: false,
        lastExitCode: 78,
      }),
  });

  const result = await getDaemonServiceStatus(client, {
    label: "com.clawguard.custom",
  });

  assert.equal(result.command, "status");
  assert.equal(result.label, "com.clawguard.custom");
  assert.equal(result.status.running, false);
  assert.match(formatServiceCommandResult(result), /loaded but not running/u);
  assert.match(formatServiceCommandResult(result), /Last exit code: 78/u);
});

test("uninstallDaemonService captures before and after service state", async () => {
  const calls: string[] = [];
  const client = createClient({
    getServiceStatus: (label) => {
      calls.push(`status:${label}`);
      return calls.length === 1
        ? createServiceStatus({ label })
        : createServiceStatus({
            label,
            installed: false,
            loaded: false,
            running: false,
            plistPath: "/Users/tester/Library/LaunchAgents/com.clawguard.daemon.plist",
          });
    },
    uninstallService: (label) => {
      calls.push(`uninstall:${label}`);
    },
  });

  const result = await uninstallDaemonService(client);

  assert.deepEqual(calls, [
    `status:${DEFAULT_DAEMON_SERVICE_LABEL}`,
    `uninstall:${DEFAULT_DAEMON_SERVICE_LABEL}`,
    `status:${DEFAULT_DAEMON_SERVICE_LABEL}`,
  ]);
  assert.equal(result.before.installed, true);
  assert.equal(result.after.installed, false);
  assert.match(formatServiceCommandResult(result), /ClawGuard daemon service uninstalled/u);
  assert.match(formatServiceCommandResult(result), /- Before: running/u);
  assert.match(formatServiceCommandResult(result), /- After: not installed/u);
});
