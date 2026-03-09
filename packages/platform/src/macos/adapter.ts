import { detonationRuntimeKinds, type PlatformCapabilities } from "@clawguard/contracts";

import { UnsupportedPlatformError } from "../errors.js";
import type { PlatformAdapter, PlatformFactoryOptions } from "../types.js";
import { createCommandRunner } from "../shared/command-runner.js";
import { createContainerRuntimeDetector } from "../shared/runtime-detection.js";
import { MacosNotificationClient } from "./notifications.js";
import { MacosServiceManager } from "./service-manager.js";
import { MacosFileWatcher } from "./watcher.js";

const macosCapabilities: PlatformCapabilities = {
  platform: "macos",
  supportsWatcher: true,
  supportsNotifications: true,
  supportsServiceInstall: true,
  supportedDetonationRuntimes: [...detonationRuntimeKinds],
};

export function createMacosPlatformAdapter(
  options: Pick<
    PlatformFactoryOptions,
    "commandRunner" | "homeDir" | "userId" | "watchFactory"
  > = {},
): PlatformAdapter {
  const commandRunner = options.commandRunner ?? createCommandRunner();
  const watcher = new MacosFileWatcher(options.watchFactory);

  return {
    capabilities: macosCapabilities,
    watcher,
    notifications: new MacosNotificationClient(commandRunner),
    services: new MacosServiceManager(commandRunner, {
      homeDir: options.homeDir ?? process.env.HOME ?? "",
      userId: resolveUserId(options.userId),
    }),
    containerRuntimes: createContainerRuntimeDetector({ commandRunner }),
  };
}

function resolveUserId(userId: number | undefined): number {
  if (userId !== undefined) {
    return userId;
  }

  if (typeof process.getuid === "function") {
    return process.getuid();
  }

  throw new UnsupportedPlatformError(process.platform);
}
