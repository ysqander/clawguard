import type { SupportedPlatform } from "@clawguard/contracts";

import { UnsupportedPlatformError } from "./errors.js";
import { createLinuxPlatformAdapter } from "./linux/adapter.js";
import { createMacosPlatformAdapter } from "./macos/adapter.js";
import type { PlatformAdapter, PlatformFactoryOptions } from "./types.js";

export {
  CommandExecutionError,
  UnsupportedFeatureError,
  UnsupportedPlatformError,
} from "./errors.js";
export { createLinuxPlatformAdapter } from "./linux/adapter.js";
export { createMacosPlatformAdapter } from "./macos/adapter.js";
export { buildDisplayNotificationScript } from "./macos/notifications.js";
export {
  parseLaunchctlPrintOutput,
  renderLaunchAgentPlist,
} from "./macos/service-manager.js";
export { normalizeWatchEventType } from "./macos/watcher.js";
export type {
  ContainerRuntimeDetector,
  DetectedContainerRuntime,
  FileWatchEvent,
  FileWatcher,
  NotificationClient,
  NotificationReceipt,
  NotificationRequest,
  PlatformAdapter,
  PlatformFactoryOptions,
  ServiceDefinition,
  ServiceManager,
  ServiceStatus,
  WatchHandlers,
  WatchOptions,
  WatchSubscription,
} from "./types.js";

export function createPlatformAdapter(options: PlatformFactoryOptions = {}): PlatformAdapter {
  switch (resolveSupportedPlatform(options.platform)) {
    case "macos":
      return createMacosPlatformAdapter(options);
    case "linux":
      return createLinuxPlatformAdapter(options);
  }
}

function resolveSupportedPlatform(
  platform: PlatformFactoryOptions["platform"] = process.platform,
): SupportedPlatform {
  switch (platform) {
    case "darwin":
    case "macos":
      return "macos";
    case "linux":
      return "linux";
    default:
      throw new UnsupportedPlatformError(platform);
  }
}
