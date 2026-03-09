import { detonationRuntimeKinds, type PlatformCapabilities } from "@clawguard/contracts";

import { UnsupportedFeatureError } from "../errors.js";
import { createCommandRunner } from "../shared/command-runner.js";
import { createContainerRuntimeDetector } from "../shared/runtime-detection.js";
import type {
  FileWatcher,
  NotificationClient,
  NotificationReceipt,
  PlatformAdapter,
  PlatformFactoryOptions,
  ServiceDefinition,
  ServiceManager,
  ServiceStatus,
  WatchSubscription,
} from "../types.js";

const linuxCapabilities: PlatformCapabilities = {
  platform: "linux",
  supportsWatcher: false,
  supportsNotifications: false,
  supportsServiceInstall: false,
  supportedDetonationRuntimes: [...detonationRuntimeKinds],
};

export function createLinuxPlatformAdapter(
  options: Pick<PlatformFactoryOptions, "commandRunner"> = {},
): PlatformAdapter {
  const commandRunner = options.commandRunner ?? createCommandRunner();

  return {
    capabilities: linuxCapabilities,
    watcher: new LinuxPlaceholderWatcher(),
    notifications: new LinuxPlaceholderNotificationClient(),
    services: new LinuxPlaceholderServiceManager(),
    containerRuntimes: createContainerRuntimeDetector({ commandRunner }),
  };
}

class LinuxPlaceholderWatcher implements FileWatcher {
  async watchDirectory(): Promise<WatchSubscription> {
    throw new UnsupportedFeatureError("linux", "filesystem watching");
  }
}

class LinuxPlaceholderNotificationClient implements NotificationClient {
  async send(): Promise<NotificationReceipt> {
    throw new UnsupportedFeatureError("linux", "notifications");
  }
}

class LinuxPlaceholderServiceManager implements ServiceManager {
  async installService(_definition: ServiceDefinition): Promise<ServiceStatus> {
    throw new UnsupportedFeatureError("linux", "service installation");
  }

  async uninstallService(_label: string): Promise<void> {
    throw new UnsupportedFeatureError("linux", "service installation");
  }

  async getServiceStatus(_label: string): Promise<ServiceStatus> {
    throw new UnsupportedFeatureError("linux", "service installation");
  }
}
