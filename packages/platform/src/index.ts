import type { PlatformCapabilities } from "@clawguard/contracts";

export interface PlatformAdapter {
  readonly capabilities: PlatformCapabilities;
}

export const macosPlatformAdapter: PlatformAdapter = {
  capabilities: {
    platform: "macos",
    supportsWatcher: true,
    supportsNotifications: true,
    supportsServiceInstall: true,
    supportedDetonationRuntimes: ["podman", "docker"]
  }
};

