import type {
  DetonationRuntimeKind,
  PlatformCapabilities,
  SupportedPlatform
} from "@clawguard/contracts";

import type { CommandRunner } from "./shared/command-runner.js";

export interface FileWatchEvent {
  path: string;
  kind: "updated" | "renamed" | "unknown";
  rawEventType: "change" | "rename" | "unknown";
  observedAt: string;
}

export interface WatchHandlers {
  onEvent(event: FileWatchEvent): void;
  onError?(error: Error): void;
}

export interface WatchOptions {
  recursive?: boolean;
  signal?: AbortSignal;
}

export interface WatchSubscription {
  close(): Promise<void>;
}

export interface FileWatcher {
  watchDirectory(
    directoryPath: string,
    handlers: WatchHandlers,
    options?: WatchOptions
  ): Promise<WatchSubscription>;
}

export interface NotificationRequest {
  title: string;
  body: string;
  subtitle?: string;
}

export interface NotificationReceipt {
  deliveredAt: string;
}

export interface NotificationClient {
  send(request: NotificationRequest): Promise<NotificationReceipt>;
}

export interface ServiceDefinition {
  label: string;
  program: string;
  args?: string[];
  workingDirectory?: string;
  environment?: Record<string, string>;
  runAtLoad?: boolean;
  keepAlive?: boolean;
  stdoutPath?: string;
  stderrPath?: string;
}

export interface ServiceStatus {
  label: string;
  plistPath: string;
  installed: boolean;
  loaded: boolean;
  running: boolean;
  pid?: number;
  lastExitCode?: number;
}

export interface ServiceManager {
  installService(definition: ServiceDefinition): Promise<ServiceStatus>;
  uninstallService(label: string): Promise<void>;
  getServiceStatus(label: string): Promise<ServiceStatus>;
}

export interface DetectedContainerRuntime {
  runtime: DetonationRuntimeKind;
  command: string;
  version?: string;
}

export interface ContainerRuntimeDetector {
  detectAvailableRuntimes(): Promise<DetectedContainerRuntime[]>;
  getPreferredRuntime(
    preferredRuntime?: DetonationRuntimeKind
  ): Promise<DetectedContainerRuntime | undefined>;
}

export interface PlatformAdapter {
  readonly capabilities: PlatformCapabilities;
  readonly watcher: FileWatcher;
  readonly notifications: NotificationClient;
  readonly services: ServiceManager;
  readonly containerRuntimes: ContainerRuntimeDetector;
}

export interface PlatformFactoryOptions {
  platform?: SupportedPlatform | NodeJS.Platform;
  homeDir?: string;
  userId?: number;
  commandRunner?: CommandRunner;
  watchFactory?: typeof import("node:fs").watch;
}
