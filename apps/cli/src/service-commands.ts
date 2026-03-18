import { fileURLToPath } from "node:url";
import path from "node:path";
import process from "node:process";

export const DEFAULT_DAEMON_SERVICE_LABEL = "com.clawguard.daemon";

export interface ServiceDefinitionLike {
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

export interface ServiceStatusLike {
  label: string;
  plistPath: string;
  installed: boolean;
  loaded: boolean;
  running: boolean;
  pid?: number;
  lastExitCode?: number;
}

export interface ServiceManagerLike {
  installService(definition: ServiceDefinitionLike): Promise<ServiceStatusLike>;
  uninstallService(label: string): Promise<void>;
  getServiceStatus(label: string): Promise<ServiceStatusLike>;
}

export interface ServiceCommandsClient {
  services: ServiceManagerLike;
}

export interface ServiceCommandOptions {
  label?: string;
  nodeExecutable?: string;
  daemonEntrypointPath?: string;
  workingDirectory?: string;
}

export interface InstallServiceCommandResult {
  command: "install";
  service: ServiceDefinitionLike;
  status: ServiceStatusLike;
}

export interface StatusServiceCommandResult {
  command: "status";
  label: string;
  status: ServiceStatusLike;
}

export interface UninstallServiceCommandResult {
  command: "uninstall";
  label: string;
  before: ServiceStatusLike;
  after: ServiceStatusLike;
}

export type ServiceCommandResult =
  | InstallServiceCommandResult
  | StatusServiceCommandResult
  | UninstallServiceCommandResult;

export function buildDaemonServiceDefinition(
  options: ServiceCommandOptions = {},
): ServiceDefinitionLike {
  const label = options.label ?? DEFAULT_DAEMON_SERVICE_LABEL;
  const daemonEntrypointPath = options.daemonEntrypointPath ?? resolveDefaultDaemonEntrypointPath();
  const args = ["--enable-source-maps", daemonEntrypointPath];

  return {
    label,
    program: options.nodeExecutable ?? process.execPath,
    args,
    workingDirectory: options.workingDirectory ?? process.cwd(),
    runAtLoad: true,
    keepAlive: true,
  };
}

export async function installDaemonService(
  client: ServiceCommandsClient,
  options: ServiceCommandOptions = {},
): Promise<InstallServiceCommandResult> {
  const service = buildDaemonServiceDefinition(options);
  const status = await client.services.installService(service);

  return {
    command: "install",
    service,
    status,
  };
}

export async function getDaemonServiceStatus(
  client: ServiceCommandsClient,
  options: ServiceCommandOptions = {},
): Promise<StatusServiceCommandResult> {
  const label = options.label ?? DEFAULT_DAEMON_SERVICE_LABEL;
  const status = await client.services.getServiceStatus(label);

  return {
    command: "status",
    label,
    status,
  };
}

export async function uninstallDaemonService(
  client: ServiceCommandsClient,
  options: ServiceCommandOptions = {},
): Promise<UninstallServiceCommandResult> {
  const label = options.label ?? DEFAULT_DAEMON_SERVICE_LABEL;
  const before = await client.services.getServiceStatus(label);
  await client.services.uninstallService(label);
  const after = await client.services.getServiceStatus(label);

  return {
    command: "uninstall",
    label,
    before,
    after,
  };
}

export function formatServiceCommandResult(result: ServiceCommandResult): string {
  switch (result.command) {
    case "install":
      return [
        "ClawGuard daemon service installed",
        formatServiceDefinition(result.service),
        formatServiceStatus(result.status),
      ].join("\n");
    case "status":
      return [`ClawGuard daemon service status (${result.label})`, formatServiceStatus(result.status)].join(
        "\n",
      );
    case "uninstall":
      return [
        "ClawGuard daemon service uninstalled",
        `- Label: ${result.label}`,
        `- Before: ${formatServiceStatusHeadline(result.before)}`,
        `- After: ${formatServiceStatusHeadline(result.after)}`,
        `- Plist: ${result.before.plistPath}`,
      ].join("\n");
  }
}

export function resolveDefaultDaemonEntrypointPath(): string {
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(moduleDirectory, "../../daemon/dist/index.js");
}

function formatServiceDefinition(service: ServiceDefinitionLike): string {
  const lines = [`- Label: ${service.label}`, `- Program: ${service.program}`];

  if (service.args !== undefined && service.args.length > 0) {
    lines.push(`- Args: ${service.args.join(" ")}`);
  }

  if (service.workingDirectory !== undefined) {
    lines.push(`- Working directory: ${service.workingDirectory}`);
  }

  return lines.join("\n");
}

function formatServiceStatus(status: ServiceStatusLike): string {
  const lines = [
    `- Status: ${formatServiceStatusHeadline(status)}`,
    `- Plist: ${status.plistPath}`,
  ];

  if (status.pid !== undefined) {
    lines.push(`- PID: ${status.pid}`);
  }

  if (status.lastExitCode !== undefined) {
    lines.push(`- Last exit code: ${status.lastExitCode}`);
  }

  return lines.join("\n");
}

function formatServiceStatusHeadline(status: ServiceStatusLike): string {
  if (!status.installed) {
    return "not installed";
  }

  if (status.running) {
    return "running";
  }

  if (status.loaded) {
    return "loaded but not running";
  }

  return "installed but not loaded";
}
