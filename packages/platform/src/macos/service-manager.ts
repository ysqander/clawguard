import { access, mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import type { ServiceDefinition, ServiceManager, ServiceStatus } from "../types.js";
import type { CommandRunner } from "../shared/command-runner.js";

export class MacosServiceManager implements ServiceManager {
  constructor(
    private readonly commandRunner: CommandRunner,
    private readonly options: { homeDir: string; userId: number }
  ) {}

  async installService(definition: ServiceDefinition): Promise<ServiceStatus> {
    const launchAgentsDirectory = path.join(this.options.homeDir, "Library", "LaunchAgents");
    const plistPath = getLaunchAgentPlistPath(definition.label, this.options.homeDir);

    await mkdir(launchAgentsDirectory, { recursive: true });
    await writeFile(plistPath, renderLaunchAgentPlist(definition), "utf8");

    await this.commandRunner.run(
      "launchctl",
      ["bootout", getLaunchctlLabel(this.options.userId, definition.label)],
      { rejectOnNonZero: false }
    );
    await this.commandRunner.run(
      "launchctl",
      ["bootstrap", getLaunchctlDomain(this.options.userId), plistPath],
      { rejectOnNonZero: true }
    );

    return this.getServiceStatus(definition.label);
  }

  async uninstallService(label: string): Promise<void> {
    const plistPath = getLaunchAgentPlistPath(label, this.options.homeDir);

    await this.commandRunner.run(
      "launchctl",
      ["bootout", getLaunchctlLabel(this.options.userId, label)],
      { rejectOnNonZero: false }
    );
    await rm(plistPath, { force: true });
  }

  async getServiceStatus(label: string): Promise<ServiceStatus> {
    const plistPath = getLaunchAgentPlistPath(label, this.options.homeDir);
    const installed = await fileExists(plistPath);

    if (!installed) {
      return {
        label,
        plistPath,
        installed: false,
        loaded: false,
        running: false
      };
    }

    const result = await this.commandRunner.run(
      "launchctl",
      ["print", getLaunchctlLabel(this.options.userId, label)],
      { rejectOnNonZero: false }
    );

    if (result.exitCode !== 0) {
      return {
        label,
        plistPath,
        installed: true,
        loaded: false,
        running: false
      };
    }

    return parseLaunchctlPrintOutput(label, plistPath, result.stdout);
  }
}

export function renderLaunchAgentPlist(definition: ServiceDefinition): string {
  const programArguments = [definition.program, ...(definition.args ?? [])]
    .map((argument) => `    <string>${escapeXml(argument)}</string>`)
    .join("\n");
  const environmentVariables =
    definition.environment !== undefined
      ? [
          "  <key>EnvironmentVariables</key>",
          "  <dict>",
          ...Object.entries(definition.environment).map(
            ([key, value]) =>
              `    <key>${escapeXml(key)}</key>\n    <string>${escapeXml(value)}</string>`
          ),
          "  </dict>"
        ].join("\n")
      : undefined;

  return [
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">",
    "<plist version=\"1.0\">",
    "<dict>",
    `  <key>Label</key>\n  <string>${escapeXml(definition.label)}</string>`,
    "  <key>ProgramArguments</key>",
    "  <array>",
    programArguments,
    "  </array>",
    `  <key>RunAtLoad</key>\n  <${definition.runAtLoad ?? true}/>`,
    `  <key>KeepAlive</key>\n  <${definition.keepAlive ?? false}/>`,
    ...(definition.workingDirectory !== undefined
      ? [
          `  <key>WorkingDirectory</key>\n  <string>${escapeXml(
            definition.workingDirectory
          )}</string>`
        ]
      : []),
    ...(definition.stdoutPath !== undefined
      ? [
          `  <key>StandardOutPath</key>\n  <string>${escapeXml(
            definition.stdoutPath
          )}</string>`
        ]
      : []),
    ...(definition.stderrPath !== undefined
      ? [
          `  <key>StandardErrorPath</key>\n  <string>${escapeXml(
            definition.stderrPath
          )}</string>`
        ]
      : []),
    ...(environmentVariables !== undefined ? [environmentVariables] : []),
    "</dict>",
    "</plist>",
    ""
  ].join("\n");
}

export function parseLaunchctlPrintOutput(
  label: string,
  plistPath: string,
  output: string
): ServiceStatus {
  const pid = parseIntegerMatch(output, /\bpid = (\d+)/u);
  const lastExitCode = parseIntegerMatch(output, /\blast exit code = (\d+)/u);
  const running = /\bstate = running\b/u.test(output) || pid !== undefined;

  return {
    label,
    plistPath,
    installed: true,
    loaded: true,
    running,
    ...(pid !== undefined ? { pid } : {}),
    ...(lastExitCode !== undefined ? { lastExitCode } : {})
  };
}

function escapeXml(value: string): string {
  return value
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;")
    .replace(/'/gu, "&apos;");
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

function parseIntegerMatch(input: string, pattern: RegExp): number | undefined {
  const match = pattern.exec(input);
  if (match === null) {
    return undefined;
  }

  const matchValue = match[1];
  if (matchValue === undefined) {
    return undefined;
  }

  const parsed = Number.parseInt(matchValue, 10);
  return Number.isNaN(parsed) ? undefined : parsed;
}

function getLaunchAgentPlistPath(label: string, homeDir: string): string {
  return path.join(homeDir, "Library", "LaunchAgents", `${label}.plist`);
}

function getLaunchctlDomain(userId: number): string {
  return `gui/${userId}`;
}

function getLaunchctlLabel(userId: number, label: string): string {
  return `${getLaunchctlDomain(userId)}/${label}`;
}
