import { spawn } from "node:child_process";

import type { GatewayServiceSignal } from "@clawguard/contracts";

export interface CommandResult {
  command: string;
  args: string[];
  exitCode: number | null;
  stdout: string;
  stderr: string;
}

export type RunCommand = (
  command: string,
  args?: string[],
  options?: { cwd?: string; env?: NodeJS.ProcessEnv },
) => Promise<CommandResult>;

export async function probeGatewayService(
  options: { now?: () => string; runCommand?: RunCommand } = {},
): Promise<{ signal?: GatewayServiceSignal; warning?: string }> {
  const runCommand = options.runCommand ?? defaultRunCommand;
  const checkedAt = options.now?.() ?? new Date().toISOString();
  const command = "openclaw";
  const args = ["gateway", "status", "--no-probe", "--json"];
  const displayCommand = `${command} ${args.join(" ")}`;

  try {
    const result = await runCommand(command, args);
    if (result.exitCode !== 0) {
      return {
        warning: `OpenClaw service probe failed: ${displayCommand} exited with ${result.exitCode}`,
      };
    }

    const payload = parseJsonObject(result.stdout, displayCommand);
    const signalState = extractSignalState(payload);

    return {
      signal: {
        source: "service",
        command: displayCommand,
        installed: signalState.installed,
        running: signalState.running,
        checkedAt,
        ...(signalState.detail !== undefined ? { detail: signalState.detail } : {}),
      },
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      warning: `OpenClaw service probe unavailable: ${message}`,
    };
  }
}

async function defaultRunCommand(
  command: string,
  args: string[] = [],
  options: { cwd?: string; env?: NodeJS.ProcessEnv } = {},
): Promise<CommandResult> {
  return new Promise<CommandResult>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: "pipe",
    });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];

    child.stdout.on("data", (chunk) => {
      stdoutChunks.push(Buffer.from(chunk));
    });
    child.stderr.on("data", (chunk) => {
      stderrChunks.push(Buffer.from(chunk));
    });
    child.on("error", reject);
    child.on("close", (exitCode) => {
      resolve({
        command,
        args: [...args],
        exitCode,
        stdout: Buffer.concat(stdoutChunks).toString("utf8"),
        stderr: Buffer.concat(stderrChunks).toString("utf8"),
      });
    });
  });
}

function parseJsonObject(rawText: string, displayCommand: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(rawText) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("Expected a JSON object");
    }

    return parsed as Record<string, unknown>;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`${displayCommand} returned invalid JSON: ${message}`);
  }
}

function extractSignalState(record: Record<string, unknown>): {
  installed: boolean;
  running: boolean;
  detail?: string;
} {
  if (hasBoolean(record.installed) || hasBoolean(record.running)) {
    return {
      installed: asBoolean(record.installed) ?? false,
      running: asBoolean(record.running) ?? false,
      ...(typeof record.status === "string" ? { detail: record.status } : {}),
    };
  }

  const gatewayRecord = asRecord(record.gateway);
  if (
    gatewayRecord !== undefined &&
    (hasBoolean(gatewayRecord.installed) || hasBoolean(gatewayRecord.running))
  ) {
    return {
      installed: asBoolean(gatewayRecord.installed) ?? false,
      running: asBoolean(gatewayRecord.running) ?? false,
      ...(typeof gatewayRecord.status === "string" ? { detail: gatewayRecord.status } : {}),
    };
  }

  const serviceItems = Array.isArray(record.services) ? record.services : undefined;
  if (serviceItems !== undefined) {
    const normalizedServices = serviceItems
      .map((value) => asRecord(value))
      .filter((value): value is Record<string, unknown> => value !== undefined);

    const installed = normalizedServices.length > 0;
    const running = normalizedServices.some((value) => {
      if (hasBoolean(value.running)) {
        return value.running;
      }

      const status = typeof value.status === "string" ? value.status.toLowerCase() : undefined;
      return status === "running" || status === "active";
    });
    const serviceNames = normalizedServices
      .map((value) => (typeof value.name === "string" ? value.name : undefined))
      .filter((value): value is string => value !== undefined);

    return {
      installed,
      running,
      ...(serviceNames.length > 0 ? { detail: serviceNames.join(", ") } : {}),
    };
  }

  throw new Error("Unable to infer installed/running state from gateway status output");
}

function hasBoolean(value: unknown): value is boolean {
  return typeof value === "boolean";
}

function asBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}
