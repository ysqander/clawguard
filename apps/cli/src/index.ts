#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import net from "node:net";
import process from "node:process";
import { fileURLToPath } from "node:url";

import {
  daemonResponseEnvelopeValidator,
  resolveDaemonSocketPath,
  type ArtifactRef,
  type DaemonErrorResponse,
  type DaemonRequestEnvelope,
  type DaemonRequestPayload,
  type DaemonResponseData,
  type DaemonResponseEnvelope,
  type DecisionRecord,
  type ReportResponseData,
  type ScanRecord,
} from "@clawguard/contracts";
import { createPlatformAdapter } from "@clawguard/platform";
import { renderStaticReport, renderStaticSummary } from "@clawguard/reports";

import {
  formatServiceCommandResult,
  getDaemonServiceStatus,
  installDaemonService,
  uninstallDaemonService,
} from "./service-commands.js";

type ServiceCommandAction = "install" | "status" | "uninstall";

type CliCommand =
  | {
      kind: "daemon";
      payload: DaemonRequestPayload;
    }
  | {
      kind: "service";
      action: ServiceCommandAction;
    };

export async function main(argv = process.argv): Promise<void> {
  const args = argv.slice(2);
  const command = args[0] ?? "status";
  const commandArgs = args.slice(1);
  const detailed = commandArgs.includes("--detailed");

  if (command === "help" || command === "--help" || command === "-h") {
    console.log(getHelpText());
    return;
  }

  const resolvedCommand = buildCommand(command, commandArgs.filter((arg) => arg !== "--detailed"));

  if (resolvedCommand.kind === "service") {
    try {
      console.log(await runServiceCommand(resolvedCommand.action));
    } catch (error) {
      console.error(error instanceof Error ? error.message : "Unknown service command failure");
      process.exitCode = 1;
    }
    return;
  }

  const payload = resolvedCommand.payload;

  let response: DaemonResponseEnvelope;
  try {
    response = await sendDaemonRequest(payload);
  } catch (error) {
    console.error(formatConnectionError(error));
    process.exitCode = 1;
    return;
  }

  if (!response.ok) {
    console.error(formatDaemonError(payload, response));
    process.exitCode = 1;
    return;
  }

  console.log(formatSuccess(payload, response.data, detailed));
}

export function buildCommand(command: string, args: string[]): CliCommand {
  if (command === "service") {
    return {
      kind: "service",
      action: buildServiceAction(args),
    };
  }

  return {
    kind: "daemon",
    payload: buildPayload(command, args),
  };
}

export function buildPayload(command: string, args: string[]): DaemonRequestPayload {
  switch (command) {
    case "status":
      return { command: "status" };
    case "audit":
      return { command: "audit" };
    case "scan": {
      const skillPath = args[0];
      if (!skillPath) {
        throw new Error("Usage: clawguard scan <skill-path>");
      }
      return { command: "scan", skillPath };
    }
    case "report": {
      const slug = args[0];
      if (!slug) {
        throw new Error("Usage: clawguard report <slug>");
      }
      return { command: "report", slug };
    }
    case "allow":
    case "block": {
      const slug = args[0];
      if (!slug) {
        throw new Error(`Usage: clawguard ${command} <slug> [reason]`);
      }
      const reason = args.slice(1).join(" ").trim();
      return {
        command,
        slug,
        ...(reason.length > 0 ? { reason } : {}),
      };
    }
    case "detonate": {
      const slug = args[0];
      if (!slug) {
        throw new Error("Usage: clawguard detonate <slug>");
      }
      return { command: "detonate", slug };
    }
    default:
      throw new Error(`Unknown command: ${command}`);
  }
}

export function formatSuccess(
  payload: DaemonRequestPayload,
  data: DaemonResponseData,
  detailed: boolean,
): string {
  switch (payload.command) {
    case "status": {
      if (!("state" in data)) {
        return JSON.stringify(data, null, 2);
      }

      const lines = [
        "ClawGuard daemon status",
        `- State: ${data.state}`,
        `- Active jobs: ${data.jobs}`,
      ];

      if (data.watcher !== undefined) {
        lines.push(`- Watcher: ${data.watcher}`);
      }

      if (data.issues !== undefined && data.issues.length > 0) {
        lines.push(...data.issues.map((issue) => `- Issue: ${issue}`));
      }

      return lines.join("\n");
    }
    case "scan": {
      if (!("scan" in data)) {
        return JSON.stringify(data, null, 2);
      }

      const lines = [`Scan completed for ${data.scan.slug}`, formatScanMetadata(data.scan)];

      if (data.report) {
        lines.push(`Recommendation: ${data.report.recommendation}`);
        lines.push(`Summary: ${renderStaticSummary(data.report)}`);

        if (detailed) {
          lines.push("", renderStaticReport(data.report));
        }
      }

      return lines.join("\n");
    }
    case "report": {
      if (!("summary" in data)) {
        return JSON.stringify(data, null, 2);
      }

      return formatReportResponse(data, detailed);
    }
    case "allow":
    case "block": {
      if (!("summary" in data)) {
        return JSON.stringify(data, null, 2);
      }

      const action = payload.command === "allow" ? "Allowed" : "Blocked";
      const lines = [
        `${action}: ${data.summary.slug}`,
        `Verdict: ${data.summary.verdict}`,
        `Score: ${data.summary.score}`,
        `Findings: ${data.summary.findingCount}`,
      ];

      if (data.decision) {
        lines.push(formatDecision(data.decision));
      }

      lines.push(`Summary: ${renderStaticSummary(data.report)}`);

      if (detailed) {
        lines.push("", renderStaticReport(data.report));
        if (data.artifacts.length > 0) {
          lines.push("", "Artifacts:", ...data.artifacts.map(formatArtifact));
        }
      }

      return lines.join("\n");
    }
    case "audit": {
      if (!("scans" in data)) {
        return JSON.stringify(data, null, 2);
      }

      if (data.scans.length === 0) {
        return "No scans recorded yet.";
      }

      return [
        "Recent scans",
        ...data.scans.map(
          (scan) => `- ${scan.slug} (${scan.status}) ${scan.startedAt} [scanId=${scan.scanId}]`,
        ),
      ].join("\n");
    }
    case "detonate":
      return JSON.stringify(data, null, 2);
  }
}

function formatReportResponse(data: ReportResponseData, detailed: boolean): string {
  const lines = [
    `Report for ${data.summary.slug}`,
    `Verdict: ${data.summary.verdict}`,
    `Score: ${data.summary.score}`,
    `Findings: ${data.summary.findingCount}`,
  ];

  if (data.decision) {
    lines.push(formatDecision(data.decision));
  }

  lines.push(`Summary: ${renderStaticSummary(data.report)}`);

  if (detailed) {
    lines.push("");
    lines.push(renderStaticReport(data.report));
    if (data.artifacts.length > 0) {
      lines.push("", "Artifacts:", ...data.artifacts.map(formatArtifact));
    }
  }

  return lines.join("\n");
}

function formatConnectionError(error: unknown): string {
  const socketPath = resolveDaemonSocketPath();

  if (
    error instanceof Error &&
    "code" in error &&
    (error.code === "ENOENT" || error.code === "ECONNREFUSED")
  ) {
    return [
      `Unable to connect to ClawGuard daemon at ${socketPath}.`,
      "Start the daemon first: node apps/daemon/dist/index.js",
      "Then retry your command.",
    ].join("\n");
  }

  return error instanceof Error ? error.message : "Unknown CLI failure";
}

function formatDaemonError(payload: DaemonRequestPayload, response: DaemonErrorResponse): string {
  if (payload.command === "detonate" && response.error.code === "not_implemented") {
    return [
      "Detonation orchestration is not available yet (planned for Milestone B).",
      "You can still run static-path triage now:",
      "- clawguard scan <skill-path>",
      `- clawguard report ${payload.slug}`,
      "Use allow/block to resolve quarantine decisions after review.",
    ].join("\n");
  }

  return `error (${response.error.code}): ${response.error.message}`;
}

function formatScanMetadata(scan: ScanRecord): string {
  return `Scan ${scan.scanId} started ${scan.startedAt}${scan.completedAt ? ` and completed ${scan.completedAt}` : ""}.`;
}

function formatDecision(decision: DecisionRecord): string {
  return `Operator decision: ${decision.decision} (${decision.reason}) at ${decision.createdAt}`;
}

function formatArtifact(artifact: ArtifactRef): string {
  return `- [${artifact.type}] ${artifact.path}`;
}

function getHelpText(): string {
  return [
    "ClawGuard CLI",
    "",
    "Commands:",
    "  clawguard status",
    "  clawguard audit",
    "  clawguard scan <skill-path> [--detailed]",
    "  clawguard report <slug> [--detailed]",
    "  clawguard allow <slug> [reason] [--detailed]",
    "  clawguard block <slug> [reason] [--detailed]",
    "  clawguard detonate <slug>",
    "  clawguard service install",
    "  clawguard service status",
    "  clawguard service uninstall",
  ].join("\n");
}

function buildServiceAction(args: string[]): ServiceCommandAction {
  const action = args[0];
  if (action === "install" || action === "status" || action === "uninstall") {
    return action;
  }

  throw new Error("Usage: clawguard service <install|status|uninstall>");
}

async function runServiceCommand(action: ServiceCommandAction): Promise<string> {
  const platform = createPlatformAdapter();

  if (!platform.capabilities.supportsServiceInstall) {
    throw new Error(`Service management is not supported on ${platform.capabilities.platform}.`);
  }

  const client = { services: platform.services };

  switch (action) {
    case "install":
      return formatServiceCommandResult(await installDaemonService(client));
    case "status":
      return formatServiceCommandResult(await getDaemonServiceStatus(client));
    case "uninstall":
      return formatServiceCommandResult(await uninstallDaemonService(client));
  }
}

async function sendDaemonRequest(payload: DaemonRequestPayload): Promise<DaemonResponseEnvelope> {
  const request: DaemonRequestEnvelope = {
    version: 1,
    requestId: randomUUID(),
    payload,
  };

  return new Promise((resolve, reject) => {
    const socket = net.createConnection(resolveDaemonSocketPath());
    let buffer = "";

    socket.setEncoding("utf8");

    socket.on("connect", () => {
      socket.write(`${JSON.stringify(request)}\n`);
    });

    socket.on("data", (chunk) => {
      buffer += chunk;
      const [line] = buffer.split("\n");
      if (!line) {
        return;
      }

      try {
        const parsed = daemonResponseEnvelopeValidator.parse(JSON.parse(line));
        resolve(parsed);
      } catch (error) {
        reject(error);
      } finally {
        socket.end();
      }
    });

    socket.on("error", (error) => {
      reject(error);
    });
  });
}

const isEntrypoint = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];

if (isEntrypoint) {
  await main();
}
