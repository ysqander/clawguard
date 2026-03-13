#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import { Socket } from "node:net";

import {
  daemonResponseEnvelopeValidator,
  defaultClawGuardConfig,
  type DaemonRequestPayload,
  type DaemonResponseEnvelope,
  type DetonateResponseData,
  type ReportResponseData,
  type ScanResponseData,
} from "@clawguard/contracts";
import { renderStaticReport, renderStaticSummary } from "@clawguard/reports";
import { expandHomePath } from "@clawguard/storage";

interface ParsedArgs {
  command: string | undefined;
  values: string[];
  flags: Set<string>;
}

function parseArgs(argv: string[]): ParsedArgs {
  const [command, ...rest] = argv;
  const flags = new Set<string>();
  const values: string[] = [];

  for (const arg of rest) {
    if (arg.startsWith("--")) {
      flags.add(arg);
    } else {
      values.push(arg);
    }
  }

  return { command, values, flags };
}

function usage(): string {
  return [
    "Usage: clawguard <command> [args] [--json] [--detailed]",
    "",
    "Commands:",
    "  status",
    "  scan <skill-path>",
    "  report <slug>",
    "  allow <slug> [reason]",
    "  block <slug> [reason]",
    "  detonate <slug>",
    "  audit",
  ].join("\n");
}

async function callDaemon(payload: DaemonRequestPayload): Promise<DaemonResponseEnvelope> {
  const socketPath = expandHomePath(defaultClawGuardConfig.paths.socketPath);
  const request = {
    version: 1 as const,
    requestId: randomUUID(),
    payload,
  };

  return await new Promise<DaemonResponseEnvelope>((resolve, reject) => {
    const socket = new Socket();
    let responseBuffer = "";

    socket.once("error", (error) => {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ECONNREFUSED") {
        reject(
          new Error(
            `ClawGuard daemon is unavailable at ${socketPath}. Start it with: node apps/daemon/dist/index.js`,
          ),
        );
        return;
      }

      reject(error);
    });

    socket.on("data", (chunk) => {
      responseBuffer += chunk.toString("utf8");
      const newlineIndex = responseBuffer.indexOf("\n");
      if (newlineIndex === -1) {
        return;
      }

      const raw = responseBuffer.slice(0, newlineIndex);
      try {
        const parsed = daemonResponseEnvelopeValidator.parse(JSON.parse(raw));
        resolve(parsed);
      } catch (error) {
        reject(error);
      } finally {
        socket.end();
      }
    });

    socket.connect(socketPath, () => {
      socket.write(`${JSON.stringify(request)}\n`);
    });
  });
}

function renderReportResponse(data: ReportResponseData, detailed: boolean): string {
  if (detailed) {
    return renderStaticReport(data.report);
  }

  return [
    renderStaticSummary(data.report),
    `decision=${data.decision?.decision ?? "none"}`,
    `artifacts=${data.artifacts.length}`,
  ].join(" | ");
}

async function main(argv: string[]): Promise<number> {
  const { command, values, flags } = parseArgs(argv);
  if (!command || command === "help" || command === "--help") {
    console.log(usage());
    return 0;
  }

  const json = flags.has("--json");
  const detailed = flags.has("--detailed");

  let payload: DaemonRequestPayload;
  switch (command) {
    case "status":
      payload = { command: "status" };
      break;
    case "scan":
      if (!values[0]) {
        throw new Error("scan requires <skill-path>");
      }
      payload = { command: "scan", skillPath: values[0] };
      break;
    case "report":
      if (!values[0]) {
        throw new Error("report requires <slug>");
      }
      payload = { command: "report", slug: values[0] };
      break;
    case "allow":
      if (!values[0]) {
        throw new Error("allow requires <slug>");
      }
      payload = {
        command: "allow",
        slug: values[0],
        ...(values[1] ? { reason: values.slice(1).join(" ") } : {}),
      };
      break;
    case "block":
      if (!values[0]) {
        throw new Error("block requires <slug>");
      }
      payload = {
        command: "block",
        slug: values[0],
        ...(values[1] ? { reason: values.slice(1).join(" ") } : {}),
      };
      break;
    case "detonate":
      if (!values[0]) {
        throw new Error("detonate requires <slug>");
      }
      payload = { command: "detonate", slug: values[0] };
      break;
    case "audit":
      payload = { command: "audit" };
      break;
    default:
      throw new Error(`Unknown command '${command}'.`);
  }

  const response = await callDaemon(payload);
  if (!response.ok) {
    throw new Error(`${response.error.code}: ${response.error.message}`);
  }

  if (json) {
    console.log(JSON.stringify(response.data, null, 2));
    return 0;
  }

  if (payload.command === "report") {
    console.log(renderReportResponse(response.data as ReportResponseData, detailed));
    return 0;
  }

  if (payload.command === "scan") {
    const scanData = response.data as ScanResponseData;
    if (scanData.report) {
      console.log(renderStaticSummary(scanData.report));
    } else {
      console.log(JSON.stringify(scanData));
    }
    return 0;
  }

  if (payload.command === "detonate") {
    console.log((response.data as DetonateResponseData).report.summary);
    return 0;
  }

  console.log(JSON.stringify(response.data));
  return 0;
}

main(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((error) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`clawguard: ${message}`);
    process.exit(1);
  });
