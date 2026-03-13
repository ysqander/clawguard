#!/usr/bin/env node

import net from "node:net";
import { randomUUID } from "node:crypto";

import {
  daemonResponseEnvelopeValidator,
  resolveDaemonSocketPath,
  type DaemonRequestEnvelope,
  type DaemonRequestPayload,
  type DaemonResponseEnvelope,
} from "@clawguard/contracts";

async function main(): Promise<void> {
  const [, , command = "status", ...rest] = process.argv;
  const payload = buildPayload(command, rest);
  const response = await sendDaemonRequest(payload);

  if (!response.ok) {
    console.error(`error (${response.error.code}): ${response.error.message}`);
    process.exitCode = 1;
    return;
  }

  console.log(JSON.stringify(response.data, null, 2));
}

function buildPayload(command: string, args: string[]): DaemonRequestPayload {
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

await main();
