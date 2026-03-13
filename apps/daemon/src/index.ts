import { randomUUID } from "node:crypto";
import { mkdirSync, rmSync } from "node:fs";
import { createServer, type Socket } from "node:net";
import { dirname } from "node:path";

import {
  daemonRequestEnvelopeValidator,
  daemonResponseEnvelopeValidator,
  defaultClawGuardConfig,
  type DaemonErrorResponse,
  type DaemonRequestEnvelope,
  type DaemonResponseEnvelope,
  type DaemonSuccessResponse,
  type DetonationReport,
} from "@clawguard/contracts";
import { SkillLifecycleManager, buildSkillSnapshot } from "@clawguard/discovery";
import { defaultDetonationRuntime } from "@clawguard/detonation";
import { createPlatformAdapter } from "@clawguard/platform";
import { persistSynthesizedStaticReport, synthesizeStaticReport } from "@clawguard/reports";
import { scanSkillSnapshot } from "@clawguard/scanner";
import { createStorage, expandHomePath } from "@clawguard/storage";

interface DaemonRuntimeState {
  activeJobs: number;
}

function createSuccess(requestId: string, data: DaemonSuccessResponse["data"]): DaemonSuccessResponse {
  return { version: 1, requestId, ok: true, data };
}

function createError(
  requestId: string,
  code: string,
  message: string,
  retryable = false,
): DaemonErrorResponse {
  return { version: 1, requestId, ok: false, error: { code, message, retryable } };
}

async function handleRequest(
  envelope: DaemonRequestEnvelope,
  state: DaemonRuntimeState,
): Promise<DaemonResponseEnvelope> {
  const storage = createStorage();
  const lifecycle = new SkillLifecycleManager({ storage });

  try {
    switch (envelope.payload.command) {
      case "status":
        return createSuccess(envelope.requestId, {
          state: state.activeJobs > 0 ? "busy" : "idle",
          jobs: state.activeJobs,
        });
      case "scan": {
        state.activeJobs += 1;
        const startedAt = new Date().toISOString();
        const scanId = `scan-${randomUUID()}`;
        const snapshotResult = await buildSkillSnapshot({
          skillPath: envelope.payload.skillPath,
          skillRootPath: dirname(envelope.payload.skillPath),
          skillRootKind: "managed",
          discoverySource: "default",
          detectedAt: startedAt,
        });

        if (!snapshotResult.ok) {
          return createError(
            envelope.requestId,
            "scan-invalid-skill",
            `${snapshotResult.error.message} (${snapshotResult.error.kind})`,
          );
        }

        const report = scanSkillSnapshot(snapshotResult.snapshot);
        const scan = await storage.persistScan({
          scan: {
            scanId,
            slug: snapshotResult.snapshot.slug,
            contentHash: snapshotResult.snapshot.contentHash,
            status: "completed",
            startedAt,
            completedAt: new Date().toISOString(),
          },
        });

        const synthesized = synthesizeStaticReport({ scan, report });
        await persistSynthesizedStaticReport(storage, synthesized);

        if (report.recommendation === "block") {
          await lifecycle.quarantineSkill({
            scanId,
            skillSlug: report.snapshot.slug,
            skillPath: report.snapshot.path,
            contentHash: report.snapshot.contentHash,
            reason: synthesized.decisionReason,
          });
        }

        return createSuccess(envelope.requestId, { scan, report });
      }
      case "report": {
        const stored = await storage.getLatestStaticReportBySlug(envelope.payload.slug);
        if (!stored) {
          return createError(
            envelope.requestId,
            "report-not-found",
            `No report found for slug '${envelope.payload.slug}'. Run 'clawguard scan <path>' first.`,
          );
        }

        return createSuccess(envelope.requestId, {
          summary: stored.summary,
          report: stored.report,
          ...(stored.decision ? { decision: stored.decision } : {}),
          artifacts: stored.artifacts,
        });
      }
      case "allow": {
        const stored = await storage.getLatestStaticReportBySlug(envelope.payload.slug);
        if (!stored) {
          return createError(
            envelope.requestId,
            "allow-missing-report",
            `Cannot allow '${envelope.payload.slug}' because no scan report exists yet.`,
          );
        }

        const decision = await lifecycle.allowHash({
          contentHash: stored.report.snapshot.contentHash,
          ...(envelope.payload.reason ? { reason: envelope.payload.reason } : {}),
        });

        return createSuccess(envelope.requestId, {
          summary: stored.summary,
          report: stored.report,
          decision,
          artifacts: stored.artifacts,
        });
      }
      case "block": {
        const stored = await storage.getLatestStaticReportBySlug(envelope.payload.slug);
        if (!stored) {
          return createError(
            envelope.requestId,
            "block-missing-report",
            `Cannot block '${envelope.payload.slug}' because no scan report exists yet.`,
          );
        }

        const decision = await lifecycle.blockHash({
          contentHash: stored.report.snapshot.contentHash,
          ...(envelope.payload.reason ? { reason: envelope.payload.reason } : {}),
        });

        return createSuccess(envelope.requestId, {
          summary: stored.summary,
          report: stored.report,
          decision,
          artifacts: stored.artifacts,
        });
      }
      case "detonate": {
        const runtime = await createPlatformAdapter().containerRuntimes.getPreferredRuntime(
          defaultDetonationRuntime,
        );
        if (!runtime) {
          return createError(
            envelope.requestId,
            "runtime-unavailable",
            "No compatible container runtime found. Install Podman (preferred) or Docker.",
          );
        }

        const stored = await storage.getLatestStaticReportBySlug(envelope.payload.slug);
        if (!stored) {
          return createError(
            envelope.requestId,
            "detonate-missing-report",
            `Cannot detonate '${envelope.payload.slug}' because no scan report exists yet.`,
          );
        }

        const report: DetonationReport = {
          request: {
            requestId: `detonate-${randomUUID()}`,
            snapshot: stored.report.snapshot,
            prompts: ["Initialize skill", "Run representative workflow"],
            timeoutSeconds: defaultClawGuardConfig.detonation.timeoutSeconds,
          },
          summary: `Runtime '${runtime.runtime}' available; full detonation execution not implemented yet.`,
          triggeredActions: [],
          artifacts: [],
          generatedAt: new Date().toISOString(),
        };

        return createSuccess(envelope.requestId, { report });
      }
      case "audit":
        return createSuccess(envelope.requestId, { scans: [] });
      default:
        return createError(envelope.requestId, "unknown-command", "Unsupported command.");
    }
  } catch (error) {
    return createError(
      envelope.requestId,
      "daemon-error",
      error instanceof Error ? error.message : String(error),
    );
  } finally {
    if (envelope.payload.command === "scan" && state.activeJobs > 0) {
      state.activeJobs -= 1;
    }
    storage.close();
  }
}

function writeResponse(socket: Socket, response: DaemonResponseEnvelope): void {
  socket.end(`${JSON.stringify(daemonResponseEnvelopeValidator.parse(response))}\n`);
}

export async function startDaemon(): Promise<string> {
  const socketPath = expandHomePath(defaultClawGuardConfig.paths.socketPath);
  const state: DaemonRuntimeState = { activeJobs: 0 };

  mkdirSync(dirname(socketPath), { recursive: true });
  rmSync(socketPath, { force: true });

  const server = createServer((socket) => {
    let buffer = "";
    socket.on("data", async (chunk) => {
      buffer += chunk.toString("utf8");
      const newlineIndex = buffer.indexOf("\n");
      if (newlineIndex < 0) {
        return;
      }

      const requestLine = buffer.slice(0, newlineIndex);
      buffer = "";

      let parsed: unknown;
      try {
        parsed = JSON.parse(requestLine);
      } catch {
        writeResponse(socket, createError("unknown", "invalid-json", "Request body must be JSON."));
        return;
      }

      try {
        const request = daemonRequestEnvelopeValidator.parse(parsed);
        writeResponse(socket, await handleRequest(request, state));
      } catch (error) {
        writeResponse(
          socket,
          createError(
            "unknown",
            "invalid-request",
            error instanceof Error ? error.message : String(error),
          ),
        );
      }
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => resolve());
  });

  return `clawguard daemon listening on ${socketPath}`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(await startDaemon());
}
