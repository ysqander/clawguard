import { randomUUID } from "node:crypto";
import { mkdirSync, rmSync } from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import {
  daemonRequestEnvelopeValidator,
  type ScanRecord,
  type StaticScanReport,
  type DaemonErrorResponse,
  type DaemonRequestEnvelope,
  type DaemonResponseEnvelope,
  type DaemonSuccessResponse,
} from "@clawguard/contracts";
import {
  SkillLifecycleManager,
  buildSkillSnapshot,
  discoverOpenClawWorkspaceModel,
  SkillWatcherPipeline,
} from "@clawguard/discovery";
import { createPlatformAdapter } from "@clawguard/platform";
import { persistSynthesizedStaticReport, synthesizeStaticReport } from "@clawguard/reports";
import { scanSkillSnapshot } from "@clawguard/scanner";
import { createStorage, type StoredStaticReport } from "@clawguard/storage";

const DEFAULT_SOCKET_PATH = path.join(os.tmpdir(), "clawguard-daemon.sock");
const MAX_QUEUE_DEPTH = 64;
const SCAN_RETRY_LIMIT = 2;
const RETRY_DELAY_MS = 150;

interface ScanJobResult {
  scan: ScanRecord;
  report?: StaticScanReport;
}

interface QueuedScanJob {
  idempotencyKey: string;
  skillPath: string;
  resolve: (value: ScanJobResult) => void;
  reject: (error: Error) => void;
}

export interface StartDaemonOptions {
  socketPath?: string;
}

export class DaemonServer {
  private readonly socketPath: string;
  private readonly server: net.Server;
  private readonly storage = createStorage();
  private readonly lifecycle = new SkillLifecycleManager({ storage: this.storage });
  private readonly scanQueue: QueuedScanJob[] = [];
  private readonly inflightScanByKey = new Map<string, Promise<ScanJobResult>>();
  private readonly platform = createPlatformAdapter();
  private watcherPipeline: SkillWatcherPipeline | undefined;
  private queueRunning = false;

  public constructor(options: StartDaemonOptions = {}) {
    this.socketPath = options.socketPath ?? resolveDaemonSocketPath();
    this.server = net.createServer((socket) => {
      let buffer = "";
      socket.setEncoding("utf8");

      socket.on("data", (chunk) => {
        buffer += chunk;
        const messages = buffer.split("\n");
        buffer = messages.pop() ?? "";
        for (const message of messages) {
          if (message.trim().length === 0) {
            continue;
          }
          void this.handleMessage(socket, message);
        }
      });
    });
  }

  public getSocketPath(): string {
    return this.socketPath;
  }

  public async start(): Promise<void> {
    mkdirSync(path.dirname(this.socketPath), { recursive: true });
    rmSync(this.socketPath, { force: true });

    await new Promise<void>((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(this.socketPath, () => {
        this.server.off("error", reject);
        resolve();
      });
    });

    await this.startWatcherPipeline();
  }

  public async stop(): Promise<void> {
    await this.watcherPipeline?.stop();
    this.watcherPipeline = undefined;

    await new Promise<void>((resolve) => {
      this.server.close(() => {
        resolve();
      });
    });

    rmSync(this.socketPath, { force: true });
    this.storage.close();
  }

  private async startWatcherPipeline(): Promise<void> {
    try {
      const workspaceModel = await discoverOpenClawWorkspaceModel();
      this.watcherPipeline = new SkillWatcherPipeline({
        workspaceModel,
        watcher: this.platform.watcher,
        onScanScheduled: async (scan) => {
          void this.enqueueScan(scan.idempotencyKey, scan.skillPath);
        },
        onRootRescanRequested: async () => {
          // Root rescans are advisory; watcher event granularity already provides skill-level scans.
        },
        onError: async () => {
          // Surface watcher errors via daemon status degradation in later tickets.
        },
      });
      await this.watcherPipeline.start();
    } catch {
      this.watcherPipeline = undefined;
    }
  }

  private async handleMessage(socket: net.Socket, message: string): Promise<void> {
    let request: DaemonRequestEnvelope;

    try {
      request = daemonRequestEnvelopeValidator.parse(JSON.parse(message));
    } catch (error) {
      const response = this.errorResponse(
        "invalid_request",
        error instanceof Error ? error.message : "Invalid daemon request payload",
        false,
      );
      socket.write(`${JSON.stringify(response)}\n`);
      return;
    }

    const response = await this.handleRequest(request);
    socket.write(`${JSON.stringify(response)}\n`);
  }

  private async handleRequest(request: DaemonRequestEnvelope): Promise<DaemonResponseEnvelope> {
    try {
      switch (request.payload.command) {
        case "status":
          return this.successResponse(request.requestId, {
            state: this.scanQueue.length > 0 || this.inflightScanByKey.size > 0 ? "busy" : "idle",
            jobs: this.scanQueue.length + this.inflightScanByKey.size,
          });
        case "scan": {
          const result = await this.enqueueScan(request.payload.skillPath, request.payload.skillPath);
          return this.successResponse(request.requestId, {
            scan: result.scan,
            ...(result.report ? { report: result.report } : {}),
          });
        }
        case "report": {
          const report = await this.storage.getLatestStaticReportBySlug(request.payload.slug);
          if (!report) {
            return this.errorResponse(
              request.requestId,
              "not_found",
              `No static report found for slug ${request.payload.slug}`,
              false,
            );
          }

          return this.successResponse(request.requestId, this.toReportResponse(report));
        }
        case "allow":
        case "block": {
          const report = await this.storage.getLatestStaticReportBySlug(request.payload.slug);
          if (!report) {
            return this.errorResponse(
              request.requestId,
              "not_found",
              `No static report found for slug ${request.payload.slug}`,
              false,
            );
          }

          const decision =
            request.payload.command === "allow"
              ? await this.lifecycle.allowHash({
                  contentHash: report.report.snapshot.contentHash,
                  ...(request.payload.reason ? { reason: request.payload.reason } : {}),
                })
              : await this.lifecycle.blockHash({
                  contentHash: report.report.snapshot.contentHash,
                  ...(request.payload.reason ? { reason: request.payload.reason } : {}),
                });

          return this.successResponse(request.requestId, {
            summary: report.summary,
            report: report.report,
            decision,
            artifacts: report.artifacts,
          });
        }
        case "audit":
          return this.successResponse(request.requestId, { scans: [] });
        case "detonate":
          return this.errorResponse(
            request.requestId,
            "not_implemented",
            "Detonation orchestration lands in Milestone B tickets.",
            false,
          );
      }
    } catch (error) {
      return this.errorResponse(
        request.requestId,
        "internal_error",
        error instanceof Error ? error.message : "Unexpected daemon error",
        true,
      );
    }
  }

  private enqueueScan(idempotencyKey: string, skillPath: string): Promise<ScanJobResult> {
    const inflight = this.inflightScanByKey.get(idempotencyKey);
    if (inflight) {
      return inflight;
    }

    if (this.scanQueue.length >= MAX_QUEUE_DEPTH) {
      throw new Error(`Scan queue is full (${MAX_QUEUE_DEPTH}).`);
    }

    const promise = new Promise<ScanJobResult>((resolve, reject) => {
      this.scanQueue.push({
        idempotencyKey,
        skillPath,
        resolve,
        reject,
      });

      void this.pumpScanQueue();
    }).finally(() => {
      this.inflightScanByKey.delete(idempotencyKey);
    });

    this.inflightScanByKey.set(idempotencyKey, promise);
    return promise;
  }

  private async pumpScanQueue(): Promise<void> {
    if (this.queueRunning) {
      return;
    }

    this.queueRunning = true;
    while (this.scanQueue.length > 0) {
      const job = this.scanQueue.shift();
      if (!job) {
        continue;
      }

      try {
        const result = await this.runScanWithRetry(job.skillPath);
        job.resolve(result);
      } catch (error) {
        job.reject(error instanceof Error ? error : new Error(String(error)));
      }
    }
    this.queueRunning = false;
  }

  private async runScanWithRetry(skillPath: string): Promise<ScanJobResult> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= SCAN_RETRY_LIMIT; attempt += 1) {
      try {
        return await this.runScan(skillPath);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        if (attempt < SCAN_RETRY_LIMIT) {
          await delay(RETRY_DELAY_MS);
        }
      }
    }

    throw lastError ?? new Error("Scan failed");
  }

  private async runScan(skillPath: string): Promise<ScanJobResult> {
    const slug = path.basename(skillPath);
    const snapshotResult = await buildSkillSnapshot({
      skillPath,
      skillSlug: slug,
      skillRootPath: path.dirname(skillPath),
      skillRootKind: "workspace",
      discoverySource: "default",
    });

    if (!snapshotResult.ok) {
      throw new Error(snapshotResult.error.message);
    }

    const scanReport = scanSkillSnapshot(snapshotResult.snapshot);
    const scanId = randomUUID();
    const startedAt = new Date().toISOString();
    const completedAt = new Date().toISOString();
    const scan = await this.storage.persistScan({
      scan: {
        scanId,
        slug: scanReport.snapshot.slug,
        contentHash: scanReport.snapshot.contentHash,
        status: "completed",
        startedAt,
        completedAt,
      },
    });

    const synthesis = synthesizeStaticReport({
      scan,
      report: scanReport,
    });
    const persisted = await persistSynthesizedStaticReport(this.storage, synthesis);

    await this.lifecycle.resolveSkillLifecycle({
      scanId: scan.scanId,
      skillSlug: scanReport.snapshot.slug,
      skillPath,
      contentHash: scanReport.snapshot.contentHash,
    });

    return {
      scan,
      report: persisted.storedReport.report,
    };
  }

  private toReportResponse(report: StoredStaticReport): DaemonSuccessResponse["data"] {
    return {
      summary: report.summary,
      report: report.report,
      ...(report.decision ? { decision: report.decision } : {}),
      artifacts: report.artifacts,
    };
  }

  private successResponse(
    requestId: string,
    data: DaemonSuccessResponse["data"],
  ): DaemonSuccessResponse {
    return {
      version: 1,
      requestId,
      ok: true,
      data,
    };
  }

  private errorResponse(
    requestId: string,
    code: string,
    message: string,
    retryable: boolean,
  ): DaemonErrorResponse;
  private errorResponse(code: string, message: string, retryable: boolean): DaemonErrorResponse;
  private errorResponse(
    requestIdOrCode: string,
    codeOrMessage: string,
    messageOrRetryable: string | boolean,
    retryable = false,
  ): DaemonErrorResponse {
    const isImplicit = typeof messageOrRetryable === "boolean";
    const requestId = isImplicit ? "unknown" : requestIdOrCode;
    const code = isImplicit ? requestIdOrCode : codeOrMessage;
    const message = isImplicit ? codeOrMessage : (messageOrRetryable as string);

    return {
      version: 1,
      requestId,
      ok: false,
      error: {
        code,
        message,
        retryable: isImplicit ? (messageOrRetryable as boolean) : retryable,
      },
    };
  }
}

export function resolveDaemonSocketPath(): string {
  return process.env.CLAWGUARD_DAEMON_SOCKET ?? DEFAULT_SOCKET_PATH;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

export async function startDaemon(options: StartDaemonOptions = {}): Promise<string> {
  const daemon = new DaemonServer(options);
  await daemon.start();
  return `clawguard daemon listening on ${daemon.getSocketPath()}`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const daemon = new DaemonServer();
  await daemon.start();
  console.log(`clawguard daemon listening on ${daemon.getSocketPath()}`);
}
