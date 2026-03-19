import { randomUUID } from "node:crypto";
import { realpathSync } from "node:fs";
import { mkdirSync, rmSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  daemonRequestEnvelopeValidator,
  resolveDaemonSocketPath,
  type OpenClawWorkspaceModel,
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
  type SkillWatcherPipelineErrorContext,
  type SkillWatcherPipelineWatchContext,
} from "@clawguard/discovery";
import { createPlatformAdapter, type PlatformAdapter } from "@clawguard/platform";
import { persistSynthesizedStaticReport, synthesizeStaticReport } from "@clawguard/reports";
import { scanSkillSnapshot } from "@clawguard/scanner";
import { createStorage, type StoragePaths, type StoredStaticReport } from "@clawguard/storage";

import { buildScanNotification, type ScanRecommendation } from "./notifications.js";

const MAX_QUEUE_DEPTH = 64;
const SCAN_RETRY_LIMIT = 2;
const RETRY_DELAY_MS = 150;
const MAX_WARNING_ISSUES = 10;

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
  storagePaths?: Partial<StoragePaths>;
  startWatcher?: boolean;
  platformAdapter?: PlatformAdapter;
  workspaceModel?: OpenClawWorkspaceModel;
  watcherDebounceMs?: number;
  watcherRetryDelayMs?: number;
}

export class DaemonServer {
  private readonly socketPath: string;
  private readonly server: net.Server;
  private readonly storage: ReturnType<typeof createStorage>;
  private readonly lifecycle: SkillLifecycleManager;
  private readonly scanQueue: QueuedScanJob[] = [];
  private readonly inflightScanByKey = new Map<string, Promise<ScanJobResult>>();
  private readonly startWatcher: boolean;
  private readonly platform: PlatformAdapter | undefined;
  private readonly workspaceModel: OpenClawWorkspaceModel | undefined;
  private readonly watcherDebounceMs: number | undefined;
  private readonly watcherRetryDelayMs: number | undefined;
  private readonly watcherIssuesByRoot = new Map<string, string>();
  private readonly watcherUnavailableRootsByPath = new Map<string, string>();
  private readonly warningIssues: string[] = [];
  private watcherStartupIssue: string | undefined;
  private watcherPipeline: SkillWatcherPipeline | undefined;
  private queueRunning = false;

  public constructor(options: StartDaemonOptions = {}) {
    this.socketPath = options.socketPath ?? resolveDaemonSocketPath();
    this.startWatcher = options.startWatcher ?? true;
    this.storage = createStorage(options.storagePaths);
    this.lifecycle = new SkillLifecycleManager({ storage: this.storage });
    this.platform = this.startWatcher
      ? (options.platformAdapter ?? createPlatformAdapter())
      : undefined;
    this.workspaceModel = options.workspaceModel;
    this.watcherDebounceMs = options.watcherDebounceMs;
    this.watcherRetryDelayMs = options.watcherRetryDelayMs;
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

    if (this.startWatcher) {
      await this.startWatcherPipeline();
    }
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
    if (!this.platform) {
      return;
    }

    try {
      this.watcherStartupIssue = undefined;
      const workspaceModel = this.workspaceModel ?? (await discoverOpenClawWorkspaceModel());
      this.watcherPipeline = new SkillWatcherPipeline({
        workspaceModel,
        watcher: this.platform.watcher,
        onScanScheduled: async (scan) => {
          void this.enqueueScan(scan.idempotencyKey, scan.skillPath);
        },
        onRootRescanRequested: async () => {
          // Root rescans are advisory; watcher event granularity already provides skill-level scans.
        },
        onWatchActivated: async (context) => {
          this.clearWatcherIssue(context);
        },
        onError: async (error, context) => {
          this.recordWatcherIssue(error, context);
        },
        ...(this.watcherDebounceMs !== undefined ? { debounceMs: this.watcherDebounceMs } : {}),
        ...(this.watcherRetryDelayMs !== undefined
          ? { retryDelayMs: this.watcherRetryDelayMs }
          : {}),
      });
      await this.watcherPipeline.start();
    } catch (error) {
      this.watcherPipeline = undefined;
      this.recordWatcherStartupIssue(
        `Watcher startup failed: ${error instanceof Error ? error.message : "unknown error"}`,
      );
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
          return this.successResponse(request.requestId, this.buildStatusResponse());
        case "scan": {
          const result = await this.enqueueScan(
            request.payload.skillPath,
            request.payload.skillPath,
          );
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

          await (request.payload.command === "allow"
            ? this.lifecycle.applyOperatorAllow({
                skillSlug: report.report.snapshot.slug,
                contentHash: report.report.snapshot.contentHash,
                ...(request.payload.reason ? { reason: request.payload.reason } : {}),
              })
            : this.lifecycle.applyOperatorBlock({
                skillSlug: report.report.snapshot.slug,
                contentHash: report.report.snapshot.contentHash,
                skillPath: report.report.snapshot.path,
                ...(request.payload.reason ? { reason: request.payload.reason } : {}),
              }));

          const refreshedReport = await this.storage.getLatestStaticReportBySlug(
            request.payload.slug,
          );
          if (!refreshedReport) {
            throw new Error(`No static report found for slug ${request.payload.slug} after update`);
          }

          return this.successResponse(request.requestId, this.toReportResponse(refreshedReport));
        }
        case "audit":
          return this.successResponse(request.requestId, { scans: await this.storage.listScans() });
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

    await this.lifecycle.applyPostScanDisposition({
      scanId: scan.scanId,
      skillSlug: scanReport.snapshot.slug,
      skillPath,
      contentHash: scanReport.snapshot.contentHash,
      recommendation: scanReport.recommendation,
    });
    await this.sendScanNotification(persisted.storedReport.report);

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

  private buildStatusResponse(): DaemonSuccessResponse["data"] {
    const jobs = this.scanQueue.length + this.inflightScanByKey.size;
    const watcher = this.getWatcherState();
    const degraded = watcher === "degraded";
    const issues = this.getActiveIssues();

    return {
      state: degraded ? "degraded" : jobs > 0 ? "busy" : "idle",
      jobs,
      watcher,
      issues,
    };
  }

  private getWatcherState(): "disabled" | "running" | "degraded" {
    if (!this.startWatcher) {
      return "disabled";
    }

    if (this.watcherStartupIssue !== undefined || this.watcherIssuesByRoot.size > 0) {
      return "degraded";
    }

    return "running";
  }

  private recordWatcherIssue(error: Error, context: SkillWatcherPipelineErrorContext): void {
    if (isMissingWatchRootError(error)) {
      this.watcherIssuesByRoot.delete(context.skillRootPath);
      this.watcherUnavailableRootsByPath.set(
        context.skillRootPath,
        `Watcher waiting for missing skill root ${context.skillRootPath} to appear.`,
      );
      return;
    }

    this.watcherUnavailableRootsByPath.delete(context.skillRootPath);
    const message = `Watcher ${context.phase} failed for ${context.skillRootPath}: ${error.message}`;

    if (context.phase === "watch-start" || context.phase === "watch-runtime") {
      this.watcherIssuesByRoot.set(context.skillRootPath, message);
      return;
    }

    this.recordWarningIssue(message);
  }

  private clearWatcherIssue(context: SkillWatcherPipelineWatchContext): void {
    this.watcherIssuesByRoot.delete(context.skillRootPath);
    this.watcherUnavailableRootsByPath.delete(context.skillRootPath);
  }

  private recordWatcherStartupIssue(message: string): void {
    this.watcherStartupIssue = message;
  }

  private recordWarningIssue(message: string): void {
    this.warningIssues.push(message);
    if (this.warningIssues.length > MAX_WARNING_ISSUES) {
      this.warningIssues.shift();
    }
  }

  private getActiveIssues(): string[] {
    return [
      ...(this.watcherStartupIssue !== undefined ? [this.watcherStartupIssue] : []),
      ...this.watcherIssuesByRoot.values(),
      ...this.watcherUnavailableRootsByPath.values(),
      ...this.warningIssues,
    ];
  }

  private async sendScanNotification(report: StaticScanReport): Promise<void> {
    if (!this.platform?.capabilities.supportsNotifications) {
      return;
    }

    try {
      await this.platform.notifications.send(
        buildScanNotification({
          slug: report.snapshot.slug,
          recommendation: toNotificationRecommendation(report.recommendation),
          score: report.score,
          findingCount: report.findings.length,
          completedAt: report.generatedAt,
        }),
      );
    } catch (error) {
      this.recordWarningIssue(
        `Notification delivery failed for ${report.snapshot.slug}: ${
          error instanceof Error ? error.message : "unknown error"
        }`,
      );
    }
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
export { resolveDaemonSocketPath };

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

const isEntrypoint =
  process.argv[1] !== undefined &&
  resolveEntrypointPath(fileURLToPath(import.meta.url)) === resolveEntrypointPath(process.argv[1]);

if (isEntrypoint) {
  const daemon = new DaemonServer();
  await daemon.start();
  console.log(`clawguard daemon listening on ${daemon.getSocketPath()}`);
}

function resolveEntrypointPath(filePath: string): string {
  try {
    return realpathSync(path.resolve(filePath));
  } catch {
    return path.resolve(filePath);
  }
}

function toNotificationRecommendation(
  recommendation: StaticScanReport["recommendation"],
): ScanRecommendation {
  switch (recommendation) {
    case "allow":
    case "review":
    case "block":
      return recommendation;
    case "unknown":
      return "review";
  }
}

function isMissingWatchRootError(error: Error): boolean {
  return (
    ("code" in error && error.code === "ENOENT") ||
    error.message.includes("ENOENT: no such file or directory")
  );
}
