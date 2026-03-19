import { randomUUID } from "node:crypto";
import { realpathSync } from "node:fs";
import { mkdirSync, rmSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  defaultClawGuardConfig,
  daemonRequestEnvelopeValidator,
  resolveDaemonSocketPath,
  type DetonationConfig,
  type DetonationReport,
  type DetonationStatusRecord,
  type OpenClawWorkspaceModel,
  type ScanRecord,
  type ScanThresholdsConfig,
  type SkillSnapshot,
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
import {
  runDetonationAnalysis,
  type RunDetonationAnalysisOptions,
  type RunDetonationAnalysisResult,
} from "@clawguard/detonation";
import { VirusTotalHttpClient } from "@clawguard/integrations";
import { createPlatformAdapter, type PlatformAdapter } from "@clawguard/platform";
import {
  persistSynthesizedStaticReport,
  renderDetonationReport,
  synthesizeStaticReport,
  synthesizeUnifiedReport,
} from "@clawguard/reports";
import { scanSkillSnapshot } from "@clawguard/scanner";
import {
  createStorage,
  type StoragePaths,
  type StoredArtifactRecord,
  type StoredDetonationRun,
  type StoredStaticReport,
} from "@clawguard/storage";

import { buildScanNotification, type ScanRecommendation } from "./notifications.js";

const MAX_QUEUE_DEPTH = 64;
const SCAN_RETRY_LIMIT = 2;
const RETRY_DELAY_MS = 150;
const MAX_WARNING_ISSUES = 10;

type SnapshotBuildError = Extract<
  Awaited<ReturnType<typeof buildSkillSnapshot>>,
  { ok: false }
>["error"];

interface ScanJobResult {
  skipped?: false;
  scan: ScanRecord;
  report?: StaticScanReport;
  storedReport?: StoredStaticReport;
}

interface SkippedScanJobResult {
  skipped: true;
  skillPath: string;
  reason: string;
}

type ScanQueueResult = ScanJobResult | SkippedScanJobResult;

type ScanOrigin = "manual" | "watcher" | "detonation-refresh";

class SnapshotBuildFailure extends Error {
  public readonly buildError: SnapshotBuildError;

  public constructor(buildError: SnapshotBuildError) {
    super(buildError.message);
    this.name = "SnapshotBuildFailure";
    this.buildError = buildError;
  }
}

interface QueuedScanJob {
  idempotencyKey: string;
  skillPath: string;
  scheduleAutoDetonation: boolean;
  origin: ScanOrigin;
  resolve: (value: ScanQueueResult) => void;
  reject: (error: Error) => void;
}

interface EnsuredStaticScanResult {
  scan: ScanRecord;
  storedReport: StoredStaticReport;
  snapshot: SkillSnapshot;
}

interface DetonationJobResult {
  status: DetonationStatusRecord;
  report?: DetonationReport;
}

interface QueuedDetonationJob {
  idempotencyKey: string;
  requestId: string;
  ensuredScan: EnsuredStaticScanResult;
  resolve: (value: DetonationJobResult) => void;
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
  detonationConfig?: Partial<DetonationConfig>;
  scanThresholds?: Partial<ScanThresholdsConfig>;
  detonationRunner?: (
    snapshot: SkillSnapshot,
    options?: RunDetonationAnalysisOptions,
  ) => Promise<RunDetonationAnalysisResult>;
}

export class DaemonServer {
  private readonly socketPath: string;
  private readonly server: net.Server;
  private readonly storage: ReturnType<typeof createStorage>;
  private readonly lifecycle: SkillLifecycleManager;
  private readonly scanQueue: QueuedScanJob[] = [];
  private readonly inflightScanByKey = new Map<string, Promise<ScanQueueResult>>();
  private readonly detonationQueue: QueuedDetonationJob[] = [];
  private readonly inflightDetonationByKey = new Map<string, Promise<DetonationJobResult>>();
  private readonly startWatcher: boolean;
  private readonly platform: PlatformAdapter | undefined;
  private readonly workspaceModel: OpenClawWorkspaceModel | undefined;
  private readonly watcherDebounceMs: number | undefined;
  private readonly watcherRetryDelayMs: number | undefined;
  private readonly detonationConfig: DetonationConfig;
  private readonly scanThresholds: ScanThresholdsConfig;
  private readonly detonationRunner: (
    snapshot: SkillSnapshot,
    options?: RunDetonationAnalysisOptions,
  ) => Promise<RunDetonationAnalysisResult>;
  private readonly virusTotalClient: VirusTotalHttpClient | undefined;
  private readonly watcherIssuesByRoot = new Map<string, string>();
  private readonly watcherUnavailableRootsByPath = new Map<string, string>();
  private readonly warningIssues: string[] = [];
  private watcherStartupIssue: string | undefined;
  private watcherPipeline: SkillWatcherPipeline | undefined;
  private queueRunning = false;
  private detonationQueueRunning = false;

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
    this.detonationConfig = {
      ...defaultClawGuardConfig.detonation,
      ...options.detonationConfig,
    };
    this.scanThresholds = {
      ...defaultClawGuardConfig.scanThresholds,
      ...options.scanThresholds,
    };
    this.detonationRunner = options.detonationRunner ?? runDetonationAnalysis;
    this.virusTotalClient = createVirusTotalClientFromEnv();
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
          void this.enqueueScan(scan.idempotencyKey, scan.skillPath, true, "watcher");
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
            true,
            "manual",
          );
          if (result.skipped) {
            throw new Error(`Scan for ${request.payload.skillPath} was skipped unexpectedly.`);
          }
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

          const detonationRun = await this.getCurrentDetonationRunForReport(report);

          return this.successResponse(
            request.requestId,
            this.toReportResponse(report, detonationRun),
          );
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

          const detonationRun = await this.getCurrentDetonationRunForReport(refreshedReport);

          return this.successResponse(
            request.requestId,
            this.toReportResponse(refreshedReport, detonationRun),
          );
        }
        case "audit":
          return this.successResponse(request.requestId, { scans: await this.storage.listScans() });
        case "detonate":
          return await this.handleDetonateRequest(request.requestId, request.payload.slug);
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

  private async handleDetonateRequest(
    requestId: string,
    slug: string,
  ): Promise<DaemonResponseEnvelope> {
    const ensuredScan = await this.ensureStaticScanForDetonation(slug);
    if (!ensuredScan) {
      return this.errorResponse(
        requestId,
        "not_found",
        `No locally installed skill named ${slug} was found in the discovered skill roots.`,
        false,
      );
    }

    const disabledStatus = await this.prepareDetonationDisabledStatus(ensuredScan);
    if (disabledStatus) {
      return this.errorResponse(
        requestId,
        mapDetonationStatusToErrorCode(disabledStatus),
        disabledStatus.errorMessage ?? "Detonation is disabled.",
        false,
      );
    }

    const detonationKey = this.buildDetonationIdempotencyKey(ensuredScan);
    const result = await this.enqueueDetonation(detonationKey, ensuredScan);

    if (result.report) {
      return this.successResponse(requestId, {
        report: result.report,
      });
    }

    return this.errorResponse(
      requestId,
      mapDetonationStatusToErrorCode(result.status),
      result.status.errorMessage ?? "Detonation did not produce a behavioral report.",
      false,
    );
  }

  private enqueueScan(
    idempotencyKey: string,
    skillPath: string,
    scheduleAutoDetonation: boolean,
    origin: ScanOrigin,
  ): Promise<ScanQueueResult> {
    const inflight = this.inflightScanByKey.get(idempotencyKey);
    if (inflight) {
      return inflight;
    }

    if (this.scanQueue.length >= MAX_QUEUE_DEPTH) {
      throw new Error(`Scan queue is full (${MAX_QUEUE_DEPTH}).`);
    }

    const promise = new Promise<ScanQueueResult>((resolve, reject) => {
      this.scanQueue.push({
        idempotencyKey,
        skillPath,
        scheduleAutoDetonation,
        origin,
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
        const result = await this.runScanWithRetry(
          job.skillPath,
          job.scheduleAutoDetonation,
          job.origin,
        );
        job.resolve(result);
      } catch (error) {
        job.reject(error instanceof Error ? error : new Error(String(error)));
      }
    }
    this.queueRunning = false;
  }

  private async runScanWithRetry(
    skillPath: string,
    scheduleAutoDetonation: boolean,
    origin: ScanOrigin,
  ): Promise<ScanQueueResult> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= SCAN_RETRY_LIMIT; attempt += 1) {
      try {
        return await this.runScan(skillPath, scheduleAutoDetonation);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        if (isSnapshotBuildFailure(lastError)) {
          if (origin === "watcher" && isSkippableWatcherSnapshotFailure(lastError)) {
            const reason = `Watcher skipped stale skill scan for ${skillPath}: ${lastError.message}`;
            this.recordWarningIssue(reason);
            return {
              skipped: true,
              skillPath,
              reason,
            };
          }

          if (isMissingSnapshotFailure(lastError)) {
            throw lastError;
          }
        }

        if (attempt < SCAN_RETRY_LIMIT) {
          await delay(RETRY_DELAY_MS);
        }
      }
    }

    throw lastError ?? new Error("Scan failed");
  }

  private async runScan(
    skillPath: string,
    scheduleAutoDetonation: boolean,
  ): Promise<ScanJobResult> {
    const slug = path.basename(skillPath);
    const snapshotResult = await buildSkillSnapshot({
      skillPath,
      skillSlug: slug,
      skillRootPath: path.dirname(skillPath),
      skillRootKind: "workspace",
      discoverySource: "default",
    });

    if (!snapshotResult.ok) {
      throw new SnapshotBuildFailure(snapshotResult.error);
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

    const disposition = await this.lifecycle.applyPostScanDisposition({
      scanId: scan.scanId,
      skillSlug: scanReport.snapshot.slug,
      skillPath,
      contentHash: scanReport.snapshot.contentHash,
      recommendation: scanReport.recommendation,
    });
    await this.sendScanNotification(persisted.storedReport.report);

    if (scheduleAutoDetonation) {
      const detonationSkillPath = resolveDetonationSkillPath(skillPath, disposition);
      if (detonationSkillPath) {
        void this.scheduleAutomaticDetonation({
          scan,
          storedReport: persisted.storedReport,
          snapshot: {
            ...scanReport.snapshot,
            path: detonationSkillPath,
          },
        }).catch((error) => {
          this.recordWarningIssue(
            `Automatic detonation scheduling failed for ${scanReport.snapshot.slug}: ${
              error instanceof Error ? error.message : "unknown error"
            }`,
          );
        });
      }
    }

    return {
      scan,
      report: persisted.storedReport.report,
      storedReport: persisted.storedReport,
    };
  }

  private async ensureStaticScanForDetonation(
    slug: string,
  ): Promise<EnsuredStaticScanResult | undefined> {
    const localSkill = await this.resolveLocalSkillSnapshot(slug);
    if (!localSkill) {
      return undefined;
    }

    const latestReport = await this.storage.getLatestStaticReportBySlug(slug);
    if (
      latestReport &&
      latestReport.report.snapshot.contentHash === localSkill.snapshot.contentHash
    ) {
      const storedScan = await this.storage.getScan(latestReport.summary.scanId);
      if (storedScan) {
        return {
          scan: storedScan,
          storedReport: latestReport,
          snapshot: localSkill.snapshot,
        };
      }
    }

    let scanResult: ScanQueueResult;
    try {
      scanResult = await this.enqueueScan(
        localSkill.snapshot.path,
        localSkill.snapshot.path,
        false,
        "detonation-refresh",
      );
    } catch (error) {
      if (isMissingSnapshotFailure(error)) {
        return undefined;
      }

      throw error;
    }

    if (scanResult.skipped) {
      return undefined;
    }
    if (!scanResult.storedReport) {
      throw new Error(`Static scan for ${slug} completed without a stored report.`);
    }

    return {
      scan: scanResult.scan,
      storedReport: scanResult.storedReport,
      snapshot: {
        ...scanResult.storedReport.report.snapshot,
        path: localSkill.snapshot.path,
      },
    };
  }

  private async resolveLocalSkillSnapshot(
    slug: string,
  ): Promise<{ snapshot: SkillSnapshot } | undefined> {
    const workspaceModel = this.workspaceModel ?? (await discoverOpenClawWorkspaceModel());

    for (const skillRoot of workspaceModel.skillRoots) {
      const snapshotResult = await buildSkillSnapshot({
        skillPath: path.join(skillRoot.path, slug),
        skillSlug: slug,
        skillRootPath: skillRoot.path,
        skillRootKind: skillRoot.kind,
        discoverySource: skillRoot.source,
        ...(skillRoot.workspaceId ? { workspaceId: skillRoot.workspaceId } : {}),
      });

      if (snapshotResult.ok) {
        return {
          snapshot: snapshotResult.snapshot,
        };
      }
    }

    return undefined;
  }

  private async prepareDetonationDisabledStatus(
    ensuredScan: EnsuredStaticScanResult,
  ): Promise<DetonationStatusRecord | undefined> {
    if (!this.detonationConfig.enabled) {
      const status = await this.storage.persistDetonationRun({
        status: {
          requestId: randomUUID(),
          scanId: ensuredScan.scan.scanId,
          slug: ensuredScan.storedReport.report.snapshot.slug,
          contentHash: ensuredScan.storedReport.report.snapshot.contentHash,
          status: "disabled",
          errorMessage: "Detonation is disabled in the current daemon configuration.",
          startedAt: new Date().toISOString(),
          completedAt: new Date().toISOString(),
        },
      });

      return status.status;
    }

    return undefined;
  }

  private async scheduleAutomaticDetonation(ensuredScan: EnsuredStaticScanResult): Promise<void> {
    if (!this.detonationConfig.enabled) {
      return;
    }

    if (ensuredScan.storedReport.report.score < this.scanThresholds.detonationScore) {
      return;
    }

    const detonationKey = this.buildDetonationIdempotencyKey(ensuredScan);
    if (await this.shouldSkipAutomaticDetonation(ensuredScan, detonationKey)) {
      return;
    }

    await this.enqueueDetonation(detonationKey, ensuredScan);
  }

  private async shouldSkipAutomaticDetonation(
    ensuredScan: EnsuredStaticScanResult,
    detonationKey: string,
  ): Promise<boolean> {
    if (this.inflightDetonationByKey.has(detonationKey)) {
      return true;
    }

    const existing = await this.storage.getLatestDetonationRunByContentHash(
      ensuredScan.storedReport.report.snapshot.contentHash,
    );
    if (!existing) {
      return false;
    }

    return (
      existing.status.slug === ensuredScan.storedReport.report.snapshot.slug &&
      (existing.status.status === "queued" ||
        existing.status.status === "running" ||
        existing.status.status === "completed")
    );
  }

  private async enqueueDetonation(
    idempotencyKey: string,
    ensuredScan: EnsuredStaticScanResult,
  ): Promise<DetonationJobResult> {
    const inflight = this.inflightDetonationByKey.get(idempotencyKey);
    if (inflight) {
      return inflight;
    }

    const existing = await this.storage.getLatestDetonationRunByContentHash(
      ensuredScan.storedReport.report.snapshot.contentHash,
    );
    if (
      existing?.status.slug === ensuredScan.storedReport.report.snapshot.slug &&
      existing.status.status === "completed" &&
      existing.report
    ) {
      return {
        status: existing.status,
        report: existing.report,
      };
    }

    if (this.detonationQueue.length >= MAX_QUEUE_DEPTH) {
      throw new Error(`Detonation queue is full (${MAX_QUEUE_DEPTH}).`);
    }

    const requestId = randomUUID();
    const queuedStatus = await this.storage.persistDetonationRun({
      status: {
        requestId,
        scanId: ensuredScan.scan.scanId,
        slug: ensuredScan.storedReport.report.snapshot.slug,
        contentHash: ensuredScan.storedReport.report.snapshot.contentHash,
        status: "queued",
        startedAt: new Date().toISOString(),
      },
    });

    const promise = new Promise<DetonationJobResult>((resolve, reject) => {
      this.detonationQueue.push({
        idempotencyKey,
        requestId: queuedStatus.status.requestId,
        ensuredScan,
        resolve,
        reject,
      });

      void this.pumpDetonationQueue();
    }).finally(() => {
      this.inflightDetonationByKey.delete(idempotencyKey);
    });

    this.inflightDetonationByKey.set(idempotencyKey, promise);
    return promise;
  }

  private async pumpDetonationQueue(): Promise<void> {
    if (this.detonationQueueRunning) {
      return;
    }

    this.detonationQueueRunning = true;
    while (this.detonationQueue.length > 0) {
      const job = this.detonationQueue.shift();
      if (!job) {
        continue;
      }

      try {
        const result = await this.runDetonation(job.requestId, job.ensuredScan);
        job.resolve(result);
      } catch (error) {
        const failure = error instanceof Error ? error : new Error(String(error));
        await this.persistUnexpectedDetonationFailure(job.requestId, job.ensuredScan, failure);
        job.reject(failure);
      }
    }
    this.detonationQueueRunning = false;
  }

  private async runDetonation(
    requestId: string,
    ensuredScan: EnsuredStaticScanResult,
  ): Promise<DetonationJobResult> {
    const runningStatus: DetonationStatusRecord = {
      requestId,
      scanId: ensuredScan.scan.scanId,
      slug: ensuredScan.storedReport.report.snapshot.slug,
      contentHash: ensuredScan.storedReport.report.snapshot.contentHash,
      status: "running",
      startedAt: new Date().toISOString(),
    };
    await this.storage.persistDetonationRun({
      status: runningStatus,
    });

    const result = await this.detonationRunner(ensuredScan.snapshot, {
      requestId,
      preferredRuntime: this.detonationConfig.defaultRuntime,
      timeoutSeconds: this.detonationConfig.timeoutSeconds,
      promptBudget: this.detonationConfig.promptBudget,
      virustotalClient: this.virusTotalClient,
    });

    if (!result.ok) {
      await this.persistDetonationRawArtifacts(ensuredScan.scan.scanId, result.artifactPayloads);
      const stored = await this.storage.persistDetonationRun({
        status: {
          requestId,
          scanId: ensuredScan.scan.scanId,
          slug: ensuredScan.storedReport.report.snapshot.slug,
          contentHash: ensuredScan.storedReport.report.snapshot.contentHash,
          status: result.status,
          ...(result.runtime ? { runtime: result.runtime } : {}),
          errorMessage: result.message,
          startedAt: result.startedAt,
          completedAt: result.completedAt,
        },
      });

      return {
        status: stored.status,
      };
    }

    const persisted = await this.persistDetonationArtifacts(
      ensuredScan.scan.scanId,
      result.report,
      result.artifactPayloads,
    );
    const stored = await this.storage.persistDetonationRun({
      status: {
        requestId,
        scanId: ensuredScan.scan.scanId,
        slug: ensuredScan.storedReport.report.snapshot.slug,
        contentHash: ensuredScan.storedReport.report.snapshot.contentHash,
        status: "completed",
        runtime: result.runtime,
        startedAt: result.startedAt,
        completedAt: result.completedAt,
      },
      report: persisted.report,
    });

    return {
      status: stored.status,
      report: persisted.report,
    };
  }

  private async persistDetonationRawArtifacts(
    scanId: string,
    artifactPayloads: RunDetonationAnalysisResult["artifactPayloads"],
  ): Promise<StoredArtifactRecord[]> {
    const storedArtifacts: StoredArtifactRecord[] = [];

    for (const artifact of artifactPayloads) {
      storedArtifacts.push(
        await this.storage.writeArtifact({
          scanId,
          type: artifact.type,
          filename: artifact.filename,
          data: artifact.data,
          mimeType: artifact.mimeType,
        }),
      );
    }

    return storedArtifacts;
  }

  private async persistDetonationArtifacts(
    scanId: string,
    report: DetonationReport,
    artifactPayloads: RunDetonationAnalysisResult["artifactPayloads"],
  ): Promise<{ report: DetonationReport; artifacts: StoredArtifactRecord[] }> {
    const rawArtifacts = await this.persistDetonationRawArtifacts(scanId, artifactPayloads);
    const rawArtifactRefs = rawArtifacts.map(toArtifactRef);
    const renderedReport = {
      ...report,
      artifacts: rawArtifactRefs,
    };
    const reportJson = await this.storage.writeJsonArtifact({
      scanId,
      type: "detonation-report-json",
      filename: `${report.request.requestId}.detonation-report.json`,
      value: renderedReport,
    });
    const reportMarkdown = await this.storage.writeArtifact({
      scanId,
      type: "detonation-report-markdown",
      filename: `${report.request.requestId}.detonation-report.md`,
      data: renderDetonationReport(renderedReport),
      mimeType: "text/markdown",
    });
    const artifacts = [...rawArtifacts, reportJson, reportMarkdown];

    return {
      report: {
        ...report,
        artifacts: artifacts.map(toArtifactRef),
      },
      artifacts,
    };
  }

  private buildDetonationIdempotencyKey(ensuredScan: EnsuredStaticScanResult): string {
    return `${ensuredScan.storedReport.report.snapshot.slug}:${ensuredScan.storedReport.report.snapshot.contentHash}`;
  }

  private async getCurrentDetonationRunForReport(
    report: StoredStaticReport,
  ): Promise<StoredDetonationRun | undefined> {
    return this.storage.getLatestDetonationRunByContentHash(report.report.snapshot.contentHash);
  }

  private toReportResponse(
    report: StoredStaticReport,
    detonationRun?: StoredDetonationRun,
  ): DaemonSuccessResponse["data"] {
    return synthesizeUnifiedReport({
      staticReport: report,
      ...(detonationRun ? { detonationRun } : {}),
    });
  }

  private async persistUnexpectedDetonationFailure(
    requestId: string,
    ensuredScan: EnsuredStaticScanResult,
    error: Error,
  ): Promise<void> {
    try {
      const existing = await this.storage.getDetonationRun(requestId);
      await this.storage.persistDetonationRun({
        status: {
          requestId,
          scanId: ensuredScan.scan.scanId,
          slug: ensuredScan.storedReport.report.snapshot.slug,
          contentHash: ensuredScan.storedReport.report.snapshot.contentHash,
          status: "failed",
          errorMessage: error.message,
          startedAt: existing?.status.startedAt ?? new Date().toISOString(),
          completedAt: new Date().toISOString(),
        },
      });
    } catch (persistError) {
      this.recordWarningIssue(
        `Failed to persist unexpected detonation failure for ${ensuredScan.storedReport.report.snapshot.slug}: ${
          persistError instanceof Error ? persistError.message : "unknown error"
        }`,
      );
    }
  }

  private buildStatusResponse(): DaemonSuccessResponse["data"] {
    const jobs =
      this.scanQueue.length +
      this.inflightScanByKey.size +
      this.detonationQueue.length +
      this.inflightDetonationByKey.size;
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

function createVirusTotalClientFromEnv(): VirusTotalHttpClient | undefined {
  const apiKey = process.env.CLAWGUARD_VIRUSTOTAL_API_KEY ?? process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return undefined;
  }

  return new VirusTotalHttpClient({
    apiKey,
    baseUrl: defaultClawGuardConfig.threatIntel.virusTotal.baseUrl,
  });
}

function resolveDetonationSkillPath(
  originalSkillPath: string,
  disposition: Awaited<ReturnType<SkillLifecycleManager["applyPostScanDisposition"]>>,
): string | undefined {
  switch (disposition.status) {
    case "allowed":
      return originalSkillPath;
    case "quarantined":
      return disposition.quarantine.quarantinePath;
    case "blocked":
      return undefined;
  }
}

function mapDetonationStatusToErrorCode(status: DetonationStatusRecord): string {
  switch (status.status) {
    case "disabled":
      return "detonation_disabled";
    case "runtime-unavailable":
      return "runtime_unavailable";
    case "failed": {
      const message = status.errorMessage?.toLowerCase() ?? "";
      if (message.includes("timed out")) {
        return "timeout";
      }

      if (
        message.includes("unable to build sandbox image") ||
        message.includes("unable to pull sandbox image")
      ) {
        return "sandbox_image_failure";
      }

      return "detonation_failed";
    }
    case "queued":
    case "running":
    case "completed":
      return "detonation_incomplete";
  }
}

function toArtifactRef(artifact: StoredArtifactRecord) {
  return {
    scanId: artifact.scanId,
    type: artifact.type,
    path: artifact.path,
    mimeType: artifact.mimeType,
  } as const;
}

function isSnapshotBuildFailure(
  error: unknown,
): error is Error & { buildError: SnapshotBuildError } {
  return (
    error instanceof Error &&
    "buildError" in error &&
    typeof error.buildError === "object" &&
    error.buildError !== null &&
    "kind" in error.buildError &&
    typeof error.buildError.kind === "string" &&
    "message" in error.buildError &&
    typeof error.buildError.message === "string"
  );
}

function isMissingSnapshotFailure(
  error: unknown,
): error is Error & { buildError: SnapshotBuildError } {
  return (
    isSnapshotBuildFailure(error) &&
    (error.buildError.kind === "missing-skill" || error.buildError.kind === "missing-skill-md")
  );
}

function isSkippableWatcherSnapshotFailure(
  error: Error & { buildError: SnapshotBuildError },
): boolean {
  return error.buildError.kind === "missing-skill" || error.buildError.kind === "missing-skill-md";
}

function isMissingWatchRootError(error: Error): boolean {
  return (
    ("code" in error && error.code === "ENOENT") ||
    error.message.includes("ENOENT: no such file or directory")
  );
}
