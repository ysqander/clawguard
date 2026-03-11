import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import {
  decisionRecordValidator,
  reportSummaryValidator,
  scanRecordValidator,
  staticScanReportValidator,
} from "@clawguard/contracts";
import type {
  ArtifactRef,
  DecisionRecord,
  ReportSummary,
  ScanRecord,
  StaticScanReport,
} from "@clawguard/contracts";

import { ArtifactStore } from "./artifact-store.js";
import type { PreparedArtifact } from "./artifact-store.js";
import { STORAGE_SCHEMA_VERSION, storageMigrations } from "./migrations.js";
import { resolveStoragePaths } from "./paths.js";
import type {
  CreateQuarantineRecordInput,
  ListQuarantineRecordsOptions,
  PersistScanInput,
  PersistStaticReportInput,
  QuarantineRecord,
  QuarantineState,
  StorageApi,
  StoragePaths,
  StoredArtifactRecord,
  StoredStaticReport,
  UpsertDecisionInput,
  WriteArtifactInput,
  WriteJsonArtifactInput,
} from "./types.js";

interface ScanRow {
  scan_id: string;
  skill_slug: string;
  content_hash: string;
  status: ScanRecord["status"];
  started_at: string;
  completed_at: string | null;
  scan_json: string;
}

interface ReportRow {
  report_id: string;
  scan_id: string;
  skill_slug: string;
  content_hash: string;
  verdict: ReportSummary["verdict"];
  score: number;
  finding_count: number;
  generated_at: string;
  report_json: string;
  summary_json: string;
}

interface ArtifactRow {
  artifact_id: string;
  scan_id: string;
  artifact_type: ArtifactRef["type"];
  relative_path: string;
  mime_type: string;
  sha256: string;
  size_bytes: number;
  created_at: string;
}

interface DecisionRow {
  content_hash: string;
  decision: DecisionRecord["decision"];
  reason: string;
  created_at: string;
}

interface QuarantineRow {
  quarantine_id: string;
  scan_id: string | null;
  skill_slug: string;
  content_hash: string;
  original_path: string;
  quarantine_path: string;
  state: QuarantineState;
  created_at: string;
  updated_at: string;
}

function parseJson<T>(value: string): T {
  return JSON.parse(value) as T;
}

function readScanRecord(row: ScanRow): ScanRecord {
  return scanRecordValidator.parse(parseJson(row.scan_json));
}

function readReportSummary(row: ReportRow): ReportSummary {
  return reportSummaryValidator.parse(parseJson(row.summary_json));
}

function readStaticScanReport(row: ReportRow): StaticScanReport {
  return staticScanReportValidator.parse(parseJson(row.report_json));
}

function readDecisionRecord(row: DecisionRow): DecisionRecord {
  return decisionRecordValidator.parse({
    contentHash: row.content_hash,
    decision: row.decision,
    reason: row.reason,
    createdAt: row.created_at,
  });
}

function readStoredArtifactRecord(row: ArtifactRow, artifactsRoot: string): StoredArtifactRecord {
  return {
    artifactId: row.artifact_id,
    scanId: row.scan_id,
    type: row.artifact_type,
    relativePath: row.relative_path,
    path: path.join(artifactsRoot, row.relative_path),
    mimeType: row.mime_type,
    sha256: row.sha256,
    sizeBytes: row.size_bytes,
    createdAt: row.created_at,
  };
}

function readQuarantineRecord(row: QuarantineRow): QuarantineRecord {
  return {
    quarantineId: row.quarantine_id,
    skillSlug: row.skill_slug,
    contentHash: row.content_hash,
    originalPath: row.original_path,
    quarantinePath: row.quarantine_path,
    state: row.state,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    ...(row.scan_id ? { scanId: row.scan_id } : {}),
  };
}

function ensureReportConsistency(summary: ReportSummary, report: StaticScanReport): void {
  if (summary.reportId !== report.reportId) {
    throw new Error(
      `Report summary/report mismatch: summary.reportId=${summary.reportId}, report.reportId=${report.reportId}`,
    );
  }

  if (summary.slug !== report.snapshot.slug) {
    throw new Error(
      `Report summary/report mismatch: summary.slug=${summary.slug}, report.snapshot.slug=${report.snapshot.slug}`,
    );
  }
}

export class ClawGuardStorage implements StorageApi {
  public readonly schemaVersion = STORAGE_SCHEMA_VERSION;
  public readonly paths: StoragePaths;

  private readonly db: DatabaseSync;
  private readonly artifactStore: ArtifactStore;

  public constructor(paths: Partial<StoragePaths> = {}) {
    this.paths = resolveStoragePaths(paths);

    mkdirSync(path.dirname(this.paths.stateDbPath), { recursive: true });
    mkdirSync(this.paths.artifactsRoot, { recursive: true });

    this.db = new DatabaseSync(this.paths.stateDbPath);
    this.artifactStore = new ArtifactStore(this.paths.artifactsRoot);

    this.db.exec("PRAGMA journal_mode = WAL");
    this.db.exec("PRAGMA foreign_keys = ON");
    this.db.exec(
      "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)",
    );

    this.applyMigrations();
  }

  public async persistScan(input: PersistScanInput): Promise<ScanRecord> {
    const scan = scanRecordValidator.parse(input.scan);

    this.db
      .prepare(
        `
          INSERT INTO scans (
            scan_id,
            skill_slug,
            content_hash,
            status,
            started_at,
            completed_at,
            scan_json
          )
          VALUES (?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(scan_id) DO UPDATE SET
            skill_slug = excluded.skill_slug,
            content_hash = excluded.content_hash,
            status = excluded.status,
            started_at = excluded.started_at,
            completed_at = excluded.completed_at,
            scan_json = excluded.scan_json
        `,
      )
      .run(
        scan.scanId,
        scan.slug,
        scan.contentHash,
        scan.status,
        scan.startedAt,
        scan.completedAt ?? null,
        JSON.stringify(scan),
      );

    const storedScan = await this.getScan(scan.scanId);
    if (!storedScan) {
      throw new Error(`Failed to read persisted scan ${scan.scanId}`);
    }

    return storedScan;
  }

  public async getScan(scanId: string): Promise<ScanRecord | undefined> {
    const row = this.db
      .prepare(
        `
          SELECT
            scan_id,
            skill_slug,
            content_hash,
            status,
            started_at,
            completed_at,
            scan_json
          FROM scans
          WHERE scan_id = ?
        `,
      )
      .get(scanId) as ScanRow | undefined;

    return row ? readScanRecord(row) : undefined;
  }

  public async findLatestScanBySlug(slug: string): Promise<ScanRecord | undefined> {
    const row = this.db
      .prepare("SELECT scan_id FROM scans WHERE skill_slug = ? ORDER BY started_at DESC LIMIT 1")
      .get(slug) as { scan_id: string } | undefined;

    return row ? this.getScan(row.scan_id) : undefined;
  }

  public async findLatestScanByContentHash(contentHash: string): Promise<ScanRecord | undefined> {
    const row = this.db
      .prepare("SELECT scan_id FROM scans WHERE content_hash = ? ORDER BY started_at DESC LIMIT 1")
      .get(contentHash) as { scan_id: string } | undefined;

    return row ? this.getScan(row.scan_id) : undefined;
  }

  public async persistStaticReport(input: PersistStaticReportInput): Promise<StoredStaticReport> {
    const summary = reportSummaryValidator.parse(input.summary);
    const report = staticScanReportValidator.parse(input.report);
    ensureReportConsistency(summary, report);

    this.db
      .prepare(
        `
          INSERT INTO reports (
            report_id,
            scan_id,
            skill_slug,
            content_hash,
            verdict,
            score,
            finding_count,
            generated_at,
            report_json,
            summary_json
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(report_id) DO UPDATE SET
            scan_id = excluded.scan_id,
            skill_slug = excluded.skill_slug,
            content_hash = excluded.content_hash,
            verdict = excluded.verdict,
            score = excluded.score,
            finding_count = excluded.finding_count,
            generated_at = excluded.generated_at,
            report_json = excluded.report_json,
            summary_json = excluded.summary_json
        `,
      )
      .run(
        report.reportId,
        summary.scanId,
        summary.slug,
        report.snapshot.contentHash,
        summary.verdict,
        summary.score,
        summary.findingCount,
        summary.generatedAt,
        JSON.stringify(report),
        JSON.stringify(summary),
      );

    const storedReport = await this.getStaticReport(report.reportId);
    if (!storedReport) {
      throw new Error(`Failed to read persisted report ${report.reportId}`);
    }

    return storedReport;
  }

  public async getStaticReport(reportId: string): Promise<StoredStaticReport | undefined> {
    const row = this.db
      .prepare(
        `
          SELECT
            report_id,
            scan_id,
            skill_slug,
            content_hash,
            verdict,
            score,
            finding_count,
            generated_at,
            report_json,
            summary_json
          FROM reports
          WHERE report_id = ?
        `,
      )
      .get(reportId) as ReportRow | undefined;

    if (!row) {
      return undefined;
    }

    const summary = readReportSummary(row);
    const report = readStaticScanReport(row);
    const artifacts = this.getArtifactsByScanId(summary.scanId);
    const decision = await this.getDecision(report.snapshot.contentHash);

    return {
      summary,
      report,
      artifacts,
      ...(decision ? { decision } : {}),
    };
  }

  public async getLatestStaticReportBySlug(slug: string): Promise<StoredStaticReport | undefined> {
    const row = this.db
      .prepare(
        "SELECT report_id FROM reports WHERE skill_slug = ? ORDER BY generated_at DESC LIMIT 1",
      )
      .get(slug) as { report_id: string } | undefined;

    return row ? this.getStaticReport(row.report_id) : undefined;
  }

  public async writeArtifact(input: WriteArtifactInput): Promise<StoredArtifactRecord> {
    const preparedArtifact = await this.artifactStore.writeArtifact(input);
    return this.indexPreparedArtifact(preparedArtifact);
  }

  public async writeJsonArtifact(input: WriteJsonArtifactInput): Promise<StoredArtifactRecord> {
    const preparedArtifact = await this.artifactStore.writeJsonArtifact(input);
    return this.indexPreparedArtifact(preparedArtifact);
  }

  public async upsertDecision(input: UpsertDecisionInput): Promise<DecisionRecord> {
    const createdAt = input.createdAt ?? new Date().toISOString();
    const decision = decisionRecordValidator.parse({
      contentHash: input.contentHash,
      decision: input.decision,
      reason: input.reason,
      createdAt,
    });

    this.db
      .prepare(
        `
          INSERT INTO decisions (
            content_hash,
            decision,
            reason,
            created_at
          )
          VALUES (?, ?, ?, ?)
          ON CONFLICT(content_hash) DO UPDATE SET
            decision = excluded.decision,
            reason = excluded.reason,
            created_at = excluded.created_at
        `,
      )
      .run(decision.contentHash, decision.decision, decision.reason, decision.createdAt);

    const storedDecision = await this.getDecision(decision.contentHash);
    if (!storedDecision) {
      throw new Error(`Failed to read decision for ${decision.contentHash}`);
    }

    return storedDecision;
  }

  public async getDecision(contentHash: string): Promise<DecisionRecord | undefined> {
    const row = this.db
      .prepare(
        `
          SELECT
            content_hash,
            decision,
            reason,
            created_at
          FROM decisions
          WHERE content_hash = ?
        `,
      )
      .get(contentHash) as DecisionRow | undefined;

    return row ? readDecisionRecord(row) : undefined;
  }

  public async createQuarantineRecord(
    input: CreateQuarantineRecordInput,
  ): Promise<QuarantineRecord> {
    const quarantineId = input.quarantineId ?? randomUUID();
    const createdAt = input.createdAt ?? new Date().toISOString();
    const updatedAt = input.updatedAt ?? createdAt;
    const state = input.state ?? "active";

    this.db
      .prepare(
        `
          INSERT INTO quarantine_entries (
            quarantine_id,
            scan_id,
            skill_slug,
            content_hash,
            original_path,
            quarantine_path,
            state,
            created_at,
            updated_at
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(quarantine_id) DO UPDATE SET
            scan_id = excluded.scan_id,
            skill_slug = excluded.skill_slug,
            content_hash = excluded.content_hash,
            original_path = excluded.original_path,
            quarantine_path = excluded.quarantine_path,
            state = excluded.state,
            updated_at = excluded.updated_at
        `,
      )
      .run(
        quarantineId,
        input.scanId ?? null,
        input.skillSlug,
        input.contentHash,
        input.originalPath,
        input.quarantinePath,
        state,
        createdAt,
        updatedAt,
      );

    const record = await this.getQuarantineRecord(quarantineId);
    if (!record) {
      throw new Error(`Failed to read quarantine entry ${quarantineId}`);
    }

    return record;
  }

  public async getQuarantineRecord(quarantineId: string): Promise<QuarantineRecord | undefined> {
    const row = this.db
      .prepare(
        `
          SELECT
            quarantine_id,
            scan_id,
            skill_slug,
            content_hash,
            original_path,
            quarantine_path,
            state,
            created_at,
            updated_at
          FROM quarantine_entries
          WHERE quarantine_id = ?
        `,
      )
      .get(quarantineId) as QuarantineRow | undefined;

    return row ? readQuarantineRecord(row) : undefined;
  }

  public async setQuarantineState(
    quarantineId: string,
    state: QuarantineState,
  ): Promise<QuarantineRecord | undefined> {
    this.db
      .prepare("UPDATE quarantine_entries SET state = ?, updated_at = ? WHERE quarantine_id = ?")
      .run(state, new Date().toISOString(), quarantineId);

    return this.getQuarantineRecord(quarantineId);
  }

  public async listQuarantineRecords(
    options: ListQuarantineRecordsOptions = {},
  ): Promise<QuarantineRecord[]> {
    const whereClauses: string[] = [];
    const parameters: string[] = [];

    if (options.state) {
      whereClauses.push("state = ?");
      parameters.push(options.state);
    }

    if (options.contentHash) {
      whereClauses.push("content_hash = ?");
      parameters.push(options.contentHash);
    }

    const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(" AND ")}` : "";
    const rows = this.db
      .prepare(
        `
          SELECT
            quarantine_id,
            scan_id,
            skill_slug,
            content_hash,
            original_path,
            quarantine_path,
            state,
            created_at,
            updated_at
          FROM quarantine_entries
          ${whereSql}
          ORDER BY created_at DESC, quarantine_id DESC
        `,
      )
      .all(...parameters) as unknown as QuarantineRow[];

    return rows.map(readQuarantineRecord);
  }

  public close(): void {
    this.db.close();
  }

  private applyMigrations(): void {
    const appliedVersions = new Set<number>(
      (
        this.db
          .prepare("SELECT version FROM schema_migrations ORDER BY version ASC")
          .all() as Array<{
          version: number;
        }>
      ).map((row) => row.version),
    );

    for (const migration of storageMigrations) {
      if (appliedVersions.has(migration.version)) {
        continue;
      }

      this.withTransaction(() => {
        for (const statement of migration.statements) {
          this.db.exec(statement);
        }

        this.db
          .prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)")
          .run(migration.version, new Date().toISOString());
      });
    }
  }

  private withTransaction<T>(operation: () => T): T {
    this.db.exec("BEGIN");

    try {
      const result = operation();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  private getArtifactsByScanId(scanId: string): StoredArtifactRecord[] {
    const rows = this.db
      .prepare(
        `
          SELECT
            artifact_id,
            scan_id,
            artifact_type,
            relative_path,
            mime_type,
            sha256,
            size_bytes,
            created_at
          FROM artifacts
          WHERE scan_id = ?
          ORDER BY created_at ASC, artifact_id ASC
        `,
      )
      .all(scanId) as unknown as ArtifactRow[];

    return rows.map((row) => readStoredArtifactRecord(row, this.paths.artifactsRoot));
  }

  private indexPreparedArtifact(
    preparedArtifact: Omit<PreparedArtifact, "artifactId">,
  ): StoredArtifactRecord {
    const artifactId = randomUUID();

    this.db
      .prepare(
        `
          INSERT INTO artifacts (
            artifact_id,
            scan_id,
            artifact_type,
            relative_path,
            mime_type,
            sha256,
            size_bytes,
            created_at
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(scan_id, relative_path) DO UPDATE SET
            artifact_type = excluded.artifact_type,
            mime_type = excluded.mime_type,
            sha256 = excluded.sha256,
            size_bytes = excluded.size_bytes,
            created_at = excluded.created_at
        `,
      )
      .run(
        artifactId,
        preparedArtifact.scanId,
        preparedArtifact.type,
        preparedArtifact.relativePath,
        preparedArtifact.mimeType,
        preparedArtifact.sha256,
        preparedArtifact.sizeBytes,
        preparedArtifact.createdAt,
      );

    const row = this.db
      .prepare(
        `
          SELECT
            artifact_id,
            scan_id,
            artifact_type,
            relative_path,
            mime_type,
            sha256,
            size_bytes,
            created_at
          FROM artifacts
          WHERE scan_id = ? AND relative_path = ?
        `,
      )
      .get(preparedArtifact.scanId, preparedArtifact.relativePath) as ArtifactRow | undefined;

    if (!row) {
      throw new Error(`Failed to index artifact ${preparedArtifact.relativePath}`);
    }

    return readStoredArtifactRecord(row, this.paths.artifactsRoot);
  }
}

export function createStorage(paths: Partial<StoragePaths> = {}): ClawGuardStorage {
  return new ClawGuardStorage(paths);
}
