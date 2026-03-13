import type {
  ArtifactRef,
  ArtifactType,
  DecisionRecord,
  ReportSummary,
  ScanRecord,
  StaticScanReport,
} from "@clawguard/contracts";

export type QuarantineState = "active" | "restored" | "deleted";

export interface StoragePaths {
  stateDbPath: string;
  artifactsRoot: string;
}

export interface StoredArtifactRecord extends ArtifactRef {
  artifactId: string;
  relativePath: string;
  sha256: string;
  sizeBytes: number;
  createdAt: string;
}

export interface PersistScanInput {
  scan: ScanRecord;
}

export interface PersistStaticReportInput {
  summary: ReportSummary;
  report: StaticScanReport;
}

export interface WriteArtifactInput {
  scanId: string;
  type: ArtifactType;
  filename: string;
  data: Uint8Array | string;
  mimeType?: string;
  encoding?: BufferEncoding;
  createdAt?: string;
}

export interface WriteJsonArtifactInput {
  scanId: string;
  type: ArtifactType;
  filename: string;
  value: unknown;
  mimeType?: string;
  createdAt?: string;
}

export interface UpsertDecisionInput {
  contentHash: string;
  decision: DecisionRecord["decision"];
  reason: string;
  createdAt?: string;
}

export interface QuarantineRecord {
  quarantineId: string;
  scanId?: string;
  skillSlug: string;
  contentHash: string;
  originalPath: string;
  quarantinePath: string;
  state: QuarantineState;
  createdAt: string;
  updatedAt: string;
}

export interface CreateQuarantineRecordInput {
  quarantineId?: string;
  scanId?: string;
  skillSlug: string;
  contentHash: string;
  originalPath: string;
  quarantinePath: string;
  state?: QuarantineState;
  createdAt?: string;
  updatedAt?: string;
}

export interface ListQuarantineRecordsOptions {
  state?: QuarantineState;
  contentHash?: string;
}

export interface StoredStaticReport {
  summary: ReportSummary;
  report: StaticScanReport;
  decision?: DecisionRecord;
  artifacts: StoredArtifactRecord[];
}

export interface StorageApi {
  readonly paths: StoragePaths;
  readonly schemaVersion: number;
  persistScan(input: PersistScanInput): Promise<ScanRecord>;
  getScan(scanId: string): Promise<ScanRecord | undefined>;
  listScans(): Promise<ScanRecord[]>;
  findLatestScanBySlug(slug: string): Promise<ScanRecord | undefined>;
  findLatestScanByContentHash(contentHash: string): Promise<ScanRecord | undefined>;
  persistStaticReport(input: PersistStaticReportInput): Promise<StoredStaticReport>;
  getStaticReport(reportId: string): Promise<StoredStaticReport | undefined>;
  getLatestStaticReportBySlug(slug: string): Promise<StoredStaticReport | undefined>;
  getLatestStaticReportByContentHash(contentHash: string): Promise<StoredStaticReport | undefined>;
  writeArtifact(input: WriteArtifactInput): Promise<StoredArtifactRecord>;
  writeJsonArtifact(input: WriteJsonArtifactInput): Promise<StoredArtifactRecord>;
  upsertDecision(input: UpsertDecisionInput): Promise<DecisionRecord>;
  getDecision(contentHash: string): Promise<DecisionRecord | undefined>;
  createQuarantineRecord(input: CreateQuarantineRecordInput): Promise<QuarantineRecord>;
  getQuarantineRecord(quarantineId: string): Promise<QuarantineRecord | undefined>;
  setQuarantineState(
    quarantineId: string,
    state: QuarantineState,
  ): Promise<QuarantineRecord | undefined>;
  listQuarantineRecords(options?: ListQuarantineRecordsOptions): Promise<QuarantineRecord[]>;
  close(): void;
}
