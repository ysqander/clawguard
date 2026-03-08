import {
  createValidator,
  parseArray,
  parseEnum,
  parseInteger,
  parseIsoDateTime,
  parseNonEmptyString,
  parseObject,
  parseOptional,
  parseStringArray
} from "./runtime.js";

export const verdictLevels = ["unknown", "allow", "review", "block"] as const;
export type VerdictLevel = (typeof verdictLevels)[number];

export const findingSeverities = ["low", "medium", "high", "critical"] as const;
export type FindingSeverity = (typeof findingSeverities)[number];

export const skillSourceKinds = ["config", "lockfile", "default", "manual", "fixture"] as const;
export type SkillSourceKind = (typeof skillSourceKinds)[number];

export const intelligenceProviders = ["clawhub", "virustotal"] as const;
export type ThreatIntelProvider = (typeof intelligenceProviders)[number];

export const intelligenceSubjects = ["skill", "file", "url", "domain", "ip"] as const;
export type ThreatIntelSubject = (typeof intelligenceSubjects)[number];

export const artifactTypes = [
  "skill-snapshot",
  "static-report",
  "detonation-stdout",
  "detonation-stderr",
  "network-capture",
  "memory-diff",
  "file-diff",
  "report-markdown",
  "report-json"
] as const;
export type ArtifactType = (typeof artifactTypes)[number];

export const decisionKinds = ["allow", "block", "quarantine"] as const;
export type DecisionKind = (typeof decisionKinds)[number];

export const daemonEventTypes = [
  "scan-requested",
  "scan-completed",
  "detonation-completed",
  "quarantine-changed",
  "notification-sent"
] as const;
export type DaemonEventType = (typeof daemonEventTypes)[number];

export interface PlatformCapabilities {
  platform: "macos" | "linux";
  supportsWatcher: boolean;
  supportsNotifications: boolean;
  supportsServiceInstall: boolean;
  supportedDetonationRuntimes: Array<"podman" | "docker">;
}

export interface SkillSourceHint {
  kind: SkillSourceKind;
  detail: string;
}

export interface SkillSnapshot {
  slug: string;
  path: string;
  sourceHints: SkillSourceHint[];
  contentHash: string;
  fileInventory: string[];
  detectedAt: string;
}

export interface StaticFinding {
  ruleId: string;
  severity: FindingSeverity;
  message: string;
  evidence: string[];
}

export interface StaticScanReport {
  reportId: string;
  snapshot: SkillSnapshot;
  score: number;
  findings: StaticFinding[];
  recommendation: VerdictLevel;
  generatedAt: string;
}

export interface ThreatIntelVerdict {
  provider: ThreatIntelProvider;
  subjectType: ThreatIntelSubject;
  subject: string;
  verdict: VerdictLevel;
  summary: string;
  maliciousDetections?: number;
  suspiciousDetections?: number;
  harmlessDetections?: number;
  undetectedDetections?: number;
  confidence?: number;
  sourceUrl?: string;
  observedAt: string;
}

export interface ArtifactRef {
  scanId: string;
  type: ArtifactType;
  path: string;
  mimeType: string;
}

export interface DetonationRequest {
  requestId: string;
  snapshot: SkillSnapshot;
  prompts: string[];
  timeoutSeconds: number;
}

export interface DetonationReport {
  request: DetonationRequest;
  summary: string;
  triggeredActions: string[];
  artifacts: ArtifactRef[];
  generatedAt: string;
}

export interface DecisionRecord {
  contentHash: string;
  decision: DecisionKind;
  reason: string;
  createdAt: string;
}

export interface ScanRecord {
  scanId: string;
  slug: string;
  contentHash: string;
  status: "pending" | "completed" | "failed";
  startedAt: string;
  completedAt?: string;
}

export interface ReportSummary {
  reportId: string;
  scanId: string;
  slug: string;
  verdict: VerdictLevel;
  score: number;
  findingCount: number;
  generatedAt: string;
}

export interface DaemonJobRecord {
  jobId: string;
  kind: "scan" | "detonate" | "audit";
  status: "queued" | "running" | "completed" | "failed";
  createdAt: string;
  updatedAt: string;
  slug?: string;
}

export interface DaemonEvent {
  type: DaemonEventType;
  message: string;
  timestamp: string;
}

function parseSkillSourceHint(input: unknown, path: string): SkillSourceHint {
  return parseObject(input, path, (record) => ({
    kind: parseEnum(record.kind, skillSourceKinds, `${path}.kind`),
    detail: parseNonEmptyString(record.detail, `${path}.detail`)
  }));
}

function parseSkillSnapshot(input: unknown, path: string): SkillSnapshot {
  return parseObject(input, path, (record) => ({
    slug: parseNonEmptyString(record.slug, `${path}.slug`),
    path: parseNonEmptyString(record.path, `${path}.path`),
    sourceHints: parseArray(record.sourceHints, parseSkillSourceHint, `${path}.sourceHints`),
    contentHash: parseNonEmptyString(record.contentHash, `${path}.contentHash`),
    fileInventory: parseStringArray(record.fileInventory, `${path}.fileInventory`),
    detectedAt: parseIsoDateTime(record.detectedAt, `${path}.detectedAt`)
  }));
}

function parseStaticFinding(input: unknown, path: string): StaticFinding {
  return parseObject(input, path, (record) => ({
    ruleId: parseNonEmptyString(record.ruleId, `${path}.ruleId`),
    severity: parseEnum(record.severity, findingSeverities, `${path}.severity`),
    message: parseNonEmptyString(record.message, `${path}.message`),
    evidence: parseStringArray(record.evidence, `${path}.evidence`)
  }));
}

function parseStaticScanReport(input: unknown, path: string): StaticScanReport {
  return parseObject(input, path, (record) => ({
    reportId: parseNonEmptyString(record.reportId, `${path}.reportId`),
    snapshot: parseSkillSnapshot(record.snapshot, `${path}.snapshot`),
    score: parseInteger(record.score, `${path}.score`),
    findings: parseArray(record.findings, parseStaticFinding, `${path}.findings`),
    recommendation: parseEnum(record.recommendation, verdictLevels, `${path}.recommendation`),
    generatedAt: parseIsoDateTime(record.generatedAt, `${path}.generatedAt`)
  }));
}

function parseThreatIntelVerdict(input: unknown, path: string): ThreatIntelVerdict {
  return parseObject(input, path, (record) => {
    const maliciousDetections = parseOptional(
      record.maliciousDetections,
      parseInteger,
      `${path}.maliciousDetections`
    );
    const suspiciousDetections = parseOptional(
      record.suspiciousDetections,
      parseInteger,
      `${path}.suspiciousDetections`
    );
    const harmlessDetections = parseOptional(
      record.harmlessDetections,
      parseInteger,
      `${path}.harmlessDetections`
    );
    const undetectedDetections = parseOptional(
      record.undetectedDetections,
      parseInteger,
      `${path}.undetectedDetections`
    );
    const confidence = parseOptional(record.confidence, parseInteger, `${path}.confidence`);
    const sourceUrl = parseOptional(record.sourceUrl, parseNonEmptyString, `${path}.sourceUrl`);

    return {
      provider: parseEnum(record.provider, intelligenceProviders, `${path}.provider`),
      subjectType: parseEnum(record.subjectType, intelligenceSubjects, `${path}.subjectType`),
      subject: parseNonEmptyString(record.subject, `${path}.subject`),
      verdict: parseEnum(record.verdict, verdictLevels, `${path}.verdict`),
      summary: parseNonEmptyString(record.summary, `${path}.summary`),
      ...(maliciousDetections !== undefined ? { maliciousDetections } : {}),
      ...(suspiciousDetections !== undefined ? { suspiciousDetections } : {}),
      ...(harmlessDetections !== undefined ? { harmlessDetections } : {}),
      ...(undetectedDetections !== undefined ? { undetectedDetections } : {}),
      ...(confidence !== undefined ? { confidence } : {}),
      ...(sourceUrl !== undefined ? { sourceUrl } : {}),
      observedAt: parseIsoDateTime(record.observedAt, `${path}.observedAt`)
    };
  });
}

function parseArtifactRef(input: unknown, path: string): ArtifactRef {
  return parseObject(input, path, (record) => ({
    scanId: parseNonEmptyString(record.scanId, `${path}.scanId`),
    type: parseEnum(record.type, artifactTypes, `${path}.type`),
    path: parseNonEmptyString(record.path, `${path}.path`),
    mimeType: parseNonEmptyString(record.mimeType, `${path}.mimeType`)
  }));
}

function parseDetonationRequest(input: unknown, path: string): DetonationRequest {
  return parseObject(input, path, (record) => ({
    requestId: parseNonEmptyString(record.requestId, `${path}.requestId`),
    snapshot: parseSkillSnapshot(record.snapshot, `${path}.snapshot`),
    prompts: parseStringArray(record.prompts, `${path}.prompts`),
    timeoutSeconds: parseInteger(record.timeoutSeconds, `${path}.timeoutSeconds`)
  }));
}

function parseDetonationReport(input: unknown, path: string): DetonationReport {
  return parseObject(input, path, (record) => ({
    request: parseDetonationRequest(record.request, `${path}.request`),
    summary: parseNonEmptyString(record.summary, `${path}.summary`),
    triggeredActions: parseStringArray(record.triggeredActions, `${path}.triggeredActions`),
    artifacts: parseArray(record.artifacts, parseArtifactRef, `${path}.artifacts`),
    generatedAt: parseIsoDateTime(record.generatedAt, `${path}.generatedAt`)
  }));
}

function parseDecisionRecord(input: unknown, path: string): DecisionRecord {
  return parseObject(input, path, (record) => ({
    contentHash: parseNonEmptyString(record.contentHash, `${path}.contentHash`),
    decision: parseEnum(record.decision, decisionKinds, `${path}.decision`),
    reason: parseNonEmptyString(record.reason, `${path}.reason`),
    createdAt: parseIsoDateTime(record.createdAt, `${path}.createdAt`)
  }));
}

function parseScanRecord(input: unknown, path: string): ScanRecord {
  return parseObject(input, path, (record) => {
    const completedAt = parseOptional(record.completedAt, parseIsoDateTime, `${path}.completedAt`);

    return {
      scanId: parseNonEmptyString(record.scanId, `${path}.scanId`),
      slug: parseNonEmptyString(record.slug, `${path}.slug`),
      contentHash: parseNonEmptyString(record.contentHash, `${path}.contentHash`),
      status: parseEnum(record.status, ["pending", "completed", "failed"] as const, `${path}.status`),
      startedAt: parseIsoDateTime(record.startedAt, `${path}.startedAt`),
      ...(completedAt !== undefined ? { completedAt } : {})
    };
  });
}

function parseReportSummary(input: unknown, path: string): ReportSummary {
  return parseObject(input, path, (record) => ({
    reportId: parseNonEmptyString(record.reportId, `${path}.reportId`),
    scanId: parseNonEmptyString(record.scanId, `${path}.scanId`),
    slug: parseNonEmptyString(record.slug, `${path}.slug`),
    verdict: parseEnum(record.verdict, verdictLevels, `${path}.verdict`),
    score: parseInteger(record.score, `${path}.score`),
    findingCount: parseInteger(record.findingCount, `${path}.findingCount`),
    generatedAt: parseIsoDateTime(record.generatedAt, `${path}.generatedAt`)
  }));
}

function parseDaemonJobRecord(input: unknown, path: string): DaemonJobRecord {
  return parseObject(input, path, (record) => {
    const slug = parseOptional(record.slug, parseNonEmptyString, `${path}.slug`);

    return {
      jobId: parseNonEmptyString(record.jobId, `${path}.jobId`),
      kind: parseEnum(record.kind, ["scan", "detonate", "audit"] as const, `${path}.kind`),
      status: parseEnum(record.status, ["queued", "running", "completed", "failed"] as const, `${path}.status`),
      createdAt: parseIsoDateTime(record.createdAt, `${path}.createdAt`),
      updatedAt: parseIsoDateTime(record.updatedAt, `${path}.updatedAt`),
      ...(slug !== undefined ? { slug } : {})
    };
  });
}

function parseDaemonEvent(input: unknown, path: string): DaemonEvent {
  return parseObject(input, path, (record) => ({
    type: parseEnum(record.type, daemonEventTypes, `${path}.type`),
    message: parseNonEmptyString(record.message, `${path}.message`),
    timestamp: parseIsoDateTime(record.timestamp, `${path}.timestamp`)
  }));
}

export const skillSnapshotValidator = createValidator(parseSkillSnapshot, "SkillSnapshot");
export const staticFindingValidator = createValidator(parseStaticFinding, "StaticFinding");
export const staticScanReportValidator = createValidator(parseStaticScanReport, "StaticScanReport");
export const threatIntelVerdictValidator = createValidator(parseThreatIntelVerdict, "ThreatIntelVerdict");
export const artifactRefValidator = createValidator(parseArtifactRef, "ArtifactRef");
export const detonationRequestValidator = createValidator(parseDetonationRequest, "DetonationRequest");
export const detonationReportValidator = createValidator(parseDetonationReport, "DetonationReport");
export const decisionRecordValidator = createValidator(parseDecisionRecord, "DecisionRecord");
export const scanRecordValidator = createValidator(parseScanRecord, "ScanRecord");
export const reportSummaryValidator = createValidator(parseReportSummary, "ReportSummary");
export const daemonJobRecordValidator = createValidator(parseDaemonJobRecord, "DaemonJobRecord");
export const daemonEventValidator = createValidator(parseDaemonEvent, "DaemonEvent");
