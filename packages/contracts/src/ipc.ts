import os from "node:os";
import path from "node:path";

import {
  createValidator,
  parseArray,
  parseBoolean,
  parseEnum,
  parseInteger,
  parseLiteral,
  parseNonEmptyString,
  parseObject,
  parseOptional,
} from "./runtime.js";
import {
  artifactRefValidator,
  decisionRecordValidator,
  detonationReportValidator,
  reportSummaryValidator,
  scanRecordValidator,
  staticScanReportValidator,
} from "./domain.js";

export const daemonCommands = [
  "status",
  "scan",
  "report",
  "allow",
  "block",
  "detonate",
  "audit",
] as const;
export type DaemonCommand = (typeof daemonCommands)[number];

export interface StatusRequest {
  command: "status";
}

export interface ScanRequest {
  command: "scan";
  skillPath: string;
}

export interface ReportRequest {
  command: "report";
  slug: string;
}

export interface AllowRequest {
  command: "allow";
  slug: string;
  reason?: string;
}

export interface BlockRequest {
  command: "block";
  slug: string;
  reason?: string;
}

export interface DetonateRequest {
  command: "detonate";
  slug: string;
}

export interface AuditRequest {
  command: "audit";
}

export type DaemonRequestPayload =
  | StatusRequest
  | ScanRequest
  | ReportRequest
  | AllowRequest
  | BlockRequest
  | DetonateRequest
  | AuditRequest;

export interface DaemonRequestEnvelope {
  version: 1;
  requestId: string;
  payload: DaemonRequestPayload;
}

export interface StatusResponseData {
  state: "idle" | "busy" | "degraded";
  jobs: number;
}

export interface ScanResponseData {
  scan: ReturnType<typeof scanRecordValidator.parse>;
  report?: ReturnType<typeof staticScanReportValidator.parse>;
}

export interface ReportResponseData {
  summary: ReturnType<typeof reportSummaryValidator.parse>;
  report: ReturnType<typeof staticScanReportValidator.parse>;
  decision?: ReturnType<typeof decisionRecordValidator.parse>;
  artifacts: Array<ReturnType<typeof artifactRefValidator.parse>>;
}

export interface DetonateResponseData {
  report: ReturnType<typeof detonationReportValidator.parse>;
}

export interface AuditResponseData {
  scans: Array<ReturnType<typeof scanRecordValidator.parse>>;
}

export type DaemonResponseData =
  | StatusResponseData
  | ScanResponseData
  | ReportResponseData
  | DetonateResponseData
  | AuditResponseData;

export interface DaemonSuccessResponse {
  version: 1;
  requestId: string;
  ok: true;
  data: DaemonResponseData;
}

export interface DaemonError {
  code: string;
  message: string;
  retryable: boolean;
}

export interface DaemonErrorResponse {
  version: 1;
  requestId: string;
  ok: false;
  error: DaemonError;
}

export type DaemonResponseEnvelope = DaemonSuccessResponse | DaemonErrorResponse;

const DEFAULT_DAEMON_SOCKET_PATH = path.join(os.tmpdir(), "clawguard-daemon.sock");

export function resolveDaemonSocketPath(): string {
  return process.env.CLAWGUARD_DAEMON_SOCKET ?? DEFAULT_DAEMON_SOCKET_PATH;
}

function parseDaemonRequestPayload(input: unknown, path: string): DaemonRequestPayload {
  return parseObject(input, path, (record) => {
    const command = parseEnum(record.command, daemonCommands, `${path}.command`);

    switch (command) {
      case "status":
      case "audit":
        return { command };
      case "scan":
        return {
          command,
          skillPath: parseNonEmptyString(record.skillPath, `${path}.skillPath`),
        };
      case "report":
      case "detonate":
        return {
          command,
          slug: parseNonEmptyString(record.slug, `${path}.slug`),
        };
      case "allow":
        return {
          command,
          slug: parseNonEmptyString(record.slug, `${path}.slug`),
          ...(record.reason !== undefined
            ? { reason: parseNonEmptyString(record.reason, `${path}.reason`) }
            : {}),
        };
      case "block":
        return {
          command,
          slug: parseNonEmptyString(record.slug, `${path}.slug`),
          ...(record.reason !== undefined
            ? { reason: parseNonEmptyString(record.reason, `${path}.reason`) }
            : {}),
        };
    }
  });
}

function parseDaemonRequestEnvelope(input: unknown, path: string): DaemonRequestEnvelope {
  return parseObject(input, path, (record) => ({
    version: parseLiteral(record.version, 1, `${path}.version`),
    requestId: parseNonEmptyString(record.requestId, `${path}.requestId`),
    payload: parseDaemonRequestPayload(record.payload, `${path}.payload`),
  }));
}

function parseStatusResponseData(input: unknown, path: string): StatusResponseData {
  return parseObject(input, path, (record) => ({
    state: parseEnum(record.state, ["idle", "busy", "degraded"] as const, `${path}.state`),
    jobs: parseInteger(record.jobs, `${path}.jobs`),
  }));
}

function parseScanResponseData(input: unknown, path: string): ScanResponseData {
  return parseObject(input, path, (record) => {
    const report = parseOptional(record.report, staticScanReportValidator.parse, `${path}.report`);

    return {
      scan: scanRecordValidator.parse(record.scan),
      ...(report !== undefined ? { report } : {}),
    };
  });
}

function parseReportResponseData(input: unknown, path: string): ReportResponseData {
  return parseObject(input, path, (record) => {
    const decision = parseOptional(
      record.decision,
      decisionRecordValidator.parse,
      `${path}.decision`,
    );

    return {
      summary: reportSummaryValidator.parse(record.summary),
      report: staticScanReportValidator.parse(record.report),
      ...(decision !== undefined ? { decision } : {}),
      artifacts: parseArray(record.artifacts, artifactRefValidator.parse, `${path}.artifacts`),
    };
  });
}

function parseDetonateResponseData(input: unknown, path: string): DetonateResponseData {
  return parseObject(input, path, (record) => ({
    report: detonationReportValidator.parse(record.report),
  }));
}

function parseAuditResponseData(input: unknown, path: string): AuditResponseData {
  return parseObject(input, path, (record) => ({
    scans: parseArray(record.scans, scanRecordValidator.parse, `${path}.scans`),
  }));
}

function parseSuccessData(input: unknown, path: string): DaemonResponseData {
  const record = parseObject(input, path, (value) => value);

  if ("state" in record && "jobs" in record) {
    return parseStatusResponseData(record, path);
  }

  if ("scan" in record) {
    return parseScanResponseData(record, path);
  }

  if ("summary" in record && "report" in record) {
    return parseReportResponseData(record, path);
  }

  if ("report" in record) {
    return parseDetonateResponseData(record, path);
  }

  if ("scans" in record) {
    return parseAuditResponseData(record, path);
  }

  throw new Error(`Unknown daemon response payload at ${path}`);
}

function parseDaemonError(input: unknown, path: string): DaemonError {
  return parseObject(input, path, (record) => ({
    code: parseNonEmptyString(record.code, `${path}.code`),
    message: parseNonEmptyString(record.message, `${path}.message`),
    retryable: parseBoolean(record.retryable, `${path}.retryable`),
  }));
}

function parseDaemonResponseEnvelope(input: unknown, path: string): DaemonResponseEnvelope {
  return parseObject(input, path, (record) => {
    const version = parseLiteral(record.version, 1, `${path}.version`);
    const requestId = parseNonEmptyString(record.requestId, `${path}.requestId`);
    const ok = parseBoolean(record.ok, `${path}.ok`);

    if (ok) {
      return {
        version,
        requestId,
        ok,
        data: parseSuccessData(record.data, `${path}.data`),
      };
    }

    return {
      version,
      requestId,
      ok,
      error: parseDaemonError(record.error, `${path}.error`),
    };
  });
}

export const daemonRequestEnvelopeValidator = createValidator(
  parseDaemonRequestEnvelope,
  "DaemonRequestEnvelope",
);
export const daemonResponseEnvelopeValidator = createValidator(
  parseDaemonResponseEnvelope,
  "DaemonResponseEnvelope",
);
