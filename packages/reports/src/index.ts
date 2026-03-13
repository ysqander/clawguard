import type {
  ReportSummary,
  ScanRecord,
  StaticScanReport,
  ThreatIntelVerdict,
  VerdictLevel,
} from "@clawguard/contracts";
import type { StorageApi, StoredArtifactRecord, StoredStaticReport } from "@clawguard/storage";

export interface StaticReportSynthesisInput {
  scan: ScanRecord;
  report: StaticScanReport;
  clawHubMetadata?: Record<string, unknown>;
  clawHubVerdict?: ThreatIntelVerdict;
  virusTotalVerdict?: ThreatIntelVerdict;
  threatIntelVerdicts?: ThreatIntelVerdict[];
  generatedAt?: string;
}

export interface SynthesizedStaticReport {
  summary: ReportSummary;
  report: StaticScanReport;
  threatIntelVerdicts: ThreatIntelVerdict[];
  clawHubMetadata?: Record<string, unknown>;
  decisionReason: string;
  plainLanguageSummary: string;
  plainLanguageReport: string;
}

export interface PersistSynthesizedStaticReportResult {
  storedReport: StoredStaticReport;
  artifacts: {
    reportJson: StoredArtifactRecord;
    summaryMarkdown: StoredArtifactRecord;
  };
}

export function synthesizeStaticReport(input: StaticReportSynthesisInput): SynthesizedStaticReport {
  assertScanAndReportConsistency(input.scan, input.report);

  const generatedAt = input.generatedAt ?? input.report.generatedAt;
  const threatIntelVerdicts = mergeThreatIntelVerdicts(input);
  const clawHubMetadata = input.clawHubMetadata;
  const summary: ReportSummary = {
    reportId: input.report.reportId,
    scanId: input.scan.scanId,
    slug: input.report.snapshot.slug,
    verdict: input.report.recommendation,
    score: input.report.score,
    findingCount: input.report.findings.length,
    generatedAt,
  };

  const decisionReason = buildDecisionReason(input.report, threatIntelVerdicts);
  const plainLanguageSummary = renderStaticSummary(input.report, threatIntelVerdicts);
  const plainLanguageReport = renderStaticReport(
    input.report,
    threatIntelVerdicts,
    decisionReason,
    clawHubMetadata,
  );

  return {
    summary,
    report: input.report,
    threatIntelVerdicts,
    ...(clawHubMetadata ? { clawHubMetadata } : {}),
    decisionReason,
    plainLanguageSummary,
    plainLanguageReport,
  };
}

export async function persistSynthesizedStaticReport(
  storage: StorageApi,
  synthesized: SynthesizedStaticReport,
): Promise<PersistSynthesizedStaticReportResult> {
  await storage.persistStaticReport({
    summary: synthesized.summary,
    report: synthesized.report,
  });

  const reportJson = await storage.writeJsonArtifact({
    scanId: synthesized.summary.scanId,
    type: "report-json",
    filename: `${synthesized.summary.reportId}.static-report.json`,
    value: {
      summary: synthesized.summary,
      report: synthesized.report,
      threatIntelVerdicts: synthesized.threatIntelVerdicts,
      ...(synthesized.clawHubMetadata ? { clawHubMetadata: synthesized.clawHubMetadata } : {}),
      decisionReason: synthesized.decisionReason,
    },
  });

  const summaryMarkdown = await storage.writeArtifact({
    scanId: synthesized.summary.scanId,
    type: "report-markdown",
    filename: `${synthesized.summary.reportId}.summary.md`,
    data: synthesized.plainLanguageReport,
    mimeType: "text/markdown",
  });

  const storedReport = await storage.getStaticReport(synthesized.summary.reportId);
  if (!storedReport) {
    throw new Error(`Failed to read persisted report ${synthesized.summary.reportId}`);
  }

  return {
    storedReport,
    artifacts: {
      reportJson,
      summaryMarkdown,
    },
  };
}

export function renderStaticSummary(
  report: StaticScanReport,
  threatIntelVerdicts: ThreatIntelVerdict[] = [],
): string {
  const findingLabel = report.findings.length === 1 ? "1 finding" : `${report.findings.length} findings`;
  const enrichmentLabel =
    threatIntelVerdicts.length === 0
      ? "no threat-intel enrichment"
      : `${threatIntelVerdicts.length} enrichment signal${threatIntelVerdicts.length === 1 ? "" : "s"}`;

  return `${report.snapshot.slug}: ${report.recommendation} (score ${report.score}, ${findingLabel}, ${enrichmentLabel})`;
}

export function renderStaticReport(
  report: StaticScanReport,
  threatIntelVerdicts: ThreatIntelVerdict[] = [],
  decisionReason = buildDecisionReason(report, threatIntelVerdicts),
  clawHubMetadata?: Record<string, unknown>,
): string {
  const lines: string[] = [
    `# ClawGuard static report: ${report.snapshot.slug}`,
    "",
    `Recommendation: **${uppercaseVerdict(report.recommendation)}**`,
    `Score: ${report.score}`,
    `Findings: ${report.findings.length}`,
    "",
    `Decision rationale: ${decisionReason}`,
    "",
    "## Local static findings",
  ];

  if (report.findings.length === 0) {
    lines.push("No local static findings were triggered.");
  } else {
    report.findings.forEach((finding, index) => {
      lines.push(`${index + 1}. [${finding.severity.toUpperCase()}] ${finding.message} (${finding.ruleId})`);
      for (const evidence of finding.evidence) {
        lines.push(`   - Evidence: ${evidence}`);
      }
    });
  }

  if (clawHubMetadata) {
    lines.push("", "## ClawHub marketplace context", ...renderClawHubMarketplaceContext(report, clawHubMetadata));
  }

  lines.push("", "## Threat-intelligence enrichment");

  if (threatIntelVerdicts.length === 0) {
    lines.push("No enrichment signals were available for this scan.");
  } else {
    for (const verdict of threatIntelVerdicts) {
      lines.push(
        `- ${verdict.provider} ${verdict.subjectType} ${verdict.subject}: ${verdict.verdict} — ${verdict.summary}`,
      );
    }

    lines.push(
      "",
      "Enrichment signals provide additional context and do not replace local static findings.",
    );
  }

  return lines.join("\n");
}

function assertScanAndReportConsistency(scan: ScanRecord, report: StaticScanReport): void {
  if (scan.slug !== report.snapshot.slug) {
    throw new Error(`scan.slug (${scan.slug}) must match report.snapshot.slug (${report.snapshot.slug})`);
  }

  if (scan.contentHash !== report.snapshot.contentHash) {
    throw new Error("scan.contentHash must match report.snapshot.contentHash");
  }
}

function mergeThreatIntelVerdicts(input: StaticReportSynthesisInput): ThreatIntelVerdict[] {
  const merged = [
    ...(input.clawHubVerdict ? [input.clawHubVerdict] : []),
    ...(input.virusTotalVerdict ? [input.virusTotalVerdict] : []),
    ...(input.threatIntelVerdicts ?? []),
  ];

  const unique = new Map<string, ThreatIntelVerdict>();
  for (const verdict of merged) {
    unique.set(`${verdict.provider}:${verdict.subjectType}:${verdict.subject}`, verdict);
  }

  return [...unique.values()];
}

function renderClawHubMarketplaceContext(
  report: StaticScanReport,
  clawHubMetadata: Record<string, unknown>,
): string[] {
  const metadataSlug = readMetadataString(clawHubMetadata, "slug");
  const name =
    readMetadataString(clawHubMetadata, "displayName") ?? readMetadataString(clawHubMetadata, "name");
  const summary =
    readMetadataString(clawHubMetadata, "summary") ?? readMetadataString(clawHubMetadata, "description");
  const hasRecognizedMetadataFields =
    metadataSlug !== undefined || name !== undefined || summary !== undefined;
  const lines = [`- Slug: ${metadataSlug ?? report.snapshot.slug}`];

  if (name) {
    lines.push(`- Name: ${name}`);
  }

  if (summary) {
    lines.push(`- Summary: ${summary}`);
  }

  if (Object.keys(clawHubMetadata).length > 0 && !hasRecognizedMetadataFields) {
    lines.push("Raw ClawHub metadata was captured in the JSON artifact for later inspection.");
  }

  return lines;
}

function buildDecisionReason(report: StaticScanReport, threatIntelVerdicts: ThreatIntelVerdict[]): string {
  const criticalFindings = report.findings.filter((finding) => finding.severity === "critical").length;

  if (report.recommendation === "block") {
    if (criticalFindings > 0) {
      return `Quarantined due to ${criticalFindings} critical local static finding${criticalFindings === 1 ? "" : "s"}; enrichment is supporting context only.`;
    }

    return "Quarantined by local static scoring thresholds; enrichment is supporting context only.";
  }

  if (report.recommendation === "review") {
    return "Marked for review by local static findings; enrichment is included for analyst context.";
  }

  if (threatIntelVerdicts.some((entry) => entry.verdict === "block" || entry.verdict === "review")) {
    return "Allowed by local static findings; enrichment flagged caution for follow-up analysis.";
  }

  return "Allowed by local static findings with no high-risk enrichment indicators.";
}

function uppercaseVerdict(verdict: VerdictLevel): string {
  return verdict.toUpperCase();
}

function readMetadataString(metadata: Record<string, unknown>, key: string): string | undefined {
  const value = metadata[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}
