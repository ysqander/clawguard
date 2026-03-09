import type { StaticScanReport } from "@clawguard/contracts";

export function renderStaticSummary(report: StaticScanReport): string {
  return `${report.snapshot.slug}: ${report.recommendation} (${report.score})`;
}
