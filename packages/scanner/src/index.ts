import type { SkillSnapshot, StaticScanReport } from "@clawguard/contracts";

export function createPlaceholderScanReport(snapshot: SkillSnapshot): StaticScanReport {
  return {
    reportId: `report-${snapshot.slug}`,
    snapshot,
    score: 0,
    findings: [],
    recommendation: "unknown",
    generatedAt: new Date(0).toISOString()
  };
}
