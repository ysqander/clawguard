import type { SkillSnapshot, StaticScanReport } from "@clawguard/contracts";

export function createPlaceholderScanReport(snapshot: SkillSnapshot): StaticScanReport {
  return {
    snapshot,
    score: 0,
    findings: [],
    recommendation: "unknown"
  };
}

