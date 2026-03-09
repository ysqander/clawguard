#!/usr/bin/env node

import { renderStaticSummary } from "@clawguard/reports";
import { createPlaceholderScanReport } from "@clawguard/scanner";

const report = createPlaceholderScanReport({
  slug: "placeholder-skill",
  path: "/tmp/placeholder-skill",
  sourceHints: [{ kind: "manual", detail: "CLI scaffold placeholder" }],
  contentHash: "placeholder",
  fileInventory: ["SKILL.md"],
  detectedAt: "2026-03-08T00:00:00.000Z",
});

console.log(`clawguard cli scaffold | ${renderStaticSummary(report)}`);
