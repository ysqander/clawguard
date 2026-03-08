#!/usr/bin/env node

import { renderStaticSummary } from "@clawguard/reports";
import { createPlaceholderScanReport } from "@clawguard/scanner";

const report = createPlaceholderScanReport({
  slug: "placeholder-skill",
  path: "/tmp/placeholder-skill",
  sourceHints: ["manual"],
  contentHash: "placeholder",
  fileInventory: ["SKILL.md"]
});

console.log(`clawguard cli scaffold | ${renderStaticSummary(report)}`);
