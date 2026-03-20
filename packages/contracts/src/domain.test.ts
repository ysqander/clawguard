import assert from "node:assert/strict";
import { test } from "node:test";

import {
  detonationReportValidator,
  exampleDetonationReport,
  exampleSkillSnapshot,
  skillSnapshotValidator,
} from "./index.js";

test("skillSnapshotValidator accepts snapshots with metadata", () => {
  const parsed = skillSnapshotValidator.parse(exampleSkillSnapshot);

  assert.equal(parsed.metadata?.skillMd.path, "SKILL.md");
  assert.equal(parsed.metadata?.manifests[0]?.path, "package.json");
});

test("skillSnapshotValidator accepts snapshots without metadata", () => {
  const parsed = skillSnapshotValidator.parse({
    slug: "minimal-skill",
    path: "/tmp/minimal-skill",
    sourceHints: [{ kind: "fixture", detail: "validator test" }],
    contentHash: "sha256:minimal",
    fileInventory: ["SKILL.md"],
    detectedAt: "2026-03-11T00:00:00.000Z",
  });

  assert.equal(parsed.slug, "minimal-skill");
  assert.equal(parsed.metadata, undefined);
});

test("detonationReportValidator accepts telemetry events with typed observations", () => {
  const parsed = detonationReportValidator.parse(exampleDetonationReport);

  assert.equal(parsed.telemetry?.[0]?.type, "network");
  assert.equal(parsed.telemetry?.[0]?.network?.address, "93.184.216.34");
  assert.equal(parsed.telemetry?.[0]?.indicator?.subjectType, "domain");
  assert.deepEqual(parsed.findings[0]?.signalIds, [
    "download-source",
    "execute-sink",
    "network-capability",
  ]);
  assert.equal(parsed.findings[0]?.confidence, 95);
});
