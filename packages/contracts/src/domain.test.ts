import assert from "node:assert/strict";
import { test } from "node:test";

import { exampleSkillSnapshot, skillSnapshotValidator } from "./index.js";

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
