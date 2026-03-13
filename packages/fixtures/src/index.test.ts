import assert from "node:assert/strict";
import { test } from "node:test";

import { getSkillFixtureById, listSkillFixtures, loadFixtureSnapshot } from "./index.js";

test("fixture corpus includes benign and malicious coverage", () => {
  const benign = listSkillFixtures({ includeIntent: ["benign"] });
  const malicious = listSkillFixtures({ includeIntent: ["malicious"] });

  assert.ok(benign.length >= 3);
  assert.ok(malicious.length >= 3);
  assert.ok(malicious.some((fixture) => fixture.id === "malicious-staged-download"));
  assert.ok(malicious.some((fixture) => fixture.id === "malicious-memory-poisoning"));
  assert.ok(malicious.some((fixture) => fixture.id === "malicious-exfiltration"));
});

test("loadFixtureSnapshot produces deterministic inventory with SKILL.md", () => {
  const fixture = getSkillFixtureById("malicious-staged-download");
  const snapshot = loadFixtureSnapshot(fixture);

  assert.equal(snapshot.slug, fixture.slug);
  assert.ok(snapshot.contentHash.startsWith("sha256:"));
  assert.ok(snapshot.fileInventory.includes("SKILL.md"));
  assert.ok(snapshot.fileInventory.includes("scripts/install.sh"));
});
