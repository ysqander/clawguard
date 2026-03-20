import assert from "node:assert/strict";
import { test } from "node:test";

import { getSkillFixtureById, listSkillFixtures, loadFixtureSnapshot } from "./index.js";

test("fixture corpus includes benign and malicious coverage", () => {
  const benign = listSkillFixtures({ includeIntent: ["benign"] });
  const malicious = listSkillFixtures({ includeIntent: ["malicious"] });

  assert.ok(benign.length >= 4);
  assert.ok(malicious.length >= 8);
  assert.ok(benign.some((fixture) => fixture.id === "benign-remote-content-researcher"));
  assert.ok(malicious.some((fixture) => fixture.id === "clawhavoc-staged-installer"));
  assert.ok(malicious.some((fixture) => fixture.id === "env-exfil-weather"));
  assert.ok(malicious.some((fixture) => fixture.id === "memory-poison-preference"));
  assert.ok(malicious.some((fixture) => fixture.id === "stego-soul-pack"));
  assert.ok(malicious.some((fixture) => fixture.id === "fake-password-dialog"));
  assert.ok(malicious.some((fixture) => fixture.id === "prompt-injection-override"));
  assert.ok(malicious.some((fixture) => fixture.id === "typoglycemia-prompt-override"));
});

test("loadFixtureSnapshot produces deterministic inventory with SKILL.md", () => {
  const fixture = getSkillFixtureById("malicious-staged-download");
  const snapshot = loadFixtureSnapshot(fixture);

  assert.equal(snapshot.slug, fixture.slug);
  assert.ok(snapshot.contentHash.startsWith("sha256:"));
  assert.ok(snapshot.fileInventory.includes("SKILL.md"));
  assert.ok(snapshot.fileInventory.includes("scripts/install.sh"));
});

test("detonation-target benchmark selection is explicit and non-empty", () => {
  const fixtures = listSkillFixtures({ benchmarkTag: "detonation-target" });

  assert.deepEqual(
    fixtures.map((fixture) => fixture.id),
    [
      "benign-markdown-formatter",
      "clawhavoc-staged-installer",
      "env-exfil-weather",
      "memory-poison-preference",
      "fake-password-dialog",
      "prompt-injection-override",
    ],
  );
});
