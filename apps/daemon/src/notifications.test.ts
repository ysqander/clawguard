import assert from "node:assert/strict";
import test from "node:test";

import { buildScanNotification } from "./notifications.js";

test("buildScanNotification emphasizes a quarantined skill", () => {
  assert.deepEqual(
    buildScanNotification({
      slug: "malicious-staged-download",
      recommendation: "block",
      score: 97,
      findingCount: 5,
      completedAt: "2026-03-18T10:15:00.000Z",
    }),
    {
      title: "ClawGuard quarantined",
      body: 'Quarantined "malicious-staged-download" so OpenClaw will not load it. Score 97 with 5 findings.',
      subtitle:
        "Review required before reinstalling or allowing it. Completed at 2026-03-18T10:15:00.000Z",
    },
  );
});

test("buildScanNotification renders completed allow scans as low-friction confirmations", () => {
  assert.deepEqual(
    buildScanNotification({
      slug: "benign-calendar-helper",
      recommendation: "allow",
      score: 2,
      findingCount: 0,
      completedAt: "2026-03-18T10:15:00.000Z",
    }),
    {
      title: "ClawGuard scan complete",
      body: 'No quarantine was needed for "benign-calendar-helper". Score 2 with 0 findings.',
      subtitle: "Completed at 2026-03-18T10:15:00.000Z",
    },
  );
});

test("buildScanNotification asks for manual review when the recommendation is review", () => {
  assert.deepEqual(
    buildScanNotification({
      slug: "suspicious-prompt-injection",
      recommendation: "review",
      score: 61,
      findingCount: 2,
    }),
    {
      title: "ClawGuard review recommended",
      body: 'Review "suspicious-prompt-injection" before the next OpenClaw session. Score 61 with 2 findings.',
      subtitle: "Manual review required",
    },
  );
});

test("buildScanNotification normalizes empty and invalid values into safe defaults", () => {
  assert.deepEqual(
    buildScanNotification({
      slug: "   ",
      recommendation: "allow",
      score: Number.NaN,
      findingCount: Number.POSITIVE_INFINITY,
      completedAt: "   ",
    }),
    {
      title: "ClawGuard scan complete",
      body: 'No quarantine was needed for "unknown-skill". Score 0 with 0 findings.',
    },
  );
});
