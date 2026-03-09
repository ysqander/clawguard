export interface StorageMigration {
  version: number;
  statements: string[];
}

export const storageMigrations: StorageMigration[] = [
  {
    version: 1,
    statements: [
      `
        CREATE TABLE IF NOT EXISTS scans (
          scan_id TEXT PRIMARY KEY,
          skill_slug TEXT NOT NULL,
          content_hash TEXT NOT NULL,
          status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'failed')),
          started_at TEXT NOT NULL,
          completed_at TEXT,
          scan_json TEXT NOT NULL
        )
      `,
      "CREATE INDEX IF NOT EXISTS scans_skill_slug_idx ON scans (skill_slug)",
      "CREATE INDEX IF NOT EXISTS scans_content_hash_idx ON scans (content_hash)",
      `
        CREATE TABLE IF NOT EXISTS reports (
          report_id TEXT PRIMARY KEY,
          scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
          skill_slug TEXT NOT NULL,
          content_hash TEXT NOT NULL,
          verdict TEXT NOT NULL CHECK (verdict IN ('unknown', 'allow', 'review', 'block')),
          score INTEGER NOT NULL,
          finding_count INTEGER NOT NULL,
          generated_at TEXT NOT NULL,
          report_json TEXT NOT NULL,
          summary_json TEXT NOT NULL
        )
      `,
      "CREATE INDEX IF NOT EXISTS reports_scan_id_idx ON reports (scan_id)",
      "CREATE INDEX IF NOT EXISTS reports_skill_slug_idx ON reports (skill_slug)",
      "CREATE INDEX IF NOT EXISTS reports_content_hash_idx ON reports (content_hash)",
      `
        CREATE TABLE IF NOT EXISTS artifacts (
          artifact_id TEXT PRIMARY KEY,
          scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
          artifact_type TEXT NOT NULL,
          relative_path TEXT NOT NULL,
          mime_type TEXT NOT NULL,
          sha256 TEXT NOT NULL,
          size_bytes INTEGER NOT NULL,
          created_at TEXT NOT NULL
        )
      `,
      "CREATE UNIQUE INDEX IF NOT EXISTS artifacts_scan_path_idx ON artifacts (scan_id, relative_path)",
      "CREATE INDEX IF NOT EXISTS artifacts_scan_id_idx ON artifacts (scan_id)",
      `
        CREATE TABLE IF NOT EXISTS decisions (
          content_hash TEXT PRIMARY KEY,
          decision TEXT NOT NULL CHECK (decision IN ('allow', 'block', 'quarantine')),
          reason TEXT NOT NULL,
          created_at TEXT NOT NULL
        )
      `,
      "CREATE INDEX IF NOT EXISTS decisions_decision_idx ON decisions (decision)",
      `
        CREATE TABLE IF NOT EXISTS quarantine_entries (
          quarantine_id TEXT PRIMARY KEY,
          scan_id TEXT REFERENCES scans(scan_id) ON DELETE SET NULL,
          skill_slug TEXT NOT NULL,
          content_hash TEXT NOT NULL,
          original_path TEXT NOT NULL,
          quarantine_path TEXT NOT NULL,
          state TEXT NOT NULL CHECK (state IN ('active', 'restored', 'deleted')),
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )
      `,
      "CREATE INDEX IF NOT EXISTS quarantine_entries_state_idx ON quarantine_entries (state)",
      "CREATE INDEX IF NOT EXISTS quarantine_entries_content_hash_idx ON quarantine_entries (content_hash)",
    ],
  },
];

export const STORAGE_SCHEMA_VERSION = storageMigrations.at(-1)?.version ?? 0;
