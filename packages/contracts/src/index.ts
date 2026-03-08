export type VerdictLevel = "unknown" | "allow" | "review" | "block";

export interface SkillSnapshot {
  slug: string;
  path: string;
  sourceHints: string[];
  contentHash: string;
  fileInventory: string[];
}

export interface StaticFinding {
  ruleId: string;
  severity: "low" | "medium" | "high" | "critical";
  message: string;
  evidence: string[];
}

export interface StaticScanReport {
  snapshot: SkillSnapshot;
  score: number;
  findings: StaticFinding[];
  recommendation: VerdictLevel;
}

export interface ThreatIntelVerdict {
  provider: "clawhub" | "virustotal";
  subject: string;
  verdict: VerdictLevel;
  summary: string;
}

export interface ArtifactRef {
  scanId: string;
  type: string;
  path: string;
}

export interface DetonationRequest {
  snapshot: SkillSnapshot;
  prompts: string[];
}

export interface DetonationReport {
  request: DetonationRequest;
  summary: string;
  artifacts: ArtifactRef[];
}

export interface DecisionRecord {
  contentHash: string;
  decision: "allow" | "block" | "quarantine";
  reason: string;
}

export interface PlatformCapabilities {
  platform: "macos" | "linux";
  supportsWatcher: boolean;
  supportsNotifications: boolean;
  supportsServiceInstall: boolean;
  supportedDetonationRuntimes: Array<"podman" | "docker">;
}

export interface DaemonEvent {
  type:
    | "scan-requested"
    | "scan-completed"
    | "detonation-completed"
    | "quarantine-changed"
    | "notification-sent";
  message: string;
  timestamp: string;
}

