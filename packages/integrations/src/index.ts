import type { ThreatIntelVerdict } from "@clawguard/contracts";

export interface ClawHubClient {
  getSkill(slug: string): Promise<ThreatIntelVerdict | null>;
}

export interface VirusTotalClient {
  getFileVerdict(contentHash: string): Promise<ThreatIntelVerdict | null>;
}

