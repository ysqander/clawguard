import type { ThreatIntelVerdict, VerdictLevel } from "@clawguard/contracts";
import { IntegrationHttpError } from "./errors.js";

export type ClawHubSort = "trending" | "installs" | "recent";

export interface ClawHubClientOptions {
  baseUrl: string;
  enabled?: boolean;
  fetchImpl?: typeof fetch;
}

export interface ClawHubSkillEnrichment {
  slug: string;
  metadata: Record<string, unknown>;
  clawHubVerdict: ThreatIntelVerdict;
  virusTotalVerdict: ThreatIntelVerdict;
}

export interface ClawHubSkillListEntry {
  slug: string;
  name?: string;
  description?: string;
}

export class HttpClawHubClient {
  private readonly baseUrl: string;
  private readonly enabled: boolean;
  private readonly fetchImpl: typeof fetch;

  constructor(options: ClawHubClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.enabled = options.enabled ?? true;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async getSkill(slug: string): Promise<ClawHubSkillEnrichment | null> {
    if (!this.enabled) {
      return null;
    }

    const requestPath = `/api/v1/skills/${encodeURIComponent(slug)}`;
    const response = await this.request(requestPath);
    if (response.status === 404) {
      return null;
    }

    this.assertJsonResponse(requestPath, response);
    const body = await response.json();
    const metadata = isRecord(body) ? body : {};

    return {
      slug,
      metadata,
      clawHubVerdict: this.resolveVerdict(metadata, "clawhub", "skill", slug),
      virusTotalVerdict: this.resolveVerdict(metadata, "virustotal", "skill", slug),
    };
  }

  async getSkillMarkdown(slug: string): Promise<string | null> {
    if (!this.enabled) {
      return null;
    }

    const response = await this.request(
      `/api/v1/skills/${encodeURIComponent(slug)}/file?path=SKILL.md`,
    );
    if (response.status === 404) {
      return null;
    }

    const text = await response.text();
    return text.length > 0 ? text : null;
  }

  async listSkills(sort: ClawHubSort): Promise<ClawHubSkillListEntry[]> {
    if (!this.enabled) {
      return [];
    }

    const response = await this.requestJson(`/api/v1/skills?sort=${encodeURIComponent(sort)}`);
    const payload = await response.json();
    const items = Array.isArray(payload)
      ? payload
      : isRecord(payload) && Array.isArray(payload.items)
        ? payload.items
        : [];

    const entries: ClawHubSkillListEntry[] = [];
    for (const item of items) {
      if (!isRecord(item)) {
        continue;
      }

      const slug = asString(item.slug);
      if (!slug) {
        continue;
      }

      const name = asString(item.displayName) ?? asString(item.name);
      const description = asString(item.summary) ?? asString(item.description);

      entries.push({
        slug,
        ...(name ? { name } : {}),
        ...(description ? { description } : {}),
      });
    }

    return entries;
  }

  private async requestJson(path: string): Promise<Response> {
    const response = await this.request(path);
    this.assertJsonResponse(path, response);
    return response;
  }

  private assertJsonResponse(path: string, response: Response): void {
    const contentType = response.headers.get("content-type") ?? "";
    if (!contentType.includes("application/json")) {
      throw new Error(`Expected JSON response for ${path}`);
    }
  }

  private async request(path: string): Promise<Response> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchImpl(url);

    if (response.ok) {
      return response;
    }

    if (response.status === 404) {
      return response;
    }

    throw new IntegrationHttpError(
      `ClawHub request failed: ${response.status} ${url}`,
      response.status,
      url,
    );
  }

  private resolveVerdict(
    metadata: Record<string, unknown>,
    provider: ThreatIntelVerdict["provider"],
    subjectType: ThreatIntelVerdict["subjectType"],
    subject: string,
  ): ThreatIntelVerdict {
    const providerRecord = this.getProviderVerdictRecord(metadata, provider);
    const verdict = coerceVerdictLevel(providerRecord?.verdict) ?? "unknown";

    const maliciousDetections = asNumber(providerRecord?.maliciousDetections);
    const suspiciousDetections = asNumber(providerRecord?.suspiciousDetections);
    const harmlessDetections = asNumber(providerRecord?.harmlessDetections);
    const undetectedDetections = asNumber(providerRecord?.undetectedDetections);
    const confidence = asNumber(providerRecord?.confidence);
    const sourceUrl = asString(providerRecord?.sourceUrl);

    return {
      provider,
      subjectType,
      subject,
      verdict,
      summary:
        asString(providerRecord?.summary) ??
        (verdict === "unknown"
          ? "No provider verdict available."
          : `Provider verdict: ${verdict}.`),
      ...(maliciousDetections !== undefined ? { maliciousDetections } : {}),
      ...(suspiciousDetections !== undefined ? { suspiciousDetections } : {}),
      ...(harmlessDetections !== undefined ? { harmlessDetections } : {}),
      ...(undetectedDetections !== undefined ? { undetectedDetections } : {}),
      ...(confidence !== undefined ? { confidence } : {}),
      ...(sourceUrl ? { sourceUrl } : {}),
      observedAt: new Date().toISOString(),
    };
  }

  private getProviderVerdictRecord(
    metadata: Record<string, unknown>,
    provider: ThreatIntelVerdict["provider"],
  ): Record<string, unknown> | undefined {
    const explicit = isRecord(metadata.verdicts) ? metadata.verdicts[provider] : undefined;
    if (isRecord(explicit)) {
      return explicit;
    }

    if (provider === "clawhub") {
      const fallback = coerceVerdictLevel(metadata.verdict);
      return fallback
        ? { verdict: fallback, summary: "ClawHub verdict extracted from skill metadata." }
        : undefined;
    }

    const vtVerdict = coerceVerdictLevel(metadata.virusTotalVerdict);
    if (vtVerdict) {
      return { verdict: vtVerdict, summary: "VirusTotal verdict extracted from skill metadata." };
    }

    return undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function coerceVerdictLevel(value: unknown): VerdictLevel | undefined {
  if (value === "allow" || value === "review" || value === "block" || value === "unknown") {
    return value;
  }

  return undefined;
}
