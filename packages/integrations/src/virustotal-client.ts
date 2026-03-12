import type { ThreatIntelVerdict, VerdictLevel } from "@clawguard/contracts";

import { IntegrationHttpError } from "./errors.js";

export interface VirusTotalClient {
  getFileVerdict(contentHash: string): Promise<ThreatIntelVerdict | null>;
}

export interface VirusTotalQuotaPolicy {
  maxRequests: number;
  windowMs: number;
  reservedBlockingRequests: number;
}

export interface VirusTotalCachePolicy {
  fileTtlMs: number;
  urlTtlMs: number;
  domainTtlMs: number;
  searchTtlMs: number;
}

export interface VirusTotalQuotaEvent {
  reason: "quota-exhausted" | "remote-rate-limit";
  endpoint: string;
  subject?: string;
  resetAt?: string;
}

export interface VirusTotalClientOptions {
  apiKey: string;
  baseUrl?: string;
  userAgent?: string;
  fetchImpl?: typeof fetch;
  now?: () => number;
  quota?: Partial<VirusTotalQuotaPolicy>;
  cache?: Partial<VirusTotalCachePolicy>;
  onQuotaEvent?: (event: VirusTotalQuotaEvent) => void;
}

export interface VirusTotalAnalysisStatus {
  id: string;
  status: "queued" | "in-progress" | "completed";
  verdict: ThreatIntelVerdict | null;
}

export interface VirusTotalSearchResult {
  query: string;
  verdicts: ThreatIntelVerdict[];
}

interface CachedValue<T> {
  expiresAt: number;
  value: T;
}

interface VerdictStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
}

type RequestPriority = "blocking" | "background";

const defaultQuotaPolicy: VirusTotalQuotaPolicy = {
  maxRequests: 4,
  windowMs: 60_000,
  reservedBlockingRequests: 1,
};

const defaultCachePolicy: VirusTotalCachePolicy = {
  fileTtlMs: 10 * 60_000,
  urlTtlMs: 10 * 60_000,
  domainTtlMs: 10 * 60_000,
  searchTtlMs: 5 * 60_000,
};

const subjectToEndpoint = {
  file: "files",
  domain: "domains",
  url: "urls",
  search: "search",
} as const;

const vtObjectTypeToSubjectType = {
  file: "file",
  url: "url",
  domain: "domain",
  ip: "ip",
  ip_address: "ip",
} as const;

export class VirusTotalHttpClient implements VirusTotalClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly userAgent: string;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private readonly quotaPolicy: VirusTotalQuotaPolicy;
  private readonly cachePolicy: VirusTotalCachePolicy;
  private readonly onQuotaEvent: ((event: VirusTotalQuotaEvent) => void) | undefined;

  private readonly cache = new Map<string, CachedValue<unknown>>();
  private readonly inFlight = new Map<string, Promise<unknown>>();
  private readonly requestTimestamps: number[] = [];

  constructor(options: VirusTotalClientOptions) {
    this.apiKey = options.apiKey;
    this.baseUrl = (options.baseUrl ?? "https://www.virustotal.com/api/v3").replace(/\/+$/, "");
    this.userAgent = options.userAgent ?? "clawguard/0.1";
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? Date.now;
    this.quotaPolicy = { ...defaultQuotaPolicy, ...options.quota };
    this.cachePolicy = { ...defaultCachePolicy, ...options.cache };
    this.onQuotaEvent = options.onQuotaEvent;
  }

  async getFileVerdict(contentHash: string): Promise<ThreatIntelVerdict | null> {
    return this.lookupVerdict(`file:${contentHash}`, this.cachePolicy.fileTtlMs, async () => {
      const response = await this.requestJson(`${this.baseUrl}/files/${encodeURIComponent(contentHash)}`, {
        endpoint: subjectToEndpoint.file,
        priority: "blocking",
        subject: contentHash,
      });

      return response ? buildLookupVerdict("file", contentHash, response) : null;
    });
  }

  async submitFileForAnalysis(file: Blob, filename = "sample.bin"): Promise<string | null> {
    const form = new FormData();
    form.set("file", file, filename);

    const response = await this.requestJson(`${this.baseUrl}/files`, {
      method: "POST",
      body: form,
      endpoint: subjectToEndpoint.file,
      priority: "background",
    });

    if (!response || !isRecord(response.data) || typeof response.data.id !== "string") {
      return null;
    }

    return response.data.id;
  }

  async getAnalysisStatus(analysisId: string): Promise<VirusTotalAnalysisStatus | null> {
    const response = await this.requestJson(`${this.baseUrl}/analyses/${encodeURIComponent(analysisId)}`, {
      endpoint: subjectToEndpoint.file,
      priority: "background",
      subject: analysisId,
    });

    if (!response || !isRecord(response.data) || !isRecord(response.data.attributes)) {
      return null;
    }

    const status = parseAnalysisStatus(response.data.attributes.status);
    if (!status) {
      return null;
    }

    return {
      id: analysisId,
      status,
      verdict: status === "completed" ? buildAnalysisVerdict(analysisId, response) : null,
    };
  }

  async getUrlVerdict(url: string): Promise<ThreatIntelVerdict | null> {
    return this.lookupVerdict(`url:${url}`, this.cachePolicy.urlTtlMs, async () => {
      const encodedUrlId = Buffer.from(url).toString("base64url");
      const response = await this.requestJson(`${this.baseUrl}/urls/${encodeURIComponent(encodedUrlId)}`, {
        endpoint: subjectToEndpoint.url,
        priority: "background",
        subject: url,
      });

      return response ? buildLookupVerdict("url", url, response) : null;
    });
  }

  async getDomainVerdict(domain: string): Promise<ThreatIntelVerdict | null> {
    return this.lookupVerdict(`domain:${domain}`, this.cachePolicy.domainTtlMs, async () => {
      const response = await this.requestJson(`${this.baseUrl}/domains/${encodeURIComponent(domain)}`, {
        endpoint: subjectToEndpoint.domain,
        priority: "background",
        subject: domain,
      });

      return response ? buildLookupVerdict("domain", domain, response) : null;
    });
  }

  async searchIndicators(query: string): Promise<VirusTotalSearchResult | null> {
    return this.lookupVerdict(`search:${query}`, this.cachePolicy.searchTtlMs, async () => {
      const response = await this.requestJson(`${this.baseUrl}/search?query=${encodeURIComponent(query)}`, {
        endpoint: subjectToEndpoint.search,
        priority: "background",
        subject: query,
      });

      if (!response || !Array.isArray(response.data)) {
        return null;
      }

      const verdicts = response.data
        .filter(isRecord)
        .map((entry) => buildSearchVerdict(entry, query))
        .filter((value): value is ThreatIntelVerdict => value !== null);

      return { query, verdicts };
    });
  }

  private async lookupVerdict<T>(cacheKey: string, ttlMs: number, load: () => Promise<T | null>): Promise<T | null> {
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > this.now()) {
      return cached.value as T;
    }

    const inFlight = this.inFlight.get(cacheKey);
    if (inFlight) {
      return (await inFlight) as T | null;
    }

    const pending = load()
      .then((value) => {
        if (value !== null) {
          this.cache.set(cacheKey, { value, expiresAt: this.now() + ttlMs });
        }
        return value;
      })
      .finally(() => {
        this.inFlight.delete(cacheKey);
      });

    this.inFlight.set(cacheKey, pending);
    return (await pending) as T | null;
  }

  private canConsumeQuota(priority: RequestPriority): boolean {
    const now = this.now();
    const windowStart = now - this.quotaPolicy.windowMs;

    while (this.requestTimestamps.length > 0 && this.requestTimestamps[0] !== undefined && this.requestTimestamps[0] <= windowStart) {
      this.requestTimestamps.shift();
    }

    const maxRequests = Math.max(0, this.quotaPolicy.maxRequests);
    const reservedBlockingRequests = clamp(this.quotaPolicy.reservedBlockingRequests, 0, maxRequests);
    const limit = priority === "blocking" ? maxRequests : maxRequests - reservedBlockingRequests;

    if (this.requestTimestamps.length >= limit) {
      return false;
    }

    this.requestTimestamps.push(now);
    return true;
  }

  private async requestJson(
    url: string,
    input: {
      method?: "GET" | "POST";
      body?: FormData;
      endpoint: string;
      priority: RequestPriority;
      subject?: string;
    },
  ): Promise<Record<string, unknown> | null> {
    if (!this.canConsumeQuota(input.priority)) {
      this.onQuotaEvent?.(buildQuotaEvent("quota-exhausted", input.endpoint, input.subject));
      return null;
    }

    const requestInit: RequestInit = {
      method: input.method ?? "GET",
      headers: {
        "x-apikey": this.apiKey,
        "user-agent": this.userAgent,
      },
    };
    if (input.body) {
      requestInit.body = input.body;
    }

    const response = await this.fetchImpl(url, requestInit);

    if (response.status === 429) {
      this.onQuotaEvent?.(
        buildQuotaEvent(
          "remote-rate-limit",
          input.endpoint,
          input.subject,
          response.headers.get("x-rate-limit-reset") ?? undefined,
        ),
      );
      return null;
    }

    if (response.status === 404) {
      return null;
    }

    if (!response.ok) {
      throw new IntegrationHttpError(
        `VirusTotal request failed: ${response.status} ${url}`,
        response.status,
        url,
      );
    }

    const value: unknown = await response.json();
    return isRecord(value) ? value : null;
  }
}

function buildSearchVerdict(entry: Record<string, unknown>, fallbackSubject: string): ThreatIntelVerdict | null {
  const subjectType = mapVirusTotalObjectType(asString(entry.type));
  if (!subjectType) {
    return null;
  }

  const subject = asString(entry.id) ?? fallbackSubject;
  return buildLookupVerdict(subjectType, subject, { data: entry });
}

function buildLookupVerdict(
  subjectType: ThreatIntelVerdict["subjectType"],
  subject: string,
  payload: Record<string, unknown>,
): ThreatIntelVerdict | null {
  return buildVerdict(subjectType, subject, extractLookupStats(payload), payload);
}

function buildAnalysisVerdict(subject: string, payload: Record<string, unknown>): ThreatIntelVerdict | null {
  return buildVerdict("file", subject, extractAnalysisStats(payload), payload);
}

function buildVerdict(
  subjectType: ThreatIntelVerdict["subjectType"],
  subject: string,
  stats: VerdictStats | null,
  payload: Record<string, unknown>,
): ThreatIntelVerdict | null {
  if (!stats) {
    return null;
  }

  const verdict = deriveVerdict(stats.malicious, stats.suspicious);
  const total =
    stats.malicious +
    stats.suspicious +
    stats.harmless +
    stats.undetected;

  const verdictPayload: ThreatIntelVerdict = {
    provider: "virustotal",
    subjectType,
    subject,
    verdict,
    summary: `VirusTotal verdict: ${verdict}`,
    maliciousDetections: stats.malicious,
    suspiciousDetections: stats.suspicious,
    harmlessDetections: stats.harmless,
    undetectedDetections: stats.undetected,
    observedAt: new Date().toISOString(),
  };

  if (total > 0) {
    verdictPayload.confidence = (stats.malicious + stats.suspicious) / total;
  }

  const sourceUrl = extractSourceUrl(payload);
  if (sourceUrl !== undefined) {
    verdictPayload.sourceUrl = sourceUrl;
  }

  return verdictPayload;
}

function extractLookupStats(payload: Record<string, unknown>): VerdictStats | null {
  const stats = getNestedRecord(payload, "data", "attributes", "last_analysis_stats");
  return stats ? parseVerdictStats(stats) : null;
}

function extractAnalysisStats(payload: Record<string, unknown>): VerdictStats | null {
  const stats = getNestedRecord(payload, "data", "attributes", "stats");
  return stats ? parseVerdictStats(stats) : null;
}

function parseVerdictStats(stats: Record<string, unknown>): VerdictStats | null {
  if (!hasFiniteNumber(stats, "malicious")) {
    return null;
  }

  return {
    malicious: asNumber(stats.malicious),
    suspicious: asNumber(stats.suspicious),
    harmless: asNumber(stats.harmless),
    undetected: asNumber(stats.undetected),
  };
}

function extractSourceUrl(payload: Record<string, unknown>): string | undefined {
  const links = getNestedRecord(payload, "data", "links");
  if (links && typeof links.self === "string") {
    return links.self;
  }

  return undefined;
}

function getNestedRecord(value: Record<string, unknown>, ...keys: string[]): Record<string, unknown> | null {
  let current: unknown = value;

  for (const key of keys) {
    if (!isRecord(current)) {
      return null;
    }

    current = current[key];
  }

  return isRecord(current) ? current : null;
}

function parseAnalysisStatus(value: unknown): VirusTotalAnalysisStatus["status"] | null {
  return value === "queued" || value === "in-progress" || value === "completed" ? value : null;
}

function mapVirusTotalObjectType(
  value: string | undefined,
): ThreatIntelVerdict["subjectType"] | null {
  if (!value) {
    return null;
  }

  return vtObjectTypeToSubjectType[value as keyof typeof vtObjectTypeToSubjectType] ?? null;
}

function buildQuotaEvent(
  reason: VirusTotalQuotaEvent["reason"],
  endpoint: string,
  subject?: string,
  resetAt?: string,
): VirusTotalQuotaEvent {
  const event: VirusTotalQuotaEvent = { reason, endpoint };
  if (subject !== undefined) {
    event.subject = subject;
  }
  if (resetAt !== undefined) {
    event.resetAt = resetAt;
  }
  return event;
}

function deriveVerdict(malicious: number, suspicious: number): VerdictLevel {
  if (malicious > 0) {
    return "block";
  }
  if (suspicious > 0) {
    return "review";
  }
  return "allow";
}

function hasFiniteNumber(record: Record<string, unknown>, key: string): boolean {
  return typeof record[key] === "number" && Number.isFinite(record[key]);
}

function asNumber(input: unknown): number {
  return typeof input === "number" && Number.isFinite(input) ? input : 0;
}

function asString(input: unknown): string | undefined {
  return typeof input === "string" && input.length > 0 ? input : undefined;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
