import type { ThreatIntelVerdict, VerdictLevel } from "@clawguard/contracts";

export interface VirusTotalQuotaPolicy {
  maxRequests: number;
  windowMs: number;
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
  status: "queued" | "running" | "completed";
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

const defaultQuotaPolicy: VirusTotalQuotaPolicy = {
  maxRequests: 4,
  windowMs: 60_000,
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

export class VirusTotalHttpClient {
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
    this.baseUrl = options.baseUrl ?? "https://www.virustotal.com/api/v3";
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
        subject: contentHash,
      });

      if (!response) {
        return null;
      }

      return buildVerdict("file", contentHash, response);
    });
  }

  async submitFileForAnalysis(file: Blob, filename = "sample.bin"): Promise<string | null> {
    const form = new FormData();
    form.set("file", file, filename);

    const response = await this.requestJson(`${this.baseUrl}/files`, {
      method: "POST",
      body: form,
      endpoint: subjectToEndpoint.file,
    });

    if (!response || !isRecord(response.data) || typeof response.data.id !== "string") {
      return null;
    }

    return response.data.id;
  }

  async getAnalysisStatus(analysisId: string): Promise<VirusTotalAnalysisStatus | null> {
    const response = await this.requestJson(`${this.baseUrl}/analyses/${encodeURIComponent(analysisId)}`, {
      endpoint: subjectToEndpoint.file,
      subject: analysisId,
    });

    if (!response || !isRecord(response.data) || !isRecord(response.data.attributes)) {
      return null;
    }

    const attributes = response.data.attributes;
    const status =
      attributes.status === "completed" ? "completed" : attributes.status === "running" ? "running" : "queued";

    return {
      id: analysisId,
      status,
      verdict: status === "completed" ? buildVerdict("file", analysisId, response) : null,
    };
  }

  async getUrlVerdict(url: string): Promise<ThreatIntelVerdict | null> {
    return this.lookupVerdict(`url:${url}`, this.cachePolicy.urlTtlMs, async () => {
      const encodedUrlId = Buffer.from(url).toString("base64url");
      const response = await this.requestJson(`${this.baseUrl}/urls/${encodeURIComponent(encodedUrlId)}`, {
        endpoint: subjectToEndpoint.url,
        subject: url,
      });

      if (!response) {
        return null;
      }

      return buildVerdict("url", url, response);
    });
  }

  async getDomainVerdict(domain: string): Promise<ThreatIntelVerdict | null> {
    return this.lookupVerdict(`domain:${domain}`, this.cachePolicy.domainTtlMs, async () => {
      const response = await this.requestJson(`${this.baseUrl}/domains/${encodeURIComponent(domain)}`, {
        endpoint: subjectToEndpoint.domain,
        subject: domain,
      });

      if (!response) {
        return null;
      }

      return buildVerdict("domain", domain, response);
    });
  }

  async searchIndicators(query: string): Promise<VirusTotalSearchResult | null> {
    const cacheKey = `search:${query}`;
    return this.lookupVerdict(cacheKey, this.cachePolicy.searchTtlMs, async () => {
      const response = await this.requestJson(`${this.baseUrl}/search?query=${encodeURIComponent(query)}`, {
        endpoint: subjectToEndpoint.search,
        subject: query,
      });

      if (!response || !Array.isArray(response.data)) {
        return null;
      }

      const verdicts = response.data
        .filter(isRecord)
        .map((entry) => {
          const id = typeof entry.id === "string" ? entry.id : query;
          return buildVerdict("file", id, { data: entry });
        })
        .filter((value): value is ThreatIntelVerdict => value !== null);

      return { query, verdicts };
    });
  }

  private async lookupVerdict<T>(cacheKey: string, ttlMs: number, load: () => Promise<T>): Promise<T> {
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > this.now()) {
      return cached.value as T;
    }

    const inFlight = this.inFlight.get(cacheKey);
    if (inFlight) {
      return (await inFlight) as T;
    }

    const pending = load()
      .then((value) => {
        this.cache.set(cacheKey, { value, expiresAt: this.now() + ttlMs });
        return value;
      })
      .finally(() => {
        this.inFlight.delete(cacheKey);
      });

    this.inFlight.set(cacheKey, pending);
    return (await pending) as T;
  }

  private canConsumeQuota(): boolean {
    const now = this.now();
    const windowStart = now - this.quotaPolicy.windowMs;

    while (this.requestTimestamps.length > 0 && this.requestTimestamps[0] !== undefined && this.requestTimestamps[0] <= windowStart) {
      this.requestTimestamps.shift();
    }

    if (this.requestTimestamps.length >= this.quotaPolicy.maxRequests) {
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
      subject?: string;
    },
  ): Promise<Record<string, unknown> | null> {
    if (!this.canConsumeQuota()) {
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
      throw new Error(`VirusTotal request failed with status ${response.status}`);
    }

    const value: unknown = await response.json();
    return isRecord(value) ? value : null;
  }
}

function buildVerdict(
  subjectType: ThreatIntelVerdict["subjectType"],
  subject: string,
  payload: Record<string, unknown>,
): ThreatIntelVerdict | null {
  if (!isRecord(payload.data) || !isRecord(payload.data.attributes)) {
    return null;
  }

  const stats = isRecord(payload.data.attributes.last_analysis_stats)
    ? payload.data.attributes.last_analysis_stats
    : undefined;

  const malicious = asNumber(stats?.malicious);
  const suspicious = asNumber(stats?.suspicious);
  const harmless = asNumber(stats?.harmless);
  const undetected = asNumber(stats?.undetected);

  const verdict = deriveVerdict(malicious, suspicious);
  const total = [malicious, suspicious, harmless, undetected].reduce((sum, value) => sum + value, 0);
  const confidence = total > 0 ? (malicious + suspicious) / total : undefined;

  const verdictPayload: ThreatIntelVerdict = {
    provider: "virustotal",
    subjectType,
    subject,
    verdict,
    summary: `VirusTotal verdict: ${verdict}`,
    maliciousDetections: malicious,
    suspiciousDetections: suspicious,
    harmlessDetections: harmless,
    undetectedDetections: undetected,
    observedAt: new Date().toISOString(),
  };

  if (confidence !== undefined) {
    verdictPayload.confidence = confidence;
  }

  const sourceUrl = asString(payload.data.links);
  if (sourceUrl !== undefined) {
    verdictPayload.sourceUrl = sourceUrl;
  }

  return verdictPayload;
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

function asNumber(input: unknown): number {
  return typeof input === "number" && Number.isFinite(input) ? input : 0;
}

function asString(input: unknown): string | undefined {
  if (typeof input === "string") {
    return input;
  }
  if (isRecord(input) && typeof input.self === "string") {
    return input.self;
  }
  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
