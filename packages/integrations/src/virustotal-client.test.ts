import assert from "node:assert/strict";
import test from "node:test";

import { IntegrationHttpError } from "./errors.js";
import { VirusTotalHttpClient } from "./virustotal-client.js";

function jsonResponse(body: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });
}

test("getFileVerdict caches successful lookups", async () => {
  let calls = 0;

  const client = new VirusTotalHttpClient({
    apiKey: "test-key",
    fetchImpl: async () => {
      calls += 1;
      return jsonResponse({
        data: {
          attributes: {
            last_analysis_stats: {
              malicious: 0,
              suspicious: 1,
              harmless: 4,
              undetected: 10,
            },
          },
        },
      });
    },
  });

  const first = await client.getFileVerdict("abc123");
  const second = await client.getFileVerdict("abc123");

  assert.equal(calls, 1);
  assert.equal(first?.verdict, "review");
  assert.equal(second?.verdict, "review");
});

test("getFileVerdict deduplicates in-flight requests", async () => {
  let calls = 0;

  const client = new VirusTotalHttpClient({
    apiKey: "test-key",
    fetchImpl: async () => {
      calls += 1;
      await new Promise((resolve) => setTimeout(resolve, 10));
      return jsonResponse({
        data: {
          attributes: {
            last_analysis_stats: {
              malicious: 1,
              suspicious: 0,
              harmless: 0,
              undetected: 0,
            },
          },
        },
      });
    },
  });

  const [a, b] = await Promise.all([
    client.getFileVerdict("def456"),
    client.getFileVerdict("def456"),
  ]);

  assert.equal(calls, 1);
  assert.equal(a?.verdict, "block");
  assert.equal(b?.verdict, "block");
});

test("getAnalysisStatus returns in-progress without a verdict", async () => {
  const client = new VirusTotalHttpClient({
    apiKey: "test-key",
    fetchImpl: async () =>
      jsonResponse({
        data: {
          attributes: {
            status: "in-progress",
            stats: {
              malicious: 0,
              suspicious: 1,
              harmless: 0,
              undetected: 0,
            },
          },
        },
      }),
  });

  const status = await client.getAnalysisStatus("analysis-123");

  assert.equal(status?.status, "in-progress");
  assert.equal(status?.verdict, null);
});

test("getAnalysisStatus reads analysis stats for completed uploads", async () => {
  const client = new VirusTotalHttpClient({
    apiKey: "test-key",
    fetchImpl: async () =>
      jsonResponse({
        data: {
          attributes: {
            status: "completed",
            stats: {
              malicious: 2,
              suspicious: 0,
              harmless: 8,
              undetected: 10,
            },
          },
        },
      }),
  });

  const status = await client.getAnalysisStatus("analysis-456");

  assert.equal(status?.status, "completed");
  assert.equal(status?.verdict?.verdict, "block");
  assert.equal(status?.verdict?.maliciousDetections, 2);
});

test("404 responses are not cached for later retries", async () => {
  let calls = 0;

  const client = new VirusTotalHttpClient({
    apiKey: "test-key",
    fetchImpl: async () => {
      calls += 1;
      if (calls === 1) {
        return jsonResponse({}, { status: 404 });
      }

      return jsonResponse({
        data: {
          attributes: {
            last_analysis_stats: {
              malicious: 0,
              suspicious: 0,
              harmless: 4,
              undetected: 8,
            },
          },
        },
      });
    },
  });

  const first = await client.getFileVerdict("retry-404");
  const second = await client.getFileVerdict("retry-404");

  assert.equal(first, null);
  assert.equal(second?.verdict, "allow");
  assert.equal(calls, 2);
});

test("quota exhaustion does not cache null results for later retries", async () => {
  let now = 0;
  let calls = 0;

  const client = new VirusTotalHttpClient({
    apiKey: "test-key",
    now: () => now,
    quota: { maxRequests: 1, windowMs: 100, reservedBlockingRequests: 0 },
    fetchImpl: async () => {
      calls += 1;
      return jsonResponse({
        data: {
          attributes: {
            last_analysis_stats: {
              malicious: 0,
              suspicious: 1,
              harmless: 2,
              undetected: 7,
            },
          },
        },
      });
    },
  });

  const first = await client.getDomainVerdict("warmup.example");
  const denied = await client.getDomainVerdict("retry.example");
  now = 101;
  const second = await client.getDomainVerdict("retry.example");

  assert.equal(first?.verdict, "review");
  assert.equal(denied, null);
  assert.equal(second?.verdict, "review");
  assert.equal(calls, 2);
});

test("remote rate limits do not cache null results for later retries", async () => {
  let calls = 0;
  const events: string[] = [];

  const client = new VirusTotalHttpClient({
    apiKey: "test-key",
    onQuotaEvent(event) {
      events.push(event.reason);
    },
    fetchImpl: async () => {
      calls += 1;
      if (calls === 1) {
        return jsonResponse({}, { status: 429, headers: { "x-rate-limit-reset": "123" } });
      }

      return jsonResponse({
        data: {
          attributes: {
            last_analysis_stats: {
              malicious: 1,
              suspicious: 0,
              harmless: 0,
              undetected: 4,
            },
          },
        },
      });
    },
  });

  const first = await client.getUrlVerdict("https://retry.example/path");
  const second = await client.getUrlVerdict("https://retry.example/path");

  assert.equal(first, null);
  assert.equal(second?.verdict, "block");
  assert.equal(calls, 2);
  assert.deepEqual(events, ["remote-rate-limit"]);
});

test("background requests respect the blocking reserve", async () => {
  const calledUrls: string[] = [];

  const client = new VirusTotalHttpClient({
    apiKey: "test-key",
    quota: { maxRequests: 2, windowMs: 1_000, reservedBlockingRequests: 1 },
    fetchImpl: async (input) => {
      calledUrls.push(String(input));
      return jsonResponse({
        data: {
          attributes: {
            last_analysis_stats: {
              malicious: 0,
              suspicious: 0,
              harmless: 3,
              undetected: 9,
            },
          },
        },
      });
    },
  });

  const firstBackground = await client.getDomainVerdict("example.com");
  const deniedBackground = await client.getUrlVerdict("https://example.com/path");
  const blockingLookup = await client.getFileVerdict("blocking-hash");

  assert.equal(firstBackground?.verdict, "allow");
  assert.equal(deniedBackground, null);
  assert.equal(blockingLookup?.verdict, "allow");
  assert.equal(calledUrls.length, 2);
  assert.match(calledUrls[0] ?? "", /\/domains\/example\.com$/);
  assert.match(calledUrls[1] ?? "", /\/files\/blocking-hash$/);
});

test("searchIndicators maps supported types and skips unsupported entries", async () => {
  const client = new VirusTotalHttpClient({
    apiKey: "test-key",
    fetchImpl: async () =>
      jsonResponse({
        data: [
          {
            id: "sha256-hash",
            type: "file",
            attributes: {
              last_analysis_stats: {
                malicious: 1,
                suspicious: 0,
                harmless: 0,
                undetected: 3,
              },
            },
          },
          {
            id: "url-id",
            type: "url",
            attributes: {
              last_analysis_stats: {
                malicious: 0,
                suspicious: 1,
                harmless: 2,
                undetected: 3,
              },
            },
          },
          {
            id: "example.com",
            type: "domain",
            attributes: {
              last_analysis_stats: {
                malicious: 0,
                suspicious: 0,
                harmless: 4,
                undetected: 5,
              },
            },
          },
          {
            id: "1.2.3.4",
            type: "ip_address",
            attributes: {
              last_analysis_stats: {
                malicious: 0,
                suspicious: 1,
                harmless: 1,
                undetected: 6,
              },
            },
          },
          {
            id: "comment-1",
            type: "comment",
            attributes: {},
          },
          {
            id: "unknown-type",
            type: "reference",
            attributes: {
              last_analysis_stats: {
                malicious: 3,
                suspicious: 0,
                harmless: 0,
                undetected: 0,
              },
            },
          },
        ],
      }),
  });

  const result = await client.searchIndicators("ioc-query");

  assert.ok(result);
  assert.equal(result.verdicts.length, 4);
  assert.deepEqual(
    result.verdicts.map((verdict) => [verdict.subjectType, verdict.verdict]),
    [
      ["file", "block"],
      ["url", "review"],
      ["domain", "allow"],
      ["ip", "review"],
    ],
  );
});

test("submitFileForAnalysis and getAnalysisStatus support async upload flow", async () => {
  const client = new VirusTotalHttpClient({
    apiKey: "test-key",
    fetchImpl: async (url, init) => {
      if (url.toString().endsWith("/files") && init?.method === "POST") {
        return jsonResponse({ data: { id: "analysis-123" } });
      }

      return jsonResponse({
        data: {
          attributes: {
            status: "completed",
            stats: {
              malicious: 0,
              suspicious: 0,
              harmless: 20,
              undetected: 5,
            },
          },
        },
      });
    },
  });

  const analysisId = await client.submitFileForAnalysis(new Blob(["sample"]), "sample.bin");
  const status = await client.getAnalysisStatus("analysis-123");

  assert.equal(analysisId, "analysis-123");
  assert.equal(status?.status, "completed");
  assert.equal(status?.verdict?.verdict, "allow");
});

test("non-404 and non-429 failures raise IntegrationHttpError", async () => {
  const client = new VirusTotalHttpClient({
    apiKey: "test-key",
    fetchImpl: async () => jsonResponse({ error: "boom" }, { status: 500 }),
  });

  await assert.rejects(
    () => client.getFileVerdict("fatal-hash"),
    (error: unknown) => error instanceof IntegrationHttpError && error.status === 500,
  );
});
