import assert from "node:assert/strict";
import test from "node:test";

import { VirusTotalHttpClient } from "./virustotal-client.js";

test("getFileVerdict caches successful lookups", async () => {
  let calls = 0;

  const client = new VirusTotalHttpClient({
    apiKey: "test-key",
    fetchImpl: async () => {
      calls += 1;
      return new Response(
        JSON.stringify({
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
        }),
        { status: 200 },
      );
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
      return new Response(
        JSON.stringify({
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
        }),
        { status: 200 },
      );
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

test("quota exhaustion degrades cleanly and emits an event", async () => {
  const events: string[] = [];

  const client = new VirusTotalHttpClient({
    apiKey: "test-key",
    quota: { maxRequests: 1, windowMs: 1_000 },
    onQuotaEvent(event) {
      events.push(event.reason);
    },
    fetchImpl: async () => {
      return new Response(
        JSON.stringify({
          data: {
            attributes: {
              last_analysis_stats: {
                malicious: 0,
                suspicious: 0,
                harmless: 1,
                undetected: 10,
              },
            },
          },
        }),
        { status: 200 },
      );
    },
  });

  const first = await client.getDomainVerdict("example.com");
  const second = await client.getUrlVerdict("https://example.com/path");

  assert.equal(first?.verdict, "allow");
  assert.equal(second, null);
  assert.deepEqual(events, ["quota-exhausted"]);
});

test("submitFileForAnalysis and getAnalysisStatus support async upload flow", async () => {
  const client = new VirusTotalHttpClient({
    apiKey: "test-key",
    fetchImpl: async (url, init) => {
      if (url.toString().endsWith("/files") && init?.method === "POST") {
        return new Response(JSON.stringify({ data: { id: "analysis-123" } }), { status: 200 });
      }

      return new Response(
        JSON.stringify({
          data: {
            attributes: {
              status: "completed",
              last_analysis_stats: {
                malicious: 0,
                suspicious: 0,
                harmless: 20,
                undetected: 5,
              },
            },
          },
        }),
        { status: 200 },
      );
    },
  });

  const analysisId = await client.submitFileForAnalysis(new Blob(["sample"]), "sample.bin");
  const status = await client.getAnalysisStatus("analysis-123");

  assert.equal(analysisId, "analysis-123");
  assert.equal(status?.status, "completed");
  assert.equal(status?.verdict?.verdict, "allow");
});
