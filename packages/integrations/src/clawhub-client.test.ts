import test from "node:test";
import assert from "node:assert/strict";
import { HttpClawHubClient } from "./clawhub-client.js";

test("getSkill returns neutral verdicts when provider verdict fields are absent", async () => {
  const client = new HttpClawHubClient({
    baseUrl: "https://clawhub.test",
    fetchImpl: async () =>
      new Response(JSON.stringify({ slug: "safe-skill", name: "Safe skill" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  });

  const result = await client.getSkill("safe-skill");
  assert.ok(result);
  assert.equal(result.clawHubVerdict.verdict, "unknown");
  assert.equal(result.virusTotalVerdict.verdict, "unknown");
});

test("getSkill extracts explicit provider verdicts", async () => {
  const client = new HttpClawHubClient({
    baseUrl: "https://clawhub.test",
    fetchImpl: async () =>
      new Response(
        JSON.stringify({
          slug: "risky",
          verdicts: {
            clawhub: { verdict: "review", summary: "Needs review", confidence: 70 },
            virustotal: { verdict: "block", summary: "Known malware", maliciousDetections: 12 },
          },
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" },
        },
      ),
  });

  const result = await client.getSkill("risky");
  assert.ok(result);
  assert.equal(result.clawHubVerdict.verdict, "review");
  assert.equal(result.virusTotalVerdict.verdict, "block");
  assert.equal(result.virusTotalVerdict.maliciousDetections, 12);
});

test("getSkill returns null for text/plain 404 responses", async () => {
  const client = new HttpClawHubClient({
    baseUrl: "https://clawhub.test",
    fetchImpl: async () =>
      new Response("Skill not found", {
        status: 404,
        headers: { "content-type": "text/plain; charset=utf-8" },
      }),
  });

  const result = await client.getSkill("missing-skill");
  assert.equal(result, null);
});

test("getSkillMarkdown requests remote SKILL.md and returns content", async () => {
  let calledUrl = "";
  const client = new HttpClawHubClient({
    baseUrl: "https://clawhub.test",
    fetchImpl: async (input) => {
      calledUrl = String(input);
      return new Response("# Remote SKILL", {
        status: 200,
        headers: { "content-type": "text/markdown" },
      });
    },
  });

  const markdown = await client.getSkillMarkdown("demo");
  assert.equal(markdown, "# Remote SKILL");
  assert.match(calledUrl, /\/api\/v1\/skills\/demo\/file\?path=SKILL\.md$/);
});

test("listSkills supports sorting endpoint", async () => {
  let calledUrl = "";
  const client = new HttpClawHubClient({
    baseUrl: "https://clawhub.test",
    fetchImpl: async (input) => {
      calledUrl = String(input);
      return new Response(
        JSON.stringify([
          { slug: "first", name: "First" },
          { slug: "second", description: "Second skill" },
          { name: "missing-slug" },
        ]),
        {
          status: 200,
          headers: { "content-type": "application/json" },
        },
      );
    },
  });

  const entries = await client.listSkills("trending");
  assert.equal(entries.length, 2);
  assert.deepEqual(entries[0], { slug: "first", name: "First" });
  assert.match(calledUrl, /\/api\/v1\/skills\?sort=trending$/);
});
