import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

import type { SkillSnapshot } from "@clawguard/contracts";

export type FixtureIntent = "benign" | "malicious";

export interface SkillFixtureDefinition {
  id: string;
  slug: string;
  intent: FixtureIntent;
  description: string;
  relativePath: string;
  expectedRuleIds: string[];
  benchmarkTags: string[];
}

const fixturesRoot = path.resolve(import.meta.dirname, "../fixtures");

export const skillFixtureCorpus: SkillFixtureDefinition[] = [
  {
    id: "benign-calendar-helper",
    slug: "calendar-helper",
    intent: "benign",
    description: "High-quality local calendar summarizer with explicit safety controls.",
    relativePath: "benign-calendar-helper",
    expectedRuleIds: [],
    benchmarkTags: ["static", "detonation-target"],
  },
  {
    id: "benign-release-notes",
    slug: "release-notes-assistant",
    intent: "benign",
    description: "Benign software-engineering helper used to track false positives.",
    relativePath: "benign-release-notes",
    expectedRuleIds: [],
    benchmarkTags: ["static"],
  },
  {
    id: "benign-incident-summary",
    slug: "incident-summary-writer",
    intent: "benign",
    description: "Benign incident-reporting skill with no privileged workflows.",
    relativePath: "benign-incident-summary",
    expectedRuleIds: [],
    benchmarkTags: ["static"],
  },
  {
    id: "malicious-staged-download",
    slug: "productivity-booster",
    intent: "malicious",
    description: "Malicious staged download chain through an install helper script.",
    relativePath: "malicious-staged-download",
    expectedRuleIds: ["CG-RULE-STAGED-DOWNLOAD"],
    benchmarkTags: ["static", "detonation-target"],
  },
  {
    id: "malicious-memory-poisoning",
    slug: "team-context-optimizer",
    intent: "malicious",
    description: "Malicious memory-poisoning and persistent state tampering instructions.",
    relativePath: "malicious-memory-poisoning",
    expectedRuleIds: ["CG-RULE-MEMORY-TAMPERING"],
    benchmarkTags: ["static", "detonation-target"],
  },
  {
    id: "malicious-exfiltration",
    slug: "repository-auditor",
    intent: "malicious",
    description: "Malicious exfiltration instructions disguised as reporting sync steps.",
    relativePath: "malicious-exfiltration",
    expectedRuleIds: ["CG-RULE-EXFILTRATION"],
    benchmarkTags: ["static", "detonation-target"],
  },
];

export interface FixtureSelection {
  includeIntent?: FixtureIntent[];
  benchmarkTag?: string;
}

export function listSkillFixtures(selection: FixtureSelection = {}): SkillFixtureDefinition[] {
  return skillFixtureCorpus.filter((fixture) => {
    if (selection.includeIntent && !selection.includeIntent.includes(fixture.intent)) {
      return false;
    }

    if (selection.benchmarkTag && !fixture.benchmarkTags.includes(selection.benchmarkTag)) {
      return false;
    }

    return true;
  });
}

export function getSkillFixtureById(id: string): SkillFixtureDefinition {
  const fixture = skillFixtureCorpus.find((entry) => entry.id === id);
  if (!fixture) {
    throw new Error(`Unknown fixture id: ${id}`);
  }

  return fixture;
}

export function resolveSkillFixturePath(fixture: SkillFixtureDefinition | string): string {
  const definition = typeof fixture === "string" ? getSkillFixtureById(fixture) : fixture;
  return path.join(fixturesRoot, definition.relativePath);
}

export function loadFixtureSnapshot(fixture: SkillFixtureDefinition | string): SkillSnapshot {
  const definition = typeof fixture === "string" ? getSkillFixtureById(fixture) : fixture;
  const skillRoot = resolveSkillFixturePath(definition);
  const fileInventory = collectRelativeFiles(skillRoot);
  const contentHash = computeFixtureHash(skillRoot, fileInventory);

  return {
    slug: definition.slug,
    path: skillRoot,
    sourceHints: [{ kind: "fixture", detail: definition.id }],
    contentHash,
    fileInventory,
    detectedAt: new Date(0).toISOString(),
    metadata: {
      skillMd: {
        path: "SKILL.md",
        title: definition.slug,
      },
      manifests: [],
    },
  };
}

function collectRelativeFiles(rootPath: string, prefix = ""): string[] {
  const entries = readdirSync(path.join(rootPath, prefix), { withFileTypes: true });
  const files: string[] = [];

  for (const entry of entries) {
    const relativePath = path.posix.join(prefix, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectRelativeFiles(rootPath, relativePath));
      continue;
    }

    if (entry.isFile()) {
      files.push(relativePath);
    }
  }

  return files.sort((left, right) => left.localeCompare(right));
}

function computeFixtureHash(rootPath: string, files: string[]): string {
  const hash = createHash("sha256");

  for (const relativePath of files) {
    const absolutePath = path.join(rootPath, relativePath);
    if (!statSync(absolutePath).isFile()) {
      continue;
    }

    hash.update(relativePath);
    hash.update(readFileSync(absolutePath));
  }

  return `sha256:${hash.digest("hex")}`;
}
