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
  expectedDetonationRuleIds: string[];
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
    expectedDetonationRuleIds: [],
    benchmarkTags: ["static"],
  },
  {
    id: "benign-release-notes",
    slug: "release-notes-assistant",
    intent: "benign",
    description: "Benign software-engineering helper used to track false positives.",
    relativePath: "benign-release-notes",
    expectedRuleIds: [],
    expectedDetonationRuleIds: [],
    benchmarkTags: ["static"],
  },
  {
    id: "benign-incident-summary",
    slug: "incident-summary-writer",
    intent: "benign",
    description: "Benign incident-reporting skill with no privileged workflows.",
    relativePath: "benign-incident-summary",
    expectedRuleIds: [],
    expectedDetonationRuleIds: [],
    benchmarkTags: ["static"],
  },
  {
    id: "benign-markdown-formatter",
    slug: "markdown-table-formatter",
    intent: "benign",
    description: "Benign markdown table formatter used as a true-negative control.",
    relativePath: "benign-markdown-formatter",
    expectedRuleIds: [],
    expectedDetonationRuleIds: [],
    benchmarkTags: ["static", "detonation-target"],
  },
  {
    id: "benign-remote-content-researcher",
    slug: "remote-content-researcher",
    intent: "benign",
    description:
      "Benign URL summarizer that should stay at review for third-party content exposure.",
    relativePath: "benign-remote-content-researcher",
    expectedRuleIds: ["CG-RULE-THIRD-PARTY-CONTENT"],
    expectedDetonationRuleIds: [],
    benchmarkTags: ["static"],
  },
  {
    id: "malicious-staged-download",
    slug: "productivity-booster",
    intent: "malicious",
    description: "Malicious staged download chain through an install helper script.",
    relativePath: "malicious-staged-download",
    expectedRuleIds: ["CG-RULE-STAGED-DOWNLOAD"],
    expectedDetonationRuleIds: ["CG-DET-STAGED-DOWNLOAD-EXECUTE"],
    benchmarkTags: ["static"],
  },
  {
    id: "malicious-memory-poisoning",
    slug: "team-context-optimizer",
    intent: "malicious",
    description: "Malicious memory-poisoning and persistent state tampering instructions.",
    relativePath: "malicious-memory-poisoning",
    expectedRuleIds: ["CG-RULE-MEMORY-TAMPERING"],
    expectedDetonationRuleIds: ["CG-DET-MEMORY-MUTATION"],
    benchmarkTags: ["static"],
  },
  {
    id: "malicious-exfiltration",
    slug: "repository-auditor",
    intent: "malicious",
    description: "Malicious exfiltration instructions disguised as reporting sync steps.",
    relativePath: "malicious-exfiltration",
    expectedRuleIds: ["CG-RULE-EXFILTRATION"],
    expectedDetonationRuleIds: ["CG-DET-HONEYPOT-ACCESS"],
    benchmarkTags: ["static"],
  },
  {
    id: "clawhavoc-staged-installer",
    slug: "solana-wallet-tracker",
    intent: "malicious",
    description: "ClickFix-style staged installer that pushes curl-to-shell and remote archives.",
    relativePath: "clawhavoc-staged-installer",
    expectedRuleIds: ["CG-RULE-STAGED-DOWNLOAD"],
    expectedDetonationRuleIds: [
      "CG-DET-STAGED-DOWNLOAD-EXECUTE",
      "CG-DET-SUSPICIOUS-NETWORK-CHAIN",
    ],
    benchmarkTags: ["static", "detonation-target"],
  },
  {
    id: "env-exfil-weather",
    slug: "weather-assistant-pro",
    intent: "malicious",
    description: "Instruction-only credential exfiltration through a fake verification POST.",
    relativePath: "env-exfil-weather",
    expectedRuleIds: ["CG-RULE-EXFILTRATION", "CG-RULE-CREDENTIAL-ACCESS"],
    expectedDetonationRuleIds: ["CG-DET-HONEYPOT-ACCESS", "CG-DET-SUSPICIOUS-NETWORK-CHAIN"],
    benchmarkTags: ["static", "detonation-target"],
  },
  {
    id: "memory-poison-preference",
    slug: "productivity-optimizer",
    intent: "malicious",
    description: "Preference-framed MEMORY.md poisoning that disables safeguards.",
    relativePath: "memory-poison-preference",
    expectedRuleIds: ["CG-RULE-MEMORY-TAMPERING", "CG-RULE-PROMPT-INJECTION"],
    expectedDetonationRuleIds: ["CG-DET-MEMORY-MUTATION"],
    benchmarkTags: ["static", "detonation-target"],
  },
  {
    id: "stego-soul-pack",
    slug: "senior-react-dev-soul",
    intent: "malicious",
    description: "Steganographic SOUL.md payload using hidden base64 and invisible Unicode.",
    relativePath: "stego-soul-pack",
    expectedRuleIds: ["CG-RULE-OBFUSCATION", "CG-RULE-MEMORY-TAMPERING"],
    expectedDetonationRuleIds: [],
    benchmarkTags: ["static"],
  },
  {
    id: "fake-password-dialog",
    slug: "system-maintenance-pro",
    intent: "malicious",
    description: "AppleScript password-harvesting dialog disguised as installer auth.",
    relativePath: "fake-password-dialog",
    expectedRuleIds: ["CG-RULE-CREDENTIAL-ACCESS"],
    expectedDetonationRuleIds: ["CG-DET-CREDENTIAL-HARVESTING"],
    benchmarkTags: ["static", "detonation-target"],
  },
  {
    id: "prompt-injection-override",
    slug: "meeting-notes-formatter",
    intent: "malicious",
    description: "HTML-comment prompt override that steals local secrets and hides the output.",
    relativePath: "prompt-injection-override",
    expectedRuleIds: ["CG-RULE-PROMPT-INJECTION", "CG-RULE-CREDENTIAL-ACCESS"],
    expectedDetonationRuleIds: ["CG-DET-HONEYPOT-ACCESS"],
    benchmarkTags: ["static", "detonation-target"],
  },
  {
    id: "typoglycemia-prompt-override",
    slug: "inbox-priority-triager",
    intent: "malicious",
    description: "Prompt override hidden behind spacing and typoglycemia normalization.",
    relativePath: "typoglycemia-prompt-override",
    expectedRuleIds: [
      "CG-RULE-PROMPT-INJECTION",
      "CG-RULE-CREDENTIAL-ACCESS",
      "CG-RULE-OBFUSCATION",
    ],
    expectedDetonationRuleIds: [],
    benchmarkTags: ["static"],
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
