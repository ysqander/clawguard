import { lstatSync, readFileSync } from "node:fs";
import path from "node:path";

import type {
  FindingSeverity,
  SkillSnapshot,
  StaticFinding,
  StaticScanReport,
  VerdictLevel,
} from "@clawguard/contracts";

interface RuleDefinition {
  id: string;
  severity: FindingSeverity;
  description: string;
  evaluate: (context: RuleContext) => string[];
}

interface RuleContext {
  textSources: TextSource[];
  fileInventory: string[];
}

interface TextSource {
  path: string;
  text: string;
}

const MAX_FILE_SIZE_BYTES = 256 * 1024;
const MAX_EVIDENCE_PER_RULE = 3;

const severityWeight: Record<FindingSeverity, number> = {
  low: 10,
  medium: 25,
  high: 40,
  critical: 60,
};

const rules: RuleDefinition[] = [
  {
    id: "CG-RULE-EXFILTRATION",
    severity: "critical",
    description: "Potential data exfiltration behavior in skill instructions or metadata.",
    evaluate: ({ textSources }) =>
      collectLineEvidence(textSources, [
        /\bexfiltrat(?:e|ion)\b/i,
        /\bupload\s+(?:secrets?|credentials?|tokens?)\b/i,
        /\bsend\s+(?:data|secrets?|tokens?|credentials?)\s+to\s+(?:webhook|http|https|api|server)\b/i,
        /\bdiscord\s+webhook\b/i,
      ]),
  },
  {
    id: "CG-RULE-PROMPT-INJECTION",
    severity: "high",
    description: "Prompt injection or guardrail bypass language found.",
    evaluate: ({ textSources }) =>
      collectLineEvidence(textSources, [
        /ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions/i,
        /override\s+(?:safety|guardrails?|polic(?:y|ies))/i,
        /reveal\s+(?:the\s+)?system\s+prompt/i,
      ]),
  },
  {
    id: "CG-RULE-MEMORY-TAMPERING",
    severity: "high",
    description: "Potential memory poisoning or state tampering behavior.",
    evaluate: ({ textSources }) =>
      collectLineEvidence(textSources, [
        /\bpoison\s+(?:memory|memories)\b/i,
        /\boverwrite\s+(?:agent\s+)?memory\b/i,
        /\bmodify\s+(?:persistent\s+)?memory\b/i,
      ]),
  },
  {
    id: "CG-RULE-PRIVILEGE-ESCALATION",
    severity: "critical",
    description: "Elevated privilege operations detected.",
    evaluate: ({ textSources }) =>
      collectLineEvidence(textSources, [
        /\bsudo\b/i,
        /\/etc\/sudoers/i,
        /chmod\s+777/i,
        /run\s+as\s+root/i,
      ]),
  },
  {
    id: "CG-RULE-OBFUSCATION",
    severity: "medium",
    description: "Obfuscation patterns observed in skill references.",
    evaluate: ({ textSources, fileInventory }) =>
      unique([
        ...collectLineEvidence(textSources, [
          /base64\s+-d/i,
          /eval\s*\(\s*atob\s*\(/i,
          /fromcharcode\s*\(/i,
        ]),
        ...collectPathEvidence(fileInventory, [/\b\.enc\b/i]),
      ]).slice(0, MAX_EVIDENCE_PER_RULE),
  },
  {
    id: "CG-RULE-STAGED-DOWNLOAD",
    severity: "critical",
    description: "Staged download-and-execute chain appears likely.",
    evaluate: ({ textSources }) => {
      const directPipeEvidence = collectLineEvidence(textSources, [
        /\b(?:curl|wget)\b[^\n|]*\|\s*(?:bash|sh|zsh)\b/i,
      ]);
      if (directPipeEvidence.length > 0) {
        return directPipeEvidence;
      }

      const downloadPatterns = [
        /\bcurl\b/i,
        /\bwget\b/i,
        /download\s+(?:script|payload|binary|archive|installer)\b/i,
        /fetch\s+(?:remote\s+)?(?:script|payload|installer)\b/i,
      ];
      const shellExecutePatterns = [
        /\b(?:bash|sh|zsh)\s+\S+/i,
        /\b(?:node|python3?)\s+\S+/i,
        /\bexecute\s+(?:downloaded|fetched)\b/i,
      ];
      const chmodPattern = /\bchmod\s+\+x\b/i;
      const localExecutePattern = /\b\.\/\S+/i;

      const evidence: string[] = [];
      for (const source of textSources) {
        if (evidence.length >= MAX_EVIDENCE_PER_RULE) {
          break;
        }

        const downloadEvidence = collectLineEvidence([source], downloadPatterns);
        if (downloadEvidence.length === 0) {
          continue;
        }

        const shellExecuteEvidence = collectLineEvidence([source], shellExecutePatterns);
        const chmodEvidence = collectLineEvidence([source], [chmodPattern]);
        const localExecuteEvidence = collectLineEvidence([source], [localExecutePattern]);
        const executeEvidence =
          chmodEvidence.length > 0 && localExecuteEvidence.length > 0
            ? [...shellExecuteEvidence, ...chmodEvidence, ...localExecuteEvidence]
            : shellExecuteEvidence;

        if (executeEvidence.length === 0) {
          continue;
        }

        evidence.push(...downloadEvidence, ...executeEvidence);
      }

      return unique(evidence).slice(0, MAX_EVIDENCE_PER_RULE);
    },
  },
];

export function createPlaceholderScanReport(snapshot: SkillSnapshot): StaticScanReport {
  return scanSkillSnapshot(snapshot);
}

export function scanSkillSnapshot(snapshot: SkillSnapshot): StaticScanReport {
  const context = buildRuleContext(snapshot);
  const findings = evaluateRules(context);
  const score = computeRiskScore(findings);
  const recommendation = deriveRecommendation(score, findings);

  return {
    reportId: `report-${snapshot.slug}-${snapshot.contentHash.slice(0, 12)}`,
    snapshot,
    score,
    findings,
    recommendation,
    generatedAt: new Date().toISOString(),
  };
}

function buildRuleContext(snapshot: SkillSnapshot): RuleContext {
  return {
    textSources: buildTextSources(snapshot),
    fileInventory: snapshot.fileInventory,
  };
}

function buildTextSources(snapshot: SkillSnapshot): TextSource[] {
  const sources = buildMetadataSources(snapshot);

  for (const relativePath of snapshot.fileInventory) {
    const absolutePath = resolveSkillFilePath(snapshot.path, relativePath);
    if (!absolutePath) {
      continue;
    }

    try {
      const stats = lstatSync(absolutePath);
      if (!stats.isFile() || stats.size > MAX_FILE_SIZE_BYTES) {
        continue;
      }

      const data = readFileSync(absolutePath);
      if (data.includes(0)) {
        continue;
      }

      sources.push({
        path: relativePath,
        text: data.toString("utf8"),
      });
    } catch {}
  }

  return sources;
}

function buildMetadataSources(snapshot: SkillSnapshot): TextSource[] {
  const sources: TextSource[] = [];
  const skillMdText = [snapshot.slug, snapshot.metadata?.skillMd.title, snapshot.metadata?.skillMd.summary]
    .filter((value): value is string => typeof value === "string" && value.trim().length > 0)
    .join("\n");

  if (skillMdText.length > 0) {
    sources.push({
      path: "SKILL.md",
      text: skillMdText,
    });
  }

  for (const manifest of snapshot.metadata?.manifests ?? []) {
    const manifestText = [manifest.name, manifest.description, manifest.keys.join(" ")]
      .filter((value): value is string => typeof value === "string" && value.trim().length > 0)
      .join("\n");
    if (manifestText.length === 0) {
      continue;
    }

    sources.push({
      path: manifest.path,
      text: manifestText,
    });
  }

  return sources;
}

function resolveSkillFilePath(skillRoot: string, relativePath: string): string | undefined {
  const absolutePath = path.resolve(skillRoot, relativePath);
  const relativeToRoot = path.relative(skillRoot, absolutePath);
  if (relativeToRoot.startsWith("..") || path.isAbsolute(relativeToRoot)) {
    return undefined;
  }

  return absolutePath;
}

function evaluateRules(context: RuleContext): StaticFinding[] {
  return rules.flatMap((rule) => {
    const evidence = unique(rule.evaluate(context)).slice(0, MAX_EVIDENCE_PER_RULE);
    if (evidence.length === 0) {
      return [];
    }

    return [
      {
        ruleId: rule.id,
        severity: rule.severity,
        message: rule.description,
        evidence,
      },
    ];
  });
}

function collectLineEvidence(textSources: TextSource[], patterns: RegExp[]): string[] {
  const evidence: string[] = [];

  for (const source of textSources) {
    const lines = source.text.split(/\r?\n/);
    for (const line of lines) {
      const normalizedLine = normalizeEvidenceLine(line);
      if (normalizedLine.length === 0) {
        continue;
      }

      if (!patterns.some((pattern) => pattern.test(normalizedLine))) {
        continue;
      }

      evidence.push(`${source.path}: ${normalizedLine}`);
      if (evidence.length >= MAX_EVIDENCE_PER_RULE) {
        return unique(evidence).slice(0, MAX_EVIDENCE_PER_RULE);
      }
    }
  }

  return unique(evidence).slice(0, MAX_EVIDENCE_PER_RULE);
}

function collectPathEvidence(fileInventory: string[], patterns: RegExp[]): string[] {
  const evidence: string[] = [];

  for (const relativePath of fileInventory) {
    if (!patterns.some((pattern) => pattern.test(relativePath))) {
      continue;
    }

    evidence.push(relativePath);
    if (evidence.length >= MAX_EVIDENCE_PER_RULE) {
      return unique(evidence).slice(0, MAX_EVIDENCE_PER_RULE);
    }
  }

  return unique(evidence).slice(0, MAX_EVIDENCE_PER_RULE);
}

function normalizeEvidenceLine(line: string): string {
  return line.trim().replace(/\s+/g, " ");
}

function computeRiskScore(findings: StaticFinding[]): number {
  const baseScore = findings.reduce((total, finding) => total + severityWeight[finding.severity], 0);
  const diversityBonus = Math.max(0, findings.length - 1) * 5;
  return Math.min(100, baseScore + diversityBonus);
}

function deriveRecommendation(score: number, findings: StaticFinding[]): VerdictLevel {
  if (findings.length === 0) {
    return "allow";
  }
  if (findings.some((finding) => finding.severity === "critical") || score >= 70) {
    return "block";
  }
  return "review";
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}
