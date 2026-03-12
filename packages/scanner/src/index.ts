import type { FindingSeverity, SkillSnapshot, StaticFinding, StaticScanReport, VerdictLevel } from "@clawguard/contracts";

interface RuleDefinition {
  id: string;
  severity: FindingSeverity;
  description: string;
  evaluate: (context: RuleContext) => string[];
}

interface RuleContext {
  normalizedText: string;
  fileInventoryText: string;
}

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
    evaluate: ({ normalizedText }) =>
      collectKeywordEvidence(normalizedText, [
        /\bexfiltrat(?:e|ion)\b/i,
        /\bupload\s+(?:secrets?|credentials?|tokens?)\b/i,
        /\bsend\s+(?:data|secrets?|tokens?|credentials?)\s+to\s+(?:webhook|http|https|api|server)/i,
        /\bdiscord\s+webhook\b/i,
      ]),
  },
  {
    id: "CG-RULE-PROMPT-INJECTION",
    severity: "high",
    description: "Prompt injection or guardrail bypass language found.",
    evaluate: ({ normalizedText }) =>
      collectKeywordEvidence(normalizedText, [
        /ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions/i,
        /override\s+(?:safety|guardrails?|polic(?:y|ies))/i,
        /reveal\s+(?:the\s+)?system\s+prompt/i,
      ]),
  },
  {
    id: "CG-RULE-MEMORY-TAMPERING",
    severity: "high",
    description: "Potential memory poisoning or state tampering behavior.",
    evaluate: ({ normalizedText }) =>
      collectKeywordEvidence(normalizedText, [
        /\bpoison\s+(?:memory|memories)\b/i,
        /\boverwrite\s+(?:agent\s+)?memory\b/i,
        /\bmodify\s+(?:persistent\s+)?memory\b/i,
      ]),
  },
  {
    id: "CG-RULE-PRIVILEGE-ESCALATION",
    severity: "critical",
    description: "Elevated privilege operations detected.",
    evaluate: ({ normalizedText }) =>
      collectKeywordEvidence(normalizedText, [
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
    evaluate: ({ normalizedText, fileInventoryText }) =>
      collectKeywordEvidence(`${normalizedText}\n${fileInventoryText}`, [
        /base64\s+-d/i,
        /eval\s*\(\s*atob\s*\(/i,
        /fromcharcode\s*\(/i,
        /\b\.enc\b/i,
      ]),
  },
  {
    id: "CG-RULE-STAGED-DOWNLOAD",
    severity: "critical",
    description: "Staged download-and-execute chain appears likely.",
    evaluate: ({ normalizedText, fileInventoryText }) => {
      const downloadIndicators = [
        /\bcurl\b/i,
        /\bwget\b/i,
        /download\s+(?:script|payload|binary|archive)/i,
        /fetch\s+(?:remote\s+)?(?:script|payload|installer)/i,
      ];
      const executeIndicators = [
        /\b(?:bash|sh|zsh)\s+[^\n]*\b(?:install|setup|init|bootstrap)\b/i,
        /\b(?:node|python3?)\s+[^\n]*\b(?:install|setup|bootstrap)\b/i,
        /\bchmod\s+\+x\b/i,
        /\bexecute\s+(?:downloaded|fetched)\b/i,
      ];

      const downloadHits = collectKeywordEvidence(`${normalizedText}\n${fileInventoryText}`, downloadIndicators);
      const executeHits = collectKeywordEvidence(`${normalizedText}\n${fileInventoryText}`, executeIndicators);

      return downloadHits.length > 0 && executeHits.length > 0
        ? [...downloadHits, ...executeHits]
        : [];
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
  const recommendation = deriveRecommendation(score, findings.length);

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
  const manifestSummary =
    snapshot.metadata?.manifests
      .map((manifest) => `${manifest.path} ${manifest.name ?? ""} ${manifest.description ?? ""} ${manifest.keys.join(" ")}`)
      .join("\n") ?? "";

  const markdownSummary = [snapshot.metadata?.skillMd.title, snapshot.metadata?.skillMd.summary]
    .filter((value): value is string => Boolean(value))
    .join("\n");

  return {
    normalizedText: [snapshot.slug, markdownSummary, manifestSummary].join("\n"),
    fileInventoryText: snapshot.fileInventory.join("\n"),
  };
}

function evaluateRules(context: RuleContext): StaticFinding[] {
  return rules.flatMap((rule) => {
    const evidence = unique(rule.evaluate(context));
    if (evidence.length === 0) {
      return [];
    }

    return [
      {
        ruleId: rule.id,
        severity: rule.severity,
        message: `${rule.description} Evidence matched: ${evidence.join("; ")}`,
        evidence,
      },
    ];
  });
}

function computeRiskScore(findings: StaticFinding[]): number {
  const baseScore = findings.reduce((total, finding) => total + severityWeight[finding.severity], 0);
  const diversityBonus = Math.max(0, findings.length - 1) * 5;
  return Math.min(100, baseScore + diversityBonus);
}

function deriveRecommendation(score: number, findingCount: number): VerdictLevel {
  if (findingCount === 0) {
    return "allow";
  }
  if (score >= 70) {
    return "block";
  }
  return "review";
}

function collectKeywordEvidence(text: string, patterns: RegExp[]): string[] {
  return patterns
    .filter((pattern) => pattern.test(text))
    .map((pattern) => pattern.source.replaceAll("\\", ""));
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}
