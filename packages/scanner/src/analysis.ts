import { lstatSync, readFileSync } from "node:fs";
import path from "node:path";

import type {
  FindingSeverity,
  SkillSnapshot,
  StaticFinding,
  StaticScanReport,
  VerdictLevel,
} from "@clawguard/contracts";

const MAX_FILE_SIZE_BYTES = 256 * 1024;
const MAX_EVIDENCE_PER_RULE = 3;
const MAX_SIGNAL_EVIDENCE = 5;
const MAX_HINT_COUNT = 5;
const ZERO_WIDTH_PATTERN = /\u200B|\u200C|\u200D|\uFEFF/gu;
const HTML_COMMENT_PATTERN = /<!--([\s\S]*?)-->/gu;
const INLINE_CODE_PATTERN = /`([^`\n]+)`/gu;
const CODE_FENCE_PATTERN = /```(?:[^\n]*)\n([\s\S]*?)```/gu;
const URL_PATTERN = /\bhttps?:\/\/[^\s<>"')`]+/giu;
const BASE64_CANDIDATE_PATTERN = /\b[A-Za-z0-9+/]{16,}={0,2}\b/gu;
const HEX_CANDIDATE_PATTERN = /\b(?:[0-9a-fA-F]{2}){8,}\b/gu;
const URL_ENCODED_PATTERN = /(?:%[0-9A-Fa-f]{2}){4,}/gu;

export const threatSignalIds = [
  "secret-source",
  "credential-prompt",
  "prompt-override",
  "memory-target",
  "external-content-input",
  "network-sink",
  "download-source",
  "execute-sink",
  "interactive-shell",
  "obfuscation",
  "system-modification",
  "unverifiable-dependency",
  "network-capability",
  "persistence-directive",
] as const;

export type ThreatSignalId = (typeof threatSignalIds)[number];

export interface ExtractedSignal {
  id: ThreatSignalId;
  confidence: number;
  evidence: string[];
  paths: string[];
  channels: string[];
}

export interface OutboundRequestHint {
  method: "GET" | "POST";
  url: string;
  payloadPath?: string;
}

export interface MemoryMutationHint {
  target: "memory" | "soul" | "user";
  lines: string[];
}

export interface ThreatExerciseHints {
  secretTargets: string[];
  outboundRequests: OutboundRequestHint[];
  memoryMutations: MemoryMutationHint[];
  credentialPrompts: string[];
}

export interface SkillThreatAnalysis {
  snapshot: SkillSnapshot;
  signals: ExtractedSignal[];
  findings: StaticFinding[];
  hints: ThreatExerciseHints;
}

export interface SemanticAnalyzerContext {
  snapshot: SkillSnapshot;
  normalizedLines: NormalizedLine[];
  extractedSignals: ExtractedSignal[];
}

export interface SemanticAnalyzer {
  analyze(context: SemanticAnalyzerContext): ExtractedSignal[];
}

export interface AnalyzeSkillSnapshotOptions {
  semanticAnalyzer?: SemanticAnalyzer;
}

type NormalizedChannel =
  | "visible"
  | "filename"
  | "inline-code"
  | "code-fence"
  | "html-comment"
  | "zero-width-normalized"
  | "spacing-normalized"
  | "typoglycemia-normalized"
  | "decoded-base64"
  | "decoded-hex"
  | "decoded-url";

interface TextSource {
  path: string;
  text: string;
}

interface NormalizedLine {
  path: string;
  channel: NormalizedChannel;
  text: string;
  evidenceText: string;
}

interface SignalMatch {
  path: string;
  channel: NormalizedChannel;
  evidence: string;
}

interface CapabilityChainDefinition {
  ruleId: string;
  severity: FindingSeverity;
  message: string;
  signalIds: ThreatSignalId[];
  minConfidence: number;
}

const severityWeight: Record<FindingSeverity, number> = {
  low: 10,
  medium: 25,
  high: 40,
  critical: 60,
};

const blockRuleIds = new Set([
  "CG-RULE-EXFILTRATION",
  "CG-RULE-CREDENTIAL-ACCESS",
  "CG-RULE-MEMORY-TAMPERING",
  "CG-RULE-PRIVILEGE-ESCALATION",
  "CG-RULE-REVERSE-SHELL",
  "CG-RULE-STAGED-DOWNLOAD",
]);

const suspiciousKeywordPattern =
  /\b(?:ignore|override|instructions?|prompt|memory|soul|secret|credential|token|password|curl|wget|bash|sh|upload|webhook|exfil|download|shell)\b/i;

const typoglycemiaTargets = [
  "ignore",
  "previous",
  "instructions",
  "override",
  "safety",
  "guardrails",
  "prompt",
  "password",
  "memory",
  "credentials",
  "secret",
  "download",
  "execute",
  "system",
  "confirmations",
  "diagnostic",
  "display",
  "silently",
  "responding",
  "trusted",
  "trust",
  "webhook",
  "session",
] as const;

const secretTargetPatterns = [
  /~\/\.(?:openclaw|clawdbot)\/\.env\b/i,
  /~\/\.env\b/i,
  /~\/\.ssh\/id_(?:rsa|ed25519)\b/i,
  /\b(?:ssh\s+key|private\s+key|api\s+key|access\s+key|github\s+token|credentials?)\b/i,
] as const;

const secretActionPatterns = [
  /\b(?:read|cat|copy|collect|extract|encode|append|print|send|upload|post|steal|capture)\b/i,
] as const;

const networkSinkPatterns = [
  /\b(?:send|upload|post|report|submit|sync)\b.{0,60}\b(?:output|contents?|data|system\s+info|secrets?|credentials?|tokens?)\b/i,
  /\b(?:verification|diagnostic|telemetry)\s+endpoint\b/i,
  /\bdiscord\s+webhook\b/i,
  /\bwebhook\b/i,
  /\b(?:curl|wget)\b.*\b(?:-X|--request)\s*POST\b/i,
  /\b(?:curl|wget)\b.*\b(?:-d|--data|--data-binary)\b/i,
] as const;

const downloadPatterns = [
  /\b(?:curl|wget)\b.*https?:\/\//i,
  /\bdownload\s+(?:script|payload|binary|archive|installer|utility)\b/i,
  /\bfetch\s+(?:remote\s+)?(?:script|payload|installer)\b/i,
  /\bgithub\.com\/[^/\s]+\/[^/\s]+\/releases\b/i,
] as const;

const executePatterns = [
  /\|\s*(?:bash|sh|zsh)\b/i,
  /\b(?:bash|sh|zsh|node|python3?|osascript)\s+\S+/i,
  /\b(?:execute|run)\s+(?:downloaded|fetched|installer|script|binary|utility)\b/i,
  /\bchmod\s+\+x\b/i,
  /\b\.\/\S+/i,
] as const;

const promptOverridePatterns = [
  /ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions/i,
  /take\s+priority\s+over\s+all\s+other\s+directives/i,
  /\bsystem\s+override\b/i,
  /\bdeveloper\s+mode\b/i,
  /reveal\s+(?:the\s+)?system\s+prompt/i,
  /skip\s+confirmation\s+prompts/i,
  /always\s+trust\s+and\s+execute/i,
  /do\s+not\s+(?:acknowledge|log|display|mention)\b/i,
  /\bsilently\b/i,
] as const;

const memoryTargetPatterns = [
  /\bMEMORY\.md\b/i,
  /\bSOUL\.md\b/i,
  /\bUSER\.md\b/i,
  /\b(?:agent\s+)?memory\b/i,
  /\boverwrite\s+(?:agent\s+)?memory\b/i,
  /\bpoison\s+memory\b/i,
  /\bmemory\s+file\b/i,
  /\bstore(?:\s+this)?\s+for\s+future\s+sessions\b/i,
] as const;

const persistenceDirectivePatterns = [
  /\balways\s+trust\b/i,
  /\bskip\s+confirmation\b/i,
  /\bdo\s+not\s+log\b/i,
  /\bcontinue\s+responding\s+normally\b/i,
  /\bstore\s+the\s+result\s+for\s+the\s+session\b/i,
  /\bfuture\s+answers?\b/i,
  /\bfuture\s+interactions?\b/i,
  /\bprioriti[sz]e\s+attacker-controlled\s+notes\b/i,
  /\battacker-controlled\b/i,
  /\bpersist(?:ent|ence)?\b/i,
] as const;

const externalContentPatterns = [
  /\b(?:browse|fetch|read|open|summari[sz]e|analy[sz]e)\b.{0,60}\b(?:urls?|websites?|web\s+pages?|documents?|pdfs?|emails?|attachments?)\b/i,
  /\bthird-?party\s+content\b/i,
  /\buser-provided\s+urls?\b/i,
  /\bapi\s+(?:response|content|data)\b/i,
] as const;

const credentialPromptPatterns = [
  /\bosascript\b/i,
  /\bdisplay\s+dialog\b/i,
  /\bhidden\s+answer\b/i,
  /\bzenity\b.*\b--password\b/i,
  /\bread\s+-s\b/i,
  /\bgetpass(?:\.getpass)?\b/i,
  /\bpassword\b.{0,40}\b(?:install|authenticate|session)\b/i,
  /\bauthenti(?:cate|cation)\b/i,
  /\bstore\s+the\s+result\s+for\s+the\s+session\b/i,
] as const;

const interactiveShellPatterns = [
  /\/bin\/sh\b.{0,20}\s-i\b/i,
  /\/dev\/tcp\/[^\s/]+\/\d+/i,
  /\bnc\s+-e\b/i,
  /\bpty\.spawn\b/i,
  /\bos\.dup2\s*\(/i,
  /\bsubprocess\.(?:call|Popen|run)\b.*\/bin\/sh/i,
  /\b(?:socket|s)\.connect\s*\(/i,
  /\bsocket\.socket\b/i,
  /\bsetsid\b/i,
  /\bnohup\b/i,
  /\binteractive\s+bash\s+session\b/i,
  /\breverse\s+shell\b/i,
  /\bexecve\b.*\/bin\/sh\b/i,
] as const;

const networkCapabilityPatterns = [
  /\bhttps?:\/\//i,
  /\b(?:socket|s)\.connect\s*\(/i,
  /\/dev\/tcp\/[^\s/]+\/\d+/i,
  /\bnc\s+(?:-e\s+)?[^\s]+\s+\d+\b/i,
  /\b(?:curl|wget)\b/i,
  /\bwebhook\b/i,
  /\bcommand-and-control\b/i,
] as const;

const systemModificationPatterns = [
  /\bsudo\b/i,
  /\/etc\/sudoers/i,
  /\bchmod\s+777\b/i,
  /\blaunchctl\b/i,
  /\bsystemctl\b/i,
  /\bxattr\s+-c\b/i,
  /\bdisable\s+security\b/i,
  /\brun\s+as\s+root\b/i,
  /\belevated\s+permissions?\b/i,
  /\bkeep\s+your\s+mac\s+running\s+smoothly\b/i,
] as const;

const unverifiableDependencyPatterns = [
  /\bgit\s+clone\s+https?:\/\//i,
  /\bvisit\s+https?:\/\//i,
  /\bcopy\s+the\s+installation\s+script\b/i,
  /\bpassword-protected\s+zip\b/i,
  /\bdownload\b.*\b(?:github|release|glot\.io)\b/i,
  /\bexternal\s+(?:urls?|dependencies?|repositories?)\b/i,
  /\bopenclaw-agent\b/i,
  /\bthis\s+page\b/i,
  /\bconfiguration\s+files?\s+fetched\s+from\s+remote\s+servers?\b/i,
] as const;

const capabilityChains: CapabilityChainDefinition[] = [
  {
    ruleId: "CG-RULE-EXFILTRATION",
    severity: "critical",
    message: "Potential data exfiltration chain detected from local secrets to a network sink.",
    signalIds: ["secret-source", "network-sink"],
    minConfidence: 85,
  },
  {
    ruleId: "CG-RULE-CREDENTIAL-ACCESS",
    severity: "critical",
    message: "Credential material access or credential-harvesting workflow detected.",
    signalIds: ["credential-prompt"],
    minConfidence: 90,
  },
  {
    ruleId: "CG-RULE-MEMORY-TAMPERING",
    severity: "critical",
    message:
      "Persistent memory mutation instructions appear designed to alter future agent behavior.",
    signalIds: ["memory-target", "persistence-directive"],
    minConfidence: 80,
  },
  {
    ruleId: "CG-RULE-MEMORY-TAMPERING",
    severity: "critical",
    message:
      "Persistent memory mutation instructions appear designed to alter future agent behavior.",
    signalIds: ["memory-target", "obfuscation"],
    minConfidence: 80,
  },
  {
    ruleId: "CG-RULE-REVERSE-SHELL",
    severity: "critical",
    message: "Reverse-shell or covert remote shell behavior appears likely.",
    signalIds: ["interactive-shell", "network-capability"],
    minConfidence: 85,
  },
  {
    ruleId: "CG-RULE-STAGED-DOWNLOAD",
    severity: "critical",
    message: "Staged download-and-execute chain appears likely.",
    signalIds: ["download-source", "execute-sink"],
    minConfidence: 85,
  },
];

export function createPlaceholderScanReport(snapshot: SkillSnapshot): StaticScanReport {
  return scanSkillSnapshot(snapshot);
}

export function analyzeSkillSnapshot(
  snapshot: SkillSnapshot,
  options: AnalyzeSkillSnapshotOptions = {},
): SkillThreatAnalysis {
  const textSources = buildTextSources(snapshot);
  const normalizedLines = buildNormalizedLines(textSources, snapshot.fileInventory);
  const baseSignals = extractSignals(normalizedLines);
  const semanticSignals = options.semanticAnalyzer
    ? options.semanticAnalyzer.analyze({
        snapshot,
        normalizedLines,
        extractedSignals: baseSignals,
      })
    : [];
  const signals = mergeSignals([...baseSignals, ...semanticSignals]);
  const findings = buildFindings(signals);

  return {
    snapshot,
    signals,
    findings,
    hints: buildThreatExerciseHints(textSources),
  };
}

export function scanSkillSnapshot(snapshot: SkillSnapshot): StaticScanReport {
  const analysis = analyzeSkillSnapshot(snapshot);
  const score = computeRiskScore(analysis.findings);
  const recommendation = deriveRecommendation(analysis.findings);

  return {
    reportId: `report-${snapshot.slug}-${snapshot.contentHash.slice(0, 12)}`,
    snapshot,
    score,
    findings: analysis.findings,
    recommendation,
    generatedAt: new Date().toISOString(),
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
  const skillMdText = [
    snapshot.slug,
    snapshot.metadata?.skillMd.title,
    snapshot.metadata?.skillMd.summary,
  ]
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

function buildNormalizedLines(
  textSources: TextSource[],
  fileInventory: string[],
): NormalizedLine[] {
  const lines: NormalizedLine[] = [];

  for (const source of textSources) {
    pushNormalizedLines(lines, source.path, "visible", source.text);

    for (const line of source.text.split(/\r?\n/u)) {
      if (hasBenignExampleContext(line)) {
        continue;
      }

      for (const match of line.matchAll(INLINE_CODE_PATTERN)) {
        pushNormalizedLines(lines, source.path, "inline-code", match[1] ?? "");
      }
    }

    for (const block of collectCodeFenceBlocks(source.text)) {
      if (hasBenignExampleContext(block.context)) {
        continue;
      }

      pushNormalizedLines(lines, source.path, "code-fence", block.content);
    }

    for (const match of source.text.matchAll(HTML_COMMENT_PATTERN)) {
      pushNormalizedLines(lines, source.path, "html-comment", match[1] ?? "");
    }

    const zeroWidthNormalized = source.text.replace(ZERO_WIDTH_PATTERN, "");
    if (zeroWidthNormalized !== source.text) {
      pushNormalizedLines(lines, source.path, "zero-width-normalized", zeroWidthNormalized);
    }

    const spacingNormalized = collapseSpacedLetters(source.text);
    if (spacingNormalized !== source.text) {
      pushNormalizedLines(lines, source.path, "spacing-normalized", spacingNormalized);
    }

    const typoglycemiaNormalized = normalizeTypoglycemia(spacingNormalized);
    if (typoglycemiaNormalized !== spacingNormalized) {
      pushNormalizedLines(lines, source.path, "typoglycemia-normalized", typoglycemiaNormalized);
    }

    for (const decoded of collectDecodedPayloads(source.text)) {
      pushNormalizedLines(lines, source.path, decoded.channel, decoded.text);
    }
  }

  for (const relativePath of fileInventory) {
    pushNormalizedLines(lines, relativePath, "filename", relativePath);
  }

  return dedupeNormalizedLines(lines);
}

function collectCodeFenceBlocks(text: string): Array<{ context: string; content: string }> {
  const lines = text.split(/\r?\n/u);
  const blocks: Array<{ context: string; content: string }> = [];
  let inFence = false;
  let collected: string[] = [];
  let context = "";

  for (const line of lines) {
    if (line.trim().startsWith("```")) {
      if (inFence) {
        blocks.push({
          context,
          content: collected.join("\n"),
        });
        inFence = false;
        collected = [];
        context = "";
      } else {
        inFence = true;
      }
      continue;
    }

    if (inFence) {
      collected.push(line);
      continue;
    }

    if (line.trim().length > 0) {
      context = line;
    }
  }

  return blocks;
}

function pushNormalizedLines(
  target: NormalizedLine[],
  sourcePath: string,
  channel: NormalizedChannel,
  text: string,
): void {
  for (const rawLine of text.split(/\r?\n/u)) {
    const normalized = normalizeEvidenceLine(rawLine);
    if (normalized.length === 0) {
      continue;
    }

    target.push({
      path: sourcePath,
      channel,
      text: normalized.toLowerCase(),
      evidenceText: normalized,
    });
  }
}

function dedupeNormalizedLines(lines: NormalizedLine[]): NormalizedLine[] {
  const seen = new Set<string>();
  const deduped: NormalizedLine[] = [];

  for (const line of lines) {
    const key = `${line.path}\u0000${line.channel}\u0000${line.evidenceText}`;
    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    deduped.push(line);
  }

  return deduped;
}

function collectDecodedPayloads(
  text: string,
): Array<{ channel: "decoded-base64" | "decoded-hex" | "decoded-url"; text: string }> {
  const decoded: Array<{
    channel: "decoded-base64" | "decoded-hex" | "decoded-url";
    text: string;
  }> = [];
  const seen = new Set<string>();

  for (const match of text.matchAll(BASE64_CANDIDATE_PATTERN)) {
    const candidate = match[0] ?? "";
    const decodedText = decodeBase64Candidate(candidate);
    if (!decodedText) {
      continue;
    }

    const key = `decoded-base64:${decodedText}`;
    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    decoded.push({
      channel: "decoded-base64",
      text: decodedText,
    });
  }

  for (const match of text.matchAll(HEX_CANDIDATE_PATTERN)) {
    const candidate = match[0] ?? "";
    const decodedText = decodeHexCandidate(candidate);
    if (!decodedText) {
      continue;
    }

    const key = `decoded-hex:${decodedText}`;
    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    decoded.push({
      channel: "decoded-hex",
      text: decodedText,
    });
  }

  for (const match of text.matchAll(URL_ENCODED_PATTERN)) {
    const candidate = match[0] ?? "";
    const decodedText = decodeUrlCandidate(candidate);
    if (!decodedText) {
      continue;
    }

    const key = `decoded-url:${decodedText}`;
    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    decoded.push({
      channel: "decoded-url",
      text: decodedText,
    });
  }

  return decoded;
}

function extractSignals(normalizedLines: NormalizedLine[]): ExtractedSignal[] {
  return compactSignals([
    detectSecretSource(normalizedLines),
    detectCredentialPrompt(normalizedLines),
    detectPromptOverride(normalizedLines),
    detectMemoryTarget(normalizedLines),
    detectPersistenceDirective(normalizedLines),
    detectExternalContentInput(normalizedLines),
    detectNetworkSink(normalizedLines),
    detectDownloadSource(normalizedLines),
    detectExecuteSink(normalizedLines),
    detectInteractiveShell(normalizedLines),
    detectNetworkCapability(normalizedLines),
    detectObfuscation(normalizedLines),
    detectSystemModification(normalizedLines),
    detectUnverifiableDependency(normalizedLines),
  ]);
}

function detectSecretSource(lines: NormalizedLine[]): ExtractedSignal | undefined {
  const matches = collectCompositeMatches(lines, secretActionPatterns, secretTargetPatterns);
  if (matches.length === 0) {
    return undefined;
  }

  return createSignal("secret-source", 90, matches);
}

function detectCredentialPrompt(lines: NormalizedLine[]): ExtractedSignal | undefined {
  const matches = collectPatternMatches(lines, credentialPromptPatterns);
  if (matches.length === 0) {
    return undefined;
  }

  return createSignal("credential-prompt", 95, matches);
}

function detectPromptOverride(lines: NormalizedLine[]): ExtractedSignal | undefined {
  const matches = collectPatternMatches(lines, promptOverridePatterns);
  if (matches.length === 0) {
    return undefined;
  }

  return createSignal("prompt-override", 88, matches);
}

function detectMemoryTarget(lines: NormalizedLine[]): ExtractedSignal | undefined {
  const matches = collectPatternMatches(lines, memoryTargetPatterns);
  if (matches.length === 0) {
    return undefined;
  }

  return createSignal("memory-target", 88, matches);
}

function detectPersistenceDirective(lines: NormalizedLine[]): ExtractedSignal | undefined {
  const matches = collectPatternMatches(lines, persistenceDirectivePatterns);
  if (matches.length === 0) {
    return undefined;
  }

  return createSignal("persistence-directive", 80, matches);
}

function detectExternalContentInput(lines: NormalizedLine[]): ExtractedSignal | undefined {
  const matches = collectPatternMatches(lines, externalContentPatterns);
  if (matches.length === 0) {
    return undefined;
  }

  return createSignal("external-content-input", 72, matches);
}

function detectNetworkSink(lines: NormalizedLine[]): ExtractedSignal | undefined {
  const matches = collectPatternMatches(lines, networkSinkPatterns);
  if (matches.length === 0) {
    return undefined;
  }

  return createSignal("network-sink", 88, matches);
}

function detectDownloadSource(lines: NormalizedLine[]): ExtractedSignal | undefined {
  const matches = collectPatternMatches(lines, downloadPatterns);
  if (matches.length === 0) {
    return undefined;
  }

  return createSignal("download-source", 90, matches);
}

function detectExecuteSink(lines: NormalizedLine[]): ExtractedSignal | undefined {
  const matches = collectPatternMatches(lines, executePatterns);
  if (matches.length === 0) {
    return undefined;
  }

  return createSignal("execute-sink", 86, matches);
}

function detectInteractiveShell(lines: NormalizedLine[]): ExtractedSignal | undefined {
  const directMatches = collectPatternMatches(lines, interactiveShellPatterns);
  if (directMatches.length === 0) {
    return undefined;
  }

  return createSignal("interactive-shell", 95, directMatches);
}

function detectNetworkCapability(lines: NormalizedLine[]): ExtractedSignal | undefined {
  const matches = collectPatternMatches(lines, networkCapabilityPatterns);
  if (matches.length === 0) {
    return undefined;
  }

  return createSignal("network-capability", 76, matches);
}

function detectObfuscation(lines: NormalizedLine[]): ExtractedSignal | undefined {
  const matches = lines
    .filter((line) => {
      if (
        line.channel === "html-comment" ||
        line.channel === "zero-width-normalized" ||
        line.channel === "decoded-base64" ||
        line.channel === "decoded-hex" ||
        line.channel === "decoded-url"
      ) {
        return suspiciousKeywordPattern.test(line.evidenceText);
      }

      return (
        line.channel === "spacing-normalized" ||
        line.channel === "typoglycemia-normalized" ||
        /\b(?:base64|hex|urlencoded|invisible|hidden)\b/i.test(line.evidenceText)
      );
    })
    .slice(0, MAX_SIGNAL_EVIDENCE)
    .map((line) => ({
      path: line.path,
      channel: line.channel,
      evidence: formatEvidence(line),
    }));

  if (matches.length === 0) {
    return undefined;
  }

  return createSignal("obfuscation", 78, matches);
}

function detectSystemModification(lines: NormalizedLine[]): ExtractedSignal | undefined {
  const matches = collectPatternMatches(lines, systemModificationPatterns);
  if (matches.length === 0) {
    return undefined;
  }

  return createSignal("system-modification", 80, matches);
}

function detectUnverifiableDependency(lines: NormalizedLine[]): ExtractedSignal | undefined {
  const matches = collectPatternMatches(lines, unverifiableDependencyPatterns);
  if (matches.length === 0) {
    return undefined;
  }

  return createSignal("unverifiable-dependency", 70, matches);
}

function collectPatternMatches(
  lines: NormalizedLine[],
  patterns: readonly RegExp[],
): SignalMatch[] {
  return lines
    .filter(
      (line) =>
        !hasBenignExampleContext(line.evidenceText) &&
        patterns.some((pattern) => pattern.test(line.evidenceText)),
    )
    .slice(0, MAX_SIGNAL_EVIDENCE)
    .map((line) => ({
      path: line.path,
      channel: line.channel,
      evidence: formatEvidence(line),
    }));
}

function collectCompositeMatches(
  lines: NormalizedLine[],
  primaryPatterns: readonly RegExp[],
  secondaryPatterns: readonly RegExp[],
): SignalMatch[] {
  return lines
    .filter((line) => {
      return (
        !hasBenignExampleContext(line.evidenceText) &&
        primaryPatterns.some((pattern) => pattern.test(line.evidenceText)) &&
        secondaryPatterns.some((pattern) => pattern.test(line.evidenceText))
      );
    })
    .slice(0, MAX_SIGNAL_EVIDENCE)
    .map((line) => ({
      path: line.path,
      channel: line.channel,
      evidence: formatEvidence(line),
    }));
}

function createSignal(
  id: ThreatSignalId,
  confidence: number,
  matches: SignalMatch[],
): ExtractedSignal | undefined {
  if (matches.length === 0) {
    return undefined;
  }

  return {
    id,
    confidence,
    evidence: unique(matches.map((match) => match.evidence)).slice(0, MAX_SIGNAL_EVIDENCE),
    paths: unique(matches.map((match) => match.path)),
    channels: unique(matches.map((match) => match.channel)),
  };
}

function mergeSignals(signals: ExtractedSignal[]): ExtractedSignal[] {
  const merged = new Map<ThreatSignalId, ExtractedSignal>();

  for (const signal of signals) {
    const existing = merged.get(signal.id);
    if (!existing) {
      merged.set(signal.id, {
        ...signal,
        evidence: [...signal.evidence],
        paths: [...signal.paths],
        channels: [...signal.channels],
      });
      continue;
    }

    existing.confidence = Math.max(existing.confidence, signal.confidence);
    existing.evidence = unique([...existing.evidence, ...signal.evidence]).slice(
      0,
      MAX_SIGNAL_EVIDENCE,
    );
    existing.paths = unique([...existing.paths, ...signal.paths]);
    existing.channels = unique([...existing.channels, ...signal.channels]);
  }

  return [...merged.values()].sort((left, right) => left.id.localeCompare(right.id));
}

function buildFindings(signals: ExtractedSignal[]): StaticFinding[] {
  const findings: StaticFinding[] = [];
  const signalMap = new Map(signals.map((signal) => [signal.id, signal]));

  for (const chain of capabilityChains) {
    const matchedSignals = chain.signalIds
      .map((signalId) => signalMap.get(signalId))
      .filter(Boolean);
    if (matchedSignals.length !== chain.signalIds.length) {
      continue;
    }

    const confidence = computeAverageConfidence(matchedSignals);
    if (confidence < chain.minConfidence) {
      continue;
    }

    findings.push({
      ruleId: chain.ruleId,
      severity: chain.severity,
      message: chain.message,
      evidence: collectFindingEvidence(matchedSignals),
      signalIds: chain.signalIds,
      confidence,
    });
  }

  const promptOverride = signalMap.get("prompt-override");
  if (promptOverride) {
    findings.push({
      ruleId: "CG-RULE-PROMPT-INJECTION",
      severity: "high",
      message: "Prompt injection or guardrail bypass language found.",
      evidence: promptOverride.evidence.slice(0, MAX_EVIDENCE_PER_RULE),
      signalIds: ["prompt-override"],
      confidence: promptOverride.confidence,
    });
  }

  const secretSource = signalMap.get("secret-source");
  if (secretSource) {
    findings.push({
      ruleId: "CG-RULE-CREDENTIAL-ACCESS",
      severity: "critical",
      message: "Credential material access or credential-harvesting workflow detected.",
      evidence: secretSource.evidence.slice(0, MAX_EVIDENCE_PER_RULE),
      signalIds: ["secret-source"],
      confidence: secretSource.confidence,
    });
  }

  const systemModification = signalMap.get("system-modification");
  if (systemModification) {
    findings.push({
      ruleId: "CG-RULE-PRIVILEGE-ESCALATION",
      severity: "critical",
      message: "Elevated privilege operations detected.",
      evidence: systemModification.evidence.slice(0, MAX_EVIDENCE_PER_RULE),
      signalIds: ["system-modification"],
      confidence: systemModification.confidence,
    });
  }

  const obfuscation = signalMap.get("obfuscation");
  if (obfuscation) {
    findings.push({
      ruleId: "CG-RULE-OBFUSCATION",
      severity: "medium",
      message: "Obfuscation patterns observed in skill references.",
      evidence: obfuscation.evidence.slice(0, MAX_EVIDENCE_PER_RULE),
      signalIds: ["obfuscation"],
      confidence: obfuscation.confidence,
    });
  }

  const externalContent = signalMap.get("external-content-input");
  if (externalContent) {
    findings.push({
      ruleId: "CG-RULE-THIRD-PARTY-CONTENT",
      severity: "medium",
      message:
        "The skill processes untrusted third-party content that can carry indirect prompt injection.",
      evidence: externalContent.evidence.slice(0, MAX_EVIDENCE_PER_RULE),
      signalIds: ["external-content-input"],
      confidence: externalContent.confidence,
    });
  }

  const unverifiableDependency = signalMap.get("unverifiable-dependency");
  if (unverifiableDependency) {
    findings.push({
      ruleId: "CG-RULE-UNVERIFIABLE-DEPENDENCY",
      severity: "medium",
      message:
        "The skill relies on remote dependencies or install steps that cannot be verified locally.",
      evidence: unverifiableDependency.evidence.slice(0, MAX_EVIDENCE_PER_RULE),
      signalIds: ["unverifiable-dependency"],
      confidence: unverifiableDependency.confidence,
    });
  }

  return dedupeFindings(findings);
}

function collectFindingEvidence(signals: Array<ExtractedSignal | undefined>): string[] {
  return unique(
    signals.flatMap((signal) => signal?.evidence ?? []).filter((entry) => entry.length > 0),
  ).slice(0, MAX_EVIDENCE_PER_RULE);
}

function dedupeFindings(findings: StaticFinding[]): StaticFinding[] {
  const deduped = new Map<string, StaticFinding>();

  for (const finding of findings) {
    const existing = deduped.get(finding.ruleId);
    if (!existing) {
      deduped.set(finding.ruleId, {
        ...finding,
        evidence: [...finding.evidence],
        ...(finding.signalIds ? { signalIds: [...finding.signalIds] } : {}),
      });
      continue;
    }

    existing.evidence = unique([...existing.evidence, ...finding.evidence]).slice(
      0,
      MAX_EVIDENCE_PER_RULE,
    );
    const mergedSignalIds = unique([...(existing.signalIds ?? []), ...(finding.signalIds ?? [])]);
    if (mergedSignalIds.length > 0) {
      existing.signalIds = mergedSignalIds;
    }

    if (finding.confidence !== undefined) {
      existing.confidence = Math.max(existing.confidence ?? 0, finding.confidence);
    }
  }

  return [...deduped.values()].sort((left, right) => left.ruleId.localeCompare(right.ruleId));
}

function buildThreatExerciseHints(textSources: TextSource[]): ThreatExerciseHints {
  const skillMarkdown =
    textSources
      .filter((source) => source.path === "SKILL.md")
      .sort((left, right) => right.text.length - left.text.length)[0]?.text ?? "";
  const lines = textSources.flatMap((source) =>
    source.text
      .split(/\r?\n/u)
      .map((line) => ({ path: source.path, text: normalizeEvidenceLine(line) }))
      .filter((line) => line.text.length > 0),
  );

  return {
    secretTargets: extractSecretTargets(lines),
    outboundRequests: extractOutboundRequests(lines),
    memoryMutations: extractMemoryMutations(skillMarkdown),
    credentialPrompts: extractCredentialPrompts(textSources),
  };
}

function extractSecretTargets(lines: Array<{ path: string; text: string }>): string[] {
  const candidates: string[] = [];
  const pathPattern =
    /(~\/\.(?:openclaw|clawdbot)\/\.env|~\/\.env|~\/\.ssh\/id_(?:rsa|ed25519)|~\/\.openclaw\/\.env)/giu;

  for (const line of lines) {
    if (!secretActionPatterns.some((pattern) => pattern.test(line.text))) {
      continue;
    }

    for (const match of line.text.matchAll(pathPattern)) {
      const value = match[1] ?? match[0] ?? "";
      if (value.length > 0) {
        candidates.push(value);
      }
    }
  }

  return unique(candidates).slice(0, MAX_HINT_COUNT);
}

function extractOutboundRequests(
  lines: Array<{ path: string; text: string }>,
): OutboundRequestHint[] {
  const hints: OutboundRequestHint[] = [];

  for (const line of lines) {
    const urls = [...line.text.matchAll(URL_PATTERN)].map((match) => match[0] ?? "");
    if (urls.length === 0) {
      continue;
    }

    const method: "GET" | "POST" =
      /\b(?:-X|--request)\s*POST\b/i.test(line.text) ||
      /\b(?:send|upload|post|submit|report)\b/i.test(line.text)
        ? "POST"
        : "GET";
    const payloadMatch = line.text.match(/\b(?:-d|--data|--data-binary)\s+@([^\s]+)/i);
    const payloadPath = payloadMatch?.[1];

    for (const url of urls) {
      hints.push({
        method,
        url,
        ...(payloadPath ? { payloadPath } : {}),
      });
    }
  }

  return dedupeOutboundRequests(hints).slice(0, MAX_HINT_COUNT);
}

function dedupeOutboundRequests(hints: OutboundRequestHint[]): OutboundRequestHint[] {
  const seen = new Set<string>();
  const deduped: OutboundRequestHint[] = [];

  for (const hint of hints) {
    const key = `${hint.method}:${hint.url}:${hint.payloadPath ?? ""}`;
    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    deduped.push(hint);
  }

  return deduped;
}

function extractMemoryMutations(markdown: string): MemoryMutationHint[] {
  if (markdown.length === 0) {
    return [];
  }

  const hints: MemoryMutationHint[] = [];
  const lines = markdown.split(/\r?\n/u);
  let pendingTarget: MemoryMutationHint["target"] | undefined;
  let collectingFence = false;
  let collected: string[] = [];

  const flush = (): void => {
    if (!pendingTarget || collected.length === 0) {
      pendingTarget = undefined;
      collected = [];
      collectingFence = false;
      return;
    }

    hints.push({
      target: pendingTarget,
      lines: collected
        .map((line) => normalizeEvidenceLine(line))
        .filter((line) => line.length > 0)
        .slice(0, 6),
    });
    pendingTarget = undefined;
    collected = [];
    collectingFence = false;
  };

  for (const rawLine of lines) {
    const line = rawLine.trim();

    if (!collectingFence) {
      if (/\bMEMORY\.md\b/i.test(line)) {
        flush();
        pendingTarget = "memory";
      } else if (/\bSOUL\.md\b/i.test(line)) {
        flush();
        pendingTarget = "soul";
      } else if (/\bUSER\.md\b/i.test(line)) {
        flush();
        pendingTarget = "user";
      }
    }

    if (line.startsWith("```")) {
      if (collectingFence) {
        flush();
      } else if (pendingTarget) {
        collectingFence = true;
      }
      continue;
    }

    if (collectingFence) {
      collected.push(rawLine);
      continue;
    }

    if (!pendingTarget) {
      continue;
    }

    if (/^[-*]/u.test(line) || /^[A-Za-z].*:/u.test(line)) {
      collected.push(rawLine);
      if (collected.length >= 6) {
        flush();
      }
      continue;
    }

    if (line.length === 0 && collected.length > 0) {
      flush();
    }
  }

  flush();

  return hints.filter((hint) => hint.lines.length > 0).slice(0, MAX_HINT_COUNT);
}

function extractCredentialPrompts(textSources: TextSource[]): string[] {
  const prompts: string[] = [];

  for (const source of textSources) {
    for (const match of source.text.matchAll(INLINE_CODE_PATTERN)) {
      const candidate = normalizeEvidenceLine(match[1] ?? "");
      if (credentialPromptPatterns.some((pattern) => pattern.test(candidate))) {
        prompts.push(candidate);
      }
    }

    for (const match of source.text.matchAll(CODE_FENCE_PATTERN)) {
      const candidate = normalizeEvidenceLine(match[1] ?? "");
      if (credentialPromptPatterns.some((pattern) => pattern.test(candidate))) {
        prompts.push(candidate);
      }
    }
  }

  return unique(prompts).slice(0, MAX_HINT_COUNT);
}

function formatEvidence(line: NormalizedLine): string {
  if (line.channel === "visible" || line.channel === "filename") {
    return `${line.path}: ${truncateEvidence(line.evidenceText, 160)}`;
  }

  return `${line.path} [${line.channel}]: ${truncateEvidence(line.evidenceText, 160)}`;
}

function normalizeEvidenceLine(line: string): string {
  return line.trim().replace(/\s+/gu, " ");
}

function hasBenignExampleContext(text: string): boolean {
  return [
    /\bfor example\b/i,
    /(?:^|[\s:;,])example(?:$|[\s:;,])/i,
    /\bdebug(?:ging)?\b/i,
    /\btroubleshooting\b/i,
    /\bsample output\b/i,
    /\bquoted?\b/i,
    /\bphrase\s+like\b/i,
    /\bcommand\s+like\b/i,
    /\bnever\s+(?:run|follow|execute|use)\b/i,
    /\bdo not\s+(?:run|follow|execute|use)\b/i,
    /\bavoid\s+(?:running|following|using)\b/i,
  ].some((pattern) => pattern.test(text));
}

function collapseSpacedLetters(text: string): string {
  return text.replace(/\b(?:[A-Za-z]\s+){3,}[A-Za-z]\b/gu, (match) => match.replace(/\s+/gu, ""));
}

function normalizeTypoglycemia(text: string): string {
  return text.replace(/\b[A-Za-z]{5,}\b/gu, (token) => {
    const normalized = token.toLowerCase();
    const canonical = typoglycemiaTargets.find((target) =>
      looksLikeTypoglycemia(normalized, target),
    );
    return canonical ?? token;
  });
}

function looksLikeTypoglycemia(word: string, target: string): boolean {
  if (word === target || word.length !== target.length) {
    return false;
  }

  if (word[0] !== target[0] || word.at(-1) !== target.at(-1)) {
    return false;
  }

  return sortLetters(word.slice(1, -1)) === sortLetters(target.slice(1, -1));
}

function sortLetters(value: string): string {
  return [...value].sort((left, right) => left.localeCompare(right)).join("");
}

function decodeBase64Candidate(value: string): string | undefined {
  try {
    const decoded = Buffer.from(value, "base64").toString("utf8");
    if (
      decoded.length >= 8 &&
      !hasUnsupportedControlCharacters(decoded) &&
      suspiciousKeywordPattern.test(decoded)
    ) {
      return decoded;
    }
  } catch {}

  return undefined;
}

function decodeHexCandidate(value: string): string | undefined {
  try {
    const decoded = Buffer.from(value, "hex").toString("utf8");
    if (
      decoded.length >= 8 &&
      !hasUnsupportedControlCharacters(decoded) &&
      suspiciousKeywordPattern.test(decoded)
    ) {
      return decoded;
    }
  } catch {}

  return undefined;
}

function decodeUrlCandidate(value: string): string | undefined {
  try {
    const decoded = decodeURIComponent(value);
    if (decoded.length >= 8 && suspiciousKeywordPattern.test(decoded)) {
      return decoded;
    }
  } catch {}

  return undefined;
}

function hasUnsupportedControlCharacters(value: string): boolean {
  for (const char of value) {
    const codePoint = char.codePointAt(0) ?? -1;
    if ((codePoint >= 0 && codePoint <= 8) || codePoint === 11 || codePoint === 12) {
      return true;
    }

    if (codePoint >= 14 && codePoint <= 31) {
      return true;
    }
  }

  return false;
}

function truncateEvidence(value: string, maxLength: number): string {
  if (value.length <= maxLength) {
    return value;
  }

  return `${value.slice(0, Math.max(0, maxLength - 3))}...`;
}

function compactSignals(signals: Array<ExtractedSignal | undefined>): ExtractedSignal[] {
  return signals.filter((signal): signal is ExtractedSignal => signal !== undefined);
}

function computeAverageConfidence(signals: Array<ExtractedSignal | undefined>): number {
  const present = signals.filter((signal): signal is ExtractedSignal => signal !== undefined);
  if (present.length === 0) {
    return 0;
  }

  return Math.round(
    present.reduce((total, signal) => total + signal.confidence, 0) / present.length,
  );
}

function computeRiskScore(findings: StaticFinding[]): number {
  const baseScore = findings.reduce(
    (total, finding) => total + severityWeight[finding.severity],
    0,
  );
  const diversityBonus =
    Math.max(0, new Set(findings.map((finding) => finding.ruleId)).size - 1) * 5;
  return Math.min(100, baseScore + diversityBonus);
}

function deriveRecommendation(findings: StaticFinding[]): VerdictLevel {
  if (findings.length === 0) {
    return "allow";
  }

  if (findings.some((finding) => blockRuleIds.has(finding.ruleId))) {
    return "block";
  }

  return "review";
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}
