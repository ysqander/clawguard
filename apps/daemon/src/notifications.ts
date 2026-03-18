export type ScanRecommendation = "allow" | "review" | "block";

export interface DaemonNotificationRequest {
  title: string;
  body: string;
  subtitle?: string;
}

export interface ScanNotificationInput {
  slug: string;
  recommendation: ScanRecommendation;
  score: number;
  findingCount: number;
  completedAt?: string;
}

export function buildScanNotification(input: ScanNotificationInput): DaemonNotificationRequest {
  const slug = formatSkillSlug(input.slug);
  const score = formatScore(input.score);
  const findingCount = formatFindingCount(input.findingCount);
  const completedAt = formatCompletedAt(input.completedAt);

  switch (input.recommendation) {
    case "allow":
      return {
        title: "ClawGuard scan complete",
        body: `No quarantine was needed for ${slug}. ${score} with ${findingCount}.`,
        ...(completedAt !== undefined ? { subtitle: completedAt } : {}),
      };
    case "review":
      return {
        title: "ClawGuard review recommended",
        body: `Review ${slug} before the next OpenClaw session. ${score} with ${findingCount}.`,
        subtitle: joinSubtitle("Manual review required", completedAt),
      };
    case "block":
      return {
        title: "ClawGuard quarantined",
        body: `Quarantined ${slug} so OpenClaw will not load it. ${score} with ${findingCount}.`,
        subtitle: joinSubtitle("Review required before reinstalling or allowing it", completedAt),
      };
  }
}

function formatSkillSlug(slug: string): string {
  const normalized = slug.trim().replace(/\s+/gu, " ");
  return `"${normalized.length > 0 ? normalized : "unknown-skill"}"`;
}

function formatScore(score: number): string {
  const normalizedScore = Number.isFinite(score) ? Math.round(score) : 0;
  return `Score ${Math.max(0, normalizedScore)}`;
}

function formatFindingCount(findingCount: number): string {
  const normalizedCount = Number.isFinite(findingCount) ? Math.max(0, Math.round(findingCount)) : 0;
  return normalizedCount === 1 ? "1 finding" : `${normalizedCount} findings`;
}

function formatCompletedAt(completedAt: string | undefined): string | undefined {
  if (completedAt === undefined) {
    return undefined;
  }

  const trimmed = completedAt.trim();
  return trimmed.length > 0 ? `Completed at ${trimmed}` : undefined;
}

function joinSubtitle(prefix: string, suffix: string | undefined): string {
  return suffix !== undefined ? `${prefix}. ${suffix}` : prefix;
}
