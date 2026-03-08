export interface DiscoveryTarget {
  workspacePath: string;
  skillsPath: string;
  source: "config" | "lockfile" | "default";
}

export function describeDiscoveryTarget(target: DiscoveryTarget): string {
  return `OpenClaw workspace at ${target.workspacePath} (${target.source})`;
}

