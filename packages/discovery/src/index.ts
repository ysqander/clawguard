import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";

import {
  defaultClawGuardConfig,
  type DiscoveredSkillRoot,
  type DiscoveredSkillRootKind,
  type DiscoveredWorkspace,
  type DiscoveryConfig,
  type OpenClawWorkspaceModel,
  type WorkspaceDiscoverySourceKind,
} from "@clawguard/contracts";

import { loadOpenClawConfig } from "./config-loader.js";
import { pathExists, resolveDiscoveryPath } from "./path-utils.js";
import { probeGatewayService, type RunCommand } from "./service-probe.js";

export interface DiscoverOpenClawWorkspaceModelOptions {
  config?: Partial<DiscoveryConfig>;
  cwd?: string;
  homeDir?: string;
  now?: () => string;
  runCommand?: RunCommand;
}

export async function discoverOpenClawWorkspaceModel(
  options: DiscoverOpenClawWorkspaceModelOptions = {},
): Promise<OpenClawWorkspaceModel> {
  const homeDir = options.homeDir ?? homedir();
  const cwd = options.cwd ?? process.cwd();
  const discoveryConfig = resolveDiscoveryConfig(options.config);
  const configPath = resolveDiscoveryPath(discoveryConfig.openClawConfigPath, {
    homeDir,
    baseDir: cwd,
  });
  const managedSkillsPath = resolveDiscoveryPath(discoveryConfig.managedSkillsPath, {
    homeDir,
    baseDir: cwd,
  });
  const fallbackSkillDirs = discoveryConfig.fallbackSkillDirs.map((skillDir) =>
    resolveDiscoveryPath(skillDir, { homeDir, baseDir: cwd }),
  );
  const warnings: string[] = [];
  const workspaces: DiscoveredWorkspace[] = [];
  const skillRoots = new Map<string, DiscoveredSkillRoot>();
  let preferredFallbackWorkspaceId: string | undefined;

  let configResult: Awaited<ReturnType<typeof loadOpenClawConfig>>;
  try {
    configResult = await loadOpenClawConfig(configPath, { homeDir });
  } catch (error) {
    warnings.push(error instanceof Error ? error.message : String(error));
  }

  if (configResult !== undefined) {
    for (const workspace of configResult.workspaces) {
      workspaces.push({
        id: workspace.id,
        workspacePath: workspace.workspacePath,
        skillsPath: workspace.skillsPath,
        source: "config",
        exists: await pathExists(workspace.workspacePath),
        precedence: WORKSPACE_PRECEDENCE.config,
        ...(workspace.agentName !== undefined ? { agentName: workspace.agentName } : {}),
        ...(workspace.isPrimary !== undefined ? { isPrimary: workspace.isPrimary } : {}),
      });
      await mergeSkillRoot(skillRoots, {
        path: workspace.skillsPath,
        kind: "workspace",
        source: "config",
        exists: await pathExists(workspace.skillsPath),
        precedence: ROOT_PRECEDENCE.workspace,
        workspaceId: workspace.id,
      });
    }

    for (const extraDirPath of configResult.extraDirs) {
      await mergeSkillRoot(skillRoots, {
        path: extraDirPath,
        kind: "extra",
        source: "config",
        exists: await pathExists(extraDirPath),
        precedence: ROOT_PRECEDENCE.extra,
      });
    }
  }

  const managedExists = await pathExists(managedSkillsPath);
  if (managedExists || skillRoots.has(managedSkillsPath)) {
    await mergeSkillRoot(skillRoots, {
      path: managedSkillsPath,
      kind: "managed",
      source: "default",
      exists: managedExists,
      precedence: ROOT_PRECEDENCE.managed,
    });
  }

  if (workspaces.length === 0) {
    const lockfileResult = await resolveLockfileWorkspace({
      cwd,
      fallbackSkillDirs,
    });
    warnings.push(...lockfileResult.warnings);

    if (lockfileResult.workspace !== undefined) {
      workspaces.push({
        id: "lockfile:0",
        workspacePath: lockfileResult.workspace.workspacePath,
        skillsPath: lockfileResult.workspace.skillsPath,
        source: "lockfile",
        exists: await pathExists(lockfileResult.workspace.workspacePath),
        precedence: WORKSPACE_PRECEDENCE.lockfile,
        isPrimary: true,
      });
      await mergeSkillRoot(skillRoots, {
        path: lockfileResult.workspace.skillsPath,
        kind: "workspace",
        source: "lockfile",
        exists: await pathExists(lockfileResult.workspace.skillsPath),
        precedence: ROOT_PRECEDENCE.workspace,
        workspaceId: "lockfile:0",
      });
    }
  }

  if (workspaces.length === 0) {
    const fallbackWorkspaces: DiscoveredWorkspace[] = await Promise.all(
      fallbackSkillDirs.map(async (skillsPath, index) => ({
        id: `fallback:${index}`,
        workspacePath: path.dirname(skillsPath),
        skillsPath,
        source: "default" as const,
        exists: await pathExists(path.dirname(skillsPath)),
        precedence: WORKSPACE_PRECEDENCE.default,
      })),
    );

    for (const workspace of fallbackWorkspaces) {
      workspaces.push(workspace);
      await mergeSkillRoot(skillRoots, {
        path: workspace.skillsPath,
        kind: "fallback",
        source: "default",
        exists: await pathExists(workspace.skillsPath),
        precedence: ROOT_PRECEDENCE.fallback,
        workspaceId: workspace.id,
      });
    }

    const primaryFallbackWorkspace =
      fallbackWorkspaces.find((workspace) => workspace.exists) ?? fallbackWorkspaces[0];
    if (primaryFallbackWorkspace !== undefined) {
      preferredFallbackWorkspaceId = primaryFallbackWorkspace.id;
    }
  }

  const primaryWorkspaceId =
    workspaces.find((workspace) => workspace.isPrimary)?.id ??
    preferredFallbackWorkspaceId ??
    workspaces[0]?.id;
  const normalizedWorkspaces = workspaces.map((workspace) => ({
    ...workspace,
    ...(workspace.id === primaryWorkspaceId ? { isPrimary: true } : {}),
  }));

  const serviceSignals: OpenClawWorkspaceModel["serviceSignals"] = [];
  const serviceProbe = await probeGatewayService({
    ...(options.now !== undefined ? { now: options.now } : {}),
    ...(options.runCommand !== undefined ? { runCommand: options.runCommand } : {}),
  });
  if (serviceProbe.signal !== undefined) {
    serviceSignals.push(serviceProbe.signal);
  }
  if (serviceProbe.warning !== undefined) {
    warnings.push(serviceProbe.warning);
  }

  return {
    configPath,
    ...(primaryWorkspaceId !== undefined ? { primaryWorkspaceId } : {}),
    workspaces: normalizedWorkspaces.sort(compareWorkspaces),
    skillRoots: [...skillRoots.values()].sort(compareSkillRoots),
    serviceSignals,
    warnings,
  };
}

export function describeOpenClawWorkspaceModel(model: OpenClawWorkspaceModel): string {
  const workspaceCount = model.workspaces.length;
  const skillRootCount = model.skillRoots.length;
  const primaryWorkspace = model.workspaces.find(
    (workspace) => workspace.id === model.primaryWorkspaceId,
  );

  return [
    `OpenClaw discovery: ${workspaceCount} workspace${workspaceCount === 1 ? "" : "s"}`,
    `${skillRootCount} skill root${skillRootCount === 1 ? "" : "s"}`,
    primaryWorkspace !== undefined ? `primary=${primaryWorkspace.workspacePath}` : "primary=none",
  ].join(" | ");
}

async function resolveLockfileWorkspace(options: {
  cwd: string;
  fallbackSkillDirs: string[];
}): Promise<{
  workspace?: {
    workspacePath: string;
    skillsPath: string;
  };
  warnings: string[];
}> {
  const candidatePaths = dedupePaths([
    path.join(options.cwd, ".clawhub", "lock.json"),
    ...options.fallbackSkillDirs.map((skillDir) =>
      path.join(path.dirname(skillDir), ".clawhub", "lock.json"),
    ),
  ]);
  const warnings: string[] = [];

  for (const candidatePath of candidatePaths) {
    if (!(await pathExists(candidatePath))) {
      continue;
    }

    try {
      const rawText = await readFile(candidatePath, "utf8");
      const parsed = JSON.parse(rawText) as unknown;
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw new Error("Expected a JSON object");
      }

      const workspacePath = path.dirname(path.dirname(candidatePath));
      return {
        workspace: {
          workspacePath,
          skillsPath: path.join(workspacePath, "skills"),
        },
        warnings,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      warnings.push(`Failed to parse lockfile ${candidatePath}: ${message}`);
    }
  }

  return { warnings };
}

async function mergeSkillRoot(
  skillRoots: Map<string, DiscoveredSkillRoot>,
  candidate: DiscoveredSkillRoot,
): Promise<void> {
  const existing = skillRoots.get(candidate.path);
  if (existing === undefined) {
    skillRoots.set(candidate.path, candidate);
    return;
  }

  const preferredRoot =
    candidate.precedence > existing.precedence ||
    (candidate.precedence === existing.precedence &&
      sourcePriority(candidate.source) > sourcePriority(existing.source))
      ? candidate
      : existing;
  const preferredSource =
    sourcePriority(candidate.source) > sourcePriority(existing.source)
      ? candidate.source
      : existing.source;
  const mergedWorkspaceId =
    preferredRoot.workspaceId ?? existing.workspaceId ?? candidate.workspaceId;

  skillRoots.set(candidate.path, {
    ...preferredRoot,
    source: preferredSource,
    exists: existing.exists || candidate.exists,
    precedence: Math.max(existing.precedence, candidate.precedence),
    ...(mergedWorkspaceId !== undefined ? { workspaceId: mergedWorkspaceId } : {}),
  });
}

function resolveDiscoveryConfig(
  configOverrides: Partial<DiscoveryConfig> | undefined,
): DiscoveryConfig {
  return {
    ...defaultClawGuardConfig.discovery,
    ...configOverrides,
  };
}

function sourcePriority(source: WorkspaceDiscoverySourceKind): number {
  switch (source) {
    case "config":
      return 3;
    case "lockfile":
      return 2;
    case "default":
      return 1;
  }
}

function compareWorkspaces(left: DiscoveredWorkspace, right: DiscoveredWorkspace): number {
  if ((left.isPrimary ?? false) !== (right.isPrimary ?? false)) {
    return left.isPrimary ? -1 : 1;
  }

  if (left.precedence !== right.precedence) {
    return right.precedence - left.precedence;
  }

  return left.id.localeCompare(right.id);
}

function compareSkillRoots(left: DiscoveredSkillRoot, right: DiscoveredSkillRoot): number {
  if (left.precedence !== right.precedence) {
    return right.precedence - left.precedence;
  }

  return left.path.localeCompare(right.path);
}

function dedupePaths(candidatePaths: string[]): string[] {
  return [...new Set(candidatePaths.map((candidatePath) => path.normalize(candidatePath)))];
}

const WORKSPACE_PRECEDENCE = {
  config: 300,
  lockfile: 200,
  default: 100,
} as const;

const ROOT_PRECEDENCE: Record<DiscoveredSkillRootKind, number> = {
  workspace: 300,
  managed: 200,
  extra: 100,
  fallback: 50,
};

export type { RunCommand } from "./service-probe.js";
export {
  type ScheduledRootRescan,
  SkillWatcherPipeline,
  type SkillWatcherPipelineErrorContext,
  resolveSkillPathFromEvent,
  type ScheduledSkillScan,
  type SkillWatcherPipelineOptions,
} from "./watcher-pipeline.js";
