import { homedir } from "node:os";
import path from "node:path";

import { defaultClawGuardConfig } from "@clawguard/contracts";

import type { StoragePaths } from "./types.js";

export function expandHomePath(inputPath: string, homeDir = homedir()): string {
  if (inputPath === "~") {
    return homeDir;
  }

  if (inputPath.startsWith("~/")) {
    return path.join(homeDir, inputPath.slice(2));
  }

  return inputPath;
}

export function createMacosStoragePaths(homeDir = homedir()): StoragePaths {
  return {
    stateDbPath: expandHomePath(defaultClawGuardConfig.paths.stateDbPath, homeDir),
    artifactsRoot: expandHomePath(defaultClawGuardConfig.paths.artifactsRoot, homeDir),
  };
}

export function resolveStoragePaths(
  overrides: Partial<StoragePaths> = {},
  homeDir = homedir(),
): StoragePaths {
  const basePaths = createMacosStoragePaths(homeDir);

  return {
    stateDbPath: expandHomePath(overrides.stateDbPath ?? basePaths.stateDbPath, homeDir),
    artifactsRoot: expandHomePath(overrides.artifactsRoot ?? basePaths.artifactsRoot, homeDir),
  };
}

export const defaultMacosStoragePaths = createMacosStoragePaths();
