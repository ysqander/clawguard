import { access } from "node:fs/promises";
import path from "node:path";

export function expandHomePath(inputPath: string, homeDir: string): string {
  if (inputPath === "~") {
    return homeDir;
  }

  if (inputPath.startsWith("~/")) {
    return path.join(homeDir, inputPath.slice(2));
  }

  return inputPath;
}

export function resolveDiscoveryPath(
  inputPath: string,
  options: { homeDir: string; baseDir: string }
): string {
  const expandedPath = expandHomePath(inputPath, options.homeDir);
  return path.isAbsolute(expandedPath)
    ? path.normalize(expandedPath)
    : path.resolve(options.baseDir, expandedPath);
}

export async function pathExists(targetPath: string): Promise<boolean> {
  try {
    await access(targetPath);
    return true;
  } catch {
    return false;
  }
}

export function isWithinDirectory(targetPath: string, directoryPath: string): boolean {
  const relativePath = path.relative(directoryPath, targetPath);
  return relativePath === "" || (!relativePath.startsWith("..") && !path.isAbsolute(relativePath));
}

