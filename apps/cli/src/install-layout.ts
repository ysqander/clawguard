import { existsSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const RELEASE_DAEMON_RELATIVE_PATH = "./daemon.js";
const REPO_DAEMON_RELATIVE_PATH = "../../daemon/dist/index.js";

export function resolveCurrentEntrypointPath(moduleUrl: string = import.meta.url): string {
  return fileURLToPath(moduleUrl);
}

export function resolveDefaultDaemonEntrypointPath(
  options: { moduleUrl?: string; pathExists?: (filePath: string) => boolean } = {},
): string {
  const moduleDirectory = path.dirname(resolveCurrentEntrypointPath(options.moduleUrl));
  const pathExists = options.pathExists ?? existsSync;
  const releaseDaemonPath = path.resolve(moduleDirectory, RELEASE_DAEMON_RELATIVE_PATH);
  const repoDaemonPath = path.resolve(moduleDirectory, REPO_DAEMON_RELATIVE_PATH);
  const candidates = [releaseDaemonPath, repoDaemonPath];

  return candidates.find((candidate) => pathExists(candidate)) ?? releaseDaemonPath;
}

export function resolveDefaultServiceWorkingDirectory(homeDirectory = process.env.HOME): string {
  return homeDirectory && homeDirectory.length > 0 ? homeDirectory : homedir();
}
