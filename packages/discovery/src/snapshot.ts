import { createHash } from "node:crypto";
import type { Dirent, Stats } from "node:fs";
import { lstat, readdir, readFile, readlink } from "node:fs/promises";
import path from "node:path";

import type {
  DiscoveredSkillRoot,
  SkillSnapshot,
  SkillSnapshotManifestMetadata,
  SkillSnapshotMetadata,
  SkillSourceHint,
} from "@clawguard/contracts";

const MANIFEST_CANDIDATES = ["package.json", "skill.json", "manifest.json"] as const;

export interface BuildSkillSnapshotInput {
  skillPath: string;
  skillSlug?: string;
  skillRootPath: string;
  skillRootKind: DiscoveredSkillRoot["kind"];
  discoverySource: DiscoveredSkillRoot["source"];
  workspaceId?: string;
  detectedAt?: string;
}

export interface BuildSkillSnapshotOptions {
  now?: () => string;
}

export interface SkillSnapshotBuildError {
  kind: "missing-skill" | "missing-skill-md" | "read-failed" | "parse-failed";
  skillPath: string;
  skillSlug: string;
  message: string;
}

export type SkillSnapshotBuildResult =
  | { ok: true; snapshot: SkillSnapshot }
  | { ok: false; error: SkillSnapshotBuildError };

type FileEntry =
  | {
      relativePath: string;
      kind: "file";
      data: Buffer;
    }
  | {
      relativePath: string;
      kind: "symlink";
      data: string;
    };

export async function buildSkillSnapshot(
  input: BuildSkillSnapshotInput,
  options: BuildSkillSnapshotOptions = {},
): Promise<SkillSnapshotBuildResult> {
  const skillSlug = input.skillSlug ?? path.basename(input.skillPath);

  let skillStats: Stats;
  try {
    skillStats = await lstat(input.skillPath);
  } catch {
    return {
      ok: false,
      error: snapshotError(
        "missing-skill",
        input.skillPath,
        skillSlug,
        "Skill directory was not found",
      ),
    };
  }

  if (!skillStats.isDirectory()) {
    return {
      ok: false,
      error: snapshotError(
        "missing-skill",
        input.skillPath,
        skillSlug,
        "Skill path exists but is not a directory",
      ),
    };
  }

  const walkedEntries = await walkSkillEntries(input.skillPath, skillSlug);
  if (!walkedEntries.ok) {
    return walkedEntries;
  }

  const skillMdEntry = walkedEntries.entries.find((entry) => entry.relativePath === "SKILL.md");
  if (!skillMdEntry || skillMdEntry.kind !== "file") {
    return {
      ok: false,
      error: snapshotError(
        "missing-skill-md",
        input.skillPath,
        skillSlug,
        "SKILL.md is required for a valid skill snapshot",
      ),
    };
  }

  const parsedMetadata = await parseSnapshotMetadata(
    input.skillPath,
    skillSlug,
    walkedEntries.entries,
    skillMdEntry,
  );
  if (!parsedMetadata.ok) {
    return parsedMetadata;
  }

  return {
    ok: true,
    snapshot: {
      slug: skillSlug,
      path: input.skillPath,
      sourceHints: buildSourceHints(input),
      contentHash: buildContentHash(walkedEntries.entries),
      fileInventory: walkedEntries.entries.map((entry) => entry.relativePath),
      detectedAt: input.detectedAt ?? (options.now ?? (() => new Date().toISOString()))(),
      metadata: parsedMetadata.metadata,
    },
  };
}

async function walkSkillEntries(
  skillPath: string,
  skillSlug: string,
): Promise<{ ok: true; entries: FileEntry[] } | { ok: false; error: SkillSnapshotBuildError }> {
  const entries: FileEntry[] = [];
  const pendingDirectories = [skillPath];

  while (pendingDirectories.length > 0) {
    const currentDirectory = pendingDirectories.pop();
    if (!currentDirectory) {
      break;
    }

    let childEntries: Dirent[];
    try {
      childEntries = await readdir(currentDirectory, { withFileTypes: true });
    } catch (error) {
      return {
        ok: false,
        error: snapshotError(
          "read-failed",
          skillPath,
          skillSlug,
          `Failed to read directory ${currentDirectory}: ${errorMessage(error)}`,
        ),
      };
    }

    childEntries.sort((left, right) => compareStableStrings(left.name, right.name));

    for (const childEntry of childEntries) {
      const childPath = path.join(currentDirectory, childEntry.name);
      const relativePath = normalizeRelativePath(skillPath, childPath);

      if (childEntry.isDirectory()) {
        pendingDirectories.push(childPath);
        continue;
      }

      if (childEntry.isFile()) {
        try {
          entries.push({
            relativePath,
            kind: "file",
            data: await readFile(childPath),
          });
        } catch (error) {
          return {
            ok: false,
            error: snapshotError(
              "read-failed",
              skillPath,
              skillSlug,
              `Failed to read file ${relativePath}: ${errorMessage(error)}`,
            ),
          };
        }
        continue;
      }

      if (childEntry.isSymbolicLink()) {
        try {
          entries.push({
            relativePath,
            kind: "symlink",
            data: await readlink(childPath),
          });
        } catch (error) {
          return {
            ok: false,
            error: snapshotError(
              "read-failed",
              skillPath,
              skillSlug,
              `Failed to read symlink ${relativePath}: ${errorMessage(error)}`,
            ),
          };
        }
      }
    }
  }

  entries.sort((left, right) => compareStableStrings(left.relativePath, right.relativePath));
  return { ok: true, entries };
}

async function parseSnapshotMetadata(
  skillPath: string,
  skillSlug: string,
  entries: FileEntry[],
  skillMdEntry: FileEntry,
): Promise<
  { ok: true; metadata: SkillSnapshotMetadata } | { ok: false; error: SkillSnapshotBuildError }
> {
  const manifestEntries = new Map(entries.map((entry) => [entry.relativePath, entry]));
  const manifests: SkillSnapshotManifestMetadata[] = [];

  for (const candidatePath of MANIFEST_CANDIDATES) {
    const manifestEntry = manifestEntries.get(candidatePath);
    if (!manifestEntry || manifestEntry.kind !== "file") {
      continue;
    }

    try {
      const parsed = JSON.parse(manifestEntry.data.toString("utf8")) as unknown;
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        return {
          ok: false,
          error: snapshotError(
            "parse-failed",
            skillPath,
            skillSlug,
            `Manifest ${candidatePath} must contain a JSON object`,
          ),
        };
      }

      const record = parsed as Record<string, unknown>;
      manifests.push({
        path: candidatePath,
        keys: Object.keys(record).sort((left, right) => compareStableStrings(left, right)),
        ...(typeof record.name === "string" && record.name.trim().length > 0
          ? { name: record.name.trim() }
          : {}),
        ...(typeof record.version === "string" && record.version.trim().length > 0
          ? { version: record.version.trim() }
          : {}),
        ...(typeof record.description === "string" && record.description.trim().length > 0
          ? { description: record.description.trim() }
          : {}),
      });
    } catch (error) {
      return {
        ok: false,
        error: snapshotError(
          "parse-failed",
          skillPath,
          skillSlug,
          `Failed to parse manifest ${candidatePath}: ${errorMessage(error)}`,
        ),
      };
    }
  }

  return {
    ok: true,
    metadata: {
      skillMd: {
        path: "SKILL.md",
        ...extractSkillMarkdownMetadata(skillMdEntry.data.toString("utf8")),
      },
      manifests,
    },
  };
}

function extractSkillMarkdownMetadata(markdown: string): {
  title?: string;
  summary?: string;
} {
  const lines = markdown.split(/\r?\n/);
  let title: string | undefined;
  let summary: string | undefined;

  for (const line of lines) {
    const match = /^#\s+(.+)$/.exec(line.trim());
    const heading = match?.[1]?.trim();
    if (heading !== undefined && heading.length > 0) {
      title = heading;
      break;
    }
  }

  const summaryLines: string[] = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.length === 0) {
      if (summaryLines.length > 0) {
        break;
      }
      continue;
    }

    if (trimmed.startsWith("#")) {
      continue;
    }

    summaryLines.push(trimmed);
  }

  if (summaryLines.length > 0) {
    summary = summaryLines.join(" ");
  }

  return {
    ...(title !== undefined ? { title } : {}),
    ...(summary !== undefined ? { summary } : {}),
  };
}

function buildContentHash(entries: FileEntry[]): string {
  const hash = createHash("sha256");

  for (const entry of entries) {
    hash.update(entry.relativePath);
    hash.update("\0");
    hash.update(entry.kind);
    hash.update("\0");
    hash.update(entry.data);
    hash.update("\0");
  }

  return `sha256:${hash.digest("hex")}`;
}

function buildSourceHints(input: BuildSkillSnapshotInput): SkillSourceHint[] {
  const workspaceDetail =
    input.workspaceId !== undefined ? ` for workspace ${input.workspaceId}` : "";

  return [
    {
      kind: input.discoverySource,
      detail: `Discovered from ${input.skillRootKind} skill root at ${input.skillRootPath}${workspaceDetail}`,
    },
  ];
}

function normalizeRelativePath(rootPath: string, targetPath: string): string {
  return path.relative(rootPath, targetPath).split(path.sep).join(path.posix.sep);
}

function compareStableStrings(left: string, right: string): number {
  if (left < right) {
    return -1;
  }

  if (left > right) {
    return 1;
  }

  return 0;
}

function snapshotError(
  kind: SkillSnapshotBuildError["kind"],
  skillPath: string,
  skillSlug: string,
  message: string,
): SkillSnapshotBuildError {
  return { kind, skillPath, skillSlug, message };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
