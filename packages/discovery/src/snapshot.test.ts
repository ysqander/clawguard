import assert from "node:assert/strict";
import { constants } from "node:fs";
import {
  chmod,
  mkdir,
  mkdtemp,
  readlink,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import { buildSkillSnapshot } from "./snapshot.js";

async function createSandbox(
  prefix: string,
): Promise<{ root: string; cleanup: () => Promise<void> }> {
  const root = await mkdtemp(path.join(tmpdir(), prefix));
  return {
    root,
    cleanup: async () => rm(root, { recursive: true, force: true }),
  };
}

function baseInput(root: string) {
  const skillPath = path.join(root, "skills", "calendar-helper");

  return {
    skillPath,
    skillRootPath: path.join(root, "skills"),
    skillRootKind: "workspace" as const,
    discoverySource: "config" as const,
    workspaceId: "workspace:default",
    detectedAt: "2026-03-11T00:00:00.000Z",
  };
}

test("buildSkillSnapshot produces a deterministic snapshot with discovery-derived source hints", async (t) => {
  const sandbox = await createSandbox("clawguard-snapshot-");
  t.after(async () => sandbox.cleanup());

  const input = baseInput(sandbox.root);
  await mkdir(path.join(input.skillPath, "scripts"), { recursive: true });
  await writeFile(path.join(input.skillPath, "SKILL.md"), "# Calendar Helper\n\nSummarize upcoming events.\n");
  await writeFile(path.join(input.skillPath, "scripts", "install.sh"), "echo install\n");

  const first = await buildSkillSnapshot(input);
  const second = await buildSkillSnapshot(input);

  assert.equal(first.ok, true);
  assert.equal(second.ok, true);
  if (!first.ok || !second.ok) {
    return;
  }

  assert.equal(first.snapshot.contentHash, second.snapshot.contentHash);
  assert.deepEqual(first.snapshot.fileInventory, ["SKILL.md", "scripts/install.sh"]);
  assert.equal(first.snapshot.sourceHints[0]?.kind, "config");
  assert.match(first.snapshot.sourceHints[0]?.detail ?? "", /workspace skill root/);
  assert.equal(first.snapshot.metadata?.skillMd.title, "Calendar Helper");
  assert.equal(first.snapshot.metadata?.skillMd.summary, "Summarize upcoming events.");
});

test("buildSkillSnapshot changes the hash when a file path changes", async (t) => {
  const sandbox = await createSandbox("clawguard-snapshot-");
  t.after(async () => sandbox.cleanup());

  const input = baseInput(sandbox.root);
  await mkdir(path.join(input.skillPath, "scripts"), { recursive: true });
  await writeFile(path.join(input.skillPath, "SKILL.md"), "# Calendar Helper\n\nSummary.\n");
  await writeFile(path.join(input.skillPath, "scripts", "install.sh"), "echo install\n");

  const original = await buildSkillSnapshot(input);
  assert.equal(original.ok, true);
  if (!original.ok) {
    return;
  }

  await rm(path.join(input.skillPath, "scripts", "install.sh"));
  await writeFile(path.join(input.skillPath, "scripts", "setup.sh"), "echo install\n");

  const renamed = await buildSkillSnapshot(input);
  assert.equal(renamed.ok, true);
  if (!renamed.ok) {
    return;
  }

  assert.notEqual(original.snapshot.contentHash, renamed.snapshot.contentHash);
});

test("buildSkillSnapshot parses root-level manifest metadata when present", async (t) => {
  const sandbox = await createSandbox("clawguard-snapshot-");
  t.after(async () => sandbox.cleanup());

  const input = baseInput(sandbox.root);
  await mkdir(input.skillPath, { recursive: true });
  await writeFile(path.join(input.skillPath, "SKILL.md"), "# Calendar Helper\n\nSummary.\n");
  await writeFile(
    path.join(input.skillPath, "package.json"),
    `${JSON.stringify(
      {
        name: "calendar-helper",
        version: "1.2.3",
        description: "Helps with calendar tasks",
        private: true,
      },
      null,
      2,
    )}\n`,
  );

  const result = await buildSkillSnapshot(input);
  assert.equal(result.ok, true);
  if (!result.ok) {
    return;
  }

  assert.deepEqual(result.snapshot.metadata?.manifests, [
    {
      path: "package.json",
      name: "calendar-helper",
      version: "1.2.3",
      description: "Helps with calendar tasks",
      keys: ["description", "name", "private", "version"],
    },
  ]);
});

test("buildSkillSnapshot inventories symlinks without traversing them", async (t) => {
  const sandbox = await createSandbox("clawguard-snapshot-");
  t.after(async () => sandbox.cleanup());

  const input = baseInput(sandbox.root);
  const externalRoot = path.join(sandbox.root, "external");
  await mkdir(input.skillPath, { recursive: true });
  await mkdir(externalRoot, { recursive: true });
  await writeFile(path.join(input.skillPath, "SKILL.md"), "# Calendar Helper\n\nSummary.\n");
  await writeFile(path.join(externalRoot, "secret.txt"), "top secret\n");
  await symlink(path.join(externalRoot, "secret.txt"), path.join(input.skillPath, "linked-secret.txt"));

  const before = await buildSkillSnapshot(input);
  assert.equal(before.ok, true);
  if (!before.ok) {
    return;
  }

  assert.deepEqual(before.snapshot.fileInventory, ["SKILL.md", "linked-secret.txt"]);
  const originalTarget = await readlink(path.join(input.skillPath, "linked-secret.txt"));

  await rm(path.join(input.skillPath, "linked-secret.txt"));
  await symlink(
    path.join(externalRoot, "renamed-secret.txt"),
    path.join(input.skillPath, "linked-secret.txt"),
  );

  const after = await buildSkillSnapshot(input);
  assert.equal(after.ok, true);
  if (!after.ok) {
    return;
  }

  assert.notEqual(originalTarget, await readlink(path.join(input.skillPath, "linked-secret.txt")));
  assert.notEqual(before.snapshot.contentHash, after.snapshot.contentHash);
});

test("buildSkillSnapshot returns missing-skill for a missing directory", async () => {
  const result = await buildSkillSnapshot({
    skillPath: "/tmp/does-not-exist",
    skillRootPath: "/tmp",
    skillRootKind: "workspace",
    discoverySource: "config",
  });

  assert.deepEqual(result, {
    ok: false,
    error: {
      kind: "missing-skill",
      skillPath: "/tmp/does-not-exist",
      skillSlug: "does-not-exist",
      message: "Skill directory was not found",
    },
  });
});

test("buildSkillSnapshot returns missing-skill-md when SKILL.md is absent", async (t) => {
  const sandbox = await createSandbox("clawguard-snapshot-");
  t.after(async () => sandbox.cleanup());

  const input = baseInput(sandbox.root);
  await mkdir(input.skillPath, { recursive: true });
  await writeFile(path.join(input.skillPath, "README.md"), "# Not the right file\n");

  const result = await buildSkillSnapshot(input);
  assert.equal(result.ok, false);
  if (result.ok) {
    return;
  }

  assert.equal(result.error.kind, "missing-skill-md");
});

test("buildSkillSnapshot returns read-failed when a file cannot be read", async (t) => {
  const sandbox = await createSandbox("clawguard-snapshot-");
  t.after(async () => sandbox.cleanup());

  const input = baseInput(sandbox.root);
  const secretPath = path.join(input.skillPath, "secret.txt");
  await mkdir(input.skillPath, { recursive: true });
  await writeFile(path.join(input.skillPath, "SKILL.md"), "# Calendar Helper\n\nSummary.\n");
  await writeFile(secretPath, "secret\n");
  await chmod(secretPath, 0);
  t.after(async () => {
    await chmod(secretPath, constants.S_IRUSR | constants.S_IWUSR).catch(() => {});
  });

  const result = await buildSkillSnapshot(input);
  assert.equal(result.ok, false);
  if (result.ok) {
    return;
  }

  assert.equal(result.error.kind, "read-failed");
  assert.match(result.error.message, /Failed to read file secret\.txt/);
});

test("buildSkillSnapshot returns parse-failed when a manifest contains invalid JSON", async (t) => {
  const sandbox = await createSandbox("clawguard-snapshot-");
  t.after(async () => sandbox.cleanup());

  const input = baseInput(sandbox.root);
  await mkdir(input.skillPath, { recursive: true });
  await writeFile(path.join(input.skillPath, "SKILL.md"), "# Calendar Helper\n\nSummary.\n");
  await writeFile(path.join(input.skillPath, "package.json"), "{ invalid json }\n");

  const result = await buildSkillSnapshot(input);
  assert.equal(result.ok, false);
  if (result.ok) {
    return;
  }

  assert.equal(result.error.kind, "parse-failed");
  assert.match(result.error.message, /Failed to parse manifest package\.json/);
});
