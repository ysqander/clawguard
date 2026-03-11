import assert from "node:assert/strict";
import { constants } from "node:fs";
import { access, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import { createStorage } from "@clawguard/storage";

import { SkillLifecycleManager } from "./lifecycle.js";

async function createSandbox(
  prefix: string,
): Promise<{ root: string; cleanup: () => Promise<void> }> {
  const root = await mkdtemp(path.join(tmpdir(), prefix));
  return {
    root,
    cleanup: async () => rm(root, { recursive: true, force: true }),
  };
}

async function exists(filePath: string): Promise<boolean> {
  try {
    await access(filePath, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

test("quarantine is non-destructive and reversible through restore", async (t) => {
  const sandbox = await createSandbox("clawguard-lifecycle-");
  t.after(async () => sandbox.cleanup());

  const stateDbPath = path.join(sandbox.root, "state.db");
  const artifactsRoot = path.join(sandbox.root, "artifacts");
  const storage = createStorage({ stateDbPath, artifactsRoot });
  t.after(() => storage.close());

  const manager = new SkillLifecycleManager({ storage });

  const skillsRoot = path.join(sandbox.root, "skills");
  const skillPath = path.join(skillsRoot, "calendar-helper");
  await mkdir(skillPath, { recursive: true });
  await writeFile(path.join(skillPath, "SKILL.md"), "# Calendar Helper\n");

  const quarantine = await manager.quarantineSkill({
    skillSlug: "calendar-helper",
    skillPath,
    contentHash: "hash-1",
  });

  assert.equal(await exists(skillPath), false);
  assert.equal(await exists(quarantine.quarantinePath), true);
  assert.equal(quarantine.state, "active");

  const restored = await manager.restoreSkill({ quarantineId: quarantine.quarantineId });
  assert.equal(restored.state, "restored");
  assert.equal(await exists(skillPath), true);
  assert.equal(await exists(quarantine.quarantinePath), false);

  const decision = await storage.getDecision("hash-1");
  assert.equal(decision?.decision, "allow");
});

test("allowed hashes bypass repeat quarantine until content changes", async (t) => {
  const sandbox = await createSandbox("clawguard-lifecycle-");
  t.after(async () => sandbox.cleanup());

  const storage = createStorage({
    stateDbPath: path.join(sandbox.root, "state.db"),
    artifactsRoot: path.join(sandbox.root, "artifacts"),
  });
  t.after(() => storage.close());

  const manager = new SkillLifecycleManager({ storage });
  await manager.allowHash({ contentHash: "allow-hash" });

  const skillsRoot = path.join(sandbox.root, "skills");
  const skillPath = path.join(skillsRoot, "allowed-skill");
  await mkdir(skillPath, { recursive: true });

  const resolution = await manager.resolveSkillLifecycle({
    skillSlug: "allowed-skill",
    skillPath,
    contentHash: "allow-hash",
  });

  assert.equal(resolution.status, "allowed");
  assert.equal(await exists(skillPath), true);

  const changedHashResolution = await manager.resolveSkillLifecycle({
    skillSlug: "allowed-skill",
    skillPath,
    contentHash: "new-hash",
  });

  assert.equal(changedHashResolution.status, "quarantined");
});

test("blocked hashes are rejected on reappearance", async (t) => {
  const sandbox = await createSandbox("clawguard-lifecycle-");
  t.after(async () => sandbox.cleanup());

  const storage = createStorage({
    stateDbPath: path.join(sandbox.root, "state.db"),
    artifactsRoot: path.join(sandbox.root, "artifacts"),
  });
  t.after(() => storage.close());

  const manager = new SkillLifecycleManager({ storage });
  await manager.blockHash({ contentHash: "blocked-hash" });

  const skillPath = path.join(sandbox.root, "skills", "blocked-skill");
  await mkdir(skillPath, { recursive: true });
  await writeFile(path.join(skillPath, "SKILL.md"), "# blocked\n");

  const resolution = await manager.resolveSkillLifecycle({
    skillSlug: "blocked-skill",
    skillPath,
    contentHash: "blocked-hash",
  });

  assert.equal(resolution.status, "blocked");
  assert.equal(await exists(skillPath), false);
});
