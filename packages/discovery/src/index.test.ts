import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";

import { discoverOpenClawWorkspaceModel } from "./index.js";
import type { RunCommand } from "./service-probe.js";

test("discovers a JSON5 config workspace, managed root, and extra dirs", async (t) => {
  const sandbox = await createSandbox(t);
  await createDirectory(path.join(sandbox.homeDir, ".openclaw", "skills"));
  await createDirectory(path.join(sandbox.homeDir, "workspace-a", "skills"));
  await createDirectory(path.join(sandbox.homeDir, ".openclaw", "shared-skills"));
  await writeTextFile(
    path.join(sandbox.homeDir, ".openclaw", "openclaw.json"),
    `{
      // comments and trailing commas should parse
      agents: {
        defaults: {
          workspace: "~/workspace-a",
        },
      },
      skills: {
        load: {
          extraDirs: ["./shared-skills"],
        },
      },
    }`
  );

  const model = await discoverOpenClawWorkspaceModel({
    homeDir: sandbox.homeDir,
    cwd: sandbox.cwd,
    runCommand: createStatusCommand({ installed: true, running: false })
  });

  assert.equal(model.primaryWorkspaceId, "default");
  assert.deepEqual(
    model.workspaces.map((workspace) => workspace.id),
    ["default"]
  );
  assert.equal(findSkillRoot(model, path.join(sandbox.homeDir, "workspace-a", "skills"))?.kind, "workspace");
  assert.equal(findSkillRoot(model, path.join(sandbox.homeDir, ".openclaw", "skills"))?.kind, "managed");
  assert.equal(
    findSkillRoot(model, path.join(sandbox.homeDir, ".openclaw", "shared-skills"))?.kind,
    "extra"
  );
  assert.equal(model.warnings.length, 0);
});

test("supports includes, sibling overrides, and multi-agent workspaces", async (t) => {
  const sandbox = await createSandbox(t);
  await createDirectory(path.join(sandbox.homeDir, "workspace-main", "skills"));
  await createDirectory(path.join(sandbox.homeDir, "workspace-ops", "skills"));
  await createDirectory(path.join(sandbox.homeDir, ".openclaw", "skills"));
  await createDirectory(path.join(sandbox.homeDir, ".openclaw", "included-extra"));

  await writeTextFile(
    path.join(sandbox.homeDir, ".openclaw", "base.json5"),
    `{
      agents: {
        defaults: {
          workspace: "~/workspace-from-base",
        },
      },
      skills: {
        load: {
          extraDirs: ["./included-extra"],
        },
      },
    }`
  );
  await writeTextFile(
    path.join(sandbox.homeDir, ".openclaw", "openclaw.json"),
    `{
      $include: "./base.json5",
      agents: {
        defaults: {
          workspace: "~/workspace-main",
        },
        list: [
          { name: "ops", workspace: "~/workspace-ops" },
          { name: "shared" },
        ],
      },
    }`
  );

  const model = await discoverOpenClawWorkspaceModel({
    homeDir: sandbox.homeDir,
    cwd: sandbox.cwd,
    runCommand: createStatusCommand({ installed: true, running: true, status: "running" })
  });

  assert.equal(model.primaryWorkspaceId, "default");
  assert.deepEqual(
    model.workspaces.map((workspace) => workspace.id),
    ["default", "agent:ops", "agent:shared"]
  );
  assert.equal(model.workspaces[0]?.workspacePath, path.join(sandbox.homeDir, "workspace-main"));
  assert.equal(model.workspaces[2]?.workspacePath, path.join(sandbox.homeDir, "workspace-main"));
  assert.equal(
    findSkillRoot(model, path.join(sandbox.homeDir, ".openclaw", "included-extra"))?.kind,
    "extra"
  );
  assert.equal(model.serviceSignals[0]?.running, true);
});

test("falls back when includes are missing or circular", async (t) => {
  const sandbox = await createSandbox(t);
  await createDirectory(path.join(sandbox.homeDir, "openclaw", "skills"));
  await writeTextFile(
    path.join(sandbox.homeDir, ".openclaw", "openclaw.json"),
    `{
      $include: "./missing.json5",
    }`
  );

  const missingIncludeModel = await discoverOpenClawWorkspaceModel({
    homeDir: sandbox.homeDir,
    cwd: sandbox.cwd,
    runCommand: createStatusCommand({ installed: false, running: false })
  });

  assert.equal(missingIncludeModel.primaryWorkspaceId, "fallback:0");
  assert.match(missingIncludeModel.warnings[0] ?? "", /missing\.json5/);

  await writeTextFile(
    path.join(sandbox.homeDir, ".openclaw", "a.json5"),
    `{
      $include: "./b.json5",
    }`
  );
  await writeTextFile(
    path.join(sandbox.homeDir, ".openclaw", "b.json5"),
    `{
      $include: "./a.json5",
    }`
  );
  await writeTextFile(
    path.join(sandbox.homeDir, ".openclaw", "openclaw.json"),
    `{
      $include: "./a.json5",
    }`
  );

  const circularModel = await discoverOpenClawWorkspaceModel({
    homeDir: sandbox.homeDir,
    cwd: sandbox.cwd,
    runCommand: createStatusCommand({ installed: false, running: false })
  });

  assert.equal(circularModel.primaryWorkspaceId, "fallback:0");
  assert.match(circularModel.warnings[0] ?? "", /circular/i);
});

test("rejects includes that escape the root directory or exceed the nesting limit", async (t) => {
  const sandbox = await createSandbox(t);
  await createDirectory(path.join(sandbox.homeDir, "openclaw", "skills"));
  await writeTextFile(
    path.join(sandbox.homeDir, ".openclaw", "openclaw.json"),
    `{
      $include: "../outside.json5",
    }`
  );

  const escapedModel = await discoverOpenClawWorkspaceModel({
    homeDir: sandbox.homeDir,
    cwd: sandbox.cwd,
    runCommand: createStatusCommand({ installed: false, running: false })
  });

  assert.equal(escapedModel.primaryWorkspaceId, "fallback:0");
  assert.match(escapedModel.warnings[0] ?? "", /escaped/i);

  for (let index = 0; index <= 10; index += 1) {
    const filePath = path.join(sandbox.homeDir, ".openclaw", `depth-${index}.json5`);
    const nextInclude = index === 10 ? "{ agents: { defaults: { workspace: \"~/too-deep\" } } }" : `{ $include: "./depth-${index + 1}.json5" }`;
    await writeTextFile(filePath, nextInclude);
  }
  await writeTextFile(
    path.join(sandbox.homeDir, ".openclaw", "openclaw.json"),
    `{
      $include: "./depth-0.json5",
    }`
  );

  const depthModel = await discoverOpenClawWorkspaceModel({
    homeDir: sandbox.homeDir,
    cwd: sandbox.cwd,
    runCommand: createStatusCommand({ installed: false, running: false })
  });

  assert.equal(depthModel.primaryWorkspaceId, "fallback:0");
  assert.match(depthModel.warnings[0] ?? "", /maximum nesting depth/i);
});

test("uses cwd lockfiles when config discovery yields no workspaces", async (t) => {
  const sandbox = await createSandbox(t);
  await createDirectory(path.join(sandbox.cwd, ".clawhub"));
  await createDirectory(path.join(sandbox.cwd, "skills"));
  await writeTextFile(path.join(sandbox.cwd, ".clawhub", "lock.json"), `{"version":1}`);

  const model = await discoverOpenClawWorkspaceModel({
    homeDir: sandbox.homeDir,
    cwd: sandbox.cwd,
    runCommand: createStatusCommand({ installed: false, running: false })
  });

  assert.equal(model.primaryWorkspaceId, "lockfile:0");
  assert.equal(model.workspaces[0]?.source, "lockfile");
  assert.equal(findSkillRoot(model, path.join(sandbox.cwd, "skills"))?.source, "lockfile");
});

test("continues scanning lockfile candidates after a malformed lockfile", async (t) => {
  const sandbox = await createSandbox(t);
  await createDirectory(path.join(sandbox.cwd, ".clawhub"));
  await createDirectory(path.join(sandbox.homeDir, "openclaw", ".clawhub"));
  await createDirectory(path.join(sandbox.homeDir, "openclaw", "skills"));
  await writeTextFile(path.join(sandbox.cwd, ".clawhub", "lock.json"), `{"broken":`);
  await writeTextFile(
    path.join(sandbox.homeDir, "openclaw", ".clawhub", "lock.json"),
    `{"version":1}`
  );

  const model = await discoverOpenClawWorkspaceModel({
    homeDir: sandbox.homeDir,
    cwd: sandbox.cwd,
    runCommand: createStatusCommand({ installed: false, running: false })
  });

  assert.equal(model.primaryWorkspaceId, "lockfile:0");
  assert.equal(model.workspaces[0]?.workspacePath, path.join(sandbox.homeDir, "openclaw"));
  assert.match(model.warnings[0] ?? "", /Failed to parse lockfile/);
});

test("falls back to configured skill dirs when config and lockfiles are absent", async (t) => {
  const sandbox = await createSandbox(t);
  await createDirectory(path.join(sandbox.homeDir, "openclaw", "skills"));
  await createDirectory(path.join(sandbox.cwd, "skills"));

  const model = await discoverOpenClawWorkspaceModel({
    homeDir: sandbox.homeDir,
    cwd: sandbox.cwd,
    runCommand: createStatusCommand({ installed: false, running: false })
  });

  assert.deepEqual(
    model.workspaces.map((workspace) => workspace.id),
    ["fallback:0", "fallback:1"]
  );
  assert.equal(model.primaryWorkspaceId, "fallback:0");
  assert.equal(findSkillRoot(model, path.join(sandbox.homeDir, "openclaw", "skills"))?.kind, "fallback");
  assert.equal(findSkillRoot(model, path.join(sandbox.cwd, "skills"))?.kind, "fallback");
});

test("deduplicates overlapping roots and preserves the strongest metadata", async (t) => {
  const sandbox = await createSandbox(t);
  await createDirectory(path.join(sandbox.homeDir, ".openclaw", "skills"));
  await createDirectory(path.join(sandbox.homeDir, "workspace-a", "skills"));
  await writeTextFile(
    path.join(sandbox.homeDir, ".openclaw", "openclaw.json"),
    `{
      agents: {
        defaults: {
          workspace: "~/workspace-a",
        },
      },
      skills: {
        load: {
          extraDirs: ["~/.openclaw/skills"],
        },
      },
    }`
  );

  const model = await discoverOpenClawWorkspaceModel({
    homeDir: sandbox.homeDir,
    cwd: sandbox.cwd,
    runCommand: createStatusCommand({ installed: false, running: false })
  });
  const managedRoot = findSkillRoot(model, path.join(sandbox.homeDir, ".openclaw", "skills"));

  assert.equal(model.skillRoots.filter((root) => root.path === managedRoot?.path).length, 1);
  assert.equal(managedRoot?.kind, "managed");
  assert.equal(managedRoot?.source, "config");
});

test("marks missing configured paths as non-existent instead of crashing", async (t) => {
  const sandbox = await createSandbox(t);
  await writeTextFile(
    path.join(sandbox.homeDir, ".openclaw", "openclaw.json"),
    `{
      agents: {
        defaults: {
          workspace: "~/missing-workspace",
        },
      },
    }`
  );

  const model = await discoverOpenClawWorkspaceModel({
    homeDir: sandbox.homeDir,
    cwd: sandbox.cwd,
    runCommand: createStatusCommand({ installed: false, running: false })
  });

  assert.equal(model.primaryWorkspaceId, "default");
  assert.equal(model.workspaces[0]?.exists, false);
  assert.equal(model.skillRoots[0]?.exists, false);
});

test("records service probe warnings without changing path discovery", async (t) => {
  const sandbox = await createSandbox(t);
  await createDirectory(path.join(sandbox.homeDir, "workspace-a", "skills"));
  await writeTextFile(
    path.join(sandbox.homeDir, ".openclaw", "openclaw.json"),
    `{
      agents: {
        defaults: {
          workspace: "~/workspace-a",
        },
      },
    }`
  );

  const missingCommandModel = await discoverOpenClawWorkspaceModel({
    homeDir: sandbox.homeDir,
    cwd: sandbox.cwd,
    runCommand: async () => {
      throw new Error("spawn openclaw ENOENT");
    }
  });

  assert.equal(missingCommandModel.primaryWorkspaceId, "default");
  assert.equal(missingCommandModel.serviceSignals.length, 0);
  assert.match(missingCommandModel.warnings.at(-1) ?? "", /probe unavailable/i);

  const badJsonModel = await discoverOpenClawWorkspaceModel({
    homeDir: sandbox.homeDir,
    cwd: sandbox.cwd,
    runCommand: async () => ({
      command: "openclaw",
      args: ["gateway", "status"],
      exitCode: 0,
      stdout: "{invalid json",
      stderr: ""
    })
  });

  assert.equal(badJsonModel.primaryWorkspaceId, "default");
  assert.equal(badJsonModel.serviceSignals.length, 0);
  assert.match(badJsonModel.warnings.at(-1) ?? "", /invalid JSON/i);
});

function findSkillRoot(
  model: Awaited<ReturnType<typeof discoverOpenClawWorkspaceModel>>,
  targetPath: string
) {
  return model.skillRoots.find((root) => root.path === targetPath);
}

function createStatusCommand(payload: Record<string, unknown>): RunCommand {
  return async (command, args = []) => ({
    command,
    args: [...args],
    exitCode: 0,
    stdout: JSON.stringify(payload),
    stderr: ""
  });
}

async function createSandbox(t: TestContext) {
  const rootPath = await mkdtemp(path.join(tmpdir(), "clawguard-discovery-"));
  t.after(async () => {
    await rm(rootPath, { recursive: true, force: true });
  });

  const homeDir = path.join(rootPath, "home");
  const cwd = path.join(rootPath, "cwd");
  await mkdir(path.join(homeDir, ".openclaw"), { recursive: true });
  await mkdir(cwd, { recursive: true });

  return { rootPath, homeDir, cwd };
}

async function createDirectory(directoryPath: string): Promise<void> {
  await mkdir(directoryPath, { recursive: true });
}

async function writeTextFile(filePath: string, contents: string): Promise<void> {
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, contents, "utf8");
}
