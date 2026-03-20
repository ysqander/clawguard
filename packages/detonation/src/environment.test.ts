import assert from "node:assert/strict";
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  readlink,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import type { DetonationRequest } from "@clawguard/contracts";
import { buildSkillSnapshot } from "@clawguard/discovery";
import { createPlatformAdapter } from "@clawguard/platform";

import {
  buildDetonationBenchmarkRequest,
  createDetonationRuntimeProvider,
  defaultDetonationHoneypotPaths,
  defaultSandboxImageTag,
  defaultDetonationSandboxLayout,
  prepareDetonationEnvironment,
  runSandboxCommand,
} from "./index.js";

test("prepareDetonationEnvironment creates the expected layout and baseline", async () => {
  const request = buildDetonationBenchmarkRequest("malicious-staged-download");
  const environment = await prepareDetonationEnvironment(request);

  try {
    assert.equal(
      environment.host.skillDir,
      path.join(environment.host.skillsDir, request.snapshot.slug),
    );
    assert.equal(environment.container.configPath, defaultDetonationSandboxLayout.configPath);

    await assertPathExists(environment.host.configPath);
    await assertPathExists(environment.host.memoryFiles.memory);
    await assertPathExists(environment.host.memoryFiles.soul);
    await assertPathExists(environment.host.memoryFiles.user);
    await assertPathExists(environment.host.honeypots.envFile);
    await assertPathExists(environment.host.honeypots.sshKey);
    await assertPathExists(environment.host.helpers.promptHarness);
    await assertPathExists(environment.host.helpers.osascript);
    await assertPathExists(environment.host.helpers.zenity);
    await assertPathExists(path.join(environment.host.workspaceDir, ".clawguard", "traces"));
    await assertPathExists(path.join(environment.host.skillDir, "SKILL.md"));
    await assertPathExists(path.join(environment.host.skillDir, "scripts", "install.sh"));
    await assertPathExists(environment.baseline.memoryFiles.memory);

    const configText = await readFile(environment.host.configPath, "utf8");
    assert.match(configText, /"workspace": "\/workspace\/openclaw"/u);

    const baselineText = await readFile(environment.baseline.memoryFiles.memory, "utf8");
    const liveText = await readFile(environment.host.memoryFiles.memory, "utf8");
    assert.equal(baselineText, liveText);
    assert.notEqual(environment.baseline.memoryFiles.memory, environment.host.memoryFiles.memory);

    const sshStats = await stat(environment.host.honeypots.sshKey);
    assert.equal(sshStats.mode & 0o777, 0o600);

    for (const aliasPath of defaultDetonationHoneypotPaths.envFiles) {
      const relativePath = path.posix.relative(defaultDetonationSandboxLayout.homeDir, aliasPath);
      await assertPathExists(path.join(environment.host.homeDir, ...relativePath.split("/")));
    }
  } finally {
    await environment.cleanup();
  }
});

test("prepareDetonationEnvironment is deterministic apart from the temp root", async () => {
  const request = buildDetonationBenchmarkRequest("malicious-staged-download");
  const leftParent = await mkdtemp(path.join(tmpdir(), "clawguard-detonation-env-left-"));
  const rightParent = await mkdtemp(path.join(tmpdir(), "clawguard-detonation-env-right-"));

  const left = await prepareDetonationEnvironment(request, { parentDir: leftParent });
  const right = await prepareDetonationEnvironment(request, { parentDir: rightParent });

  try {
    assert.equal(path.dirname(left.host.rootDir), leftParent);
    assert.equal(path.dirname(right.host.rootDir), rightParent);
    assert.notEqual(left.host.rootDir, leftParent);
    assert.notEqual(right.host.rootDir, rightParent);

    assert.deepEqual(
      await collectRelativeFiles(left.host.rootDir),
      await collectRelativeFiles(right.host.rootDir),
    );

    const leftMemory = await readFile(left.host.memoryFiles.memory, "utf8");
    const rightMemory = await readFile(right.host.memoryFiles.memory, "utf8");
    const leftScript = await readFile(
      path.join(left.host.skillDir, "scripts", "install.sh"),
      "utf8",
    );
    const rightScript = await readFile(
      path.join(right.host.skillDir, "scripts", "install.sh"),
      "utf8",
    );

    assert.equal(leftMemory, rightMemory);
    assert.equal(leftScript, rightScript);
  } finally {
    await left.cleanup();
    await right.cleanup();
    await rm(leftParent, { recursive: true, force: true });
    await rm(rightParent, { recursive: true, force: true });
  }
});

test("prepareDetonationEnvironment cleanup only removes the owned child directory", async () => {
  const parentDir = await mkdtemp(path.join(tmpdir(), "clawguard-detonation-parent-"));
  const siblingFile = path.join(parentDir, "keep.txt");
  const siblingDirectory = path.join(parentDir, "keep-dir");
  const request = buildDetonationBenchmarkRequest("malicious-staged-download");

  await writeFile(siblingFile, "keep\n", "utf8");
  await mkdir(siblingDirectory, { recursive: true });

  const environment = await prepareDetonationEnvironment(request, { parentDir });

  try {
    await assertPathExists(environment.host.rootDir);
    await environment.cleanup();

    await assertPathMissing(environment.host.rootDir);
    assert.equal(await readFile(siblingFile, "utf8"), "keep\n");
    await assertPathExists(siblingDirectory);
  } finally {
    await rm(parentDir, { recursive: true, force: true });
  }
});

test("prepareDetonationEnvironment preserves external-file symlinks from discovery snapshots", async () => {
  const sandbox = await createSandbox("clawguard-detonation-symlink-");
  const skillPath = path.join(sandbox.root, "skills", "linked-skill");
  const externalRoot = path.join(sandbox.root, "external");
  const externalFile = path.join(externalRoot, "secret.txt");
  const sourceLink = path.join(skillPath, "linked-secret.txt");

  await mkdir(skillPath, { recursive: true });
  await mkdir(externalRoot, { recursive: true });
  await writeFile(path.join(skillPath, "SKILL.md"), "# Linked Skill\n\nSummary.\n", "utf8");
  await writeFile(externalFile, "top secret\n", "utf8");
  await symlink(externalFile, sourceLink);

  const request = await buildDetonationRequest(sandbox.root, skillPath, "linked-skill");
  const environment = await prepareDetonationEnvironment(request);

  try {
    const copiedLink = path.join(environment.host.skillDir, "linked-secret.txt");
    const copiedStats = await lstat(copiedLink);

    assert.equal(copiedStats.isSymbolicLink(), true);
    assert.equal(await readlink(copiedLink), await readlink(sourceLink));
  } finally {
    await environment.cleanup();
    await sandbox.cleanup();
  }
});

test("prepareDetonationEnvironment preserves dangling symlinks from discovery snapshots", async () => {
  const sandbox = await createSandbox("clawguard-detonation-dangling-");
  const skillPath = path.join(sandbox.root, "skills", "dangling-skill");
  const missingTarget = path.join(sandbox.root, "external", "missing.txt");
  const sourceLink = path.join(skillPath, "dangling-link.txt");

  await mkdir(skillPath, { recursive: true });
  await writeFile(path.join(skillPath, "SKILL.md"), "# Dangling Skill\n\nSummary.\n", "utf8");
  await symlink(missingTarget, sourceLink);

  const request = await buildDetonationRequest(sandbox.root, skillPath, "dangling-skill");
  const environment = await prepareDetonationEnvironment(request);

  try {
    const copiedLink = path.join(environment.host.skillDir, "dangling-link.txt");
    const copiedStats = await lstat(copiedLink);

    assert.equal(copiedStats.isSymbolicLink(), true);
    assert.equal(await readlink(copiedLink), await readlink(sourceLink));
  } finally {
    await environment.cleanup();
    await sandbox.cleanup();
  }
});

test("runSandboxCommand exposes the mounted environment when a Podman runtime is operational", async (t) => {
  const provider = await createOperationalRuntimeProvider();
  if (!provider) {
    t.skip("No operational Podman runtime is available.");
    return;
  }

  const request = buildDetonationBenchmarkRequest("malicious-staged-download");
  const environment = await prepareDetonationEnvironment(request);

  try {
    const result = await runSandboxCommand(provider, environment, "bash", [
      "-lc",
      [
        `test -f ${environment.container.configPath}`,
        `test -f ${environment.container.memoryFiles.memory}`,
        `test -f ${environment.container.memoryFiles.soul}`,
        `test -f ${environment.container.memoryFiles.user}`,
        `test -f ${environment.container.honeypots.envFile}`,
        `test -f ${environment.container.honeypots.sshKey}`,
        `test -f ${path.posix.join(environment.container.skillDir, "SKILL.md")}`,
        `test -f ${path.posix.join(environment.container.skillDir, "scripts", "install.sh")}`,
      ].join(" && "),
    ]);

    assert.equal(result.exitCode, 0);
  } finally {
    await environment.cleanup();
  }
});

test("runSandboxCommand preserves the baseline when memory files mutate", async (t) => {
  const provider = await createOperationalRuntimeProvider();
  if (!provider) {
    t.skip("No operational Podman runtime is available.");
    return;
  }

  const request = buildDetonationBenchmarkRequest("malicious-memory-poisoning");
  const environment = await prepareDetonationEnvironment(request);

  try {
    const result = await runSandboxCommand(provider, environment, "bash", [
      "-lc",
      `printf '\\n- poisoned by smoke test\\n' >> ${environment.container.memoryFiles.memory}`,
    ]);

    assert.equal(result.exitCode, 0);

    const baselineText = await readFile(environment.baseline.memoryFiles.memory, "utf8");
    const liveText = await readFile(environment.host.memoryFiles.memory, "utf8");

    assert.equal(baselineText.includes("poisoned by smoke test"), false);
    assert.equal(liveText.includes("poisoned by smoke test"), true);
  } finally {
    await environment.cleanup();
  }
});

test("runSandboxCommand forwards timeout options to the runtime provider", async () => {
  const request = buildDetonationBenchmarkRequest("malicious-staged-download");
  const environment = await prepareDetonationEnvironment(request);
  let observedTimeoutMs: number | undefined;
  let observedArgs: string[] = [];

  try {
    await runSandboxCommand(
      {
        runtime: "podman",
        command: "podman",
        async ensureSandboxImage() {
          return {
            runtime: "podman",
            runtimeCommand: "podman",
            imageTag: defaultSandboxImageTag,
            source: "cache",
          };
        },
        async runRuntimeCommand(args, options) {
          observedArgs = args;
          observedTimeoutMs = options?.timeoutMs;
          return {
            exitCode: 0,
            stdout: "",
            stderr: "",
          };
        },
      },
      environment,
      "bash",
      ["-lc", "true"],
      { timeoutMs: 2500 },
    );

    assert.equal(observedTimeoutMs, 2500);
    assert.equal(observedArgs.includes("--cap-add=SYS_PTRACE"), true);
    const seccompIndex = observedArgs.indexOf("seccomp=unconfined");
    assert.ok(seccompIndex > 0, "seccomp=unconfined should be present in args");
    assert.equal(
      observedArgs[seccompIndex - 1],
      "--security-opt",
      "seccomp=unconfined should follow --security-opt",
    );
  } finally {
    await environment.cleanup();
  }
});

async function assertPathExists(filePath: string): Promise<void> {
  await stat(filePath);
}

async function assertPathMissing(filePath: string): Promise<void> {
  await assert.rejects(stat(filePath));
}

async function collectRelativeFiles(rootDir: string): Promise<string[]> {
  const files: string[] = [];

  async function visit(prefix: string): Promise<void> {
    const directoryPath = path.join(rootDir, prefix);
    const entries = await readdir(directoryPath, { withFileTypes: true });

    for (const entry of entries) {
      const relativePath = path.posix.join(prefix, entry.name);
      if (entry.isDirectory()) {
        await visit(relativePath);
        continue;
      }

      if (entry.isFile()) {
        files.push(relativePath);
      }
    }
  }

  await visit("");
  return files.sort((left, right) => left.localeCompare(right));
}

async function createOperationalRuntimeProvider() {
  try {
    const runtimeDetector = createPlatformAdapter().containerRuntimes;
    const provider = await createDetonationRuntimeProvider({
      runtimeDetector,
      preferredRuntime: "podman",
    });
    if (provider.runtime !== "podman") {
      return undefined;
    }

    const image = await provider.ensureSandboxImage();
    const smoke = await provider.runRuntimeCommand([
      "run",
      "--rm",
      image.imageTag ?? defaultSandboxImageTag,
      "node",
      "--version",
    ]);
    if (smoke.exitCode !== 0) {
      return undefined;
    }

    return provider;
  } catch {
    return undefined;
  }
}

async function createSandbox(
  prefix: string,
): Promise<{ root: string; cleanup: () => Promise<void> }> {
  const root = await mkdtemp(path.join(tmpdir(), prefix));
  return {
    root,
    cleanup: async () => rm(root, { recursive: true, force: true }),
  };
}

async function buildDetonationRequest(
  sandboxRoot: string,
  skillPath: string,
  skillSlug: string,
): Promise<DetonationRequest> {
  const snapshotResult = await buildSkillSnapshot({
    skillPath,
    skillSlug,
    skillRootPath: path.join(sandboxRoot, "skills"),
    skillRootKind: "workspace",
    discoverySource: "config",
    workspaceId: "workspace:default",
    detectedAt: "2026-03-14T00:00:00.000Z",
  });

  if (!snapshotResult.ok) {
    assert.fail(snapshotResult.error.message);
  }

  return {
    requestId: `test-${skillSlug}`,
    snapshot: snapshotResult.snapshot,
    prompts: ["Initialize the skill."],
    timeoutSeconds: 30,
  };
}
