import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import type { ContainerRuntimeDetector, DetectedContainerRuntime } from "@clawguard/platform";

import {
  createChildProcessRuntimeCommandExecutor,
  createDetonationRuntimeProvider,
  RuntimeCommandTimeoutError,
} from "./index.js";
import { resolveDefaultSandboxBuildAssets } from "./runtime-provider.js";

function createRuntimeDetector(
  runtime?: DetectedContainerRuntime,
  available: DetectedContainerRuntime[] = runtime ? [runtime] : [],
): ContainerRuntimeDetector {
  return {
    async detectAvailableRuntimes() {
      return available;
    },
    async getPreferredRuntime(preferredRuntime) {
      if (preferredRuntime !== undefined) {
        const preferredMatch = available.find(
          (candidate) => candidate.runtime === preferredRuntime,
        );
        if (preferredMatch !== undefined) {
          return preferredMatch;
        }
      }

      return available[0];
    },
  };
}

test("createDetonationRuntimeProvider prefers Podman when both runtimes are available", async () => {
  const runtimeDetector = createRuntimeDetector(undefined, [
    {
      runtime: "docker",
      command: "docker",
    },
    {
      runtime: "podman",
      command: "podman",
    },
  ]);

  const provider = await createDetonationRuntimeProvider({
    runtimeDetector,
    commandExecutor: {
      async run() {
        return {
          exitCode: 0,
          stdout: "",
          stderr: "",
        };
      },
    },
  });

  assert.equal(provider.runtime, "podman");
  assert.equal(provider.command, "podman");
});

test("createDetonationRuntimeProvider uses the default child-process executor", async () => {
  const tempRoot = await mkdtemp(path.join(tmpdir(), "clawguard-detonation-provider-"));
  const fakeRuntimePath = path.join(tempRoot, "fake-runtime.mjs");

  await writeFile(
    fakeRuntimePath,
    `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === "image" && args[1] === "exists") {
  process.exit(1);
}
process.stdout.write("ok");
`,
    "utf8",
  );
  await chmod(fakeRuntimePath, 0o755);

  try {
    const provider = await createDetonationRuntimeProvider({
      runtimeDetector: createRuntimeDetector({
        runtime: "podman",
        command: fakeRuntimePath,
      }),
    });

    const result = await provider.ensureSandboxImage({ strategy: "pull" });

    assert.equal(result.runtime, "podman");
    assert.equal(result.runtimeCommand, fakeRuntimePath);
    assert.equal(result.source, "pulled");
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
});

test("createChildProcessRuntimeCommandExecutor captures successful output", async () => {
  const executor = createChildProcessRuntimeCommandExecutor();
  const result = await executor.run(process.execPath, [
    "--input-type=module",
    "--eval",
    "process.stdout.write('ok'); process.stderr.write('warn');",
  ]);

  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "ok");
  assert.equal(result.stderr, "warn");
});

test("createChildProcessRuntimeCommandExecutor returns non-zero exits without throwing", async () => {
  const executor = createChildProcessRuntimeCommandExecutor();
  const result = await executor.run(process.execPath, [
    "--input-type=module",
    "--eval",
    "process.stderr.write('bad'); process.exit(7);",
  ]);

  assert.equal(result.exitCode, 7);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "bad");
});

test("createChildProcessRuntimeCommandExecutor rejects missing commands", async () => {
  const executor = createChildProcessRuntimeCommandExecutor();

  await assert.rejects(() =>
    executor.run("/definitely/missing/clawguard-runtime-command", ["--version"]),
  );
});

test("createChildProcessRuntimeCommandExecutor times out long-running commands", async () => {
  const executor = createChildProcessRuntimeCommandExecutor();

  await assert.rejects(
    () =>
      executor.run(
        process.execPath,
        ["--input-type=module", "--eval", "setInterval(() => {}, 1000);"],
        { timeoutMs: 50 },
      ),
    (error) => {
      assert.ok(error instanceof RuntimeCommandTimeoutError);
      assert.match(error.message, /timed out/u);
      return true;
    },
  );
});

test("runtime providers share image-cache semantics across podman and docker", async () => {
  for (const runtime of ["podman", "docker"] as const) {
    const commandCalls: Array<{ command: string; args: string[] }> = [];
    const runtimeDetector = createRuntimeDetector({ runtime, command: runtime });

    const provider = await createDetonationRuntimeProvider({
      runtimeDetector,
      commandExecutor: {
        async run(command, args) {
          commandCalls.push({ command, args });

          const isImageCheck =
            runtime === "podman"
              ? args.join(" ") === "image exists ghcr.io/clawguard/detonation-sandbox:0.1.0"
              : args.join(" ") === "image inspect ghcr.io/clawguard/detonation-sandbox:0.1.0";

          if (isImageCheck) {
            return {
              exitCode: 1,
              stdout: "",
              stderr: "not found",
            };
          }

          return {
            exitCode: 0,
            stdout: "ok",
            stderr: "",
          };
        },
      },
    });

    const result = await provider.ensureSandboxImage();

    assert.equal(result.runtime, runtime);
    assert.equal(result.runtimeCommand, runtime);
    assert.equal(result.source, "built");
    assert.equal(commandCalls[0]?.command, runtime);
    assert.ok(commandCalls[1]?.args.includes("build"));
  }
});

test("resolveDefaultSandboxBuildAssets prefers a packaged sandbox beside bundled dist output", async () => {
  const tempRoot = await mkdtemp(path.join(tmpdir(), "clawguard-detonation-packaged-assets-"));

  try {
    const moduleDirectory = path.join(tempRoot, "dist");
    const sandboxDirectory = path.join(tempRoot, "sandbox");
    await mkdir(moduleDirectory, { recursive: true });
    await mkdir(sandboxDirectory, { recursive: true });
    await writeFile(path.join(sandboxDirectory, "Containerfile"), "FROM scratch\n", "utf8");

    const assets = resolveDefaultSandboxBuildAssets({
      moduleDirectory,
      cwd: path.join(tempRoot, "cwd"),
    });

    assert.deepEqual(assets, {
      containerfilePath: path.join(sandboxDirectory, "Containerfile"),
      contextDirectory: sandboxDirectory,
    });
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
});

test("resolveDefaultSandboxBuildAssets falls back to the workspace package sandbox", async () => {
  const tempRoot = await mkdtemp(path.join(tmpdir(), "clawguard-detonation-workspace-assets-"));

  try {
    const moduleDirectory = path.join(tempRoot, "packages", "detonation", "dist");
    const sandboxDirectory = path.join(tempRoot, "packages", "detonation", "sandbox");
    await mkdir(moduleDirectory, { recursive: true });
    await mkdir(sandboxDirectory, { recursive: true });
    await writeFile(path.join(sandboxDirectory, "Containerfile"), "FROM scratch\n", "utf8");

    const assets = resolveDefaultSandboxBuildAssets({
      moduleDirectory,
      cwd: path.join(tempRoot, "cwd"),
    });

    assert.deepEqual(assets, {
      containerfilePath: path.join(sandboxDirectory, "Containerfile"),
      contextDirectory: sandboxDirectory,
    });
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
});

test("ensureSandboxImage falls back to pulling when an explicit build context is missing", async () => {
  const commandCalls: Array<{ command: string; args: string[] }> = [];
  const provider = await createDetonationRuntimeProvider({
    runtimeDetector: createRuntimeDetector({ runtime: "docker", command: "docker" }),
    commandExecutor: {
      async run(command, args) {
        commandCalls.push({ command, args });

        if (args.join(" ") === "image inspect ghcr.io/clawguard/detonation-sandbox:0.1.0") {
          return {
            exitCode: 1,
            stdout: "",
            stderr: "not found",
          };
        }

        return {
          exitCode: 0,
          stdout: "ok",
          stderr: "",
        };
      },
    },
  });

  const result = await provider.ensureSandboxImage({
    containerfilePath: "/missing/Containerfile",
    contextDirectory: "/missing",
  });

  assert.equal(result.source, "pulled");
  assert.equal(
    commandCalls.some((call) => call.args.includes("build")),
    false,
  );
  assert.equal(
    commandCalls.some((call) => call.args.includes("pull")),
    true,
  );
});

test("sandbox Containerfile pins the base image by digest", async () => {
  const containerfilePath = path.resolve(import.meta.dirname, "../sandbox/Containerfile");
  const containerfile = await readFile(containerfilePath, "utf8");
  const firstLine = containerfile.split(/\r?\n/u)[0];

  assert.match(firstLine ?? "", /^FROM\s+\S+@sha256:[a-f0-9]{64}$/u);
});
