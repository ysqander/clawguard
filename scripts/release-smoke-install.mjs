import { access, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDirectory, "..");
const releaseDirectory = path.join(repoRoot, ".release");
const smokeSkillSlug = "release-smoke-skill";

async function main() {
  const tarballPath = await resolveTarballPath();
  const installRoot = mkdtempSync(path.join(tmpdir(), "clawguard-release-install-"));
  const socketPath = path.join(installRoot, "clawguard-daemon.sock");
  const env = {
    ...process.env,
    npm_config_audit: "false",
    npm_config_fund: "false",
    npm_config_update_notifier: "false",
  };

  try {
    createSmokeSkill(path.join(installRoot, "skills"), smokeSkillSlug);
    await run("npm", ["install", "--prefix", installRoot, tarballPath], { env });

    const binPath = path.join(installRoot, "node_modules", ".bin", "clawguard");
    await access(binPath);

    await run(binPath, ["--help"], { cwd: installRoot, env });
    const daemon = startDaemon(binPath, installRoot, socketPath, env);

    try {
      await waitForDaemonReady(daemon);
      await run(binPath, ["status"], {
        cwd: installRoot,
        env: {
          ...env,
          CLAWGUARD_DAEMON_SOCKET: socketPath,
        },
      });
      const detonate = await runAllowFailure(binPath, ["detonate", smokeSkillSlug], {
        cwd: installRoot,
        env: {
          ...env,
          CLAWGUARD_DAEMON_SOCKET: socketPath,
        },
      });

      if (detonate.code !== 0 && !detonate.stderr.includes("runtime_unavailable")) {
        throw new Error(
          `Installed detonation smoke failed unexpectedly (code=${detonate.code} stderr=${detonate.stderr.trim()})`,
        );
      }
    } finally {
      await stopDaemon(daemon);
    }
  } finally {
    await rm(installRoot, { recursive: true, force: true });
  }
}

async function resolveTarballPath() {
  const releaseFiles = await readdir(releaseDirectory);
  const tarballName = releaseFiles.find((filePath) => filePath.endsWith(".tgz"));

  if (!tarballName) {
    throw new Error("No packed release tarball found under .release");
  }

  return path.join(releaseDirectory, tarballName);
}

function startDaemon(binPath, cwd, socketPath, env) {
  return spawn(binPath, ["daemon"], {
    cwd,
    env: {
      ...env,
      CLAWGUARD_DAEMON_SOCKET: socketPath,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function waitForDaemonReady(daemon) {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    let resolved = false;

    const cleanup = () => {
      daemon.stdout.off("data", onStdout);
      daemon.stderr.off("data", onStderr);
      daemon.off("error", onError);
      daemon.off("exit", onExit);
    };

    const onStdout = (chunk) => {
      stdout += chunk.toString("utf8");
      if (stdout.includes("clawguard daemon listening on")) {
        resolved = true;
        cleanup();
        resolve();
      }
    };

    const onStderr = (chunk) => {
      stderr += chunk.toString("utf8");
    };

    const onError = (error) => {
      cleanup();
      reject(error);
    };

    const onExit = (code, signal) => {
      if (resolved) {
        return;
      }

      cleanup();
      reject(
        new Error(
          `Installed daemon exited before becoming ready (code=${String(code)} signal=${String(signal)} stderr=${stderr.trim()})`,
        ),
      );
    };

    daemon.stdout.on("data", onStdout);
    daemon.stderr.on("data", onStderr);
    daemon.on("error", onError);
    daemon.on("exit", onExit);
  });
}

async function stopDaemon(daemon) {
  if (daemon.exitCode !== null || daemon.killed) {
    return;
  }

  daemon.kill("SIGTERM");

  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      if (daemon.exitCode === null) {
        daemon.kill("SIGKILL");
      }
    }, 2000);

    daemon.once("exit", (code, signal) => {
      clearTimeout(timer);
      if (
        code === 0 ||
        code === 129 ||
        code === 130 ||
        code === 143 ||
        signal === "SIGTERM" ||
        signal === "SIGKILL"
      ) {
        resolve();
        return;
      }

      reject(
        new Error(
          `Installed daemon failed to stop cleanly (code=${String(code)} signal=${String(signal)})`,
        ),
      );
    });
  });
}

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd ?? repoRoot,
      env: options.env ?? process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    const stdout = [];
    const stderr = [];

    child.stdout.on("data", (chunk) => {
      stdout.push(Buffer.from(chunk));
    });
    child.stderr.on("data", (chunk) => {
      stderr.push(Buffer.from(chunk));
    });

    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve({
          stdout: Buffer.concat(stdout).toString("utf8"),
          stderr: Buffer.concat(stderr).toString("utf8"),
        });
        return;
      }

      reject(
        new Error(
          `${command} ${args.join(" ")} failed with exit code ${String(code)}: ${Buffer.concat(
            stderr,
          )
            .toString("utf8")
            .trim()}`,
        ),
      );
    });
  });
}

function runAllowFailure(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd ?? repoRoot,
      env: options.env ?? process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    const stdout = [];
    const stderr = [];

    child.stdout.on("data", (chunk) => {
      stdout.push(Buffer.from(chunk));
    });
    child.stderr.on("data", (chunk) => {
      stderr.push(Buffer.from(chunk));
    });

    child.on("error", reject);
    child.on("close", (code) => {
      resolve({
        code: code ?? 1,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });
  });
}

function createSmokeSkill(skillsRoot, slug) {
  const skillRoot = path.join(skillsRoot, slug);
  mkdirSync(skillRoot, { recursive: true });
  writeFileSync(
    path.join(skillRoot, "SKILL.md"),
    "# Release Smoke Skill\nSummarize release notes for the operator.\n",
    "utf8",
  );
}

await main();
