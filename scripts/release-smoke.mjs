import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDirectory, "..");
const smokeRoot = mkdtempSync(path.join(tmpdir(), "clawguard-release-smoke-"));
const socketPath = path.join(smokeRoot, "clawguard-daemon.sock");
const smokeSkillSlug = "release-smoke-skill";
const repoCliEntrypoint = path.join(repoRoot, "apps", "cli", "dist", "index.js");
const repoDaemonEntrypoint = path.join(repoRoot, "apps", "daemon", "dist", "index.js");

async function main() {
  try {
    createSmokeSkill(path.join(smokeRoot, "skills"), smokeSkillSlug);
    await run(process.execPath, [repoCliEntrypoint, "--help"], {
      cwd: smokeRoot,
    });
    const daemon = startDaemon();

    try {
      await waitForDaemonReady(daemon);
      await run(process.execPath, [repoCliEntrypoint, "status"], {
        cwd: smokeRoot,
        env: {
          ...process.env,
          CLAWGUARD_DAEMON_SOCKET: socketPath,
        },
      });
      const detonate = await runAllowFailure(
        process.execPath,
        [repoCliEntrypoint, "detonate", smokeSkillSlug],
        {
          cwd: smokeRoot,
          env: {
            ...process.env,
            CLAWGUARD_DAEMON_SOCKET: socketPath,
          },
        },
      );

      if (detonate.code !== 0 && !detonate.stderr.includes("runtime_unavailable")) {
        throw new Error(
          `Detonation smoke failed unexpectedly (code=${detonate.code} stderr=${detonate.stderr.trim()})`,
        );
      }
    } finally {
      await stopDaemon(daemon);
    }
  } finally {
    rmSync(smokeRoot, { recursive: true, force: true });
  }
}

function startDaemon() {
  return spawn(process.execPath, [repoDaemonEntrypoint], {
    cwd: smokeRoot,
    env: {
      ...process.env,
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
          `Daemon exited before becoming ready (code=${String(code)} signal=${String(signal)} stderr=${stderr.trim()})`,
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

  await new Promise((resolve) => {
    const timer = setTimeout(() => {
      if (daemon.exitCode === null) {
        daemon.kill("SIGKILL");
      }
    }, 2000);

    daemon.once("exit", () => {
      clearTimeout(timer);
      resolve();
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
          `${command} ${args.join(" ")} failed with exit code ${String(code)}: ${Buffer.concat(stderr).toString("utf8").trim()}`,
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
