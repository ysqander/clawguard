import { mkdir, readFile, rm } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDirectory, "..");
const releaseDirectory = path.join(repoRoot, ".release");

async function main() {
  const dryRunResult = await pack(["--json", "--dry-run"]);
  await assertPackResult(dryRunResult);

  await rm(releaseDirectory, { recursive: true, force: true });
  await mkdir(releaseDirectory, { recursive: true });

  const packResult = await pack(["--json", "--pack-destination", releaseDirectory]);
  console.log(path.join(releaseDirectory, packResult.filename));
}

async function pack(args) {
  const result = await run("npm", ["pack", ...args], { cwd: repoRoot });
  const [packResult] = JSON.parse(result.stdout);

  if (!packResult || typeof packResult !== "object") {
    throw new Error("npm pack did not return a valid pack result");
  }

  return packResult;
}

async function assertPackResult(packResult) {
  const packageJson = JSON.parse(await readFile(path.join(repoRoot, "package.json"), "utf8"));
  const filePaths = packResult.files.map((file) => file.path);

  if (packageJson.bin?.clawguard !== "./dist/index.js") {
    throw new Error("Root package must expose the clawguard bin from ./dist/index.js");
  }

  if (!filePaths.includes("dist/index.js")) {
    throw new Error("Packed artifact is missing dist/index.js");
  }

  if (!filePaths.includes("dist/daemon.js")) {
    throw new Error("Packed artifact is missing dist/daemon.js");
  }

  if (!filePaths.includes("sandbox/Containerfile")) {
    throw new Error("Packed artifact is missing sandbox/Containerfile");
  }

  for (const filePath of filePaths) {
    if (
      filePath === "package.json" ||
      filePath === "README.md" ||
      filePath.startsWith("dist/") ||
      filePath === "sandbox/Containerfile"
    ) {
      continue;
    }

    throw new Error(`Packed artifact included an unexpected file: ${filePath}`);
  }
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

await main();
