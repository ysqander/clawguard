import { copyFile, mkdir, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDirectory, "..");
const distDirectory = path.join(repoRoot, "dist");
const releaseSandboxDirectory = path.join(repoRoot, "sandbox");
const detonationSandboxDirectory = path.join(repoRoot, "packages", "detonation", "sandbox");

async function main() {
  await rm(distDirectory, { recursive: true, force: true });
  await mkdir(distDirectory, { recursive: true });
  await rm(releaseSandboxDirectory, { recursive: true, force: true });
  await mkdir(releaseSandboxDirectory, { recursive: true });

  await Promise.all([
    buildEntrypoint({
      entryPoint: path.join(repoRoot, "apps", "cli", "dist", "index.js"),
      outputPath: path.join(distDirectory, "index.js"),
    }),
    buildEntrypoint({
      entryPoint: path.join(repoRoot, "apps", "daemon", "dist", "index.js"),
      outputPath: path.join(distDirectory, "daemon.js"),
    }),
    copyFile(
      path.join(detonationSandboxDirectory, "Containerfile"),
      path.join(releaseSandboxDirectory, "Containerfile"),
    ),
  ]);
}

async function buildEntrypoint(options) {
  await build({
    absWorkingDir: repoRoot,
    entryPoints: [options.entryPoint],
    outfile: options.outputPath,
    bundle: true,
    format: "esm",
    platform: "node",
    target: "node22",
    sourcemap: true,
    logLevel: "info",
    legalComments: "none",
  });
}

await main();
