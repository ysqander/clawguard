import path from "node:path";
import { pathToFileURL } from "node:url";

import { runDetonationPreflightBenchmarkCli } from "./index.js";

async function main(): Promise<void> {
  const { summary, exitCode } = await runDetonationPreflightBenchmarkCli();
  console.log(JSON.stringify(summary, null, 2));
  if (exitCode !== 0) {
    process.exitCode = exitCode;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  await main();
}
