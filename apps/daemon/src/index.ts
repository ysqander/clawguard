import { defaultDetonationRuntime } from "@clawguard/detonation";
import { macosPlatformAdapter } from "@clawguard/platform";
import { defaultMacosStoragePaths } from "@clawguard/storage";

export function startDaemon(): string {
  return [
    "clawguard daemon scaffold",
    `platform=${macosPlatformAdapter.capabilities.platform}`,
    `runtime=${defaultDetonationRuntime}`,
    `state=${defaultMacosStoragePaths.stateDbPath}`
  ].join(" | ");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(startDaemon());
}

