import { defaultDetonationRuntime } from "@clawguard/detonation";
import { createPlatformAdapter } from "@clawguard/platform";
import { resolveStoragePaths } from "@clawguard/storage";

export async function startDaemon(): Promise<string> {
  const platformAdapter = createPlatformAdapter();
  const storagePaths = resolveStoragePaths();
  const preferredRuntime =
    await platformAdapter.containerRuntimes.getPreferredRuntime(defaultDetonationRuntime);

  return [
    "clawguard daemon scaffold",
    `platform=${platformAdapter.capabilities.platform}`,
    `runtime=${preferredRuntime?.runtime ?? `${defaultDetonationRuntime} (unavailable)`}`,
    `state=${storagePaths.stateDbPath}`,
  ].join(" | ");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(await startDaemon());
}
