export interface StoragePaths {
  stateDbPath: string;
  artifactsRoot: string;
}

export const defaultMacosStoragePaths: StoragePaths = {
  stateDbPath: "~/Library/Application Support/ClawGuard/state.db",
  artifactsRoot: "~/Library/Application Support/ClawGuard/artifacts"
};

