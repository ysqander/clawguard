export { ArtifactStore } from "./artifact-store.js";
export { ClawGuardStorage, createStorage } from "./database.js";
export { STORAGE_SCHEMA_VERSION, storageMigrations } from "./migrations.js";
export {
  createMacosStoragePaths,
  defaultMacosStoragePaths,
  expandHomePath,
  resolveStoragePaths,
} from "./paths.js";

export type {
  CreateQuarantineRecordInput,
  ListQuarantineRecordsOptions,
  PersistScanInput,
  PersistStaticReportInput,
  QuarantineRecord,
  QuarantineState,
  StorageApi,
  StoragePaths,
  StoredArtifactRecord,
  StoredDetonationRun,
  StoredStaticReport,
  UpsertDecisionInput,
  WriteArtifactInput,
  WriteJsonArtifactInput,
} from "./types.js";
