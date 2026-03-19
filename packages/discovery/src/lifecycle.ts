import { rm, rename } from "node:fs/promises";
import path from "node:path";

import { defaultClawGuardConfig, type PathsConfig } from "@clawguard/contracts";
import type { DecisionRecord, VerdictLevel } from "@clawguard/contracts";
import type { QuarantineRecord, StorageApi } from "@clawguard/storage";

export type LifecycleResolution =
  | {
      status: "allowed";
      decision: DecisionRecord;
    }
  | {
      status: "blocked";
      decision: DecisionRecord;
      blockedPath: string;
    }
  | {
      status: "quarantined";
      quarantine: QuarantineRecord;
    };

export interface SkillLifecycleManagerOptions {
  storage: StorageApi;
  now?: () => string;
  pathsConfig?: Pick<PathsConfig, "quarantineSuffix">;
}

export interface ResolveSkillLifecycleInput {
  scanId?: string;
  skillSlug: string;
  skillPath: string;
  contentHash: string;
}

export interface QuarantineSkillInput extends ResolveSkillLifecycleInput {
  reason?: string;
}

export interface ApplyPostScanDispositionInput extends ResolveSkillLifecycleInput {
  recommendation: VerdictLevel;
}

export interface AllowHashInput {
  contentHash: string;
  reason?: string;
}

export interface BlockHashInput {
  contentHash: string;
  reason?: string;
}

export interface RestoreSkillInput {
  quarantineId: string;
  reason?: string;
}

export interface DeleteSkillInput {
  quarantineId: string;
  reason?: string;
}

export interface ApplyOperatorAllowInput {
  skillSlug: string;
  contentHash: string;
  reason?: string;
}

export interface ApplyOperatorBlockInput extends ApplyOperatorAllowInput {
  skillPath: string;
}

export type PostScanLifecycleResolution =
  | {
      status: "allowed";
      decision?: DecisionRecord;
    }
  | {
      status: "blocked";
      decision: DecisionRecord;
      blockedPath: string;
    }
  | {
      status: "quarantined";
      quarantine: QuarantineRecord;
    };

const DEFAULT_ALLOW_REASON = "Allowed by operator";
const DEFAULT_BLOCK_REASON = "Blocked by operator";

export class SkillLifecycleManager {
  private readonly storage: StorageApi;
  private readonly now: () => string;
  private readonly quarantineSuffix: string;

  public constructor(options: SkillLifecycleManagerOptions) {
    this.storage = options.storage;
    this.now = options.now ?? (() => new Date().toISOString());
    this.quarantineSuffix =
      options.pathsConfig?.quarantineSuffix ?? defaultClawGuardConfig.paths.quarantineSuffix;
  }

  public async resolveSkillLifecycle(
    input: ResolveSkillLifecycleInput,
  ): Promise<LifecycleResolution> {
    const decision = await this.storage.getDecision(input.contentHash);

    if (decision?.decision === "allow") {
      return { status: "allowed", decision };
    }

    if (decision?.decision === "block") {
      await rm(input.skillPath, { recursive: true, force: true });
      return {
        status: "blocked",
        decision,
        blockedPath: input.skillPath,
      };
    }

    const quarantine = await this.quarantineSkill({
      ...input,
      reason: "Auto-quarantined pending operator review",
    });
    return { status: "quarantined", quarantine };
  }

  public async quarantineSkill(input: QuarantineSkillInput): Promise<QuarantineRecord> {
    const quarantinePath = await moveToQuarantine(input.skillPath, this.quarantineSuffix);
    await this.storage.upsertDecision({
      contentHash: input.contentHash,
      decision: "quarantine",
      reason: input.reason ?? "Skill quarantined pending review",
      createdAt: this.now(),
    });

    return this.storage.createQuarantineRecord({
      ...(input.scanId !== undefined ? { scanId: input.scanId } : {}),
      skillSlug: input.skillSlug,
      contentHash: input.contentHash,
      originalPath: input.skillPath,
      quarantinePath,
      state: "active",
      createdAt: this.now(),
      updatedAt: this.now(),
    });
  }

  public async applyPostScanDisposition(
    input: ApplyPostScanDispositionInput,
  ): Promise<PostScanLifecycleResolution> {
    const decision = await this.storage.getDecision(input.contentHash);

    if (decision?.decision === "allow") {
      return { status: "allowed", decision };
    }

    if (decision?.decision === "block") {
      await rm(input.skillPath, { recursive: true, force: true });
      return {
        status: "blocked",
        decision,
        blockedPath: input.skillPath,
      };
    }

    if (input.recommendation === "allow") {
      return { status: "allowed" };
    }

    const quarantine = await this.quarantineSkill({
      ...input,
      reason: "Auto-quarantined pending operator review",
    });
    return { status: "quarantined", quarantine };
  }

  public async allowHash(input: AllowHashInput): Promise<DecisionRecord> {
    return this.storage.upsertDecision({
      contentHash: input.contentHash,
      decision: "allow",
      reason: input.reason ?? DEFAULT_ALLOW_REASON,
      createdAt: this.now(),
    });
  }

  public async applyOperatorAllow(input: ApplyOperatorAllowInput): Promise<DecisionRecord> {
    const record = await this.findMatchingQuarantineRecord(input.skillSlug, input.contentHash);

    if (record?.state === "active") {
      await this.restoreSkill({
        quarantineId: record.quarantineId,
        ...(input.reason ? { reason: input.reason } : {}),
      });
    } else {
      await this.allowHash(input);
    }

    const decision = await this.storage.getDecision(input.contentHash);
    if (!decision) {
      throw new Error(`Failed to read allow decision for ${input.contentHash}`);
    }

    return decision;
  }

  public async applyOperatorBlock(input: ApplyOperatorBlockInput): Promise<DecisionRecord> {
    const record = await this.findMatchingQuarantineRecord(input.skillSlug, input.contentHash);

    if (record) {
      await this.deleteSkill({
        quarantineId: record.quarantineId,
        ...(input.reason ? { reason: input.reason } : {}),
      });
    } else {
      await rm(input.skillPath, { recursive: true, force: true });
      await this.blockHash(input);
    }

    const decision = await this.storage.getDecision(input.contentHash);
    if (!decision) {
      throw new Error(`Failed to read block decision for ${input.contentHash}`);
    }

    return decision;
  }

  public async blockHash(input: BlockHashInput): Promise<DecisionRecord> {
    return this.storage.upsertDecision({
      contentHash: input.contentHash,
      decision: "block",
      reason: input.reason ?? DEFAULT_BLOCK_REASON,
      createdAt: this.now(),
    });
  }

  public async restoreSkill(input: RestoreSkillInput): Promise<QuarantineRecord> {
    const record = await this.storage.getQuarantineRecord(input.quarantineId);
    if (!record) {
      throw new Error(`Unknown quarantine entry: ${input.quarantineId}`);
    }

    if (record.state === "deleted") {
      throw new Error(`Cannot restore deleted quarantine entry ${input.quarantineId}`);
    }

    await rename(record.quarantinePath, record.originalPath);
    const updated = await this.storage.setQuarantineState(input.quarantineId, "restored");
    if (!updated) {
      throw new Error(`Failed to update quarantine state for ${input.quarantineId}`);
    }

    await this.allowHash({
      contentHash: record.contentHash,
      reason: input.reason ?? DEFAULT_ALLOW_REASON,
    });

    return updated;
  }

  public async deleteSkill(input: DeleteSkillInput): Promise<QuarantineRecord> {
    const record = await this.storage.getQuarantineRecord(input.quarantineId);
    if (!record) {
      throw new Error(`Unknown quarantine entry: ${input.quarantineId}`);
    }

    if (record.state === "deleted") {
      throw new Error(`Cannot delete quarantine entry ${input.quarantineId} twice`);
    }

    const pathToDelete = record.state === "restored" ? record.originalPath : record.quarantinePath;
    await rm(pathToDelete, { recursive: true, force: true });

    const updated = await this.storage.setQuarantineState(input.quarantineId, "deleted");
    if (!updated) {
      throw new Error(`Failed to update quarantine state for ${input.quarantineId}`);
    }

    await this.blockHash({
      contentHash: record.contentHash,
      reason: input.reason ?? DEFAULT_BLOCK_REASON,
    });

    return updated;
  }

  private async findMatchingQuarantineRecord(
    skillSlug: string,
    contentHash: string,
  ): Promise<QuarantineRecord | undefined> {
    const records = await this.storage.listQuarantineRecords({ contentHash });
    const matching = records.filter(
      (record) => record.skillSlug === skillSlug && record.state !== "deleted",
    );

    return (
      matching.find((record) => record.state === "active") ??
      matching.find((record) => record.state === "restored")
    );
  }
}

async function moveToQuarantine(skillPath: string, quarantineSuffix: string): Promise<string> {
  const parentDir = path.dirname(skillPath);
  const basename = path.basename(skillPath);

  for (let attempt = 0; attempt < 100; attempt += 1) {
    const suffix = attempt === 0 ? "" : `-${attempt}`;
    const candidatePath = path.join(parentDir, `${basename}${quarantineSuffix}${suffix}`);

    try {
      await rename(skillPath, candidatePath);
      return candidatePath;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "EEXIST" || code === "ENOTEMPTY") {
        continue;
      }

      throw error;
    }
  }

  throw new Error(`Failed to move ${skillPath} to quarantine after multiple attempts`);
}
