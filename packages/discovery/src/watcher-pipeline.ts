import path from "node:path";

import {
  defaultClawGuardConfig,
  type DiscoveredSkillRoot,
  type OpenClawWorkspaceModel,
} from "@clawguard/contracts";
import type {
  FileWatchEvent,
  FileWatcher,
  WatchHandlers,
  WatchSubscription,
} from "@clawguard/platform";

export interface ScheduledSkillScan {
  idempotencyKey: string;
  requestedAt: string;
  trigger: "watcher";
  skillPath: string;
  skillSlug: string;
  skillRootPath: string;
  skillRootKind: DiscoveredSkillRoot["kind"];
  discoverySource: DiscoveredSkillRoot["source"];
  workspaceId?: string;
  events: FileWatchEvent[];
}

export interface ScheduledRootRescan {
  idempotencyKey: string;
  requestedAt: string;
  trigger: "watcher";
  skillRootPath: string;
  skillRootKind: DiscoveredSkillRoot["kind"];
  discoverySource: DiscoveredSkillRoot["source"];
  workspaceId?: string;
  events: FileWatchEvent[];
}

export interface SkillWatcherPipelineErrorContext {
  phase: "watch-start" | "watch-runtime" | "schedule-skill-scan" | "schedule-root-rescan";
  skillRootPath: string;
  skillRootKind: DiscoveredSkillRoot["kind"];
  discoverySource: DiscoveredSkillRoot["source"];
  workspaceId?: string;
  skillPath?: string;
}

export interface SkillWatcherPipelineWatchContext {
  skillRootPath: string;
  skillRootKind: DiscoveredSkillRoot["kind"];
  discoverySource: DiscoveredSkillRoot["source"];
  workspaceId?: string;
}

export interface SkillWatcherPipelineOptions {
  workspaceModel: OpenClawWorkspaceModel;
  watcher: FileWatcher;
  onScanScheduled(scan: ScheduledSkillScan): void | Promise<void>;
  onRootRescanRequested(request: ScheduledRootRescan): void | Promise<void>;
  onWatchActivated?(context: SkillWatcherPipelineWatchContext): void | Promise<void>;
  onError(error: Error, context: SkillWatcherPipelineErrorContext): void | Promise<void>;
  debounceMs?: number;
  retryDelayMs?: number;
  now?: () => string;
}

interface RootWatchState {
  root: DiscoveredSkillRoot;
  subscription: WatchSubscription | undefined;
  retryTimer: NodeJS.Timeout | undefined;
}

interface PendingScanBatch {
  root: DiscoveredSkillRoot;
  events: FileWatchEvent[];
  timer: NodeJS.Timeout;
}

interface PendingRootRescanBatch {
  root: DiscoveredSkillRoot;
  events: FileWatchEvent[];
  timer: NodeJS.Timeout;
}

type WatchEventTarget = { kind: "skill"; skillPath: string } | { kind: "root" };

const quarantinePathPattern = new RegExp(
  `${escapeForRegExp(defaultClawGuardConfig.paths.quarantineSuffix)}(?:-\\d+)?$`,
);

export class SkillWatcherPipeline {
  private readonly debounceMs: number;
  private readonly retryDelayMs: number;
  private readonly now: () => string;
  private readonly rootStateByPath = new Map<string, RootWatchState>();
  private readonly pendingScans = new Map<string, PendingScanBatch>();
  private readonly pendingRootRescans = new Map<string, PendingRootRescanBatch>();
  private running = false;

  constructor(private readonly options: SkillWatcherPipelineOptions) {
    this.debounceMs = options.debounceMs ?? 250;
    this.retryDelayMs = options.retryDelayMs ?? 1000;
    this.now = options.now ?? (() => new Date().toISOString());

    for (const root of options.workspaceModel.skillRoots) {
      this.rootStateByPath.set(root.path, { root, subscription: undefined, retryTimer: undefined });
    }
  }

  async start(): Promise<void> {
    if (this.running) {
      return;
    }

    this.running = true;
    await Promise.all(
      [...this.rootStateByPath.values()].map(async (state) => {
        await this.startRootWatch(state);
      }),
    );
  }

  async stop(): Promise<void> {
    this.running = false;

    await Promise.all(
      [...this.rootStateByPath.values()].map(async (state) => {
        if (state.retryTimer !== undefined) {
          clearTimeout(state.retryTimer);
          state.retryTimer = undefined;
        }
        if (state.subscription !== undefined) {
          await state.subscription.close();
          state.subscription = undefined;
        }
      }),
    );

    for (const batch of this.pendingScans.values()) {
      clearTimeout(batch.timer);
    }
    this.pendingScans.clear();

    for (const batch of this.pendingRootRescans.values()) {
      clearTimeout(batch.timer);
    }
    this.pendingRootRescans.clear();
  }

  private async startRootWatch(state: RootWatchState): Promise<void> {
    if (!this.running || state.subscription !== undefined) {
      return;
    }

    const handlers: WatchHandlers = {
      onEvent: (event) => {
        this.onWatchEvent(state.root, event);
      },
      onError: (error) => {
        void this.recoverRootWatch(state, error);
      },
    };

    try {
      state.subscription = await this.options.watcher.watchDirectory(state.root.path, handlers, {
        recursive: true,
      });
      await this.reportWatchActivated({
        skillRootPath: state.root.path,
        skillRootKind: state.root.kind,
        discoverySource: state.root.source,
        ...(state.root.workspaceId !== undefined ? { workspaceId: state.root.workspaceId } : {}),
      });
    } catch (error) {
      await this.reportError(error, {
        phase: "watch-start",
        skillRootPath: state.root.path,
        skillRootKind: state.root.kind,
        discoverySource: state.root.source,
        ...(state.root.workspaceId !== undefined ? { workspaceId: state.root.workspaceId } : {}),
      });
      this.scheduleRootRetry(state);
    }
  }

  private async recoverRootWatch(state: RootWatchState, error: Error): Promise<void> {
    await this.reportError(error, {
      phase: "watch-runtime",
      skillRootPath: state.root.path,
      skillRootKind: state.root.kind,
      discoverySource: state.root.source,
      ...(state.root.workspaceId !== undefined ? { workspaceId: state.root.workspaceId } : {}),
    });

    if (state.subscription !== undefined) {
      await state.subscription.close();
      state.subscription = undefined;
    }

    this.scheduleRootRetry(state);
  }

  private scheduleRootRetry(state: RootWatchState): void {
    if (!this.running || state.retryTimer !== undefined) {
      return;
    }

    state.retryTimer = setTimeout(() => {
      state.retryTimer = undefined;
      void this.startRootWatch(state);
    }, this.retryDelayMs);
  }

  private onWatchEvent(root: DiscoveredSkillRoot, event: FileWatchEvent): void {
    const target = resolveWatchEventTarget(root.path, event.path);
    if (target === undefined) {
      return;
    }

    if (target.kind === "root") {
      this.queueRootRescan(root, event);
    } else {
      this.queueSkillScan(root, target.skillPath, event);
    }
  }

  private queueSkillScan(
    root: DiscoveredSkillRoot,
    skillPath: string,
    event: FileWatchEvent,
  ): void {
    const existing = this.pendingScans.get(skillPath);
    if (existing !== undefined) {
      existing.events.push(event);
      this.resetSkillScanTimer(skillPath, existing);
      return;
    }

    const batch: PendingScanBatch = {
      root,
      events: [event],
      timer: setTimeout(() => {
        void this.flushSkillScan(skillPath);
      }, this.debounceMs),
    };
    this.pendingScans.set(skillPath, batch);
  }

  private resetSkillScanTimer(skillPath: string, batch: PendingScanBatch): void {
    clearTimeout(batch.timer);
    batch.timer = setTimeout(() => {
      void this.flushSkillScan(skillPath);
    }, this.debounceMs);
  }

  private async flushSkillScan(skillPath: string): Promise<void> {
    const batch = this.pendingScans.get(skillPath);
    if (batch === undefined) {
      return;
    }

    this.pendingScans.delete(skillPath);

    try {
      await this.options.onScanScheduled({
        idempotencyKey: `watcher:${skillPath}`,
        requestedAt: this.now(),
        trigger: "watcher",
        skillPath,
        skillSlug: path.basename(skillPath),
        skillRootPath: batch.root.path,
        skillRootKind: batch.root.kind,
        discoverySource: batch.root.source,
        ...(batch.root.workspaceId !== undefined ? { workspaceId: batch.root.workspaceId } : {}),
        events: [...batch.events],
      });
    } catch (error) {
      await this.reportError(error, {
        phase: "schedule-skill-scan",
        skillRootPath: batch.root.path,
        skillRootKind: batch.root.kind,
        discoverySource: batch.root.source,
        ...(batch.root.workspaceId !== undefined ? { workspaceId: batch.root.workspaceId } : {}),
        skillPath,
      });
    }
  }

  private queueRootRescan(root: DiscoveredSkillRoot, event: FileWatchEvent): void {
    const existing = this.pendingRootRescans.get(root.path);
    if (existing !== undefined) {
      existing.events.push(event);
      this.resetRootRescanTimer(root.path, existing);
      return;
    }

    const batch: PendingRootRescanBatch = {
      root,
      events: [event],
      timer: setTimeout(() => {
        void this.flushRootRescan(root.path);
      }, this.debounceMs),
    };
    this.pendingRootRescans.set(root.path, batch);
  }

  private resetRootRescanTimer(rootPath: string, batch: PendingRootRescanBatch): void {
    clearTimeout(batch.timer);
    batch.timer = setTimeout(() => {
      void this.flushRootRescan(rootPath);
    }, this.debounceMs);
  }

  private async flushRootRescan(rootPath: string): Promise<void> {
    const batch = this.pendingRootRescans.get(rootPath);
    if (batch === undefined) {
      return;
    }

    this.pendingRootRescans.delete(rootPath);

    try {
      await this.options.onRootRescanRequested({
        idempotencyKey: `watcher-root:${rootPath}`,
        requestedAt: this.now(),
        trigger: "watcher",
        skillRootPath: batch.root.path,
        skillRootKind: batch.root.kind,
        discoverySource: batch.root.source,
        ...(batch.root.workspaceId !== undefined ? { workspaceId: batch.root.workspaceId } : {}),
        events: [...batch.events],
      });
    } catch (error) {
      await this.reportError(error, {
        phase: "schedule-root-rescan",
        skillRootPath: batch.root.path,
        skillRootKind: batch.root.kind,
        discoverySource: batch.root.source,
        ...(batch.root.workspaceId !== undefined ? { workspaceId: batch.root.workspaceId } : {}),
      });
    }
  }

  private async reportError(
    error: unknown,
    context: SkillWatcherPipelineErrorContext,
  ): Promise<void> {
    try {
      await this.options.onError(
        error instanceof Error ? error : new Error(String(error)),
        context,
      );
    } catch {}
  }

  private async reportWatchActivated(context: SkillWatcherPipelineWatchContext): Promise<void> {
    if (!this.options.onWatchActivated) {
      return;
    }

    try {
      await this.options.onWatchActivated(context);
    } catch {}
  }
}

export function resolveSkillPathFromEvent(rootPath: string, eventPath: string): string | undefined {
  const relativePath = path.relative(rootPath, eventPath);
  if (relativePath.startsWith("..") || path.isAbsolute(relativePath) || relativePath.length === 0) {
    return undefined;
  }

  const [skillSlug] = splitPath(relativePath);
  if (skillSlug === undefined || skillSlug.length === 0) {
    return undefined;
  }

  if (quarantinePathPattern.test(skillSlug)) {
    return undefined;
  }

  return path.join(rootPath, skillSlug);
}

function resolveWatchEventTarget(
  rootPath: string,
  eventPath: string,
): WatchEventTarget | undefined {
  if (path.normalize(eventPath) === path.normalize(rootPath)) {
    return { kind: "root" };
  }

  const skillPath = resolveSkillPathFromEvent(rootPath, eventPath);
  if (skillPath === undefined) {
    return undefined;
  }

  return { kind: "skill", skillPath };
}

function splitPath(filePath: string): string[] {
  return filePath
    .split(path.sep)
    .map((segment) => segment.trim())
    .filter((segment) => segment.length > 0 && segment !== ".");
}

function escapeForRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
