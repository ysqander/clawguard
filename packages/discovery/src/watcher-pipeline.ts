import path from "node:path";

import type { DiscoveredSkillRoot, OpenClawWorkspaceModel } from "@clawguard/contracts";
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

export interface SkillWatcherPipelineOptions {
  workspaceModel: OpenClawWorkspaceModel;
  watcher: FileWatcher;
  onScanScheduled(scan: ScheduledSkillScan): void | Promise<void>;
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

export class SkillWatcherPipeline {
  private readonly debounceMs: number;
  private readonly retryDelayMs: number;
  private readonly now: () => string;
  private readonly rootStateByPath = new Map<string, RootWatchState>();
  private readonly pendingScans = new Map<string, PendingScanBatch>();
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
    } catch {
      this.scheduleRootRetry(state);
    }
  }

  private async recoverRootWatch(state: RootWatchState, _error: Error): Promise<void> {
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
    const skillPath = resolveSkillPathFromEvent(root.path, event.path);
    if (skillPath === undefined) {
      return;
    }

    const existing = this.pendingScans.get(skillPath);
    if (existing !== undefined) {
      existing.events.push(event);
      return;
    }

    const timer = setTimeout(() => {
      const batch = this.pendingScans.get(skillPath);
      if (batch === undefined) {
        return;
      }

      this.pendingScans.delete(skillPath);
      void this.options.onScanScheduled({
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
    }, this.debounceMs);

    this.pendingScans.set(skillPath, {
      root,
      events: [event],
      timer,
    });
  }
}

export function resolveSkillPathFromEvent(
  rootPath: string,
  eventPath: string,
): string | undefined {
  const relativePath = path.relative(rootPath, eventPath);
  if (relativePath.startsWith("..") || path.isAbsolute(relativePath) || relativePath.length === 0) {
    return undefined;
  }

  const [skillSlug] = splitPath(relativePath);
  if (skillSlug === undefined || skillSlug.length === 0) {
    return undefined;
  }

  return path.join(rootPath, skillSlug);
}

function splitPath(filePath: string): string[] {
  return filePath
    .split(path.sep)
    .map((segment) => segment.trim())
    .filter((segment) => segment.length > 0 && segment !== ".");
}
