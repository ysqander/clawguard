import assert from "node:assert/strict";
import test from "node:test";

import type { OpenClawWorkspaceModel } from "@clawguard/contracts";
import type {
  FileWatchEvent,
  FileWatcher,
  WatchHandlers,
  WatchSubscription,
} from "@clawguard/platform";

import { SkillWatcherPipeline, resolveSkillPathFromEvent } from "./watcher-pipeline.js";

test("resolveSkillPathFromEvent maps nested changes to the top-level skill dir", () => {
  assert.equal(
    resolveSkillPathFromEvent("/tmp/workspace/skills", "/tmp/workspace/skills/example/src/index.ts"),
    "/tmp/workspace/skills/example",
  );
  assert.equal(resolveSkillPathFromEvent("/tmp/workspace/skills", "/tmp/other/location"), undefined);
});

test("coalesces repeated file writes into one scheduled scan per skill", async () => {
  const fakeWatcher = new FakeFileWatcher();
  const scheduled: Array<{ skillPath: string; eventCount: number; workspaceId?: string }> = [];

  const pipeline = new SkillWatcherPipeline({
    workspaceModel: buildWorkspaceModel(),
    watcher: fakeWatcher,
    debounceMs: 20,
    now: () => "2026-03-09T00:00:00.000Z",
    onScanScheduled(scan) {
      scheduled.push({
        skillPath: scan.skillPath,
        eventCount: scan.events.length,
        ...(scan.workspaceId !== undefined ? { workspaceId: scan.workspaceId } : {}),
      });
    },
  });

  await pipeline.start();

  fakeWatcher.emit("/tmp/workspace/skills", createEvent("/tmp/workspace/skills/weather/SKILL.md"));
  fakeWatcher.emit("/tmp/workspace/skills", createEvent("/tmp/workspace/skills/weather/SKILL.md"));
  fakeWatcher.emit(
    "/tmp/workspace/skills",
    createEvent("/tmp/workspace/skills/weather/prompts/setup.md"),
  );

  await wait(40);

  assert.deepEqual(scheduled, [
    {
      skillPath: "/tmp/workspace/skills/weather",
      eventCount: 3,
      workspaceId: "config:primary",
    },
  ]);

  await pipeline.stop();
});

test("watches all discovered roots and recovers after transient watch failures", async () => {
  const fakeWatcher = new FakeFileWatcher({
    failFirstWatchFor: new Set(["/tmp/managed-skills"]),
  });
  const scheduled: string[] = [];

  const pipeline = new SkillWatcherPipeline({
    workspaceModel: buildWorkspaceModel(),
    watcher: fakeWatcher,
    debounceMs: 10,
    retryDelayMs: 20,
    onScanScheduled(scan) {
      scheduled.push(`${scan.skillRootPath}=>${scan.skillSlug}`);
    },
  });

  await pipeline.start();
  await wait(30);

  fakeWatcher.emit("/tmp/managed-skills", createEvent("/tmp/managed-skills/clock/SKILL.md"));
  fakeWatcher.emit("/tmp/fallback-skills", createEvent("/tmp/fallback-skills/alarm/SKILL.md"));

  await wait(40);

  assert.deepEqual(scheduled.sort(), [
    "/tmp/fallback-skills=>alarm",
    "/tmp/managed-skills=>clock",
  ]);

  await pipeline.stop();
});

class FakeFileWatcher implements FileWatcher {
  private readonly handlersByRoot = new Map<string, WatchHandlers>();
  private readonly failFirstWatchFor: Set<string>;

  constructor(options: { failFirstWatchFor?: Set<string> } = {}) {
    this.failFirstWatchFor = options.failFirstWatchFor ?? new Set<string>();
  }

  async watchDirectory(
    directoryPath: string,
    handlers: WatchHandlers,
    _options?: { recursive?: boolean },
  ): Promise<WatchSubscription> {
    if (this.failFirstWatchFor.has(directoryPath)) {
      this.failFirstWatchFor.delete(directoryPath);
      throw new Error(`simulated watch failure for ${directoryPath}`);
    }

    this.handlersByRoot.set(directoryPath, handlers);
    return {
      close: async () => {
        this.handlersByRoot.delete(directoryPath);
      },
    };
  }

  emit(directoryPath: string, event: FileWatchEvent): void {
    const handlers = this.handlersByRoot.get(directoryPath);
    if (handlers === undefined) {
      throw new Error(`expected a watcher for ${directoryPath}`);
    }
    handlers.onEvent(event);
  }
}

function buildWorkspaceModel(): OpenClawWorkspaceModel {
  return {
    configPath: "/tmp/.openclaw/openclaw.json",
    primaryWorkspaceId: "config:primary",
    workspaces: [
      {
        id: "config:primary",
        workspacePath: "/tmp/workspace",
        skillsPath: "/tmp/workspace/skills",
        source: "config",
        exists: true,
        precedence: 300,
        isPrimary: true,
      },
    ],
    skillRoots: [
      {
        path: "/tmp/workspace/skills",
        kind: "workspace",
        source: "config",
        exists: true,
        precedence: 300,
        workspaceId: "config:primary",
      },
      {
        path: "/tmp/managed-skills",
        kind: "managed",
        source: "default",
        exists: false,
        precedence: 200,
      },
      {
        path: "/tmp/fallback-skills",
        kind: "fallback",
        source: "default",
        exists: false,
        precedence: 50,
      },
    ],
    serviceSignals: [],
    warnings: [],
  };
}

function createEvent(path: string): FileWatchEvent {
  return {
    path,
    kind: "updated",
    rawEventType: "change",
    observedAt: "2026-03-09T00:00:00.000Z",
  };
}

async function wait(milliseconds: number): Promise<void> {
  await new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}
