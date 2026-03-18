import assert from "node:assert/strict";
import test from "node:test";

import type { OpenClawWorkspaceModel } from "@clawguard/contracts";
import type {
  FileWatchEvent,
  FileWatcher,
  WatchOptions,
  WatchHandlers,
  WatchSubscription,
} from "@clawguard/platform";

import {
  SkillWatcherPipeline,
  resolveSkillPathFromEvent,
  type SkillWatcherPipelineErrorContext,
} from "./watcher-pipeline.js";

test("resolveSkillPathFromEvent maps nested changes to the top-level skill dir", () => {
  assert.equal(
    resolveSkillPathFromEvent(
      "/tmp/workspace/skills",
      "/tmp/workspace/skills/example/src/index.ts",
    ),
    "/tmp/workspace/skills/example",
  );
  assert.equal(
    resolveSkillPathFromEvent("/tmp/workspace/skills", "/tmp/other/location"),
    undefined,
  );
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
    onRootRescanRequested() {},
    onError() {},
  });

  await pipeline.start();

  fakeWatcher.emit("/tmp/workspace/skills", createEvent("/tmp/workspace/skills/weather/SKILL.md"));
  await wait(15);
  fakeWatcher.emit("/tmp/workspace/skills", createEvent("/tmp/workspace/skills/weather/src/a.ts"));
  await wait(15);
  fakeWatcher.emit("/tmp/workspace/skills", createEvent("/tmp/workspace/skills/weather/src/b.ts"));

  await wait(30);

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
  const rootRescans: string[] = [];
  const errors: SkillWatcherPipelineErrorContext[] = [];
  const activated: string[] = [];

  const pipeline = new SkillWatcherPipeline({
    workspaceModel: buildWorkspaceModel(),
    watcher: fakeWatcher,
    debounceMs: 10,
    retryDelayMs: 20,
    onScanScheduled(scan) {
      scheduled.push(`${scan.skillRootPath}=>${scan.skillSlug}`);
    },
    onRootRescanRequested(request) {
      rootRescans.push(request.skillRootPath);
    },
    onWatchActivated(context) {
      activated.push(context.skillRootPath);
    },
    onError(_error, context) {
      errors.push(context);
    },
  });

  await pipeline.start();
  await wait(30);

  fakeWatcher.emit("/tmp/managed-skills", createEvent("/tmp/managed-skills/clock/SKILL.md"));
  fakeWatcher.emit("/tmp/extra-skills", createEvent("/tmp/extra-skills"));
  fakeWatcher.triggerError("/tmp/extra-skills", new Error("runtime watch failure"));
  await wait(30);
  fakeWatcher.emit("/tmp/extra-skills", createEvent("/tmp/extra-skills/timer/SKILL.md"));
  fakeWatcher.emit("/tmp/fallback-skills", createEvent("/tmp/fallback-skills/alarm/SKILL.md"));

  await wait(50);

  assert.deepEqual(scheduled.sort(), [
    "/tmp/extra-skills=>timer",
    "/tmp/fallback-skills=>alarm",
    "/tmp/managed-skills=>clock",
  ]);
  assert.deepEqual(rootRescans, ["/tmp/extra-skills"]);
  assert.deepEqual(activated.sort(), [
    "/tmp/extra-skills",
    "/tmp/extra-skills",
    "/tmp/fallback-skills",
    "/tmp/managed-skills",
    "/tmp/workspace/skills",
  ]);
  assert.deepEqual(errors.map((error) => error.phase).sort(), ["watch-runtime", "watch-start"]);

  await pipeline.stop();
});

test("coalesces repeated root-level events into one root rescan request", async () => {
  const fakeWatcher = new FakeFileWatcher();
  const rootRescans: Array<{ path: string; eventCount: number; workspaceId?: string }> = [];

  const pipeline = new SkillWatcherPipeline({
    workspaceModel: buildWorkspaceModel(),
    watcher: fakeWatcher,
    debounceMs: 20,
    now: () => "2026-03-09T00:00:00.000Z",
    onScanScheduled() {},
    onRootRescanRequested(request) {
      rootRescans.push({
        path: request.skillRootPath,
        eventCount: request.events.length,
        ...(request.workspaceId !== undefined ? { workspaceId: request.workspaceId } : {}),
      });
    },
    onError() {},
  });

  await pipeline.start();

  fakeWatcher.emit("/tmp/workspace/skills", createEvent("/tmp/workspace/skills"));
  await wait(10);
  fakeWatcher.emit("/tmp/workspace/skills", createEvent("/tmp/workspace/skills"));

  await wait(30);

  assert.deepEqual(rootRescans, [
    {
      path: "/tmp/workspace/skills",
      eventCount: 2,
      workspaceId: "config:primary",
    },
  ]);

  await pipeline.stop();
});

test("routes scan scheduling failures to onError without unhandled rejections", async () => {
  const fakeWatcher = new FakeFileWatcher();
  const errors: SkillWatcherPipelineErrorContext[] = [];
  const unhandled: string[] = [];
  const onUnhandledRejection = (error: unknown) => {
    unhandled.push(error instanceof Error ? error.message : String(error));
  };
  process.on("unhandledRejection", onUnhandledRejection);

  const pipeline = new SkillWatcherPipeline({
    workspaceModel: buildWorkspaceModel(),
    watcher: fakeWatcher,
    debounceMs: 10,
    onScanScheduled: async () => {
      throw new Error("schedule failed");
    },
    onRootRescanRequested() {},
    onError(_error, context) {
      errors.push(context);
    },
  });

  try {
    await pipeline.start();
    fakeWatcher.emit(
      "/tmp/workspace/skills",
      createEvent("/tmp/workspace/skills/weather/SKILL.md"),
    );

    await wait(30);

    assert.deepEqual(unhandled, []);
    assert.deepEqual(errors, [
      {
        phase: "schedule-skill-scan",
        skillRootPath: "/tmp/workspace/skills",
        skillRootKind: "workspace",
        discoverySource: "config",
        workspaceId: "config:primary",
        skillPath: "/tmp/workspace/skills/weather",
      },
    ]);
  } finally {
    process.off("unhandledRejection", onUnhandledRejection);
    await pipeline.stop();
  }
});

test("routes root rescan scheduling failures to onError", async () => {
  const fakeWatcher = new FakeFileWatcher();
  const errors: SkillWatcherPipelineErrorContext[] = [];

  const pipeline = new SkillWatcherPipeline({
    workspaceModel: buildWorkspaceModel(),
    watcher: fakeWatcher,
    debounceMs: 10,
    onScanScheduled() {},
    onRootRescanRequested: async () => {
      throw new Error("root rescan failed");
    },
    onError(_error, context) {
      errors.push(context);
    },
  });

  await pipeline.start();
  fakeWatcher.emit("/tmp/extra-skills", createEvent("/tmp/extra-skills"));

  await wait(30);

  assert.deepEqual(errors, [
    {
      phase: "schedule-root-rescan",
      skillRootPath: "/tmp/extra-skills",
      skillRootKind: "extra",
      discoverySource: "config",
    },
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
    _options?: WatchOptions,
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

  triggerError(directoryPath: string, error: Error): void {
    const handlers = this.handlersByRoot.get(directoryPath);
    if (handlers === undefined) {
      throw new Error(`expected a watcher for ${directoryPath}`);
    }
    handlers.onError?.(error);
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
        path: "/tmp/extra-skills",
        kind: "extra",
        source: "config",
        exists: true,
        precedence: 100,
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
