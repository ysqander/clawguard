import path from "node:path";
import { watch } from "node:fs";

import type { FileWatcher, WatchHandlers, WatchOptions, WatchSubscription } from "../types.js";

export class MacosFileWatcher implements FileWatcher {
  constructor(private readonly watchFactory: typeof watch = watch) {}

  async watchDirectory(
    directoryPath: string,
    handlers: WatchHandlers,
    options: WatchOptions = {},
  ): Promise<WatchSubscription> {
    const watcher = this.watchFactory(
      directoryPath,
      {
        recursive: options.recursive ?? true,
        signal: options.signal,
      },
      (eventType, fileName) => {
        const relativePath = fileName === null ? "" : typeof fileName === "string" ? fileName : "";

        handlers.onEvent({
          path: relativePath.length > 0 ? path.join(directoryPath, relativePath) : directoryPath,
          kind: normalizeWatchEventType(eventType),
          rawEventType: isKnownWatchEventType(eventType) ? eventType : "unknown",
          observedAt: new Date().toISOString(),
        });
      },
    );

    watcher.on("error", (error) => {
      handlers.onError?.(error instanceof Error ? error : new Error(String(error)));
    });

    return {
      async close() {
        watcher.close();
      },
    };
  }
}

export function normalizeWatchEventType(eventType: string): "updated" | "renamed" | "unknown" {
  switch (eventType) {
    case "change":
      return "updated";
    case "rename":
      return "renamed";
    default:
      return "unknown";
  }
}

function isKnownWatchEventType(eventType: string): eventType is "change" | "rename" {
  return eventType === "change" || eventType === "rename";
}
