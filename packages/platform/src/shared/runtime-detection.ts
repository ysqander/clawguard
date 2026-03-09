import { detonationRuntimeKinds, type DetonationRuntimeKind } from "@clawguard/contracts";

import type { ContainerRuntimeDetector, DetectedContainerRuntime } from "../types.js";
import type { CommandRunner } from "./command-runner.js";

export interface RuntimeDetectorOptions {
  commandRunner: CommandRunner;
  commandOverrides?: Partial<Record<DetonationRuntimeKind, string>>;
}

export function createContainerRuntimeDetector(
  options: RuntimeDetectorOptions,
): ContainerRuntimeDetector {
  return {
    async detectAvailableRuntimes() {
      const runtimes = await Promise.all(
        detonationRuntimeKinds.map(async (runtime) =>
          detectRuntime(
            runtime,
            resolveRuntimeCommand(runtime, options.commandOverrides),
            options.commandRunner,
          ),
        ),
      );

      return runtimes.filter(
        (runtime): runtime is DetectedContainerRuntime => runtime !== undefined,
      );
    },

    async getPreferredRuntime(preferredRuntime) {
      const availableRuntimes = await this.detectAvailableRuntimes();

      if (preferredRuntime !== undefined) {
        const preferredMatch = availableRuntimes.find(
          (runtime) => runtime.runtime === preferredRuntime,
        );
        if (preferredMatch !== undefined) {
          return preferredMatch;
        }
      }

      return availableRuntimes[0];
    },
  };
}

async function detectRuntime(
  runtime: DetonationRuntimeKind,
  command: string,
  commandRunner: CommandRunner,
): Promise<DetectedContainerRuntime | undefined> {
  try {
    const result = await commandRunner.run(command, ["--version"]);
    if (result.exitCode !== 0) {
      return undefined;
    }

    const version = firstLine(result.stdout.trim()) ?? firstLine(result.stderr.trim());

    return {
      runtime,
      command,
      ...(version !== undefined ? { version } : {}),
    };
  } catch {
    return undefined;
  }
}

function resolveRuntimeCommand(
  runtime: DetonationRuntimeKind,
  overrides?: Partial<Record<DetonationRuntimeKind, string>>,
): string {
  return overrides?.[runtime] ?? runtime;
}

function firstLine(value: string): string | undefined {
  return value.split(/\r?\n/u).find((line) => line.trim().length > 0);
}
