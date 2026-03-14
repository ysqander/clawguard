import { spawn } from "node:child_process";
import path from "node:path";

import type { DetonationRuntimeKind } from "@clawguard/contracts";
import { createPlatformAdapter, type ContainerRuntimeDetector } from "@clawguard/platform";

export type DetonationRuntime = DetonationRuntimeKind;

export const defaultDetonationRuntime: DetonationRuntimeKind = "podman";
export const defaultSandboxImageTag = "ghcr.io/clawguard/detonation-sandbox:0.1.0";

const SANDBOX_CONTAINERFILE_PATH = path.resolve(import.meta.dirname, "../sandbox/Containerfile");
const SANDBOX_CONTEXT_DIR = path.resolve(import.meta.dirname, "../sandbox");

export interface RuntimeCommandResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

export interface RuntimeCommandExecutor {
  run(command: string, args: string[]): Promise<RuntimeCommandResult>;
}

export interface EnsureSandboxImageOptions {
  imageTag?: string;
  strategy?: "build" | "pull";
  containerfilePath?: string;
  contextDirectory?: string;
}

export interface EnsureSandboxImageResult {
  runtime: DetonationRuntimeKind;
  runtimeCommand: string;
  imageTag: string;
  source: "cache" | "built" | "pulled";
}

export interface DetonationRuntimeProvider {
  readonly runtime: DetonationRuntimeKind;
  readonly command: string;
  ensureSandboxImage(options?: EnsureSandboxImageOptions): Promise<EnsureSandboxImageResult>;
  runRuntimeCommand(args: string[]): Promise<RuntimeCommandResult>;
}

export interface CreateDetonationRuntimeProviderOptions {
  preferredRuntime?: DetonationRuntimeKind;
  runtimeDetector?: ContainerRuntimeDetector;
  commandExecutor?: RuntimeCommandExecutor;
}

export function createChildProcessRuntimeCommandExecutor(): RuntimeCommandExecutor {
  return {
    async run(command, args) {
      return await new Promise<RuntimeCommandResult>((resolve, reject) => {
        const child = spawn(command, args, {
          stdio: "pipe",
        });

        const stdoutChunks: Buffer[] = [];
        const stderrChunks: Buffer[] = [];

        child.stdout.on("data", (chunk) => {
          stdoutChunks.push(Buffer.from(chunk));
        });
        child.stderr.on("data", (chunk) => {
          stderrChunks.push(Buffer.from(chunk));
        });

        child.on("error", reject);
        child.on("close", (exitCode) => {
          resolve({
            exitCode: exitCode ?? 1,
            stdout: Buffer.concat(stdoutChunks).toString("utf8"),
            stderr: Buffer.concat(stderrChunks).toString("utf8"),
          });
        });
      });
    },
  };
}

export async function createDetonationRuntimeProvider(
  options: CreateDetonationRuntimeProviderOptions = {},
): Promise<DetonationRuntimeProvider> {
  const runtimeDetector = options.runtimeDetector ?? createPlatformAdapter().containerRuntimes;
  const detectedRuntime = await runtimeDetector.getPreferredRuntime(
    options.preferredRuntime ?? defaultDetonationRuntime,
  );

  if (detectedRuntime === undefined) {
    throw new Error(
      "No supported container runtime is available. Install Podman (preferred) or Docker.",
    );
  }

  const commandExecutor = options.commandExecutor ?? createChildProcessRuntimeCommandExecutor();

  return new ContainerRuntimeProvider(
    detectedRuntime.runtime,
    detectedRuntime.command,
    commandExecutor,
  );
}

class ContainerRuntimeProvider implements DetonationRuntimeProvider {
  public constructor(
    public readonly runtime: DetonationRuntimeKind,
    public readonly command: string,
    private readonly commandExecutor: RuntimeCommandExecutor,
  ) {}

  public async ensureSandboxImage(
    options: EnsureSandboxImageOptions = {},
  ): Promise<EnsureSandboxImageResult> {
    const imageTag = options.imageTag ?? defaultSandboxImageTag;

    if (await this.imageExists(imageTag)) {
      return {
        runtime: this.runtime,
        runtimeCommand: this.command,
        imageTag,
        source: "cache",
      };
    }

    const strategy = options.strategy ?? "build";
    if (strategy === "pull") {
      await this.runOrThrow(["pull", imageTag], `Unable to pull sandbox image ${imageTag}.`);
      return {
        runtime: this.runtime,
        runtimeCommand: this.command,
        imageTag,
        source: "pulled",
      };
    }

    const containerfilePath = options.containerfilePath ?? SANDBOX_CONTAINERFILE_PATH;
    const contextDirectory = options.contextDirectory ?? SANDBOX_CONTEXT_DIR;

    await this.runOrThrow(
      ["build", "--file", containerfilePath, "--tag", imageTag, contextDirectory],
      `Unable to build sandbox image ${imageTag}.`,
    );

    return {
      runtime: this.runtime,
      runtimeCommand: this.command,
      imageTag,
      source: "built",
    };
  }

  public async runRuntimeCommand(args: string[]): Promise<RuntimeCommandResult> {
    return await this.commandExecutor.run(this.command, args);
  }

  private async imageExists(imageTag: string): Promise<boolean> {
    if (this.runtime === "podman") {
      const result = await this.commandExecutor.run(this.command, ["image", "exists", imageTag]);
      return result.exitCode === 0;
    }

    const result = await this.commandExecutor.run(this.command, ["image", "inspect", imageTag]);
    return result.exitCode === 0;
  }

  private async runOrThrow(args: string[], message: string): Promise<void> {
    const result = await this.commandExecutor.run(this.command, args);

    if (result.exitCode !== 0) {
      throw new Error(`${message} ${result.stderr || result.stdout}`.trim());
    }
  }
}
