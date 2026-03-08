import { spawn } from "node:child_process";

import { CommandExecutionError } from "../errors.js";

export interface CommandResult {
  command: string;
  args: string[];
  exitCode: number | null;
  stdout: string;
  stderr: string;
}

export interface RunCommandOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  input?: string;
  rejectOnNonZero?: boolean;
}

export interface CommandRunner {
  run(command: string, args?: string[], options?: RunCommandOptions): Promise<CommandResult>;
}

export function createCommandRunner(): CommandRunner {
  return {
    async run(command, args = [], options = {}) {
      const result = await new Promise<CommandResult>((resolve, reject) => {
        const child = spawn(command, args, {
          cwd: options.cwd,
          env: options.env,
          stdio: "pipe"
        });

        const stdoutChunks: Buffer[] = [];
        const stderrChunks: Buffer[] = [];

        child.stdout.on("data", (chunk) => {
          stdoutChunks.push(Buffer.from(chunk));
        });
        child.stderr.on("data", (chunk) => {
          stderrChunks.push(Buffer.from(chunk));
        });

        child.on("error", (error) => {
          reject(new CommandExecutionError(command, args, null, "", { cause: error }));
        });
        child.on("close", (exitCode) => {
          resolve({
            command,
            args: [...args],
            exitCode,
            stdout: Buffer.concat(stdoutChunks).toString("utf8"),
            stderr: Buffer.concat(stderrChunks).toString("utf8")
          });
        });

        if (options.input !== undefined) {
          child.stdin.write(options.input);
        }
        child.stdin.end();
      });

      if (options.rejectOnNonZero && result.exitCode !== 0) {
        throw new CommandExecutionError(command, args, result.exitCode, result.stderr);
      }

      return result;
    }
  };
}
