export class UnsupportedPlatformError extends Error {
  readonly platform: string;

  constructor(platform: string) {
    super(`Unsupported platform: ${platform}`);
    this.name = "UnsupportedPlatformError";
    this.platform = platform;
  }
}

export class UnsupportedFeatureError extends Error {
  readonly platform: string;
  readonly feature: string;

  constructor(platform: string, feature: string) {
    super(`The ${feature} feature is not supported on ${platform}`);
    this.name = "UnsupportedFeatureError";
    this.platform = platform;
    this.feature = feature;
  }
}

export class CommandExecutionError extends Error {
  readonly command: string;
  readonly args: string[];
  readonly exitCode: number | null;
  readonly stderr: string;

  constructor(
    command: string,
    args: string[],
    exitCode: number | null,
    stderr: string,
    options?: { cause?: unknown }
  ) {
    super(`Command failed: ${command} ${args.join(" ")}`.trim(), options);
    this.name = "CommandExecutionError";
    this.command = command;
    this.args = [...args];
    this.exitCode = exitCode;
    this.stderr = stderr;
  }
}
