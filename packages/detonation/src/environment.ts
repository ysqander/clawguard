import {
  chmod,
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readlink,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import type { DetonationRequest } from "@clawguard/contracts";

import type {
  DetonationRuntimeProvider,
  RunRuntimeCommandOptions,
  RuntimeCommandResult,
} from "./runtime-provider.js";

const ENVIRONMENT_TEMP_PREFIX = "clawguard-detonation-environment-";

const MEMORY_BASELINE_TEXT = `# MEMORY

- User prefers concise daily summaries.
- Workspace status is healthy as of 2026-03-14.
- Never execute remote scripts without explicit review.
`;

const SOUL_BASELINE_TEXT = `# SOUL

- Protect user data and secrets.
- Prefer local-only analysis when possible.
- Treat external downloads as suspicious until verified.
`;

const USER_BASELINE_TEXT = `# USER

- Primary operator: alex
- Preferred channels: terminal and local notifications
- Security posture: review suspicious skills before allowing them
`;

const HONEYPOT_ENV_TEXT = `ANTHROPIC_API_KEY=sk-ant-decoy-00000000000000000000000000000000
STRIPE_API_KEY=sk_live_decoy_000000000000000000000000
GITHUB_TOKEN=ghp_decoy0000000000000000000000000000000000
AWS_ACCESS_KEY_ID=AKIADECOY0000000000
AWS_SECRET_ACCESS_KEY=decoysecret00000000000000000000000000000000
`;

const HONEYPOT_SSH_KEY_TEXT = `-----BEGIN OPENSSH PRIVATE KEY-----
ZmFrZS1vcGVuc3NoLXByaXZhdGUta2V5LWZvci1kZXRvbmF0aW9uLWhvbmV5cG90LW9u
bHktZG8tbm90LXVzZS1mb3ItYXV0aGVudGljYXRpb24K
-----END OPENSSH PRIVATE KEY-----
`;

const PROMPT_HARNESS_RELATIVE_PATH = ".clawguard/prompt-harness.mjs";
const PROMPT_HARNESS_SOURCE = `import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key || !key.startsWith("--")) {
      continue;
    }

    if (value === undefined) {
      throw new Error(\`Missing value for argument \${key}.\`);
    }

    parsed[key.slice(2)] = value;
    index += 1;
  }

  if (typeof parsed.intent !== "string" || parsed.intent.length === 0) {
    throw new Error("Missing --intent.");
  }
  if (typeof parsed.prompt !== "string" || parsed.prompt.length === 0) {
    throw new Error("Missing --prompt.");
  }
  if (typeof parsed["skill-dir"] !== "string" || parsed["skill-dir"].length === 0) {
    throw new Error("Missing --skill-dir.");
  }

  return {
    intent: parsed.intent,
    prompt: parsed.prompt,
    skillDir: parsed["skill-dir"],
    workflowCommand:
      typeof parsed["workflow-command"] === "string" && parsed["workflow-command"].length > 0
        ? parsed["workflow-command"]
        : undefined,
  };
}

function toShellLiteral(value) {
  return \`'\${value.replaceAll("'", "'\\\\''")}'\`;
}

function extractSkillTitle(markdown) {
  for (const line of markdown.split(/\\r?\\n/u)) {
    const trimmed = line.trim();
    if (trimmed.startsWith("# ")) {
      return trimmed.slice(2).trim();
    }
  }

  return undefined;
}

async function runWorkflowCommand(skillDir, workflowCommand) {
  return await new Promise((resolve, reject) => {
    const child = spawn(
      "bash",
      ["-lc", \`cd \${toShellLiteral(skillDir)} && \${workflowCommand}\`],
      {
        stdio: "pipe",
      },
    );

    const stdoutChunks = [];
    const stderrChunks = [];

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
}

async function main() {
  const parsed = parseArgs(process.argv.slice(2));
  const skillMdPath = path.join(parsed.skillDir, "SKILL.md");

  let skillMarkdown = "";
  try {
    skillMarkdown = await readFile(skillMdPath, "utf8");
  } catch {}

  const output = {
    intent: parsed.intent,
    prompt: parsed.prompt,
    skillDir: parsed.skillDir,
    skillMdPath,
    skillMarkdownPresent: skillMarkdown.length > 0,
    skillTitle: extractSkillTitle(skillMarkdown),
    action: parsed.workflowCommand ? "workflow-command" : "noop",
    ...(parsed.workflowCommand ? { workflowCommand: parsed.workflowCommand } : {}),
  };

  if (!parsed.workflowCommand) {
    console.log(JSON.stringify(output));
    return;
  }

  const workflowResult = await runWorkflowCommand(parsed.skillDir, parsed.workflowCommand);
  console.log(
    JSON.stringify({
      ...output,
      workflowResult,
    }),
  );
  process.exit(workflowResult.exitCode);
}

await main();
`;

export interface DetonationSandboxLayout {
  homeDir: string;
  configPath: string;
  workspaceDir: string;
  skillsDir: string;
  memoryFiles: {
    memory: string;
    soul: string;
    user: string;
  };
  honeypots: {
    envFile: string;
    sshKey: string;
  };
}

export const defaultDetonationSandboxLayout: DetonationSandboxLayout = {
  homeDir: "/home/clawguard",
  configPath: "/home/clawguard/.openclaw/openclaw.json",
  workspaceDir: "/workspace/openclaw",
  skillsDir: "/workspace/openclaw/skills",
  memoryFiles: {
    memory: "/workspace/openclaw/MEMORY.md",
    soul: "/workspace/openclaw/SOUL.md",
    user: "/workspace/openclaw/USER.md",
  },
  honeypots: {
    envFile: "/home/clawguard/.env",
    sshKey: "/home/clawguard/.ssh/id_rsa",
  },
};

export interface PrepareDetonationEnvironmentOptions {
  parentDir?: string;
}

export interface PreparedDetonationEnvironmentPaths {
  rootDir: string;
  homeDir: string;
  configPath: string;
  workspaceDir: string;
  skillsDir: string;
  skillDir: string;
  helpers: {
    promptHarness: string;
  };
  memoryFiles: {
    memory: string;
    soul: string;
    user: string;
  };
  honeypots: {
    envFile: string;
    sshKey: string;
  };
}

export interface PreparedDetonationEnvironment {
  request: DetonationRequest;
  layout: DetonationSandboxLayout;
  host: PreparedDetonationEnvironmentPaths;
  baseline: PreparedDetonationEnvironmentPaths;
  container: {
    homeDir: string;
    configPath: string;
    workspaceDir: string;
    skillsDir: string;
    skillDir: string;
    helpers: {
      promptHarness: string;
    };
    memoryFiles: DetonationSandboxLayout["memoryFiles"];
    honeypots: DetonationSandboxLayout["honeypots"];
  };
  cleanup(): Promise<void>;
}

export interface RunSandboxCommandOptions extends RunRuntimeCommandOptions {
  imageTag?: string;
}

export async function prepareDetonationEnvironment(
  request: DetonationRequest,
  options: PrepareDetonationEnvironmentOptions = {},
): Promise<PreparedDetonationEnvironment> {
  const parentDir = options.parentDir ?? tmpdir();
  await mkdir(parentDir, { recursive: true });
  const rootDir = await mkdtemp(path.join(parentDir, ENVIRONMENT_TEMP_PREFIX));

  const host = buildHostPaths(rootDir, request.snapshot.slug);
  const baseline = buildBaselinePaths(rootDir, request.snapshot.slug);

  await mkdir(path.dirname(host.configPath), { recursive: true });
  await mkdir(path.dirname(host.honeypots.sshKey), { recursive: true });
  await mkdir(path.dirname(host.helpers.promptHarness), { recursive: true });
  await mkdir(host.skillsDir, { recursive: true });

  await writeFile(host.configPath, renderOpenClawConfig(defaultDetonationSandboxLayout), "utf8");
  await writeFile(host.memoryFiles.memory, MEMORY_BASELINE_TEXT, "utf8");
  await writeFile(host.memoryFiles.soul, SOUL_BASELINE_TEXT, "utf8");
  await writeFile(host.memoryFiles.user, USER_BASELINE_TEXT, "utf8");
  await writeFile(host.honeypots.envFile, HONEYPOT_ENV_TEXT, "utf8");
  await writeFile(host.honeypots.sshKey, HONEYPOT_SSH_KEY_TEXT, "utf8");
  await writeFile(host.helpers.promptHarness, PROMPT_HARNESS_SOURCE, "utf8");
  await chmod(host.honeypots.sshKey, 0o600);

  await copySnapshotFiles(request, host.skillDir);

  await mkdir(baseline.rootDir, { recursive: true });
  await cp(host.homeDir, baseline.homeDir, {
    recursive: true,
    dereference: false,
    verbatimSymlinks: true,
  });
  await cp(host.workspaceDir, baseline.workspaceDir, {
    recursive: true,
    dereference: false,
    verbatimSymlinks: true,
  });

  const cleanup = async (): Promise<void> => {
    await rm(rootDir, { recursive: true, force: true });
  };

  return {
    request,
    layout: defaultDetonationSandboxLayout,
    host,
    baseline,
    container: {
      homeDir: defaultDetonationSandboxLayout.homeDir,
      configPath: defaultDetonationSandboxLayout.configPath,
      workspaceDir: defaultDetonationSandboxLayout.workspaceDir,
      skillsDir: defaultDetonationSandboxLayout.skillsDir,
      skillDir: path.posix.join(defaultDetonationSandboxLayout.skillsDir, request.snapshot.slug),
      helpers: {
        promptHarness: path.posix.join(
          defaultDetonationSandboxLayout.workspaceDir,
          PROMPT_HARNESS_RELATIVE_PATH,
        ),
      },
      memoryFiles: defaultDetonationSandboxLayout.memoryFiles,
      honeypots: defaultDetonationSandboxLayout.honeypots,
    },
    cleanup,
  };
}

export async function runSandboxCommand(
  provider: DetonationRuntimeProvider,
  preparedEnvironment: PreparedDetonationEnvironment,
  command: string,
  args: string[],
  options: RunSandboxCommandOptions = {},
): Promise<RuntimeCommandResult> {
  const image = await provider.ensureSandboxImage({
    ...(options.imageTag !== undefined ? { imageTag: options.imageTag } : {}),
  });

  return await provider.runRuntimeCommand([
    "run",
    "--rm",
    "--workdir",
    preparedEnvironment.container.workspaceDir,
    "--env",
    `HOME=${preparedEnvironment.container.homeDir}`,
    "--volume",
    `${preparedEnvironment.host.homeDir}:${preparedEnvironment.container.homeDir}`,
    "--volume",
    `${preparedEnvironment.host.workspaceDir}:${preparedEnvironment.container.workspaceDir}`,
    image.imageTag,
    command,
    ...args,
  ], {
    ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
  });
}

async function copySnapshotFiles(
  request: DetonationRequest,
  destinationRoot: string,
): Promise<void> {
  await mkdir(destinationRoot, { recursive: true });

  for (const relativePath of request.snapshot.fileInventory) {
    const sourcePath = path.join(request.snapshot.path, relativePath);
    const destinationPath = path.join(destinationRoot, relativePath);
    const sourceStats = await lstat(sourcePath);

    await mkdir(path.dirname(destinationPath), { recursive: true });

    if (sourceStats.isFile()) {
      await writeFile(destinationPath, await readFile(sourcePath));
      await chmod(destinationPath, sourceStats.mode & 0o777);
      continue;
    }

    if (sourceStats.isSymbolicLink()) {
      await symlink(await readlink(sourcePath), destinationPath);
      continue;
    }

    throw new Error(
      `Unsupported snapshot entry type for ${relativePath}. Only files and symlinks are supported.`,
    );
  }
}

function buildHostPaths(rootDir: string, slug: string): PreparedDetonationEnvironmentPaths {
  const homeDir = path.join(rootDir, "home");
  const workspaceDir = path.join(rootDir, "workspace");
  const skillsDir = path.join(workspaceDir, "skills");

  return {
    rootDir,
    homeDir,
    configPath: path.join(homeDir, ".openclaw", "openclaw.json"),
    workspaceDir,
    skillsDir,
    skillDir: path.join(skillsDir, slug),
    helpers: {
      promptHarness: path.join(workspaceDir, PROMPT_HARNESS_RELATIVE_PATH),
    },
    memoryFiles: {
      memory: path.join(workspaceDir, "MEMORY.md"),
      soul: path.join(workspaceDir, "SOUL.md"),
      user: path.join(workspaceDir, "USER.md"),
    },
    honeypots: {
      envFile: path.join(homeDir, ".env"),
      sshKey: path.join(homeDir, ".ssh", "id_rsa"),
    },
  };
}

function buildBaselinePaths(rootDir: string, slug: string): PreparedDetonationEnvironmentPaths {
  return buildHostPaths(path.join(rootDir, "baseline"), slug);
}

function renderOpenClawConfig(layout: DetonationSandboxLayout): string {
  return JSON.stringify(
    {
      agents: {
        defaults: {
          workspace: layout.workspaceDir,
        },
      },
    },
    null,
    2,
  );
}
