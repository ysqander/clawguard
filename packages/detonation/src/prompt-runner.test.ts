import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import type { DetonationRequest } from "@clawguard/contracts";
import { loadFixtureSnapshot } from "@clawguard/fixtures";

import {
  buildPromptRunnerPlan,
  runPromptRunner,
  type PromptRunnerExecutionRecord,
} from "./prompt-runner.js";

const REQUEST_TIMEOUT_SECONDS = 90;

test("buildPromptRunnerPlan selects 3-5 prompts and follows setup instructions from SKILL.md", async () => {
  const request = {
    requestId: "request-setup",
    snapshot: loadFixtureSnapshot("malicious-staged-download"),
    prompts: ["Initialize skill once."],
    timeoutSeconds: REQUEST_TIMEOUT_SECONDS,
  };

  const plan = await buildPromptRunnerPlan(request);

  assert.equal(plan.promptCount >= 3, true);
  assert.equal(plan.promptCount <= 5, true);
  assert.equal(plan.setupCommandCount, 1);
  assert.equal(plan.steps.some((step) => step.type === "setup-command"), true);
  assert.equal(
    plan.steps.some((step) => step.value === "bash scripts/install.sh"),
    true,
  );
});

test("buildPromptRunnerPlan deduplicates prompts and keeps deterministic ordering", async () => {
  const request = {
    requestId: "request-dedupe",
    snapshot: loadFixtureSnapshot("benign-calendar-helper"),
    prompts: [
      "Review SKILL.md and summarize declared capabilities.",
      "Review SKILL.md and summarize declared capabilities.",
      "Execute one representative workflow end-to-end and note side effects.",
    ],
    timeoutSeconds: REQUEST_TIMEOUT_SECONDS,
  };

  const plan = await buildPromptRunnerPlan(request);

  const promptValues = plan.steps
    .filter((step) => step.type === "prompt")
    .map((step) => step.value);
  const uniquePromptValues = [...new Set(promptValues)];

  assert.deepEqual(promptValues, uniquePromptValues);
  assert.equal(promptValues[0], "Review SKILL.md and summarize declared capabilities.");
});

test("runPromptRunner records execution sequence including setup command intent", async () => {
  const request = {
    requestId: "request-execution",
    snapshot: loadFixtureSnapshot("malicious-staged-download"),
    prompts: ["Initialize skill once."],
    timeoutSeconds: REQUEST_TIMEOUT_SECONDS,
  };

  const execution: PromptRunnerExecutionRecord[] = [];

  const result = await runPromptRunner(
    {
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
    },
    request,
    {
      async prepareEnvironment(requestInput) {
        return {
          request: requestInput,
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
            skillDir: "/tmp/root/workspace/skills/productivity-booster",
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
            skillDir: "/tmp/root/baseline/workspace/skills/productivity-booster",
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
            skillDir: "/workspace/openclaw/skills/productivity-booster",
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
          async cleanup() {},
        };
      },
      async commandRunner(_provider, _environment, command, args) {
        execution.push({
          stepId: `stub-${execution.length + 1}`,
          type: "setup-command",
          intent: "follow-declared-setup-instructions",
          value: `${command} ${args.join(" ")}`,
          startedAt: new Date(0).toISOString(),
          completedAt: new Date(0).toISOString(),
        });

        return {
          exitCode: 0,
          stdout: "ok",
          stderr: "",
        };
      },
    },
  );

  assert.equal(result.execution.length >= result.plan.promptCount, true);
  assert.equal(
    result.execution.some((entry) => entry.type === "setup-command" && entry.result?.exitCode === 0),
    true,
  );
  assert.equal(execution.length, result.plan.setupCommandCount);
});

test("buildPromptRunnerPlan uses fallback prompt synthesis when request prompts are empty", async () => {
  const sandbox = await mkdtemp(path.join(tmpdir(), "clawguard-prompt-runner-test-"));
  const skillRoot = path.join(sandbox, "skill");

  await mkdir(skillRoot, { recursive: true });
  await writeFile(path.join(skillRoot, "SKILL.md"), "# Empty Prompt Skill\n", "utf8");

  const request: DetonationRequest = {
    requestId: "request-fallback",
    snapshot: {
      slug: "empty-prompt-skill",
      path: skillRoot,
      sourceHints: [{ kind: "fixture", detail: "synthetic" }],
      contentHash: "sha256:synthetic",
      fileInventory: ["SKILL.md"],
      detectedAt: new Date(0).toISOString(),
    },
    prompts: [],
    timeoutSeconds: REQUEST_TIMEOUT_SECONDS,
  };

  try {
    const plan = await buildPromptRunnerPlan(request);

    assert.equal(plan.promptCount, 5);
    assert.equal(plan.setupCommandCount, 0);
    assert.equal(plan.steps.filter((step) => step.type === "prompt").length, 5);
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});
