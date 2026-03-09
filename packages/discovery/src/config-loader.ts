import { readFile } from "node:fs/promises";
import path from "node:path";

import JSON5 from "json5";

import { pathExists, resolveDiscoveryPath } from "./path-utils.js";

type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;

interface JsonObject {
  [key: string]: JsonValue;
}

export interface LoadedConfigWorkspace {
  id: string;
  workspacePath: string;
  skillsPath: string;
  agentName?: string;
  isPrimary?: boolean;
}

export interface LoadedOpenClawConfig {
  workspaces: LoadedConfigWorkspace[];
  extraDirs: string[];
}

export async function loadOpenClawConfig(
  configPath: string,
  options: {
    homeDir: string;
    readTextFile?: (filePath: string) => Promise<string>;
  }
): Promise<LoadedOpenClawConfig | undefined> {
  const readTextFile = options.readTextFile ?? defaultReadTextFile;
  if (!(await pathExists(configPath))) {
    return undefined;
  }

  const resolvedConfig = await resolveConfigFile(configPath, {
    rootDirectoryPath: path.dirname(configPath),
    currentFilePath: configPath,
    depth: 0,
    stack: [configPath],
    readTextFile
  });

  if (!isJsonObject(resolvedConfig)) {
    throw new Error(`Expected ${configPath} to contain an object`);
  }

  return {
    workspaces: extractConfiguredWorkspaces(resolvedConfig, {
      configDirectoryPath: path.dirname(configPath),
      homeDir: options.homeDir
    }),
    extraDirs: extractExtraDirs(resolvedConfig, {
      configDirectoryPath: path.dirname(configPath),
      homeDir: options.homeDir
    })
  };
}

async function resolveConfigFile(
  filePath: string,
  state: ResolveState
): Promise<JsonValue> {
  const rawText = await state.readTextFile(filePath);
  const parsed = parseJson5Object(rawText, filePath);

  return resolveJsonValue(parsed, {
    ...state,
    currentFilePath: filePath
  });
}

async function resolveJsonValue(
  input: JsonValue,
  state: ResolveState
): Promise<JsonValue> {
  if (Array.isArray(input)) {
    const resolvedItems = await Promise.all(
      input.map((item) => resolveJsonValue(item, state))
    );
    return resolvedItems;
  }

  if (!isJsonObject(input)) {
    return input;
  }

  let baseRecord: JsonObject = {};
  if ("$include" in input) {
    const includeSpec = input.$include;
    baseRecord = await resolveIncludeSpec(includeSpec, state);
  }

  const siblingEntries = Object.entries(input).filter(([key]) => key !== "$include");
  const resolvedSiblingEntries = await Promise.all(
    siblingEntries.map(async ([key, value]) => [key, await resolveJsonValue(value, state)] as const)
  );

  return deepMergeRecords(baseRecord, Object.fromEntries(resolvedSiblingEntries));
}

async function resolveIncludeSpec(
  includeSpec: JsonValue,
  state: ResolveState
): Promise<JsonObject> {
  if (typeof includeSpec === "string") {
    return loadIncludedRecord(includeSpec, state);
  }

  if (Array.isArray(includeSpec)) {
    let mergedRecord: JsonObject = {};

    for (const entry of includeSpec) {
      if (typeof entry !== "string") {
        throw new Error(
          `Expected ${state.currentFilePath}#$include entries to be strings`
        );
      }

      mergedRecord = deepMergeRecords(mergedRecord, await loadIncludedRecord(entry, state));
    }

    return mergedRecord;
  }

  throw new Error(`Expected ${state.currentFilePath}#$include to be a string or string[]`);
}

async function loadIncludedRecord(
  includePath: string,
  state: ResolveState
): Promise<JsonObject> {
  const nextDepth = state.depth + 1;
  if (nextDepth > 10) {
    throw new Error(`Config includes exceeded the maximum nesting depth at ${includePath}`);
  }

  const resolvedIncludePath = path.isAbsolute(includePath)
    ? path.normalize(includePath)
    : path.resolve(path.dirname(state.currentFilePath), includePath);

  if (!isWithinRootBoundary(resolvedIncludePath, state.rootDirectoryPath)) {
    throw new Error(`Config include escaped the root config directory: ${includePath}`);
  }

  if (state.stack.includes(resolvedIncludePath)) {
    throw new Error(`Detected circular config include at ${resolvedIncludePath}`);
  }

  const resolvedValue = await resolveConfigFile(resolvedIncludePath, {
    ...state,
    currentFilePath: resolvedIncludePath,
    depth: nextDepth,
    stack: [...state.stack, resolvedIncludePath]
  });

  if (!isJsonObject(resolvedValue)) {
    throw new Error(`Expected included config ${resolvedIncludePath} to contain an object`);
  }

  return resolvedValue;
}

function extractConfiguredWorkspaces(
  configRecord: JsonObject,
  options: { configDirectoryPath: string; homeDir: string }
): LoadedConfigWorkspace[] {
  const agentsRecord = expectOptionalObject(configRecord.agents, "agents");
  const defaultsRecord = expectOptionalObject(agentsRecord?.defaults, "agents.defaults");
  const defaultWorkspaceRaw = expectOptionalString(
    defaultsRecord?.workspace,
    "agents.defaults.workspace"
  );

  const workspaces: LoadedConfigWorkspace[] = [];
  if (defaultWorkspaceRaw !== undefined) {
    const workspacePath = resolveDiscoveryPath(defaultWorkspaceRaw, {
      homeDir: options.homeDir,
      baseDir: options.configDirectoryPath
    });
    workspaces.push({
      id: "default",
      workspacePath,
      skillsPath: path.join(workspacePath, "skills"),
      agentName: "default",
      isPrimary: true
    });
  }

  const agentList = expectOptionalArray(agentsRecord?.list, "agents.list");
  if (agentList === undefined) {
    return workspaces;
  }

  for (const [index, value] of agentList.entries()) {
    const agentRecord = expectObject(value, `agents.list[${index}]`);
    const agentWorkspaceRaw =
      expectOptionalString(agentRecord.workspace, `agents.list[${index}].workspace`) ??
      defaultWorkspaceRaw;

    if (agentWorkspaceRaw === undefined) {
      continue;
    }

    const workspacePath = resolveDiscoveryPath(agentWorkspaceRaw, {
      homeDir: options.homeDir,
      baseDir: options.configDirectoryPath
    });
    const agentName =
      expectOptionalString(agentRecord.name, `agents.list[${index}].name`) ??
      expectOptionalString(agentRecord.id, `agents.list[${index}].id`);

    workspaces.push({
      id: agentName !== undefined ? `agent:${agentName}` : `agent:${index}`,
      workspacePath,
      skillsPath: path.join(workspacePath, "skills"),
      ...(agentName !== undefined ? { agentName } : {})
    });
  }

  return workspaces;
}

function extractExtraDirs(
  configRecord: JsonObject,
  options: { configDirectoryPath: string; homeDir: string }
): string[] {
  const skillsRecord = expectOptionalObject(configRecord.skills, "skills");
  const loadRecord = expectOptionalObject(skillsRecord?.load, "skills.load");
  const extraDirsRaw = loadRecord?.extraDirs;
  if (extraDirsRaw === undefined) {
    return [];
  }

  const extraDirItems = expectArray(extraDirsRaw, "skills.load.extraDirs");
  return extraDirItems.map((item, index) =>
    resolveDiscoveryPath(
      expectString(item, `skills.load.extraDirs[${index}]`),
      {
        homeDir: options.homeDir,
        baseDir: options.configDirectoryPath
      }
    )
  );
}

function deepMergeRecords(baseRecord: JsonObject, overrideRecord: JsonObject): JsonObject {
  const mergedRecord: JsonObject = { ...baseRecord };

  for (const [key, overrideValue] of Object.entries(overrideRecord)) {
    const baseValue = mergedRecord[key];
    if (isJsonObject(baseValue) && isJsonObject(overrideValue)) {
      mergedRecord[key] = deepMergeRecords(baseValue, overrideValue);
      continue;
    }

    mergedRecord[key] = overrideValue;
  }

  return mergedRecord;
}

function parseJson5Object(rawText: string, filePath: string): JsonValue {
  try {
    return JSON5.parse(rawText) as JsonValue;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to parse ${filePath}: ${message}`);
  }
}

function expectObject(input: JsonValue, pathDescription: string): JsonObject {
  if (!isJsonObject(input)) {
    throw new Error(`Expected ${pathDescription} to be an object`);
  }

  return input;
}

function expectOptionalObject(
  input: JsonValue | undefined,
  pathDescription: string
): JsonObject | undefined {
  if (input === undefined) {
    return undefined;
  }

  return expectObject(input, pathDescription);
}

function expectArray(input: JsonValue, pathDescription: string): JsonValue[] {
  if (!Array.isArray(input)) {
    throw new Error(`Expected ${pathDescription} to be an array`);
  }

  return input;
}

function expectOptionalArray(
  input: JsonValue | undefined,
  pathDescription: string
): JsonValue[] | undefined {
  if (input === undefined) {
    return undefined;
  }

  return expectArray(input, pathDescription);
}

function expectString(input: JsonValue, pathDescription: string): string {
  if (typeof input !== "string" || input.trim().length === 0) {
    throw new Error(`Expected ${pathDescription} to be a non-empty string`);
  }

  return input;
}

function expectOptionalString(
  input: JsonValue | undefined,
  pathDescription: string
): string | undefined {
  if (input === undefined) {
    return undefined;
  }

  return expectString(input, pathDescription);
}

function isJsonObject(input: JsonValue | undefined): input is JsonObject {
  return typeof input === "object" && input !== null && !Array.isArray(input);
}

function isWithinRootBoundary(targetPath: string, rootDirectoryPath: string): boolean {
  const relativePath = path.relative(rootDirectoryPath, targetPath);
  return relativePath === "" || (!relativePath.startsWith("..") && !path.isAbsolute(relativePath));
}

async function defaultReadTextFile(filePath: string): Promise<string> {
  return readFile(filePath, "utf8");
}

interface ResolveState {
  rootDirectoryPath: string;
  currentFilePath: string;
  depth: number;
  stack: string[];
  readTextFile: (filePath: string) => Promise<string>;
}
