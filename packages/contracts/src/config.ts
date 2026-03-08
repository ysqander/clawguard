import {
  createValidator,
  parseBoolean,
  parseEnum,
  parseInteger,
  parseLiteral,
  parseNonEmptyString,
  parseObject,
  parseStringArray
} from "./runtime.js";

export interface PathsConfig {
  stateDbPath: string;
  artifactsRoot: string;
  socketPath: string;
  quarantineSuffix: string;
}

export interface DiscoveryConfig {
  openClawConfigPath: string;
  fallbackSkillDirs: string[];
}

export interface DaemonConfig {
  debounceMs: number;
  maxConcurrentJobs: number;
  notificationsEnabled: boolean;
}

export interface ScanThresholdsConfig {
  quarantineScore: number;
  detonationScore: number;
}

export interface DetonationConfig {
  enabled: boolean;
  defaultRuntime: "podman" | "docker";
  timeoutSeconds: number;
  promptBudget: number;
}

export interface ClawHubConfig {
  baseUrl: string;
  enabled: boolean;
}

export interface VirusTotalConfig {
  baseUrl: string;
  enabled: boolean;
  hashLookupEnabled: boolean;
  backgroundUploadsEnabled: boolean;
  domainEnrichmentEnabled: boolean;
  maxRequestsPerMinute: number;
}

export interface ThreatIntelConfig {
  clawHub: ClawHubConfig;
  virusTotal: VirusTotalConfig;
}

export interface ClawGuardConfig {
  version: 1;
  paths: PathsConfig;
  discovery: DiscoveryConfig;
  daemon: DaemonConfig;
  scanThresholds: ScanThresholdsConfig;
  detonation: DetonationConfig;
  threatIntel: ThreatIntelConfig;
}

function parsePathsConfig(input: unknown, path: string): PathsConfig {
  return parseObject(input, path, (record) => ({
    stateDbPath: parseNonEmptyString(record.stateDbPath, `${path}.stateDbPath`),
    artifactsRoot: parseNonEmptyString(record.artifactsRoot, `${path}.artifactsRoot`),
    socketPath: parseNonEmptyString(record.socketPath, `${path}.socketPath`),
    quarantineSuffix: parseNonEmptyString(record.quarantineSuffix, `${path}.quarantineSuffix`)
  }));
}

function parseDiscoveryConfig(input: unknown, path: string): DiscoveryConfig {
  return parseObject(input, path, (record) => ({
    openClawConfigPath: parseNonEmptyString(record.openClawConfigPath, `${path}.openClawConfigPath`),
    fallbackSkillDirs: parseStringArray(record.fallbackSkillDirs, `${path}.fallbackSkillDirs`)
  }));
}

function parseDaemonConfig(input: unknown, path: string): DaemonConfig {
  return parseObject(input, path, (record) => ({
    debounceMs: parseInteger(record.debounceMs, `${path}.debounceMs`),
    maxConcurrentJobs: parseInteger(record.maxConcurrentJobs, `${path}.maxConcurrentJobs`),
    notificationsEnabled: parseBoolean(record.notificationsEnabled, `${path}.notificationsEnabled`)
  }));
}

function parseScanThresholdsConfig(input: unknown, path: string): ScanThresholdsConfig {
  return parseObject(input, path, (record) => ({
    quarantineScore: parseInteger(record.quarantineScore, `${path}.quarantineScore`),
    detonationScore: parseInteger(record.detonationScore, `${path}.detonationScore`)
  }));
}

function parseDetonationConfig(input: unknown, path: string): DetonationConfig {
  return parseObject(input, path, (record) => ({
    enabled: parseBoolean(record.enabled, `${path}.enabled`),
    defaultRuntime: parseEnum(record.defaultRuntime, ["podman", "docker"] as const, `${path}.defaultRuntime`),
    timeoutSeconds: parseInteger(record.timeoutSeconds, `${path}.timeoutSeconds`),
    promptBudget: parseInteger(record.promptBudget, `${path}.promptBudget`)
  }));
}

function parseClawHubConfig(input: unknown, path: string): ClawHubConfig {
  return parseObject(input, path, (record) => ({
    baseUrl: parseNonEmptyString(record.baseUrl, `${path}.baseUrl`),
    enabled: parseBoolean(record.enabled, `${path}.enabled`)
  }));
}

function parseVirusTotalConfig(input: unknown, path: string): VirusTotalConfig {
  return parseObject(input, path, (record) => ({
    baseUrl: parseNonEmptyString(record.baseUrl, `${path}.baseUrl`),
    enabled: parseBoolean(record.enabled, `${path}.enabled`),
    hashLookupEnabled: parseBoolean(record.hashLookupEnabled, `${path}.hashLookupEnabled`),
    backgroundUploadsEnabled: parseBoolean(record.backgroundUploadsEnabled, `${path}.backgroundUploadsEnabled`),
    domainEnrichmentEnabled: parseBoolean(record.domainEnrichmentEnabled, `${path}.domainEnrichmentEnabled`),
    maxRequestsPerMinute: parseInteger(record.maxRequestsPerMinute, `${path}.maxRequestsPerMinute`)
  }));
}

function parseThreatIntelConfig(input: unknown, path: string): ThreatIntelConfig {
  return parseObject(input, path, (record) => ({
    clawHub: parseClawHubConfig(record.clawHub, `${path}.clawHub`),
    virusTotal: parseVirusTotalConfig(record.virusTotal, `${path}.virusTotal`)
  }));
}

function parseClawGuardConfig(input: unknown, path: string): ClawGuardConfig {
  return parseObject(input, path, (record) => ({
    version: parseLiteral(record.version, 1, `${path}.version`),
    paths: parsePathsConfig(record.paths, `${path}.paths`),
    discovery: parseDiscoveryConfig(record.discovery, `${path}.discovery`),
    daemon: parseDaemonConfig(record.daemon, `${path}.daemon`),
    scanThresholds: parseScanThresholdsConfig(record.scanThresholds, `${path}.scanThresholds`),
    detonation: parseDetonationConfig(record.detonation, `${path}.detonation`),
    threatIntel: parseThreatIntelConfig(record.threatIntel, `${path}.threatIntel`)
  }));
}

export const defaultClawGuardConfig: ClawGuardConfig = {
  version: 1,
  paths: {
    stateDbPath: "~/Library/Application Support/ClawGuard/state.db",
    artifactsRoot: "~/Library/Application Support/ClawGuard/artifacts",
    socketPath: "~/Library/Application Support/ClawGuard/clawguard.sock",
    quarantineSuffix: ".quarantine"
  },
  discovery: {
    openClawConfigPath: "~/.openclaw/openclaw.json",
    fallbackSkillDirs: ["~/.openclaw/skills", "~/openclaw/skills", "./skills"]
  },
  daemon: {
    debounceMs: 500,
    maxConcurrentJobs: 2,
    notificationsEnabled: true
  },
  scanThresholds: {
    quarantineScore: 60,
    detonationScore: 40
  },
  detonation: {
    enabled: true,
    defaultRuntime: "podman",
    timeoutSeconds: 90,
    promptBudget: 5
  },
  threatIntel: {
    clawHub: {
      baseUrl: "https://clawhub.ai",
      enabled: true
    },
    virusTotal: {
      baseUrl: "https://www.virustotal.com/api/v3",
      enabled: true,
      hashLookupEnabled: true,
      backgroundUploadsEnabled: false,
      domainEnrichmentEnabled: true,
      maxRequestsPerMinute: 4
    }
  }
};

export const clawGuardConfigValidator = createValidator(parseClawGuardConfig, "ClawGuardConfig");

export function mergeClawGuardConfig(
  overrides: Partial<ClawGuardConfig>
): ClawGuardConfig {
  return {
    ...defaultClawGuardConfig,
    ...overrides,
    paths: { ...defaultClawGuardConfig.paths, ...overrides.paths },
    discovery: { ...defaultClawGuardConfig.discovery, ...overrides.discovery },
    daemon: { ...defaultClawGuardConfig.daemon, ...overrides.daemon },
    scanThresholds: { ...defaultClawGuardConfig.scanThresholds, ...overrides.scanThresholds },
    detonation: { ...defaultClawGuardConfig.detonation, ...overrides.detonation },
    threatIntel: {
      clawHub: {
        ...defaultClawGuardConfig.threatIntel.clawHub,
        ...overrides.threatIntel?.clawHub
      },
      virusTotal: {
        ...defaultClawGuardConfig.threatIntel.virusTotal,
        ...overrides.threatIntel?.virusTotal
      }
    }
  };
}
