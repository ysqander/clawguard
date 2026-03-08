import { SchemaValidationError, type ValidationIssue } from "./errors.js";

type Path = string;

function issue(path: Path, message: string): never {
  throw new SchemaValidationError("Schema validation failed", [{ path, message }]);
}

function asRecord(input: unknown, path: Path): Record<string, unknown> {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    issue(path, "Expected an object");
  }

  return input as Record<string, unknown>;
}

export function parseString(input: unknown, path: Path): string {
  if (typeof input !== "string") {
    issue(path, "Expected a string");
  }

  return input;
}

export function parseNonEmptyString(input: unknown, path: Path): string {
  const value = parseString(input, path).trim();
  if (value.length === 0) {
    issue(path, "Expected a non-empty string");
  }

  return value;
}

export function parseBoolean(input: unknown, path: Path): boolean {
  if (typeof input !== "boolean") {
    issue(path, "Expected a boolean");
  }

  return input;
}

export function parseNumber(input: unknown, path: Path): number {
  if (typeof input !== "number" || Number.isNaN(input)) {
    issue(path, "Expected a number");
  }

  return input;
}

export function parseInteger(input: unknown, path: Path): number {
  const value = parseNumber(input, path);
  if (!Number.isInteger(value)) {
    issue(path, "Expected an integer");
  }

  return value;
}

export function parseOptional<T>(
  input: unknown,
  parser: (value: unknown, path: Path) => T,
  path: Path
): T | undefined {
  if (input === undefined) {
    return undefined;
  }

  return parser(input, path);
}

export function parseStringArray(input: unknown, path: Path): string[] {
  if (!Array.isArray(input)) {
    issue(path, "Expected an array");
  }

  return input.map((value, index) => parseNonEmptyString(value, `${path}[${index}]`));
}

export function parseArray<T>(
  input: unknown,
  parser: (value: unknown, path: Path) => T,
  path: Path
): T[] {
  if (!Array.isArray(input)) {
    issue(path, "Expected an array");
  }

  return input.map((value, index) => parser(value, `${path}[${index}]`));
}

export function parseEnum<const T extends readonly string[]>(
  input: unknown,
  allowed: T,
  path: Path
): T[number] {
  const value = parseNonEmptyString(input, path);
  if (!allowed.includes(value)) {
    issue(path, `Expected one of: ${allowed.join(", ")}`);
  }

  return value as T[number];
}

export function parseLiteral<const T extends string | number | boolean>(
  input: unknown,
  expected: T,
  path: Path
): T {
  if (input !== expected) {
    issue(path, `Expected literal ${String(expected)}`);
  }

  return expected;
}

export function parseIsoDateTime(input: unknown, path: Path): string {
  const value = parseNonEmptyString(input, path);
  if (Number.isNaN(Date.parse(value))) {
    issue(path, "Expected an ISO-8601 datetime string");
  }

  return value;
}

export function parseRecord(input: unknown, path: Path): Record<string, unknown> {
  return asRecord(input, path);
}

export function parseObject<T>(
  input: unknown,
  path: Path,
  reader: (record: Record<string, unknown>) => T
): T {
  const record = asRecord(input, path);
  return reader(record);
}

export function collectOptionalIssues<T>(
  factory: () => T,
  fallbackMessage: string,
  path: Path
): T {
  try {
    return factory();
  } catch (error) {
    if (error instanceof SchemaValidationError) {
      throw error;
    }

    throw new SchemaValidationError(fallbackMessage, [{ path, message: fallbackMessage }]);
  }
}

export function createValidator<T>(
  parser: (input: unknown, path: Path) => T,
  rootName: string
): {
  parse: (input: unknown) => T;
  is: (input: unknown) => input is T;
} {
  return {
    parse(input: unknown): T {
      return parser(input, rootName);
    },
    is(input: unknown): input is T {
      try {
        parser(input, rootName);
        return true;
      } catch (error) {
        if (error instanceof SchemaValidationError) {
          return false;
        }

        throw error;
      }
    }
  };
}

export type { ValidationIssue };
