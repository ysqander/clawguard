import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import type { ArtifactType } from "@clawguard/contracts";

import type { WriteArtifactInput, WriteJsonArtifactInput } from "./types.js";

export interface PreparedArtifact {
  artifactId: string;
  scanId: string;
  type: ArtifactType;
  relativePath: string;
  absolutePath: string;
  mimeType: string;
  sha256: string;
  sizeBytes: number;
  createdAt: string;
}

function sanitizeSegment(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/-+/g, "-").replace(/^[-.]+|[-.]+$/g, "");
}

function normalizeArtifactFilename(filename: string, sha256: string): string {
  const parsed = path.parse(filename);
  const baseName = sanitizeSegment(parsed.name) || "artifact";
  const extension = parsed.ext.replace(/[^A-Za-z0-9.]/g, "").slice(0, 16);

  return `${sha256.slice(0, 16)}-${baseName}${extension}`;
}

function buildArtifactRelativePath(
  scanId: string,
  type: ArtifactType,
  filename: string,
  sha256: string
): string {
  const safeScanId = sanitizeSegment(scanId) || "scan";
  const safeType = sanitizeSegment(type) || "artifact";

  return path.join(safeScanId, safeType, normalizeArtifactFilename(filename, sha256));
}

function toBuffer(data: Uint8Array | string, encoding: BufferEncoding): Buffer {
  return typeof data === "string" ? Buffer.from(data, encoding) : Buffer.from(data);
}

export class ArtifactStore {
  public constructor(private readonly artifactsRoot: string) {}

  public async ensureRoot(): Promise<void> {
    await mkdir(this.artifactsRoot, { recursive: true });
  }

  public async writeArtifact(input: WriteArtifactInput): Promise<Omit<PreparedArtifact, "artifactId">> {
    await this.ensureRoot();

    const createdAt = input.createdAt ?? new Date().toISOString();
    const buffer = toBuffer(input.data, input.encoding ?? "utf8");
    const sha256 = createHash("sha256").update(buffer).digest("hex");
    const relativePath = buildArtifactRelativePath(input.scanId, input.type, input.filename, sha256);
    const absolutePath = path.join(this.artifactsRoot, relativePath);

    await mkdir(path.dirname(absolutePath), { recursive: true });
    await writeFile(absolutePath, buffer);

    return {
      scanId: input.scanId,
      type: input.type,
      relativePath,
      absolutePath,
      mimeType: input.mimeType ?? "application/octet-stream",
      sha256,
      sizeBytes: buffer.byteLength,
      createdAt
    };
  }

  public async writeJsonArtifact(input: WriteJsonArtifactInput): Promise<Omit<PreparedArtifact, "artifactId">> {
    const artifactInput: WriteArtifactInput = {
      scanId: input.scanId,
      type: input.type,
      filename: input.filename,
      data: `${JSON.stringify(input.value, null, 2)}\n`,
      mimeType: input.mimeType ?? "application/json"
    };

    if (input.createdAt) {
      artifactInput.createdAt = input.createdAt;
    }

    return this.writeArtifact(artifactInput);
  }
}

