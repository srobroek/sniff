import { createHash, randomBytes } from "node:crypto";
import type { AnalyzerObservation } from "./analyzer-output.ts";

export const ANALYZER_ARTIFACT_SCHEMA_VERSION = "1.0.0" as const;
export const ANALYZER_ARTIFACT_CHUNK_BYTES = 64 * 1024;
export const ANALYZER_ARTIFACT_TTL_MS = 30 * 60 * 1_000;
export const ANALYZER_ARTIFACT_MAX_AGE_MS = 4 * 60 * 60 * 1_000;
export const MAX_ANALYZER_ARTIFACT_REGISTRY_ENTRIES = 32;
export const MAX_ANALYZER_ARTIFACT_REGISTRY_BYTES = 32 * 1024 * 1024;
export const MAX_PUBLIC_ANALYZER_DESCRIPTORS = 128;
/** Keep analyzer tool envelopes well below the MCP structured-output limit. */
export const MAX_ANALYZER_PREVIEW_BYTES = 96 * 1024;

export type AnalyzerArtifactKind = "index" | "source-file";

export interface AnalyzerArtifactDescriptor {
  readonly kind: AnalyzerArtifactKind;
  readonly relativePath: string;
  readonly sourcePath?: string;
  readonly sha256: string;
  readonly bytes: number;
  readonly observationCount?: number;
}

export interface AnalyzerArtifactIndex {
  readonly schemaVersion: typeof ANALYZER_ARTIFACT_SCHEMA_VERSION;
  readonly analyzerResultId: string;
  readonly recipeId: string;
  readonly totalObservations: number;
  readonly sourceCount: number;
  readonly files: readonly Pick<AnalyzerArtifactDescriptor, "sourcePath" | "relativePath" | "sha256" | "bytes" | "observationCount">[];
}

export interface AnalyzerArtifactDescriptorProjection {
  readonly descriptors: readonly AnalyzerArtifactDescriptor[];
  readonly descriptorCount: number;
  readonly descriptorsTruncated: boolean;
}

export interface AnalyzerSourceArtifact {
  readonly relativePath: string;
  readonly sourcePath: string;
  readonly observations: readonly AnalyzerObservation[];
  readonly json: string;
  readonly sha256: string;
  readonly bytes: number;
}

export interface AnalyzerArtifacts {
  readonly analyzerResultId: string;
  readonly recipeId: string;
  readonly observations: readonly AnalyzerObservation[];
  readonly index: AnalyzerArtifactIndex;
  readonly indexJson: string;
  readonly sourceArtifacts: readonly AnalyzerSourceArtifact[];
  readonly descriptors: readonly AnalyzerArtifactDescriptor[];
}

export interface AnalyzerObservationPreview {
  readonly total: number;
  readonly returned: number;
  readonly truncated: boolean;
}

export interface AnalyzerArtifactReadOptions {
  readonly capability: string;
  readonly analyzerResultId: string;
  readonly relativePath?: string;
  readonly sourcePath?: string;
  readonly offset?: number;
}

export interface AnalyzerArtifactReadResult {
  readonly analyzerResultId: string;
  readonly relativePath: string;
  readonly sourcePath?: string;
  readonly content: string;
  readonly offset: number;
  readonly nextOffset: number;
  readonly eof: boolean;
  readonly bytes: number;
  readonly totalBytes: number;
  readonly sha256: string;
}

interface RegisteredAnalyzer {
  readonly analyzerResultId: string;
  readonly contents: ReadonlyMap<string, string>;
  readonly descriptors: ReadonlyMap<string, AnalyzerArtifactDescriptor>;
  readonly sourcePaths: ReadonlyMap<string, string>;
  readonly bytes: number;
  readonly createdAt: number;
  expiresAt: number;
}

const analyzers = new Map<string, RegisteredAnalyzer>();

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).filter(([, entry]) => entry !== undefined).sort(([a], [b]) => compareText(a, b)).map(([key, entry]) => [key, canonicalValue(entry)]));
  }
  return value;
}

function canonicalJson(value: unknown): string {
  return `${JSON.stringify(canonicalValue(value), null, 2)}\n`;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function normalizedSourcePath(value: string): string {
  if (!value || value.includes("\\") || value.includes("\0") || value.startsWith("/") || value.split("/").some((part) => !part || part === "." || part === "..")) {
    throw new Error("Analyzer observation path must be a normalized relative path");
  }
  return value;
}

function observationKey(observation: AnalyzerObservation): string {
  return JSON.stringify([observation.path, observation.start.line, observation.start.column, observation.ruleId, observation.message, observation.severity]);
}

function sourceArtifactPath(sourcePath: string): string {
  return `files/${sourcePath}.json`;
}

export function createAnalyzerArtifacts(recipeId: string, observations: readonly AnalyzerObservation[], analyzerResultId = `analyzer-${sha256(`${recipeId}\n${observations.map(observationKey).sort(compareText).join("\n")}`).slice(0, 16)}`): AnalyzerArtifacts {
  const normalized = observations.map((observation) => ({ ...observation, path: normalizedSourcePath(observation.path) })).sort((left, right) => compareText(observationKey(left), observationKey(right)));
  const bySource = new Map<string, AnalyzerObservation[]>();
  for (const observation of normalized) {
    const group = bySource.get(observation.path) ?? [];
    group.push(observation);
    bySource.set(observation.path, group);
  }
  const sourceArtifacts: AnalyzerSourceArtifact[] = [];
  for (const sourcePath of [...bySource.keys()].sort(compareText)) {
    const grouped = bySource.get(sourcePath) ?? [];
    const relativePath = sourceArtifactPath(sourcePath);
    const json = canonicalJson({ observations: grouped, sourcePath });
    sourceArtifacts.push({ relativePath, sourcePath, observations: grouped, json, sha256: sha256(json), bytes: Buffer.byteLength(json) });
  }
  const files: AnalyzerArtifactDescriptor[] = sourceArtifacts.map((artifact) => ({ kind: "source-file", relativePath: artifact.relativePath, sourcePath: artifact.sourcePath, sha256: artifact.sha256, bytes: artifact.bytes, observationCount: artifact.observations.length }));
  const index: AnalyzerArtifactIndex = { schemaVersion: ANALYZER_ARTIFACT_SCHEMA_VERSION, analyzerResultId, recipeId, totalObservations: normalized.length, sourceCount: sourceArtifacts.length, files };
  const indexJson = canonicalJson(index);
  const indexDescriptor: AnalyzerArtifactDescriptor = { kind: "index", relativePath: "index.json", sha256: sha256(indexJson), bytes: Buffer.byteLength(indexJson) };
  return { analyzerResultId, recipeId, observations: normalized, index, indexJson, sourceArtifacts, descriptors: [indexDescriptor, ...files] };
}

function purgeExpired(now = Date.now()): void {
  for (const [capability, entry] of analyzers) if (entry.expiresAt <= now || entry.createdAt + ANALYZER_ARTIFACT_MAX_AGE_MS <= now) analyzers.delete(capability);
}

function retainedBytes(): number {
  let bytes = 0;
  for (const entry of analyzers.values()) bytes += entry.bytes;
  return bytes;
}

export function registerAnalyzerArtifacts(artifacts: AnalyzerArtifacts, now = Date.now()): string {
  purgeExpired(now);
  const capability = randomBytes(32).toString("base64url");
  const contents = new Map<string, string>([["index.json", artifacts.indexJson]]);
  const descriptors = new Map<string, AnalyzerArtifactDescriptor>();
  const sourcePaths = new Map<string, string>();
  for (const artifact of artifacts.sourceArtifacts) contents.set(artifact.relativePath, artifact.json);
  let bytes = 0;
  for (const descriptor of artifacts.descriptors) {
    const content = contents.get(descriptor.relativePath);
    if (content === undefined) throw new Error(`Missing analyzer artifact content: ${descriptor.relativePath}`);
    if (Buffer.byteLength(content) !== descriptor.bytes) throw new Error(`Analyzer artifact byte count does not match descriptor: ${descriptor.relativePath}`);
    if (sha256(content) !== descriptor.sha256) throw new Error(`Analyzer artifact digest does not match descriptor: ${descriptor.relativePath}`);
    bytes += descriptor.bytes;
    descriptors.set(descriptor.relativePath, descriptor);
    if (descriptor.sourcePath) sourcePaths.set(descriptor.sourcePath, descriptor.relativePath);
  }
  if (bytes > MAX_ANALYZER_ARTIFACT_REGISTRY_BYTES) throw new Error("Analyzer artifacts exceed registry byte budget");
  analyzers.set(capability, { analyzerResultId: artifacts.analyzerResultId, contents, descriptors, sourcePaths, bytes, createdAt: now, expiresAt: now + ANALYZER_ARTIFACT_TTL_MS });
  while (analyzers.size > MAX_ANALYZER_ARTIFACT_REGISTRY_ENTRIES || retainedBytes() > MAX_ANALYZER_ARTIFACT_REGISTRY_BYTES) {
    const oldest = analyzers.keys().next().value;
    if (typeof oldest !== "string") break;
    analyzers.delete(oldest);
  }
  return capability;
}

function isContinuationByte(value: number): boolean {
  return (value & 0xc0) === 0x80;
}
export function readAnalyzerArtifact(options: AnalyzerArtifactReadOptions, now = Date.now()): AnalyzerArtifactReadResult {
  purgeExpired(now);
  const entry = analyzers.get(options.capability);
  if (!entry) throw new Error("Unknown Sniff analyzer artifact capability");
  if (entry.analyzerResultId !== options.analyzerResultId) throw new Error("Sniff analyzer artifact capability does not match analyzer result ID");
  const relativePath = options.relativePath ?? entry.sourcePaths.get(options.sourcePath ?? "");
  if (!relativePath) throw new Error(`Unknown Sniff analyzer source path: ${options.sourcePath}`);
  const descriptor = entry.descriptors.get(relativePath);
  const source = entry.contents.get(relativePath);
  if (!descriptor || source === undefined) throw new Error(`Unknown Sniff analyzer artifact: ${relativePath}`);
  const offset = options.offset ?? 0;
  if (!Number.isSafeInteger(offset) || offset < 0) throw new Error("Sniff analyzer artifact offset must be a non-negative integer");
  const buffer = Buffer.from(source, "utf8");
  if (offset > buffer.length) throw new Error("Sniff analyzer artifact offset is beyond the artifact");
  if (offset < buffer.length && isContinuationByte(buffer[offset] ?? 0)) throw new Error("Sniff analyzer artifact offset must be a UTF-8 boundary");
  entry.expiresAt = Math.min(entry.createdAt + ANALYZER_ARTIFACT_MAX_AGE_MS, now + ANALYZER_ARTIFACT_TTL_MS);
  let end = Math.min(buffer.length, offset + ANALYZER_ARTIFACT_CHUNK_BYTES);
  while (end < buffer.length && isContinuationByte(buffer[end] ?? 0)) end -= 1;
  const chunk = buffer.subarray(offset, end);
  return { analyzerResultId: entry.analyzerResultId, relativePath: descriptor.relativePath, ...(descriptor.sourcePath ? { sourcePath: descriptor.sourcePath } : {}), content: chunk.toString("utf8"), offset, nextOffset: end, eof: end === buffer.length, bytes: chunk.byteLength, totalBytes: buffer.byteLength, sha256: descriptor.sha256 };
}

export function projectAnalyzerObservations(observations: readonly AnalyzerObservation[], maxBytes = MAX_ANALYZER_PREVIEW_BYTES): { readonly observations: readonly AnalyzerObservation[]; readonly preview: AnalyzerObservationPreview } {
  const ordered = [...observations].sort((left, right) => compareText(observationKey(left), observationKey(right)));
  const projected: AnalyzerObservation[] = [];
  let bytes = 2;
  for (const observation of ordered) {
    const candidateBytes = Buffer.byteLength(JSON.stringify(observation)) + (projected.length ? 1 : 0);
    if (bytes + candidateBytes > maxBytes) break;
    projected.push(observation);
    bytes += candidateBytes;
  }
  return { observations: projected, preview: { total: observations.length, returned: projected.length, truncated: projected.length < observations.length } };
}

export function publicAnalyzerDescriptors(artifacts: AnalyzerArtifacts): AnalyzerArtifactDescriptorProjection {
  const descriptors = artifacts.descriptors.slice(0, MAX_PUBLIC_ANALYZER_DESCRIPTORS);
  return { descriptors, descriptorCount: artifacts.descriptors.length, descriptorsTruncated: descriptors.length < artifacts.descriptors.length };
}

export function clearAnalyzerArtifactRegistryForTests(): void {
  analyzers.clear();
}
