import { createHash, randomBytes } from "node:crypto";
import { canonicalJson } from "./canonical-json.ts";
import type { ReportArtifactDescriptor, ReportArtifacts } from "./report.ts";

export const REPORT_ARTIFACT_CHUNK_BYTES = 64 * 1024;
export const MAX_REPORT_ARTIFACT_REGISTRY_ENTRIES = 32;
export const MAX_REPORT_ARTIFACT_REGISTRY_BYTES = 32 * 1024 * 1024;
export const REPORT_ARTIFACT_IDLE_TTL_MS = 30 * 60 * 1_000;
export const REPORT_ARTIFACT_MAX_AGE_MS = 4 * 60 * 60 * 1_000;

export interface ReportArtifactReadOptions {
  readonly capability: string;
  readonly reportId: string;
  readonly relativePath: string;
  readonly offset?: number;
}

export interface ReportArtifactReadResult {
  readonly reportId: string;
  readonly relativePath: string;
  readonly content: string;
  readonly offset: number;
  readonly nextOffset: number;
  readonly eof: boolean;
  readonly bytes: number;
  readonly totalBytes: number;
  readonly sha256: string;
}

type RegisteredReport = {
  readonly reportId: string;
  /** UTF-8 bytes encoded once at registration, so paging never re-encodes the artifact. */
  readonly contents: ReadonlyMap<string, Buffer>;
  readonly descriptors: ReadonlyMap<string, ReportArtifactDescriptor>;
  readonly bytes: number;
  readonly createdAt: number;
  expiresAt: number;
};

const reports = new Map<string, RegisteredReport>();

function purgeExpired(now: number): void {
  for (const [capability, entry] of reports) if (entry.expiresAt <= now || entry.createdAt + REPORT_ARTIFACT_MAX_AGE_MS <= now) reports.delete(capability);
}

function retainedBytes(): number {
  let bytes = 0;
  for (const entry of reports.values()) bytes += entry.bytes;
  return bytes;
}

function contentsFor(artifacts: ReportArtifacts): Map<string, string> {
  const contents = new Map<string, string>([
    ["index.json", artifacts.indexJson],
    ["report.json", artifacts.json],
    ["summary.md", artifacts.fullMarkdown],
    ["manifest.json", artifacts.manifestJson],
    ["coverage.json", artifacts.coverageJson],
    ["receipt.json", canonicalJson(artifacts.receipt)],
  ]);
  for (const file of artifacts.fileArtifacts) contents.set(file.relativePath, file.json);
  return contents;
}
export function registerReportArtifacts(artifacts: ReportArtifacts, now = Date.now()): string {
  purgeExpired(now);
  const capability = randomBytes(32).toString("base64url");
  const descriptors = new Map(artifacts.descriptors.map((descriptor) => [descriptor.relativePath, descriptor] as const));
  const sources = contentsFor(artifacts);
  const contents = new Map<string, Buffer>();
  let bytes = 0;
  for (const descriptor of artifacts.descriptors) {
    const source = sources.get(descriptor.relativePath);
    if (source === undefined) throw new Error(`Missing report artifact content: ${descriptor.relativePath}`);
    const content = Buffer.from(source, "utf8");
    if (content.byteLength !== descriptor.bytes) throw new Error(`Report artifact byte count does not match descriptor: ${descriptor.relativePath}`);
    if (createHash("sha256").update(content).digest("hex") !== descriptor.sha256) throw new Error(`Report artifact digest does not match descriptor: ${descriptor.relativePath}`);
    contents.set(descriptor.relativePath, content);
    bytes += descriptor.bytes;
  }
  if (bytes > MAX_REPORT_ARTIFACT_REGISTRY_BYTES) throw new Error("Report artifacts exceed registry byte budget");
  reports.set(capability, { reportId: artifacts.report.reportId, contents, descriptors, bytes, createdAt: now, expiresAt: now + REPORT_ARTIFACT_IDLE_TTL_MS });
  while (reports.size > MAX_REPORT_ARTIFACT_REGISTRY_ENTRIES || retainedBytes() > MAX_REPORT_ARTIFACT_REGISTRY_BYTES) {
    const oldest = reports.keys().next().value;
    if (typeof oldest !== "string") break;
    reports.delete(oldest);
  }
  return capability;
}

function isContinuationByte(value: number): boolean {
  return (value & 0xc0) === 0x80;
}

export function readReportArtifact(options: ReportArtifactReadOptions, now = Date.now()): ReportArtifactReadResult {
  purgeExpired(now);
  const entry = reports.get(options.capability);
  if (!entry) throw new Error("Unknown Sniff report artifact capability");
  if (entry.reportId !== options.reportId) throw new Error("Sniff report artifact capability does not match report ID");
  const descriptor = entry.descriptors.get(options.relativePath);
  const buffer = entry.contents.get(options.relativePath);
  if (!descriptor || buffer === undefined) throw new Error(`Unknown Sniff report artifact: ${options.relativePath}`);
  entry.expiresAt = Math.min(entry.createdAt + REPORT_ARTIFACT_MAX_AGE_MS, now + REPORT_ARTIFACT_IDLE_TTL_MS);

  const offset = options.offset ?? 0;
  if (!Number.isSafeInteger(offset) || offset < 0) throw new Error("Sniff report artifact offset must be a non-negative integer");
  if (offset > buffer.length) throw new Error("Sniff report artifact offset is beyond the artifact");
  if (offset < buffer.length && isContinuationByte(buffer[offset] ?? 0)) throw new Error("Sniff report artifact offset must be a UTF-8 boundary");
  // An offset at the end yields the empty EOF page through the same path as any other page.
  let end = Math.min(buffer.length, offset + REPORT_ARTIFACT_CHUNK_BYTES);
  while (end < buffer.length && isContinuationByte(buffer[end] ?? 0)) end -= 1;
  const chunk = buffer.subarray(offset, end);
  return {
    reportId: entry.reportId,
    relativePath: descriptor.relativePath,
    content: chunk.toString("utf8"),
    offset,
    nextOffset: end,
    eof: end === buffer.length,
    bytes: chunk.byteLength,
    totalBytes: buffer.byteLength,
    sha256: descriptor.sha256,
  };
}

export function clearReportArtifactRegistryForTests(): void {
  reports.clear();
}
