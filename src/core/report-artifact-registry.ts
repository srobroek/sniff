import { createHash, randomBytes } from "node:crypto";
import { canonicalJson } from "./canonical-json.ts";
import type { ReportArtifactDescriptor, ReportArtifacts } from "./report.ts";
import { assertUsableOwner, issuingOwner, type OwnerResource, ownerResource, ownerSees, type SniffRunOwner } from "./run-owner.ts";

export const REPORT_ARTIFACT_CHUNK_BYTES = 64 * 1024;
/** Per-owner entry and byte budgets: one owner's registrations never evict another's. */
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
  readonly owner: SniffRunOwner;
  /** The owning bucket, which tracks this owner's budget and eviction order. */
  readonly bucket: OwnerReports;
  readonly reportId: string;
  /** UTF-8 bytes encoded once at registration, so paging never re-encodes the artifact. */
  readonly contents: ReadonlyMap<string, Buffer>;
  readonly descriptors: ReadonlyMap<string, ReportArtifactDescriptor>;
  readonly bytes: number;
  readonly createdAt: number;
  expiresAt: number;
};

type OwnerReports = OwnerResource & { readonly entries: Map<string, RegisteredReport>; bytes: number };

/** Every registered report by capability; each entry names its owner and lives in that owner's bucket. */
const reports = new Map<string, RegisteredReport>();
const OWNER_REPORTS = Symbol("sniff.report-artifacts");

function ownerReports(owner: SniffRunOwner): OwnerReports {
  return ownerResource(owner, OWNER_REPORTS, (): OwnerReports => {
    const bucket: OwnerReports = {
      entries: new Map(),
      bytes: 0,
      dispose: () => {
        for (const capability of [...bucket.entries.keys()]) forget(capability);
      },
    };
    return bucket;
  });
}

function forget(capability: string): void {
  const entry = reports.get(capability);
  if (!entry) return;
  reports.delete(capability);
  entry.bucket.entries.delete(capability);
  entry.bucket.bytes -= entry.bytes;
}

function purgeExpired(now: number): void {
  for (const [capability, entry] of reports) if (entry.expiresAt <= now || entry.createdAt + REPORT_ARTIFACT_MAX_AGE_MS <= now) forget(capability);
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
/** Registers artifacts under `owner` (the process owner when omitted) and returns their read capability. */
export function registerReportArtifacts(artifacts: ReportArtifacts, now = Date.now(), owner?: SniffRunOwner): string {
  const issuer = issuingOwner(owner);
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
  const bucket = ownerReports(issuer);
  const entry: RegisteredReport = { owner: issuer, bucket, reportId: artifacts.report.reportId, contents, descriptors, bytes, createdAt: now, expiresAt: now + REPORT_ARTIFACT_IDLE_TTL_MS };
  reports.set(capability, entry);
  bucket.entries.set(capability, entry);
  bucket.bytes += bytes;
  while (bucket.entries.size > MAX_REPORT_ARTIFACT_REGISTRY_ENTRIES || bucket.bytes > MAX_REPORT_ARTIFACT_REGISTRY_BYTES) {
    const oldest = bucket.entries.keys().next().value;
    if (typeof oldest !== "string") break;
    forget(oldest);
  }
  return capability;
}

function isContinuationByte(value: number): boolean {
  return (value & 0xc0) === 0x80;
}

/**
 * Reads one page through `owner`. Another owner's capability fails exactly like an unknown one;
 * omitting the owner reads as the process owner.
 */
export function readReportArtifact(options: ReportArtifactReadOptions, now = Date.now(), owner?: SniffRunOwner): ReportArtifactReadResult {
  assertUsableOwner(owner);
  purgeExpired(now);
  const entry = reports.get(options.capability);
  if (!entry || !ownerSees(entry.owner, owner)) throw new Error("Unknown Sniff report artifact capability");
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
  for (const capability of [...reports.keys()]) forget(capability);
}
