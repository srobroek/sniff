import type { AnalyzerArtifactDescriptor, AnalyzerArtifactReadResult, AnalyzerObservationPreview } from "./analyzer-artifact-registry.ts";
import type { AnalyzerCapture, AnalyzerObservation } from "./analyzer-output.ts";
import type { SniffAnalyzerOutcome, SniffAnalyzerRunResult, SniffToolResult } from "./install.ts";
import type { PublicReportArtifacts } from "./report.ts";
import type { ReportArtifactReadResult } from "./report-artifact-registry.ts";

/** Native adapters keep every model-facing text result strictly below one 64 KiB artifact page. */
export const MAX_MODEL_CONTENT_BYTES = 64 * 1024 - 1;

function jsonBytes(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value));
}

/** The longest prefix of `value` that fits in `maxBytes` UTF-8 bytes without splitting a code point. */
export function utf8Prefix(value: string, maxBytes: number): string {
  const bytes = Buffer.from(value, "utf8");
  let end = Math.min(bytes.length, Math.max(0, maxBytes));
  while (end > 0 && (bytes[end] ?? 0) >= 0x80 && (bytes[end] ?? 0) < 0xc0) end -= 1;
  return bytes.subarray(0, end).toString("utf8");
}

/** Analyzer preflight without install output or stderr, which can carry host paths and secrets. */
export function publicPreflight(value: SniffToolResult | null): SniffToolResult | null {
  if (!value) return null;
  const safe = { ...value };
  delete safe.install;
  safe.attempts = value.attempts.map(({ argv, exitCode, timedOut, error, timeoutMs }) => ({ argv, exitCode, stderr: "", timedOut, ...(error ? { error } : {}), timeoutMs }));
  return safe;
}

export type AnalyzerContentProjection = {
  readonly ok: boolean;
  readonly analyzer: string;
  readonly outcome: SniffAnalyzerOutcome;
  readonly capture?: AnalyzerCapture;
  readonly observationPreview?: AnalyzerObservationPreview;
  readonly analyzerResultId?: string;
  readonly readCapability?: string;
  readonly descriptors: readonly AnalyzerArtifactDescriptor[];
  readonly descriptorCount?: number;
  readonly descriptorsTruncated?: boolean;
  readonly observations: readonly AnalyzerObservation[];
};

/**
 * The analyzer result projected for the model: every descriptor and observation that fits in
 * {@link MAX_MODEL_CONTENT_BYTES}. Observations are dropped before descriptors, so the read
 * capability always survives and the complete observations stay reachable through paging.
 */
export function analyzerProjection(
  analyzer: string,
  result: Pick<SniffAnalyzerRunResult, "ok" | "outcome" | "capture" | "observationPreview" | "analyzerResultId" | "readCapability" | "descriptors" | "descriptorCount" | "descriptorsTruncated" | "observations">,
): AnalyzerContentProjection {
  const descriptors = [...(result.descriptors ?? [])];
  const observations = [...(result.observations ?? [])];
  const base = (selectedDescriptors: readonly AnalyzerArtifactDescriptor[], selectedObservations: readonly AnalyzerObservation[], descriptorTruncated: boolean): AnalyzerContentProjection => ({
    ok: result.ok,
    analyzer,
    outcome: result.outcome,
    ...(result.capture ? { capture: result.capture } : {}),
    ...(result.observationPreview ? { observationPreview: { ...result.observationPreview, returned: selectedObservations.length, truncated: selectedObservations.length < result.observationPreview.total } } : {}),
    ...(result.analyzerResultId ? { analyzerResultId: result.analyzerResultId } : {}),
    ...(result.readCapability ? { readCapability: result.readCapability } : {}),
    descriptors: selectedDescriptors,
    ...(result.descriptorCount !== undefined ? { descriptorCount: result.descriptorCount } : {}),
    ...(result.descriptorsTruncated || descriptorTruncated ? { descriptorsTruncated: true } : {}),
    observations: selectedObservations,
  });

  let selectedDescriptors = descriptors;
  let selectedObservations = observations;
  let descriptorTruncated = false;
  let projection = base(selectedDescriptors, selectedObservations, descriptorTruncated);
  if (jsonBytes(projection) > MAX_MODEL_CONTENT_BYTES) {
    selectedObservations = [];
    projection = base(selectedDescriptors, selectedObservations, descriptorTruncated);
    if (jsonBytes(projection) > MAX_MODEL_CONTENT_BYTES) {
      let low = 0;
      let high = selectedDescriptors.length;
      while (low < high) {
        const middle = Math.ceil((low + high) / 2);
        const candidate = base(selectedDescriptors.slice(0, middle), [], middle < selectedDescriptors.length);
        if (jsonBytes(candidate) <= MAX_MODEL_CONTENT_BYTES) low = middle;
        else high = middle - 1;
      }
      selectedDescriptors = selectedDescriptors.slice(0, low);
      descriptorTruncated = selectedDescriptors.length < descriptors.length;
      projection = base(selectedDescriptors, [], descriptorTruncated);
    }
    let low = 0;
    let high = observations.length;
    while (low < high) {
      const middle = Math.ceil((low + high) / 2);
      const candidate = base(selectedDescriptors, observations.slice(0, middle), descriptorTruncated);
      if (jsonBytes(candidate) <= MAX_MODEL_CONTENT_BYTES) low = middle;
      else high = middle - 1;
    }
    selectedObservations = observations.slice(0, low);
    projection = base(selectedDescriptors, selectedObservations, descriptorTruncated);
  }
  return projection;
}

/** The validated `maxBytes` of an analyzer artifact read, or undefined when the caller set none. */
export function analyzerPageLimit(value: unknown): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 4 || value > MAX_MODEL_CONTENT_BYTES + 1) {
    throw new Error(`Analyzer artifact maxBytes must be an integer from 4 through ${MAX_MODEL_CONTENT_BYTES + 1}`);
  }
  return value;
}

/** One analyzer artifact page as model text plus the page it describes; both carry the same cursor. */
export function analyzerArtifactPage(result: AnalyzerArtifactReadResult, maxBytes?: number): BoundedPage<AnalyzerArtifactReadResult> {
  return boundedPage(result, (page) => JSON.stringify({
    analyzerResultId: page.analyzerResultId,
    relativePath: page.relativePath,
    ...(page.sourcePath ? { sourcePath: page.sourcePath } : {}),
    offset: page.offset,
    nextOffset: page.nextOffset,
    eof: page.eof,
    bytes: page.bytes,
    totalBytes: page.totalBytes,
    sha256: page.sha256,
    content: page.content,
  }), maxBytes);
}

/** One report artifact page as model text plus the page it describes; both carry the same cursor. */
export function reportArtifactPage(result: ReportArtifactReadResult): BoundedPage<ReportArtifactReadResult> {
  return boundedPage(result, (page) => JSON.stringify({
    relativePath: page.relativePath,
    offset: page.offset,
    nextOffset: page.nextOffset,
    eof: page.eof,
    bytes: page.bytes,
    content: page.content,
  }));
}

type PageCursor = { readonly content: string; readonly offset: number; readonly nextOffset: number; readonly eof: boolean; readonly bytes: number };

export type BoundedPage<Page> = { readonly text: string; readonly page: Page };

/**
 * Shorten a page at a UTF-8 boundary until its encoding fits {@link MAX_MODEL_CONTENT_BYTES}
 * (and `maxBytes` of content when given). The returned page's `bytes`, `nextOffset`, and `eof`
 * describe exactly the content kept, so a reader continuing from `nextOffset` skips nothing.
 */
function boundedPage<Page extends PageCursor>(result: Page, encode: (page: Page) => string, maxBytes?: number): BoundedPage<Page> {
  const source = Buffer.from(result.content, "utf8");
  const pageOf = (limit: number): Page => {
    let end = Math.min(source.length, Math.max(0, limit));
    while (end > 0 && end < source.length && ((source[end] ?? 0) & 0xc0) === 0x80) end -= 1;
    return { ...result, content: source.subarray(0, end).toString("utf8"), bytes: end, nextOffset: result.offset + end, eof: result.eof && end === source.length };
  };
  const fits = (text: string): boolean => Buffer.byteLength(text, "utf8") <= MAX_MODEL_CONTENT_BYTES;
  const first = pageOf(maxBytes ?? source.length);
  const firstText = encode(first);
  if (fits(firstText)) return { text: firstText, page: first };
  let low = 0;
  let high = first.bytes;
  let best = pageOf(0);
  let bestText = encode(best);
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const candidate = pageOf(middle);
    const text = encode(candidate);
    if (fits(text)) {
      best = candidate;
      bestText = text;
      low = middle + 1;
    } else high = middle - 1;
  }
  return { text: bestText, page: best };
}

function reportMetadata(publicArtifacts: PublicReportArtifacts, descriptors: PublicReportArtifacts["descriptors"]): string {
  return JSON.stringify({ reportId: publicArtifacts.reportId, readCapability: publicArtifacts.readCapability, descriptors });
}

/** Report metadata line plus the summary, keeping as many descriptors as fit before shortening the summary. */
export function reportRenderContent(publicArtifacts: PublicReportArtifacts): string {
  const allDescriptors = [...publicArtifacts.descriptors];
  const encode = (descriptors: PublicReportArtifacts["descriptors"], summary: string): string => `${reportMetadata(publicArtifacts, descriptors)}\n${summary}`;
  const fits = (descriptors: PublicReportArtifacts["descriptors"], summary: string): boolean => Buffer.byteLength(encode(descriptors, summary), "utf8") <= MAX_MODEL_CONTENT_BYTES;

  let low = 0;
  let high = allDescriptors.length;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (fits(allDescriptors.slice(0, middle), publicArtifacts.summary)) low = middle;
    else high = middle - 1;
  }
  const selectedDescriptors = allDescriptors.slice(0, low);
  if (fits(selectedDescriptors, publicArtifacts.summary)) return encode(selectedDescriptors, publicArtifacts.summary);

  let descriptorLow = 0;
  let descriptorHigh = allDescriptors.length;
  while (descriptorLow < descriptorHigh) {
    const middle = Math.ceil((descriptorLow + descriptorHigh) / 2);
    if (fits(allDescriptors.slice(0, middle), "")) descriptorLow = middle;
    else descriptorHigh = middle - 1;
  }
  const boundedDescriptors = allDescriptors.slice(0, descriptorLow);
  const summaryBudget = MAX_MODEL_CONTENT_BYTES - Buffer.byteLength(reportMetadata(publicArtifacts, boundedDescriptors), "utf8") - 1;
  return encode(boundedDescriptors, utf8Prefix(publicArtifacts.summary, summaryBudget));
}
