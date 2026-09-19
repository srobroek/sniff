import type { TSchema } from "@oh-my-pi/pi-ai";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { type AnalyzerArtifactDescriptor, type AnalyzerArtifactReadOptions, type AnalyzerObservationPreview, readAnalyzerArtifact } from "../src/core/analyzer-artifact-registry.ts";
import type { AnalyzerCapture, AnalyzerObservation } from "../src/core/analyzer-output.ts";
import {
  runSniffAnalyzer,
  runSniffInstall,
  type SniffAnalyzerOutcome,
  type SniffInstallMode,
  type SniffToolResult,
} from "../src/core/install.ts";
import { sniffInstallApproval, sniffToolInputSchemas } from "../src/core/tool-schemas.ts";

function publicPreflight(value: SniffToolResult | null): SniffToolResult | null {
  if (!value) return null;
  const safe = { ...value };
  delete safe.install;
  safe.attempts = value.attempts.map(({ argv, exitCode, timedOut, error, timeoutMs }) => ({ argv, exitCode, stderr: "", timedOut, ...(error ? { error } : {}), timeoutMs }));
  return safe;
}
const MAX_MODEL_CONTENT_BYTES = 64 * 1024 - 1;

type AnalyzerContentProjection = {
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

function jsonBytes(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value));
}

function analyzerProjection(
  analyzer: string,
  result: {
    ok: boolean;
    outcome: SniffAnalyzerOutcome;
    capture?: AnalyzerCapture;
    observationPreview?: AnalyzerObservationPreview;
    analyzerResultId?: string;
    readCapability?: string;
    descriptors?: readonly AnalyzerArtifactDescriptor[];
    descriptorCount?: number;
    descriptorsTruncated?: boolean;
    observations?: readonly AnalyzerObservation[];
  },
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

function utf8Prefix(value: string, maxBytes: number): string {
  const bytes = Buffer.from(value, "utf8");
  let end = Math.min(bytes.length, Math.max(0, maxBytes));
  while (end > 0 && (bytes[end] ?? 0) >= 0x80 && (bytes[end] ?? 0) < 0xc0) end -= 1;
  return bytes.subarray(0, end).toString("utf8");
}

function analyzerArtifactEnvelope(result: {
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
}): string {
  const metadata = {
    analyzerResultId: result.analyzerResultId,
    relativePath: result.relativePath,
    ...(result.sourcePath ? { sourcePath: result.sourcePath } : {}),
    offset: result.offset,
    nextOffset: result.nextOffset,
    eof: result.eof,
    bytes: result.bytes,
    totalBytes: result.totalBytes,
    sha256: result.sha256,
  };
  const encode = (content: string, consumed: number): string => JSON.stringify({ ...metadata, nextOffset: result.offset + consumed, eof: result.eof && consumed === result.bytes, bytes: consumed, content });
  const originalBytes = Buffer.byteLength(result.content, "utf8");
  const original = encode(result.content, originalBytes);
  if (Buffer.byteLength(original) <= MAX_MODEL_CONTENT_BYTES) return original;
  let low = 0;
  let high = originalBytes;
  let best = encode("", 0);
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const content = utf8Prefix(result.content, middle);
    const candidate = encode(content, Buffer.byteLength(content, "utf8"));
    if (Buffer.byteLength(candidate) <= MAX_MODEL_CONTENT_BYTES) {
      best = candidate;
      low = middle + 1;
    } else high = middle - 1;
  }
  return best;
}

type SniffReadAnalyzerArtifactParams = Omit<AnalyzerArtifactReadOptions, "capability"> & {
  readonly readCapability: string;
};

function registerAnalyzerArtifactReader(pi: ExtensionAPI): void {
  pi.registerTool<TSchema, { readonly ok: boolean; readonly error?: string }>({
    name: "sniff_read_analyzer_artifact",
    label: "Read Sniff analyzer artifact",
    description: "Read one UTF-8-safe page from complete analyzer observations using the readCapability returned by sniff_run_analyzer. Provide relativePath or sourcePath.",
    approval: "read",
    parameters: sniffToolInputSchemas.sniff_read_analyzer_artifact as unknown as TSchema,
    execute: async (_id, params: SniffReadAnalyzerArtifactParams) => {
      try {
        const { readCapability, ...options } = params;
        const result = readAnalyzerArtifact({ ...options, capability: readCapability });
        return { content: [{ type: "text", text: analyzerArtifactEnvelope(result) }], details: { ok: true, analyzerResultId: result.analyzerResultId, relativePath: result.relativePath, sourcePath: result.sourcePath, offset: result.offset, nextOffset: result.nextOffset, eof: result.eof, bytes: result.bytes, totalBytes: result.totalBytes, sha256: result.sha256 } };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return { content: [{ type: "text", text: `sniff_read_analyzer_artifact failed: ${message}` }], details: { ok: false, error: message }, isError: true };
      }
    },
  });
}

export default function sniffInstallTool(pi: ExtensionAPI): void {
  pi.registerTool({
    name: "sniff_install_tools",
    label: "Sniff install tools",
    description: "Probe, diagnose, list, or install sniff analyzer catalog entries. Diagnose is inventory-only and never authorizes execution. Managed installs require mise and are re-probed from a Sniff-owned toolkit. Never sudo or bypass trust policy. Default mode is probe.",
    approval: sniffInstallApproval,
    parameters: sniffToolInputSchemas.sniff_install_tools as unknown as TSchema,
    execute: async (_id, params: { mode?: SniffInstallMode; bundles?: string[]; all?: boolean; dryRun?: boolean; path?: string }, signal, _onUpdate, ctx) => {
      try {
        const result = await runSniffInstall({ ...params, cwd: params.path ?? ctx?.cwd ?? process.cwd(), signal });
        return { content: [{ type: "text", text: result.report }], details: { ok: result.ok, tools: result.tools }, isError: !result.ok };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return { content: [{ type: "text", text: `sniff_install_tools failed: ${message}` }], details: { ok: false, error: message, tools: [] }, isError: true };
      }
    },
  });

  pi.registerTool<TSchema, { readonly ok: boolean; readonly error?: string; readonly preflight: SniffToolResult | null; readonly acceptedExitCodes?: number[]; readonly outcome?: SniffAnalyzerOutcome; readonly analyzerResultId?: string; readonly readCapability?: string; readonly descriptors?: readonly AnalyzerArtifactDescriptor[]; readonly descriptorCount?: number; readonly descriptorsTruncated?: boolean; readonly observationPreview?: AnalyzerObservationPreview; readonly observations?: readonly AnalyzerObservation[]; readonly capture?: AnalyzerCapture }>({
    name: "sniff_run_analyzer",
    label: "Sniff run analyzer",
    description: "Run one analyzer selected by a live sniff_intake capability. The host revalidates the materialized target and enforces the catalogued fixed recipe immediately before execution.",
    approval: "exec",
    parameters: sniffToolInputSchemas.sniff_run_analyzer as unknown as TSchema,
    execute: async (_id, params: { capability: string; manifestId: string; analyzer: string }, signal) => {
      try {
        const result = await runSniffAnalyzer({ ...params, signal });
        const text = result.ok
          ? JSON.stringify(analyzerProjection(params.analyzer, result))
          : result.report;
        return { content: [{ type: "text", text }], details: { ok: result.ok, preflight: publicPreflight(result.preflight), acceptedExitCodes: result.acceptedExitCodes, outcome: result.outcome, analyzerResultId: result.analyzerResultId, readCapability: result.readCapability, descriptors: result.descriptors, descriptorCount: result.descriptorCount, descriptorsTruncated: result.descriptorsTruncated, observationPreview: result.observationPreview, observations: result.observations, capture: result.capture }, isError: !result.ok };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return { content: [{ type: "text", text: `sniff_run_analyzer failed: ${message}` }], details: { ok: false, error: message, preflight: null }, isError: true };
      }
    },
  });
  registerAnalyzerArtifactReader(pi);
}
