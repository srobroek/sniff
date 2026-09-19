import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
import { SNIFF_ANALYZER_RECIPES, type SniffAnalyzerRecipe } from "./catalog.ts";
import { canonicalManifestJson, type RunManifest } from "./intake.ts";
import { type SpawnedProcess, terminateAndAwait } from "./process-control.ts";
import { type ResolvedTarget, type ResolvedTargetLease, targetFingerprint, validateResolvedTarget } from "./target.ts";

const LEASE_TTL_MS = 60 * 60 * 1_000;
const TERMINAL_LIMIT = 1_024;

type TerminalState = "cancelled" | "expired" | "released";
type TerminalRecord = { readonly state: TerminalState; readonly reason?: string };
type ReservationState = "reserved" | "running" | "completed" | "failed";

type AnalyzerReservation = {
  readonly id: string;
  readonly analyzer: string;
  state: ReservationState;
};

type LeaseRecord = {
  readonly capability: string;
  readonly manifestId: string;
  readonly manifest: RunManifest;
  readonly canonicalManifest: string;
  readonly target: ResolvedTarget;
  readonly targetIdentity: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly home: string;
  readonly now: () => number;
  readonly sandboxGrant?: string;
  readonly releaseTarget: () => void;
  readonly reservations: Map<string, AnalyzerReservation>;
  readonly activeProcesses: Map<number, SpawnedProcess>;
  pendingRelease?: Promise<void>;
  expiryTimer?: NodeJS.Timeout;
};



export type RunLeaseReceipt = {
  readonly capability: string;
  readonly manifestId: string;
  readonly expiresAt: string;
};

export type AnalyzerRunAuthorization = {
  readonly reservationId: string;
  readonly target: ResolvedTarget;
  readonly recipe: SniffAnalyzerRecipe;
  readonly argv: readonly string[];
  readonly operands: readonly string[];
  readonly maxFiles?: number;
  readonly acceptedExitCodes: readonly number[];
  readonly home: string;
  readonly trust: RunManifest["route"]["trust"];
  readonly remainingBudgetMs: number;
};

const activeLeases = new Map<string, LeaseRecord>();
const terminalLeases = new Map<string, TerminalRecord>();

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, entry]) => [key, stableValue(entry)]));
  }
  return value;
}

function rememberTerminal(capability: string, state: TerminalState, reason?: string): void {
  terminalLeases.set(capability, { state, ...(reason ? { reason } : {}) });
  while (terminalLeases.size > TERMINAL_LIMIT) {
    const oldest = terminalLeases.keys().next().value;
    if (typeof oldest !== "string") break;
    terminalLeases.delete(oldest);
  }
}

const boundedReason = (reason: string): string => reason.trim().slice(0, 256) || "process shutdown";

function finishRelease(record: LeaseRecord): void {
  try {
    record.releaseTarget();
  } finally {
    rmSync(record.home, { recursive: true, force: true });
  }
}

/**
 * Detaches a lease, then terminates every child it spawned and waits for their exits before
 * releasing the target and deleting the home, so no analyzer can write into a released tree.
 * Leases with no live child release synchronously; the returned promise settles once cleanup ran.
 */
function releaseRecord(record: LeaseRecord, state: TerminalState, reason?: string): Promise<void> {
  if (activeLeases.get(record.capability) !== record) return record.pendingRelease ?? Promise.resolve();
  activeLeases.delete(record.capability);
  clearTimeout(record.expiryTimer);
  rememberTerminal(record.capability, state, reason);
  const tracked = [...record.activeProcesses.values()];
  record.activeProcesses.clear();
  if (tracked.length === 0) {
    finishRelease(record);
    return Promise.resolve();
  }
  const pending = Promise.all(tracked.map((spawned) => terminateAndAwait(spawned))).then(() => {
    finishRelease(record);
  });
  record.pendingRelease = pending;
  return pending;
}

function activeLease(capability: string, manifestId: string): LeaseRecord {
  const record = activeLeases.get(capability);
  if (!record) {
    const terminal = terminalLeases.get(capability);
    throw new Error(terminal ? `Sniff run capability was already ${terminal.state}${terminal.reason ? ` (${terminal.reason})` : ""}` : "Unknown Sniff run capability");
  }
  if (record.manifestId !== manifestId) throw new Error("Sniff run capability does not match the manifest ID");
  if (record.now() >= record.expiresAt) {
    void releaseRecord(record, "expired");
    throw new Error("Sniff run capability expired");
  }
  return record;
}

function analyzerDeadline(record: LeaseRecord): number {
  const minutes = record.manifest.budget.maxMinutes;
  return minutes === undefined ? record.expiresAt : Math.min(record.expiresAt, record.issuedAt + minutes * 60_000);
}

function authorizedTarget(record: LeaseRecord, recipe: SniffAnalyzerRecipe): { target: ResolvedTarget; operands: string[] } {
  const target = validateResolvedTarget(record.target);
  if (target.root !== record.target.root || targetFingerprint(target) !== record.targetIdentity) {
    throw new Error("Materialized target changed after intake authorization");
  }
  let operands: string[] = [];
  if (recipe.scope === "scoped-files") {
    operands = recipe.fileExtensions
      ? target.files.filter((file) => recipe.fileExtensions?.includes(extname(file).toLowerCase()))
      : [...target.files];
    if (operands.length === 0) throw new Error(`Analyzer ${recipe.id} has no compatible files in the exact target scope`);
  } else if (recipe.scope === "repository-wide" && target.kind !== "repository" && target.kind !== "whole-repo" && target.kind !== "history") {
    throw new Error(`Analyzer ${recipe.id} requires an explicitly repository-wide target`);
  } else if (recipe.scope === "bounded-history" && target.kind !== "history") {
    throw new Error(`Analyzer ${recipe.id} requires an explicitly bounded history target`);
  }
  const accessedFiles = recipe.scope === "scoped-files" ? operands.length : target.files.length;
  if (recipe.scope !== "scoped-files" && record.manifest.budget.maxFiles !== undefined && accessedFiles > record.manifest.budget.maxFiles) {
    throw new Error(`Analyzer ${recipe.id} exceeds the manifest maxFiles budget`);
  }
  return { target, operands };
}

function authorizationFor(record: LeaseRecord, analyzer: string, reservationId: string): AnalyzerRunAuthorization {
  const disposition = record.manifest.analyzers.find((candidate) => candidate.name === analyzer && candidate.disposition === "selected");
  if (!disposition) throw new Error(`Analyzer ${analyzer} was not selected by the issued manifest`);
  if (!(analyzer in SNIFF_ANALYZER_RECIPES)) throw new Error(`Analyzer ${analyzer} has no fixed runtime recipe`);
  const recipe = SNIFF_ANALYZER_RECIPES[analyzer as keyof typeof SNIFF_ANALYZER_RECIPES];
  if (disposition.tool !== recipe.tool || disposition.recipe !== recipe.id) throw new Error(`Analyzer ${analyzer} mapping differs from the issued policy`);
  if (record.manifest.route.trust === "untrusted-remote" && (!recipe.remoteSafe || !recipe.configFree || recipe.projectControlled)) {
    throw new Error(`Analyzer ${analyzer} is not remote-safe and config-free`);
  }
  if (recipe.projectControlled && !record.sandboxGrant) throw new Error(`Analyzer ${analyzer} requires a host-issued sandbox grant`);
  const remainingBudgetMs = analyzerDeadline(record) - record.now();
  if (remainingBudgetMs <= 0) throw new Error("Sniff analyzer maxMinutes budget expired");
  const { target, operands } = authorizedTarget(record, recipe);
  return {
    reservationId,
    target,
    recipe,
    argv: [...recipe.args, ...(recipe.scope === "scoped-files" ? [...("targetSeparator" in recipe ? recipe.targetSeparator : ["--"]), ...operands] : [])],
    operands,
    ...(record.manifest.budget.maxFiles !== undefined ? { maxFiles: record.manifest.budget.maxFiles } : {}),
    acceptedExitCodes: recipe.acceptedExitCodes,
    home: record.home,
    trust: record.manifest.route.trust,
    remainingBudgetMs,
  };
}

export function issueRunLease(
  manifest: RunManifest,
  targetLease: ResolvedTargetLease,
  options: { readonly ttlMs?: number; readonly sandboxGrant?: string; readonly now?: () => number } = {},
): RunLeaseReceipt {
  const canonicalManifest = canonicalManifestJson(manifest);
  const target = validateResolvedTarget(targetLease.target);
  if (canonicalManifestJson({ ...manifest, resolvedTarget: target }) !== canonicalManifest) {
    targetLease.release();
    throw new Error("Run manifest target does not match the materialized lease target");
  }
  const capability = randomBytes(32).toString("base64url");
  const now = options.now ?? Date.now;
  const issuedAt = now();
  const expiresAt = issuedAt + (options.ttlMs ?? LEASE_TTL_MS);
  const home = mkdtempSync(join(tmpdir(), "sniff-run-home-"));
  const record: LeaseRecord = {
    capability,
    manifestId: manifest.manifestId,
    manifest,
    canonicalManifest,
    target,
    targetIdentity: targetFingerprint(target),
    issuedAt,
    expiresAt,
    now,
    home,
    ...(options.sandboxGrant ? { sandboxGrant: options.sandboxGrant } : {}),
    releaseTarget: targetLease.release,
    reservations: new Map(),
    activeProcesses: new Map(),
  };
  activeLeases.set(capability, record);
  record.expiryTimer = setTimeout(() => {
    try {
      if (activeLeases.get(capability) === record) void releaseRecord(record, "expired");
    } catch {
      // Expiry is best-effort cleanup and must never crash the extension host.
    }
  }, Math.max(0, expiresAt - now()));
  record.expiryTimer.unref();
  return { capability, manifestId: manifest.manifestId, expiresAt: new Date(expiresAt).toISOString() };
}

export function authorizeAnalyzerRun(capability: string, manifestId: string, analyzer: string): AnalyzerRunAuthorization {
  const record = activeLease(capability, manifestId);
  if (record.reservations.has(analyzer)) throw new Error(`Analyzer ${analyzer} capability is one-shot and was already reserved`);
  const maxAnalyzers = record.manifest.budget.maxAnalyzers;
  if (maxAnalyzers !== undefined && record.reservations.size >= maxAnalyzers) throw new Error("Sniff run exceeds the manifest maxAnalyzers budget");
  const reservation: AnalyzerReservation = { id: randomBytes(16).toString("base64url"), analyzer, state: "reserved" };
  const authorization = authorizationFor(record, analyzer, reservation.id);
  record.reservations.set(analyzer, reservation);
  return authorization;
}

/**
 * Adopts a spawned analyzer child. A lease that expired between the spawn decision and this call
 * would otherwise orphan the child, so it is terminated before the expiry error propagates.
 */
export function registerActiveProcess(capability: string, manifestId: string, spawned: SpawnedProcess): void {
  let record: LeaseRecord;
  try {
    record = activeLease(capability, manifestId);
  } catch (error) {
    void terminateAndAwait(spawned);
    throw error;
  }
  record.activeProcesses.set(spawned.pid, spawned);
}

export function unregisterActiveProcess(capability: string, manifestId: string, pid: number): void {
  const record = activeLeases.get(capability);
  if (record?.manifestId === manifestId) record.activeProcesses.delete(pid);
}

export function prepareAnalyzerSpawn(capability: string, manifestId: string, analyzer: string, reservationId: string): AnalyzerRunAuthorization {
  const record = activeLease(capability, manifestId);
  const reservation = record.reservations.get(analyzer);
  if (!reservation || reservation.id !== reservationId || reservation.state !== "reserved") throw new Error(`Analyzer ${analyzer} reservation is not available for launch`);
  const authorization = authorizationFor(record, analyzer, reservationId);
  reservation.state = "running";
  return authorization;
}

export function abandonAnalyzerReservation(capability: string, manifestId: string, analyzer: string, reservationId: string): void {
  const record = activeLease(capability, manifestId);
  const reservation = record.reservations.get(analyzer);
  if (reservation?.id === reservationId && reservation.state === "reserved") record.reservations.delete(analyzer);
}

export function completeAnalyzerReservation(capability: string, manifestId: string, analyzer: string, reservationId: string): void {
  const record = activeLease(capability, manifestId);
  const reservation = record.reservations.get(analyzer);
  if (!reservation || reservation.id !== reservationId || reservation.state !== "running") throw new Error(`Analyzer ${analyzer} reservation cannot be completed`);
  try {
    authorizedTarget(record, SNIFF_ANALYZER_RECIPES[analyzer as keyof typeof SNIFF_ANALYZER_RECIPES]);
    if (record.now() > analyzerDeadline(record)) throw new Error("Sniff analyzer exceeded the manifest maxMinutes budget");
  } catch (error) {
    reservation.state = "failed";
    throw error;
  }
  reservation.state = "completed";
}

export function readRunManifest(capability: string, manifestId: string): RunManifest {
	return activeLease(capability, manifestId).manifest;
}
export function validateReportManifest(capability: string, manifestId: string, supplied: unknown): RunManifest {
  const lease = activeLease(capability, manifestId);
  let serialized: string;
  try {
    serialized = JSON.stringify(stableValue(supplied));
  } catch {
    throw new Error("sniff.intake manifest is not serializable");
  }
  if (serialized !== lease.canonicalManifest) throw new Error("sniff.intake manifest differs from the issued manifest");
  return lease.manifest;
}
export function validateReportCoverage(capability: string, manifestId: string, coverage: readonly { readonly tool: string; readonly status: string }[]): void {
  const record = activeLease(capability, manifestId);
  for (const entry of coverage) {
    if (entry.status !== "ran") continue;
    const selected = record.manifest.analyzers.filter((candidate) => candidate.disposition === "selected" && candidate.tool === entry.tool);
    if (selected.length === 0) throw new Error(`Report coverage claims an unauthorized analyzer: ${entry.tool}`);
    if (!selected.some((candidate) => record.reservations.get(candidate.name)?.state === "completed")) throw new Error(`Report coverage claims analyzer ${entry.tool} without a completed reservation`);
  }
}

/** Resolves once spawned analyzers have exited and the target and home were cleaned up. */
export function releaseRunLease(capability: string, manifestId: string): Promise<void> {
  return releaseRecord(activeLease(capability, manifestId), "released");
}

export function cancelRunLease(capability: string, manifestId: string): Promise<void> {
  return releaseRecord(activeLease(capability, manifestId), "cancelled");
}

export function finalizeRunLease(capability: string, manifestId: string): Promise<void> {
  const record = activeLeases.get(capability);
  return record?.manifestId === manifestId ? releaseRecord(record, "released") : Promise.resolve();
}

export function releaseAllRunLeases(reason: string): Promise<void> {
  const bounded = boundedReason(reason);
  const pending: Promise<void>[] = [];
  for (const record of [...activeLeases.values()]) {
    try {
      pending.push(releaseRecord(record, "cancelled", bounded));
    } catch {
      // Shutdown cleanup is best-effort; continue releasing every active lease.
    }
  }
  return Promise.all(pending).then(() => undefined);
}
