import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
import { recipeTargetSeparator, SNIFF_ANALYZER_RECIPES, type SniffAnalyzerRecipe } from "./analyzer-recipes.ts";
import { stableJson } from "./canonical-json.ts";
import { canonicalManifestJson, type RunManifest } from "./intake.ts";
import { type SpawnedProcess, terminateAndAwait } from "./process-control.ts";
import { assertUsableOwner, disposeAllSniffRunOwners, issuingOwner, MAX_LIVE_LEASES_PER_OWNER, type OwnerResource, ownerResource, type SniffRunOwner } from "./run-owner.ts";
import { type ResolvedTarget, type ResolvedTargetLease, targetFingerprint, validateResolvedTarget } from "./target.ts";

const LEASE_TTL_MS = 60 * 60 * 1_000;
const TERMINAL_LIMIT = 1_024;

type TerminalState = "cancelled" | "expired" | "released";
type TerminalRecord = { readonly state: TerminalState; readonly reason?: string; readonly owner: SniffRunOwner };
type ReservationState = "reserved" | "running" | "completed" | "failed";

type AnalyzerReservation = {
  readonly id: string;
  readonly analyzer: string;
  state: ReservationState;
};

type LeaseRecord = {
  readonly capability: string;
  readonly owner: SniffRunOwner;
  /** The issuing owner's live set; the record leaves it when released. */
  readonly ownerLeases: Map<string, LeaseRecord>;
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
  /** The one in-flight report attempt; a second concurrent attempt on the same lease is rejected. */
  reportClaim?: string;
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

/**
 * Every live lease by capability, for the unscoped host view; each record names its owner, and an
 * owner-scoped lookup sees only its own. Terminal records keep replay evidence the same way.
 */
const activeLeases = new Map<string, LeaseRecord>();
const terminalLeases = new Map<string, TerminalRecord>();

const OWNER_LEASES = Symbol("sniff.run-leases");

/** The owner's live leases; disposing the owner cancels them all. */
function ownerLeases(owner: SniffRunOwner): Map<string, LeaseRecord> {
  const resource = ownerResource(owner, OWNER_LEASES, (): OwnerResource & { readonly leases: Map<string, LeaseRecord> } => {
    const leases = new Map<string, LeaseRecord>();
    return {
      leases,
      dispose: (reason) => Promise.allSettled([...leases.values()].map((record) => releaseRecord(record, "cancelled", boundedReason(reason)))).then(() => undefined),
    };
  });
  return resource.leases;
}

/** Whether a record owned by `recordOwner` is visible to a call under `owner`; `undefined` is the trusted unscoped view. */
function visibleTo(recordOwner: SniffRunOwner, owner: SniffRunOwner | undefined): boolean {
  return owner === undefined || recordOwner === owner;
}

function rememberTerminal(capability: string, owner: SniffRunOwner, state: TerminalState, reason?: string): void {
  terminalLeases.set(capability, { state, owner, ...(reason ? { reason } : {}) });
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

/** Expiry cleanup is best-effort: a failed target release or home removal must never surface as an unhandled rejection. */
function swallowReleaseFailure(): void {}

/**
 * Detaches a lease, then terminates every child it spawned and waits for their exits before
 * releasing the target and deleting the home, so no analyzer can write into a released tree.
 * Leases with no live child release synchronously; the returned promise settles once cleanup ran
 * and rejects, never throws, when release fails.
 */
function releaseRecord(record: LeaseRecord, state: TerminalState, reason?: string): Promise<void> {
  if (activeLeases.get(record.capability) !== record) return record.pendingRelease ?? Promise.resolve();
  activeLeases.delete(record.capability);
  record.ownerLeases.delete(record.capability);
  clearTimeout(record.expiryTimer);
  rememberTerminal(record.capability, record.owner, state, reason);
  const tracked = [...record.activeProcesses.values()];
  record.activeProcesses.clear();
  if (tracked.length === 0) {
    try {
      finishRelease(record);
      return Promise.resolve();
    } catch (error) {
      return Promise.reject(error);
    }
  }
  const pending = Promise.all(tracked.map((spawned) => terminateAndAwait(spawned))).then(() => {
    finishRelease(record);
  });
  record.pendingRelease = pending;
  return pending;
}

/**
 * The live lease for a capability as seen by `owner`. Another owner's capability, live or
 * terminal, fails exactly like one that was never issued, so its existence never leaks.
 */
function activeLease(capability: string, manifestId: string, owner: SniffRunOwner | undefined): LeaseRecord {
  assertUsableOwner(owner);
  const record = activeLeases.get(capability);
  if (!record || !visibleTo(record.owner, owner)) {
    const terminal = terminalLeases.get(capability);
    throw new Error(terminal && visibleTo(terminal.owner, owner) ? `Sniff run capability was already ${terminal.state}${terminal.reason ? ` (${terminal.reason})` : ""}` : "Unknown Sniff run capability");
  }
  if (record.manifestId !== manifestId) throw new Error("Sniff run capability does not match the manifest ID");
  if (record.now() >= record.expiresAt) {
    releaseRecord(record, "expired").catch(swallowReleaseFailure);
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
  if (!recipe) throw new Error(`Analyzer ${analyzer} has no fixed runtime recipe`);
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
    argv: [...recipe.args, ...(recipe.scope === "scoped-files" ? [...recipeTargetSeparator(recipe), ...operands] : [])],
    operands,
    ...(record.manifest.budget.maxFiles !== undefined ? { maxFiles: record.manifest.budget.maxFiles } : {}),
    acceptedExitCodes: recipe.acceptedExitCodes,
    home: record.home,
    trust: record.manifest.route.trust,
    remainingBudgetMs,
  };
}

/** The owner's live leases after releasing expired ones; throws once the owner is at its lease cap. */
function leasesWithCapacity(owner: SniffRunOwner): Map<string, LeaseRecord> {
  const leases = ownerLeases(owner);
  for (const record of [...leases.values()]) if (record.now() >= record.expiresAt) releaseRecord(record, "expired").catch(swallowReleaseFailure);
  if (leases.size >= MAX_LIVE_LEASES_PER_OWNER) throw new Error(`A Sniff run owner may hold at most ${MAX_LIVE_LEASES_PER_OWNER} live Sniff runs; cancel or finish one first`);
  return leases;
}

/** Throws when `owner` (or the process owner) could not take another lease, before any target is resolved. */
export function assertRunLeaseCapacity(owner?: SniffRunOwner): void {
  leasesWithCapacity(issuingOwner(owner));
}

export function issueRunLease(
  manifest: RunManifest,
  targetLease: ResolvedTargetLease,
  options: { readonly ttlMs?: number; readonly sandboxGrant?: string; readonly now?: () => number; readonly owner?: SniffRunOwner } = {},
): RunLeaseReceipt {
  const now = options.now ?? Date.now;
  let home: string | undefined;
  let record: LeaseRecord;
  try {
    const owner = issuingOwner(options.owner);
    const leases = leasesWithCapacity(owner);
    const canonicalManifest = canonicalManifestJson(manifest);
    const target = validateResolvedTarget(targetLease.target);
    if (canonicalManifestJson({ ...manifest, resolvedTarget: target }) !== canonicalManifest) {
      throw new Error("Run manifest target does not match the materialized lease target");
    }
    const issuedAt = now();
    home = mkdtempSync(join(tmpdir(), "sniff-run-home-"));
    record = {
      capability: randomBytes(32).toString("base64url"),
      owner,
      ownerLeases: leases,
      manifestId: manifest.manifestId,
      manifest,
      canonicalManifest,
      target,
      targetIdentity: targetFingerprint(target),
      issuedAt,
      expiresAt: issuedAt + (options.ttlMs ?? LEASE_TTL_MS),
      now,
      home,
      ...(options.sandboxGrant ? { sandboxGrant: options.sandboxGrant } : {}),
      releaseTarget: targetLease.release,
      reservations: new Map(),
      activeProcesses: new Map(),
    };
  } catch (error) {
    // Until the lease is registered nothing else owns the target or home, so every failure releases both.
    if (home !== undefined) rmSync(home, { recursive: true, force: true });
    try {
      targetLease.release();
    } catch {
      // Preserve the issuance failure.
    }
    throw error;
  }
  const { capability, expiresAt } = record;
  activeLeases.set(capability, record);
  record.ownerLeases.set(capability, record);
  record.expiryTimer = setTimeout(() => {
    // Expiry is best-effort cleanup and must never crash the extension host.
    if (activeLeases.get(capability) === record) releaseRecord(record, "expired").catch(swallowReleaseFailure);
  }, Math.max(0, expiresAt - now()));
  record.expiryTimer.unref();
  return { capability, manifestId: manifest.manifestId, expiresAt: new Date(expiresAt).toISOString() };
}

export function authorizeAnalyzerRun(capability: string, manifestId: string, analyzer: string, owner?: SniffRunOwner): AnalyzerRunAuthorization {
  const record = activeLease(capability, manifestId, owner);
  if (record.reservations.has(analyzer)) throw new Error(`Analyzer ${analyzer} capability is one-shot and was already reserved`);
  const maxAnalyzers = record.manifest.budget.maxAnalyzers;
  if (maxAnalyzers !== undefined && record.reservations.size >= maxAnalyzers) throw new Error("Sniff run exceeds the manifest maxAnalyzers budget");
  const reservation: AnalyzerReservation = { id: randomBytes(16).toString("base64url"), analyzer, state: "reserved" };
  const authorization = authorizationFor(record, analyzer, reservation.id);
  record.reservations.set(analyzer, reservation);
  return authorization;
}

/** The live record for a capability when it belongs to `owner` and the manifest; never throws. */
function ownedRecord(capability: string, manifestId: string, owner: SniffRunOwner | undefined): LeaseRecord | undefined {
  const record = activeLeases.get(capability);
  return record !== undefined && record.manifestId === manifestId && visibleTo(record.owner, owner) ? record : undefined;
}

/**
 * Adopts a spawned analyzer child. The handle joins the lease's tracked set before the expiry
 * check so that a lease which expired between the spawn decision and this call releases through
 * the ordinary path: the child is terminated and awaited before the target and home go away.
 */
export function registerActiveProcess(capability: string, manifestId: string, spawned: SpawnedProcess, owner?: SniffRunOwner): void {
  const record = ownedRecord(capability, manifestId, owner);
  record?.activeProcesses.set(spawned.pid, spawned);
  try {
    activeLease(capability, manifestId, owner);
  } catch (error) {
    // An owned record that expired released through releaseRecord, which adopted and cleared the
    // handle; any other failure leaves the child untracked, so terminate it here.
    if (!record || record.activeProcesses.has(spawned.pid)) {
      record?.activeProcesses.delete(spawned.pid);
      void terminateAndAwait(spawned);
    }
    throw error;
  }
}

export function unregisterActiveProcess(capability: string, manifestId: string, pid: number, owner?: SniffRunOwner): void {
  ownedRecord(capability, manifestId, owner)?.activeProcesses.delete(pid);
}

export function prepareAnalyzerSpawn(capability: string, manifestId: string, analyzer: string, reservationId: string, owner?: SniffRunOwner): AnalyzerRunAuthorization {
  const record = activeLease(capability, manifestId, owner);
  const reservation = record.reservations.get(analyzer);
  if (!reservation || reservation.id !== reservationId || reservation.state !== "reserved") throw new Error(`Analyzer ${analyzer} reservation is not available for launch`);
  const authorization = authorizationFor(record, analyzer, reservationId);
  reservation.state = "running";
  return authorization;
}

export function abandonAnalyzerReservation(capability: string, manifestId: string, analyzer: string, reservationId: string, owner?: SniffRunOwner): void {
  const record = activeLease(capability, manifestId, owner);
  const reservation = record.reservations.get(analyzer);
  if (reservation?.id === reservationId && reservation.state === "reserved") record.reservations.delete(analyzer);
}

export function completeAnalyzerReservation(capability: string, manifestId: string, analyzer: string, reservationId: string, owner?: SniffRunOwner): void {
  const record = activeLease(capability, manifestId, owner);
  const reservation = record.reservations.get(analyzer);
  if (!reservation || reservation.id !== reservationId || reservation.state !== "running") throw new Error(`Analyzer ${analyzer} reservation cannot be completed`);
  try {
    const recipe = SNIFF_ANALYZER_RECIPES[analyzer as keyof typeof SNIFF_ANALYZER_RECIPES];
    if (!recipe) throw new Error(`Analyzer ${analyzer} has no fixed runtime recipe`);
    authorizedTarget(record, recipe);
    if (record.now() > analyzerDeadline(record)) throw new Error("Sniff analyzer exceeded the manifest maxMinutes budget");
  } catch (error) {
    reservation.state = "failed";
    throw error;
  }
  reservation.state = "completed";
}

/**
 * Takes the lease's one-shot reporting state before a report attempt awaits anything, so a second
 * attempt with the same capability cannot race the first into producing two reports.
 */
export function beginRunReport(capability: string, manifestId: string, owner?: SniffRunOwner): string {
  const record = activeLease(capability, manifestId, owner);
  if (record.reportClaim !== undefined) throw new Error("A Sniff report is already in progress for this run capability");
  const claim = randomBytes(16).toString("base64url");
  record.reportClaim = claim;
  return claim;
}

/** Throws unless the lease is still live and the report attempt still holds its claim, e.g. after a cancel while awaiting approval. */
export function assertRunReport(capability: string, manifestId: string, claim: string, owner?: SniffRunOwner): void {
  if (activeLease(capability, manifestId, owner).reportClaim !== claim) throw new Error("Sniff report attempt no longer holds this run capability");
}

/** Ends a report attempt that wrote nothing, keeping the lease for a corrected retry. */
export function endRunReport(capability: string, manifestId: string, claim: string, owner?: SniffRunOwner): void {
  const record = ownedRecord(capability, manifestId, owner);
  if (record?.reportClaim === claim) record.reportClaim = undefined;
}

export function readRunManifest(capability: string, manifestId: string, owner?: SniffRunOwner): RunManifest {
  return activeLease(capability, manifestId, owner).manifest;
}
export function validateReportManifest(capability: string, manifestId: string, supplied: unknown, owner?: SniffRunOwner): RunManifest {
  const lease = activeLease(capability, manifestId, owner);
  let serialized: string;
  try {
    serialized = stableJson(supplied);
  } catch {
    throw new Error("sniff.intake manifest is not serializable");
  }
  if (serialized !== lease.canonicalManifest) throw new Error("sniff.intake manifest differs from the issued manifest");
  return lease.manifest;
}
export function validateReportCoverage(capability: string, manifestId: string, coverage: readonly { readonly tool: string; readonly status: string }[], owner?: SniffRunOwner): void {
  const record = activeLease(capability, manifestId, owner);
  for (const entry of coverage) {
    if (entry.status !== "ran") continue;
    const selected = record.manifest.analyzers.filter((candidate) => candidate.disposition === "selected" && candidate.tool === entry.tool);
    if (selected.length === 0) throw new Error(`Report coverage claims an unauthorized analyzer: ${entry.tool}`);
    if (!selected.some((candidate) => record.reservations.get(candidate.name)?.state === "completed")) throw new Error(`Report coverage claims analyzer ${entry.tool} without a completed reservation`);
  }
}

/** Resolves once spawned analyzers have exited and the target and home were cleaned up. */
export function releaseRunLease(capability: string, manifestId: string, owner?: SniffRunOwner): Promise<void> {
  return releaseRecord(activeLease(capability, manifestId, owner), "released");
}

export function cancelRunLease(capability: string, manifestId: string, owner?: SniffRunOwner): Promise<void> {
  return releaseRecord(activeLease(capability, manifestId, owner), "cancelled");
}

export function finalizeRunLease(capability: string, manifestId: string, owner?: SniffRunOwner): Promise<void> {
  const record = ownedRecord(capability, manifestId, owner);
  return record ? releaseRecord(record, "released") : Promise.resolve();
}

/**
 * Process shutdown: disposes every run owner, releasing every active lease. Cleanup is
 * best-effort: the promise settles only once every lease's children exited and its cleanup ran,
 * and one failed release never cuts the others short.
 */
export function releaseAllRunLeases(reason: string): Promise<void> {
  return disposeAllSniffRunOwners(boundedReason(reason));
}
