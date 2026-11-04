import { randomBytes } from "node:crypto";

/** Default cap on concurrently live run leases one owner may hold. */
export const MAX_LIVE_LEASES_PER_OWNER = 8;

/**
 * The scope that issued a set of runs and artifacts: one per client, plugin instance, or project.
 * Every capability resolves only under the owner that issued it, budgets are counted per owner,
 * and disposing an owner releases exactly what it holds. Owners are opaque: the core recognizes
 * only objects it created, so a look-alike object is refused.
 */
export interface SniffRunOwner {
  readonly id: string;
  readonly label: string;
  /** True once disposal started; a disposed owner refuses every further call. */
  readonly disposed: boolean;
  /**
   * Releases this owner's leases (awaiting their analyzer children and cleanup), drops its
   * artifacts, and refuses further use. Idempotent; settles once cleanup ran and never rejects.
   */
  dispose(reason?: string): Promise<void>;
}

/** State a core module keeps for one owner; released when the owner is disposed. */
export interface OwnerResource {
  dispose(reason: string): void | Promise<void>;
}

type OwnerScope = {
  disposed: boolean;
  disposal?: Promise<void>;
  readonly resources: Map<symbol, OwnerResource>;
};

const scopes = new WeakMap<SniffRunOwner, OwnerScope>();
const liveOwners = new Set<SniffRunOwner>();
let processOwner: SniffRunOwner | undefined;

const DISPOSED_REASON = "run owner disposed";

function disposeScope(owner: SniffRunOwner, scope: OwnerScope, reason: string): Promise<void> {
  if (scope.disposal) return scope.disposal;
  scope.disposed = true;
  liveOwners.delete(owner);
  if (processOwner === owner) processOwner = undefined;
  // Each resource starts its cleanup synchronously, so everything without a live child is gone
  // before this returns; the promise settles once every child exited and its cleanup ran.
  const pending = [...scope.resources.values()].map((resource) => {
    try {
      return Promise.resolve(resource.dispose(reason));
    } catch (error) {
      return Promise.reject(error);
    }
  });
  scope.resources.clear();
  scope.disposal = Promise.allSettled(pending).then(() => undefined);
  return scope.disposal;
}

export function createSniffRunOwner(options: { readonly label?: string } = {}): SniffRunOwner {
  const scope: OwnerScope = { disposed: false, resources: new Map() };
  const owner: SniffRunOwner = {
    id: `owner-${randomBytes(12).toString("base64url")}`,
    label: (options.label ?? "").trim().slice(0, 256) || "sniff",
    get disposed() {
      return scope.disposed;
    },
    dispose: (reason?: string) => disposeScope(owner, scope, reason?.trim().slice(0, 256) || DISPOSED_REASON),
  };
  Object.freeze(owner);
  scopes.set(owner, scope);
  liveOwners.add(owner);
  return owner;
}

/**
 * The process owner used when a caller names none, as a single-client embedding or a test does.
 * After it is disposed (for example by process shutdown) the next call creates a fresh one.
 */
export function defaultSniffRunOwner(): SniffRunOwner {
  processOwner ??= createSniffRunOwner({ label: "process" });
  return processOwner;
}

function liveScope(owner: SniffRunOwner): OwnerScope {
  const scope = scopes.get(owner);
  if (!scope) throw new Error("Unknown Sniff run owner");
  if (scope.disposed) throw new Error("Sniff run owner was disposed");
  return scope;
}

/** Throws unless `owner` is an issued, undisposed owner; `undefined` is the trusted unscoped view. */
export function assertUsableOwner(owner: SniffRunOwner | undefined): void {
  if (owner !== undefined) liveScope(owner);
}

/** The owner that new state registers under: the given one, or the process owner. */
export function issuingOwner(owner: SniffRunOwner | undefined): SniffRunOwner {
  const resolved = owner ?? defaultSniffRunOwner();
  liveScope(resolved);
  return resolved;
}

/** The owner's resource for `key`, created on first use and disposed with the owner. */
export function ownerResource<T extends OwnerResource>(owner: SniffRunOwner, key: symbol, create: () => T): T {
  const scope = liveScope(owner);
  let resource = scope.resources.get(key) as T | undefined;
  if (!resource) {
    resource = create();
    scope.resources.set(key, resource);
  }
  return resource;
}

/** Process shutdown: disposes every live owner; one failed release never cuts the others short. */
export function disposeAllSniffRunOwners(reason: string): Promise<void> {
  return Promise.allSettled([...liveOwners].map((owner) => owner.dispose(reason))).then(() => undefined);
}
