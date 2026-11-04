import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve, sep } from "node:path";


export type ArgvResult = {
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
};

export type ArgvRunner = (argv: readonly string[], options?: { readonly cwd?: string; readonly env?: Readonly<Record<string, string>> }) => ArgvResult | Promise<ArgvResult>;

export type TargetKind =
  | "whole-repo"
  | "working-tree"
  | "files"
  | "directory"
  | "module"
  | "commit"
  | "range"
  | "branch"
  | "ref"
  | "repository"
  | "release"
  | "history"
  | "pr"
  | "mr";

/** Well-known SHA-1 empty tree: the base of a root commit and of a repository with no commits yet. */
export const EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

export type HistoryWindow =
  | {
    readonly kind: "refs";
    readonly base: string;
    readonly head: string;
    /** Captured selection: the exact commits the user confirmed, kept through materialization. */
    readonly commits?: readonly string[];
    /** Captured diff base (merge base, or the empty tree); the change set is `diffBase..head`. */
    readonly diffBase?: string;
  }
  | { readonly kind: "since-date"; readonly date: string; readonly head?: string }
  | { readonly kind: "last-commits"; readonly count: number; readonly head?: string }
  | { readonly kind: "since-release"; readonly release: string; readonly head?: string }
  | { readonly kind: "previous-release"; readonly release?: string; readonly head?: string }
  | { readonly kind: "context-aware-default"; readonly head?: string };

export type TargetRequest =
  | { readonly kind: "whole-repo"; readonly root: string }
  | { readonly kind: "working-tree"; readonly root: string }
  | { readonly kind: "files"; readonly root: string; readonly paths: readonly string[] }
  | { readonly kind: "directory" | "module"; readonly root: string; readonly path: string }
  | { readonly kind: "commit"; readonly root: string; readonly commit: string }
  | { readonly kind: "range"; readonly root: string; readonly base: string; readonly head: string }
  | { readonly kind: "branch"; readonly root: string; readonly branch: string; readonly base?: string }
  | { readonly kind: "ref"; readonly root: string; readonly ref: string }
  | { readonly kind: "repository"; readonly repository: string; readonly ref?: string }
  | { readonly kind: "release"; readonly repository: string; readonly tag: string; readonly previousTag?: string }
  | { readonly kind: "history"; readonly rootOrRepository: string; readonly window: HistoryWindow }
  | { readonly kind: "pr"; readonly repository: string; readonly number: string | number }
  | { readonly kind: "mr"; readonly repository: string; readonly iid: string | number };


export type TargetChange = {
  readonly path: string;
  readonly status: "added" | "modified" | "deleted" | "renamed" | "unknown";
  readonly basePath?: string;
  readonly headPath?: string;
};

/** A known limit of the resolved target (same shape as an intake gap) that the plan and report must surface. */
export type TargetGap = {
  readonly field: string;
  readonly reason: string;
  readonly impact: "low" | "medium" | "high";
};

export type ResolvedTarget = {
  readonly kind: TargetKind;
  readonly label: string;
  readonly root: string;
  readonly files: readonly string[];
  readonly changes?: readonly TargetChange[];
  readonly baseRef?: string;
  readonly headRef?: string;
  readonly immutableRef?: string;
  readonly repository?: string;
  readonly release?: { readonly tag: string; readonly previousTag?: string; readonly previousRef?: string; readonly deltaFiles: readonly string[]; readonly snapshotFiles: readonly string[] };
  readonly history?: { readonly window: HistoryWindow; readonly capturedWindow?: HistoryWindow; readonly commits: readonly string[] };
  readonly materialization: "in-place" | "temporary-checkout";
  /** Gaps in the file/change set, e.g. git could not produce the PR diff or disagrees with the provider's count. */
  readonly gaps?: readonly TargetGap[];
  /** Server refs that carry the head commit (`refs/pull/<n>/head`); used only when a SHA fetch is refused. */
  readonly providerRefs?: readonly string[];
  /** The provider's own changed-file count, kept to cross-check the git-derived change set. */
  readonly providerChangedFiles?: number;
  /** The repository has no commits yet; `baseRef` is the empty tree. */
  readonly unborn?: true;
};

export type CheckoutInfo = {
  /** `sha`: shallow fetch by SHA; `refs`: via provider refs; `full-fallback`: server refused unadvertised SHAs; `full`: ancestry was required. */
  readonly fetch: "sha" | "refs" | "full-fallback" | "full";
  /** Extra commits that could not be obtained. */
  readonly missing: readonly string[];
  /** Whether the requested `connect` commit shares a merge base with the checkout head. */
  readonly connected: boolean;
};

export type ProviderTargetResolver = (request: TargetRequest, runner: ArgvRunner) => Promise<ResolvedTarget>;
export type ProviderTargetMaterializer = (target: ResolvedTarget, runner: ArgvRunner, checkout?: CheckoutInfo) => Promise<ResolvedTarget>;

export type TargetFailureCode =
  | "invalid-target"
  | "missing-cli"
  | "authentication-failure"
  | "ambiguous-release"
  | "absent-release"
  | "invalid-ref"
  | "command-failure";

export class TargetResolutionError extends Error {
  readonly code: TargetFailureCode;
  readonly provider?: "github" | "gitlab" | "git";
  readonly details?: string;

  constructor(code: TargetFailureCode, message: string, options: { readonly provider?: "github" | "gitlab" | "git"; readonly details?: string } = {}) {
    super(redactTransportValues(message));
    this.name = "TargetResolutionError";
    this.code = code;
    this.provider = options.provider;
    this.details = options.details ? redactTransportValues(options.details) : undefined;
  }
}

function processErrorText(error: unknown): string {
  const candidate = error as { code?: string; message?: string };
  return redactTransportValues(candidate?.message ?? String(error));
}

const defaultArgvRunner: ArgvRunner = async (argv, options = {}) => {
  try {
    const child = Bun.spawn([...argv], { cwd: options.cwd, ...(options.env ? { env: { ...process.env, ...options.env } } : {}), stdout: "pipe", stderr: "pipe" });
    const [stdout, stderr, code] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ]);
    return { code, stdout, stderr: redactTransportValues(stderr) };
  } catch (error) {
    const missing = (error as { code?: string }).code === "ENOENT" || /(?:not found|no such file)/i.test(processErrorText(error));
    return { code: missing ? 127 : 126, stdout: "", stderr: processErrorText(error) };
  }
};

export const runArgv: ArgvRunner = defaultArgvRunner;

export function redactTransportValues(value: string): string {
  return value
    .replace(/([a-z][a-z0-9+.-]*:\/\/)[^/@\s]+@/gi, "$1<redacted>@")
    .replace(/\b(token|password|passwd|secret)=([^\s&]+)/gi, "$1=<redacted>");
}

export function validateGitOperand(value: string, label: string): string {
  const trimmed = value.trim();
  if (!trimmed || trimmed.startsWith("-") || /[\0\r\n]/.test(trimmed)) {
    throw new TargetResolutionError("invalid-target", `${label} is not a safe Git operand`);
  }
  return trimmed;
}

export function validateRepository(repository: string): string {
  const value = validateGitOperand(repository, "Repository");
  if (/\s/.test(value)) throw new TargetResolutionError("invalid-target", "Repository URL contains whitespace");
  if (/^git@[A-Za-z0-9.-]+:[A-Za-z0-9._~/-]+(?:\.git)?$/.test(value)) return value;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new TargetResolutionError("invalid-target", "Repository must use an allowlisted remote URL form");
  }
  if (!["https:", "ssh:", "git:"].includes(parsed.protocol) || !parsed.hostname || parsed.pathname === "/") {
    throw new TargetResolutionError("invalid-target", "Repository must use https, ssh, git, or git@host:path");
  }
  if (parsed.username || parsed.password) {
    throw new TargetResolutionError("invalid-target", "Repository URLs must not contain userinfo or credentials");
  }
  if (parsed.search || parsed.hash) {
    throw new TargetResolutionError("invalid-target", "Repository URLs must not contain query or fragment values");
  }
  return value;
}

function cleanOutput(output: string): string[] {
  return output.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

/** Split NUL-delimited git output (`-z`) without trimming names. */
export function splitNul(output: string): string[] {
  return output.split("\0").filter((field) => field.length > 0);
}

function isContained(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

function ensureRoot(root: string): string {
  const resolved = resolve(root);
  if (!existsSync(resolved) || !lstatSync(resolved).isDirectory()) {
    throw new TargetResolutionError("invalid-target", "Target root does not exist or is not a directory");
  }
  return realpathSync(resolved);
}

function normalizeRelativePath(root: string, candidate: string, requireExisting = false): string {
  const rootCanonical = ensureRoot(root);
  const absolute = isAbsolute(candidate) ? resolve(candidate) : resolve(rootCanonical, candidate);
  if (!isContained(rootCanonical, absolute)) {
    throw new TargetResolutionError("invalid-target", "Target path escapes repository root");
  }
  if (existsSync(absolute)) {
    const canonical = realpathSync(absolute);
    if (!isContained(rootCanonical, canonical)) {
      throw new TargetResolutionError("invalid-target", "Target path resolves outside repository root");
    }
  } else if (requireExisting) {
    throw new TargetResolutionError("invalid-target", "Target path does not exist");
  }
  return relative(rootCanonical, absolute).split(sep).join("/");
}

function listFiles(root: string, path = ""): string[] {
  const rootCanonical = ensureRoot(root);
  const absolute = resolve(rootCanonical, path);
  if (!existsSync(absolute)) return [];
  const canonical = realpathSync(absolute);
  if (!isContained(rootCanonical, canonical)) throw new TargetResolutionError("invalid-target", "Target path resolves outside repository root");
  const stat = lstatSync(absolute);
  if (stat.isFile()) return [normalizeRelativePath(rootCanonical, path, true)];
  if (!stat.isDirectory()) return [];
  const entries = readdirSync(absolute, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name));
  const files: string[] = [];
  for (const entry of entries) {
    const child = path ? join(path, entry.name) : entry.name;
    if (entry.name === ".git" || entry.name === "node_modules") continue;
    if (entry.isDirectory()) files.push(...listFiles(rootCanonical, child));
    else if (entry.isFile()) files.push(normalizeRelativePath(rootCanonical, child, true));
    else if (entry.isSymbolicLink()) normalizeRelativePath(rootCanonical, child, true);
  }
  return files;
}

function uniqueExistingFiles(root: string, files: readonly string[]): string[] {
  const rootCanonical = ensureRoot(root);
  const found = new Set<string>();
  for (const file of files) {
    const normalized = normalizeRelativePath(rootCanonical, file);
    const absolute = resolve(rootCanonical, normalized);
    if (existsSync(absolute) && lstatSync(absolute).isFile()) found.add(normalized);
    else if (existsSync(absolute) && lstatSync(absolute).isSymbolicLink()) normalizeRelativePath(rootCanonical, normalized, true);
  }
  return [...found].sort((left, right) => left.localeCompare(right));
}

async function execute(runner: ArgvRunner, argv: readonly string[], cwd: string, env?: Readonly<Record<string, string>>): Promise<ArgvResult> {
  let result: ArgvResult;
  try {
    result = await runner(argv, env ? { cwd, env } : { cwd });
  } catch (error) {
    const detail = processErrorText(error);
    const missing = (error as { code?: string }).code === "ENOENT" || /(?:not found|no such file)/i.test(detail);
    throw new TargetResolutionError(missing ? "missing-cli" : "command-failure", missing ? "Required Git executable is unavailable" : "Git process failed to start", { provider: "git", details: detail });
  }
  if (result.code !== 0) {
    const detail = redactTransportValues(result.stderr.trim() || result.stdout.trim() || `exit ${result.code}`);
    throw new TargetResolutionError(result.code === 127 ? "missing-cli" : "command-failure", "Git command failed", { provider: "git", details: detail });
  }
  return result;
}

async function git(runner: ArgvRunner, root: string, args: readonly string[]): Promise<string> {
  return (await execute(runner, ["git", ...args], root)).stdout.trim();
}

async function immutableRef(runner: ArgvRunner, root: string, ref: string): Promise<string> {
  const safeRef = validateGitOperand(ref, "Git ref");
  const output = await execute(runner, ["git", "rev-parse", "--verify", `${safeRef}^{commit}`], root);
  const value = output.stdout.trim().split(/\s+/)[0];
  if (!value || !isImmutableRef(value)) {
    throw new TargetResolutionError("invalid-ref", "Could not resolve an immutable commit", { provider: "git" });
  }
  return value.toLowerCase();
}

export function parseGitNameStatus(output: string): TargetChange[] {
  const changes: TargetChange[] = [];
  if (output.includes("\0")) {
    const fields = output.split("\0").filter(Boolean);
    for (let index = 0; index < fields.length;) {
      const code = fields[index++] ?? "";
      const status = code.startsWith("A") || code.startsWith("C") ? "added" : code.startsWith("D") ? "deleted" : code.startsWith("R") ? "renamed" : code.startsWith("M") ? "modified" : "unknown";
      const first = fields[index++] ?? "";
      const copied = code.startsWith("C");
      const second = status === "renamed" || copied ? fields[index++] : undefined;
      const basePath = status === "added" || copied ? undefined : first;
      const headPath = status === "deleted" ? undefined : (second ?? first);
      const path = headPath ?? basePath;
      if (path) changes.push({ path, status, ...(basePath ? { basePath } : {}), ...(headPath ? { headPath } : {}) });
    }
  } else {
    for (const line of cleanOutput(output)) {
      const fields = line.split("\t");
      const code = fields.length > 1 ? fields[0] ?? "" : "";
      const first = fields.length > 1 ? fields[1] ?? "" : line;
      const second = fields[2];
      const status = code.startsWith("A") ? "added" : code.startsWith("D") ? "deleted" : code.startsWith("R") ? "renamed" : code.startsWith("M") ? "modified" : "unknown";
      const basePath = status === "added" ? undefined : first;
      const headPath = status === "deleted" ? undefined : (second ?? first);
      changes.push({ path: headPath ?? basePath ?? first, status, ...(basePath ? { basePath } : {}), ...(headPath ? { headPath } : {}) });
    }
  }
  return changes.sort((left, right) => left.path.localeCompare(right.path));
}

async function changedEntries(runner: ArgvRunner, root: string, base: string, head: string): Promise<TargetChange[]> {
  // The empty tree is not a commit, so it has no merge base: diff it directly.
  const range = base === EMPTY_TREE ? [base, head] : [`${base}...${head}`];
  const output = await execute(runner, ["git", "diff", "--name-status", "--find-renames", "-z", ...range], root);
  return parseGitNameStatus(output.stdout);
}

/** The empty tree object id of the repository (SHA-1 unless the repository says otherwise). */
export async function emptyTreeId(runner: ArgvRunner, root: string): Promise<string> {
  const value = (await execute(runner, ["git", "hash-object", "-t", "tree", "/dev/null"], root)).stdout.trim();
  return isImmutableRef(value) ? value.toLowerCase() : EMPTY_TREE;
}

/**
 * The first parent of a commit, or undefined for a true root commit. A missing parent is distinguished from
 * command failures, and from a shallow-boundary commit whose parents are merely absent.
 */
export async function firstParent(runner: ArgvRunner, root: string, commit: string): Promise<string | undefined> {
  const output = await execute(runner, ["git", "rev-list", "--parents", "-n", "1", commit], root);
  const [self, parent] = output.stdout.trim().split(/\s+/);
  if (!self || !isImmutableRef(self)) throw new TargetResolutionError("invalid-ref", "Could not read commit parents", { provider: "git" });
  if (parent) return immutableRef(runner, root, parent);
  const shallow = (await execute(runner, ["git", "rev-parse", "--git-path", "shallow"], root)).stdout.trim();
  const shallowPath = isAbsolute(shallow) ? shallow : resolve(root, shallow);
  if (existsSync(shallowPath) && readFileSync(shallowPath, "utf8").split(/\s+/).includes(self.toLowerCase())) {
    throw new TargetResolutionError("command-failure", "Commit parent is unavailable in a shallow checkout", { provider: "git", details: self });
  }
  return undefined;
}

function analyzableChangeFiles(changes: readonly TargetChange[]): string[] {
  return [...new Set(changes.flatMap((change) => change.headPath ? [change.headPath] : []))].sort((left, right) => left.localeCompare(right));
}

async function snapshotFiles(runner: ArgvRunner, root: string, ref: string): Promise<string[]> {
  const tree = await execute(runner, ["git", "ls-tree", "-r", "--name-only", "-z", ref], root);
  return [...new Set(splitNul(tree.stdout))].sort((left, right) => left.localeCompare(right));
}

/** Parse `git status --porcelain=v1 -z` into changes; renames/copies carry two paths (new, then old). */
export function parseGitStatusPorcelain(output: string): TargetChange[] {
  const fields = splitNul(output);
  const changes: TargetChange[] = [];
  for (let index = 0; index < fields.length;) {
    const entry = fields[index++] ?? "";
    const x = entry[0] ?? " ";
    const y = entry[1] ?? " ";
    const path = entry.slice(3);
    const origin = x === "R" || x === "C" ? fields[index++] : undefined;
    if (!path) continue;
    if (x === "!") continue;
    if (x === "U" || y === "U" || (x === "A" && y === "A") || (x === "D" && y === "D")) {
      changes.push({ path, status: "unknown", basePath: path, headPath: path });
    } else if (x === "A" && y === "D") {
    } else if (x === "R" && origin !== undefined) {
      if (y === "D") changes.push({ path: origin, status: "deleted", basePath: origin });
      else changes.push({ path, status: "renamed", basePath: origin, headPath: path });
    } else if (x === "D" || y === "D") {
      changes.push({ path, status: "deleted", basePath: path });
    } else if (x === "A" || x === "C" || x === "?") {
      changes.push({ path, status: "added", headPath: path });
    } else {
      changes.push({ path, status: "modified", basePath: path, headPath: path });
    }
  }
  return changes.sort((left, right) => left.path.localeCompare(right.path));
}

async function resolveWorkingTree(root: string, runner: ArgvRunner): Promise<ResolvedTarget> {
  const resolvedRoot = ensureRoot(root);
  const status = await execute(runner, ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], resolvedRoot);
  const changes = parseGitStatusPorcelain(status.stdout);
  const files = uniqueExistingFiles(resolvedRoot, changes.flatMap((change) => change.headPath ? [change.headPath] : []));
  const unborn = await execute(runner, ["git", "rev-parse", "--verify", "--quiet", "HEAD^{commit}"], resolvedRoot).then(() => false, (error: unknown) => {
    // `--quiet` exits 1 without output only when HEAD names no commit yet; anything else is a real failure.
    if (error instanceof TargetResolutionError && error.code === "command-failure" && error.details === "exit 1") return true;
    throw error;
  });
  if (unborn) {
    return { kind: "working-tree", label: "uncommitted changes", root: resolvedRoot, files, changes, baseRef: await emptyTreeId(runner, resolvedRoot), materialization: "in-place", unborn: true };
  }
  const head = await immutableRef(runner, resolvedRoot, "HEAD");
  return { kind: "working-tree", label: "uncommitted changes", root: resolvedRoot, files, changes, baseRef: head, immutableRef: head, materialization: "in-place" };
}

export async function resolveTarget(request: TargetRequest, runner: ArgvRunner = runArgv, providerResolver?: ProviderTargetResolver): Promise<ResolvedTarget> {
  switch (request.kind) {
    case "whole-repo": {
      const root = ensureRoot(request.root);
      const head = await immutableRef(runner, root, "HEAD");
      return { kind: "whole-repo", label: "whole repository", root, files: await snapshotFiles(runner, root, head), headRef: head, immutableRef: head, materialization: "temporary-checkout" };
    }
    case "working-tree":
      return resolveWorkingTree(request.root, runner);
    case "files": {
      const root = ensureRoot(request.root);
      return { kind: "files", label: request.paths.join(", "), root, files: uniqueExistingFiles(root, request.paths), materialization: "in-place" };
    }
    case "directory":
    case "module": {
      const root = ensureRoot(request.root);
      const path = normalizeRelativePath(root, request.path, true);
      return { kind: request.kind, label: path, root, files: listFiles(root, path), materialization: "in-place" };
    }
    case "commit": {
      const root = ensureRoot(request.root);
      const head = await immutableRef(runner, root, request.commit);
      const base = (await firstParent(runner, root, head)) ?? (await emptyTreeId(runner, root));
      const changes = await changedEntries(runner, root, base, head);
      return { kind: "commit", label: `commit ${head}`, root, files: await snapshotFiles(runner, root, head), changes, baseRef: base, headRef: head, immutableRef: head, materialization: "temporary-checkout" };
    }
    case "range": {
      const root = ensureRoot(request.root);
      const base = await immutableRef(runner, root, request.base);
      const head = await immutableRef(runner, root, request.head);
      const changes = await changedEntries(runner, root, base, head);
      return { kind: "range", label: `${base}...${head}`, root, files: analyzableChangeFiles(changes), changes, baseRef: base, headRef: head, immutableRef: head, materialization: "temporary-checkout" };
    }
    case "branch": {
      const root = ensureRoot(request.root);
      const head = await immutableRef(runner, root, request.branch);
      const baseName = request.base ? validateGitOperand(request.base, "Base ref") : await git(runner, root, ["symbolic-ref", "--short", "refs/remotes/origin/HEAD"]).catch(() => "HEAD");
      const base = await immutableRef(runner, root, baseName);
      const changes = await changedEntries(runner, root, base, head);
      return { kind: "branch", label: `branch ${request.branch}`, root, files: analyzableChangeFiles(changes), changes, baseRef: base, headRef: head, immutableRef: head, materialization: "temporary-checkout" };
    }
    case "ref": {
      const root = ensureRoot(request.root);
      const head = await immutableRef(runner, root, request.ref);
      return { kind: "ref", label: request.ref, root, files: await snapshotFiles(runner, root, head), headRef: head, immutableRef: head, materialization: "temporary-checkout" };
    }
    default:
      if (!providerResolver) throw new TargetResolutionError("invalid-target", "Provider target resolution is unavailable in this host");
      return providerResolver(request, runner);
  }
}

export function validateResolvedTarget(target: ResolvedTarget): ResolvedTarget {
  const root = ensureRoot(target.root);
  const files = uniqueExistingFiles(root, target.files);
  const changes = target.changes?.map((change) => {
    const suppliedBase = change.basePath ? normalizeRelativePath(root, change.basePath) : undefined;
    const suppliedHead = change.headPath ? normalizeRelativePath(root, change.headPath) : undefined;
    const path = normalizeRelativePath(root, change.path);
    const headExists = suppliedHead ? existsSync(resolve(root, suppliedHead)) : false;
    const status = change.status === "unknown" ? (headExists ? "modified" : "deleted") : change.status;
    const basePath = status === "added" ? undefined : (suppliedBase ?? path);
    const headPath = status === "deleted" ? undefined : (suppliedHead ?? path);
    return { path, status, ...(basePath ? { basePath } : {}), ...(headPath ? { headPath } : {}) };
  }).sort((left, right) => left.path.localeCompare(right.path));
  return { ...target, root, files, ...(changes ? { changes } : {}) };
}

export function targetFingerprint(target: ResolvedTarget): string {
  const stable = JSON.stringify({
    kind: target.kind,
    immutableRef: target.immutableRef,
    baseRef: target.baseRef,
    headRef: target.headRef,
    repository: target.repository,
    files: [...target.files].sort(),
    changes: target.changes ? [...target.changes].sort((left, right) => left.path.localeCompare(right.path)) : undefined,
  });
  return createHash("sha256").update(stable).digest("hex");
}

export type TemporaryCheckoutLease = CheckoutInfo & {
  readonly directory: string;
  readonly immutableRef: string;
  release(): void;
};

export type CheckoutOptions = {
  /** How much history of the checked-out commit (and the extra commits) to fetch. Default: just the commit. */
  readonly history?: "tip" | "full" | { readonly depth: number } | { readonly since: string };
  /** Also fetch tags (e.g. for `git describe`). */
  readonly tags?: boolean;
  /** Further commits to fetch best-effort; failures are reported in `missing`, not thrown. */
  readonly extraCommits?: readonly string[];
  /** Deepen until the first extra commit shares a merge base with the checked-out commit. */
  readonly connect?: boolean;
  /** Server refs that carry the commit, tried when the server refuses to serve an unadvertised SHA. */
  readonly refspecs?: readonly string[];
};

// Untrusted checkouts must not run the user's git hooks or LFS smudge filters.
// Credential helpers stay available (no GIT_CONFIG_GLOBAL override) for private remotes.
const UNTRUSTED_GIT_CONFIG = ["-c", "core.hooksPath=/dev/null"] as const;
const UNTRUSTED_GIT_ENV: Readonly<Record<string, string>> = { GIT_LFS_SKIP_SMUDGE: "1" };
const REFUSED_SHA_FETCH = /(?:not our ref|unadvertised|allow(?:Reachable|Any|Tip)SHA1InWant|does not allow request|couldn't find remote ref|no such remote ref|reference is not a tree|bad object)/i;

async function hasCommit(runner: ArgvRunner, directory: string, sha: string): Promise<boolean> {
  const result = await runner(["git", "-C", directory, "cat-file", "-e", `${sha}^{commit}`], { cwd: directory });
  return result.code === 0;
}

function depthArguments(history: CheckoutOptions["history"]): string[] {
  if (history === undefined || history === "tip") return ["--depth=1"];
  if (history === "full") return [];
  if ("depth" in history) return [`--depth=${Math.max(1, Math.floor(history.depth))}`];
  return [`--shallow-since=${validateGitOperand(history.since, "History date")}`];
}

/**
 * Fetch commits into a checkout: by SHA first, then through provider refs, and only then a full
 * fetch of the branches. The mode that was needed is returned so the fallback is recorded.
 */
async function fetchCommits(
  runner: ArgvRunner,
  directory: string,
  commits: readonly string[],
  depth: readonly string[],
  tags: boolean,
  refspecs: readonly string[],
): Promise<"sha" | "refs" | "full-fallback"> {
  const base = ["git", "-C", directory, ...UNTRUSTED_GIT_CONFIG, "fetch", "--force", tags ? "--tags" : "--no-tags"];
  const run = (args: readonly string[]) => execute(runner, [...base, ...args], directory, UNTRUSTED_GIT_ENV);
  try {
    await run([...depth, "origin", ...commits]);
    return "sha";
  } catch (error) {
    const refused = error instanceof TargetResolutionError && error.code === "command-failure" && REFUSED_SHA_FETCH.test(error.details ?? "");
    if (!refused) throw error;
  }
  if (refspecs.length > 0) {
    try {
      await run([...depth, "origin", ...refspecs.map((ref, index) => `+${validateGitOperand(ref, "Provider ref")}:refs/sniff/${index}`)]);
      const present = await Promise.all(commits.map((commit) => hasCommit(runner, directory, commit)));
      if (present.every(Boolean)) return "refs";
    } catch {
      // Fall through to the full fetch; a genuine failure repeats there.
    }
  }
  await run(["origin", "+refs/heads/*:refs/remotes/origin/*", ...refspecs.map((ref, index) => `+${validateGitOperand(ref, "Provider ref")}:refs/sniff/${index}`)]);
  return "full-fallback";
}

async function connectCommits(runner: ArgvRunner, directory: string, commits: readonly string[], tags: boolean, refspecs: readonly string[], head: string, other: string): Promise<boolean> {
  const mergeBase = async () => (await runner(["git", "-C", directory, "merge-base", other, head], { cwd: directory })).code === 0;
  if (await mergeBase()) return true;
  for (const step of [50, 500, 5000, 2_147_483_647]) {
    try {
      await fetchCommits(runner, directory, commits, step === 2_147_483_647 ? ["--depth=2147483647"] : [`--deepen=${step}`], tags, refspecs);
    } catch {
      return false;
    }
    if (await mergeBase()) return true;
  }
  return false;
}

export async function createTemporaryCheckout(
  repository: string,
  ref: string,
  runner: ArgvRunner = runArgv,
  options: CheckoutOptions | boolean = {},
): Promise<TemporaryCheckoutLease> {
  if (!isImmutableRef(ref)) throw new TargetResolutionError("invalid-ref", "Temporary checkout requires a full commit SHA");
  const settings: CheckoutOptions = typeof options === "boolean" ? (options ? { history: "full", tags: true } : {}) : options;
  const local = existsSync(resolve(repository));
  const source = local ? ensureRoot(repository) : validateRepository(repository);
  const directory = mkdtempSync(join(tmpdir(), "sniff-target-"));
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    rmSync(directory, { recursive: true, force: true });
  };
  try {
    const sub = (...args: string[]) => execute(runner, ["git", "-C", directory, ...UNTRUSTED_GIT_CONFIG, ...args], directory, UNTRUSTED_GIT_ENV);
    // Start empty and fetch only the wanted commits, instead of cloning every branch's history.
    await execute(runner, ["git", ...UNTRUSTED_GIT_CONFIG, "init", "-q", directory], directory, UNTRUSTED_GIT_ENV);
    await sub("remote", "add", "origin", "--", source);
    const extras = [...new Set((settings.extraCommits ?? []).map((commit) => (isImmutableRef(commit) ? commit.toLowerCase() : validateGitOperand(commit, "Git ref"))))].filter((commit) => commit !== ref.toLowerCase() && commit !== EMPTY_TREE);
    const refspecs = settings.refspecs ?? [];
    const tags = settings.tags === true;
    const wanted = [ref.toLowerCase(), ...extras];
    let depth = depthArguments(settings.history);
    let fetch: CheckoutInfo["fetch"];
    const since = settings.history && typeof settings.history === "object" && "since" in settings.history;
    try {
      fetch = await fetchCommits(runner, directory, wanted, depth, tags, refspecs);
    } catch (error) {
      // A date window with no commits is refused by the server; the tip alone is still the checkout.
      if (!since || !(error instanceof TargetResolutionError) || !/no commits selected/i.test(error.details ?? "")) throw error;
      depth = ["--depth=1"];
      fetch = await fetchCommits(runner, directory, wanted, depth, tags, refspecs);
    }
    if (since && depth[0]?.startsWith("--shallow-since")) {
      // --shallow-since cuts at the boundary; one more generation provides the parent of the oldest commit.
      await fetchCommits(runner, directory, [ref.toLowerCase()], ["--deepen=1"], tags, refspecs);
    }
    if (!(await hasCommit(runner, directory, ref))) throw new TargetResolutionError("invalid-ref", "The requested commit could not be fetched", { provider: "git" });
    const missing: string[] = [];
    for (const extra of extras) if (!(await hasCommit(runner, directory, extra))) missing.push(extra);
    let connected = true;
    const first = extras[0];
    if (settings.connect && first && !missing.includes(first)) {
      connected = await connectCommits(runner, directory, wanted.filter((commit) => !missing.includes(commit)), tags, refspecs, ref.toLowerCase(), first);
    } else if (settings.connect) {
      connected = false;
    }
    await sub("checkout", "--detach", ref);
    const resolved = await execute(runner, ["git", "-C", directory, "rev-parse", "--verify", "HEAD^{commit}"], directory);
    const immutable = resolved.stdout.trim().toLowerCase();
    if (!isImmutableRef(immutable) || immutable !== ref.toLowerCase()) throw new TargetResolutionError("invalid-ref", "Checkout did not produce the requested immutable commit");
    const mode = settings.history === "full" && fetch === "sha" ? "full" : fetch;
    return { directory: ensureRoot(directory), immutableRef: immutable, release, fetch: mode, missing, connected };
  } catch (error) {
    release();
    throw error;
  }
}

export async function withTemporaryCheckout<T>(
  repository: string,
  ref: string,
  callback: (checkout: { readonly directory: string; readonly immutableRef: string }) => T | Promise<T>,
  runner: ArgvRunner = runArgv,
): Promise<T> {
  const checkout = await createTemporaryCheckout(repository, ref, runner);
  try {
    return await callback(checkout);
  } finally {
    checkout.release();
  }
}

/** Fetch only what the target needs: ancestry for history and release deltas, both ends for PR/MR diffs. */
export function checkoutOptions(target: ResolvedTarget): CheckoutOptions {
  if (target.kind === "pr" || target.kind === "mr") {
    return { extraCommits: target.baseRef ? [target.baseRef] : [], connect: true, refspecs: target.providerRefs ?? [] };
  }
  if (target.kind === "release" && target.release?.previousRef) return { history: "full", extraCommits: [target.release.previousRef] };
  if (target.kind !== "history" || !target.history) return {};
  const window = target.history.capturedWindow ?? target.history.window;
  switch (window.kind) {
    case "refs":
      // A captured selection only needs the two trees; an unresolved range needs its ancestry.
      return window.commits && window.diffBase ? { extraCommits: [window.diffBase] } : { history: "full", extraCommits: [window.base] };
    case "last-commits":
      return { history: { depth: window.count + 1 } };
    case "context-aware-default":
      return { history: { depth: 2 } };
    case "since-date":
      return { history: { since: window.date } };
    case "since-release":
      return { history: "full", extraCommits: [window.release] };
    case "previous-release":
      return { history: "full", tags: true, extraCommits: window.release ? [window.release] : [] };
  }
}

export type ResolvedTargetLease = {
  readonly target: ResolvedTarget;
  release(): void;
};

export async function resolveTargetLease(request: TargetRequest, runner: ArgvRunner = runArgv, providerResolver?: ProviderTargetResolver, materializer?: ProviderTargetMaterializer): Promise<ResolvedTargetLease> {
  const resolved = await resolveTarget(request, runner, providerResolver);
  if (resolved.materialization === "in-place") return { target: validateResolvedTarget(resolved), release: () => undefined };
  const immutable = resolved.immutableRef ?? resolved.headRef;
  if (!immutable || !isImmutableRef(immutable)) throw new TargetResolutionError("invalid-ref", "Resolved target lacks a full commit SHA");
  const checkout = await createTemporaryCheckout(resolved.repository ?? resolved.root, immutable, runner, checkoutOptions(resolved));
  try {
    if (!materializer) throw new TargetResolutionError("invalid-target", "Provider target materialization is unavailable in this host");
    const { fetch, missing, connected } = checkout;
    const materialized = await materializer({ ...resolved, root: checkout.directory, immutableRef: checkout.immutableRef, headRef: checkout.immutableRef }, runner, { fetch, missing, connected });
    return { target: validateResolvedTarget(materialized), release: checkout.release };
  } catch (error) {
    checkout.release();
    throw error;
  }
}

export async function withResolvedTarget<T>(
  request: TargetRequest,
  callback: (target: ResolvedTarget) => T | Promise<T>,
  runner: ArgvRunner = runArgv,
  providerResolver?: ProviderTargetResolver,
  materializer?: ProviderTargetMaterializer,
): Promise<T> {
  const lease = await resolveTargetLease(request, runner, providerResolver, materializer);
  try {
    return await callback(lease.target);
  } finally {
    lease.release();
  }
}

export function isImmutableRef(value: string): boolean {
  return /^[0-9a-f]{40}$/i.test(value);
}
