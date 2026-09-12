import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdtempSync, readdirSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve, sep } from "node:path";


export type ArgvResult = {
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
};

export type ArgvRunner = (argv: readonly string[], options?: { readonly cwd?: string }) => ArgvResult | Promise<ArgvResult>;

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

export type HistoryWindow =
  | { readonly kind: "refs"; readonly base: string; readonly head: string }
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
};

export type ProviderTargetResolver = (request: TargetRequest, runner: ArgvRunner) => Promise<ResolvedTarget>;
export type ProviderTargetMaterializer = (target: ResolvedTarget, runner: ArgvRunner) => Promise<ResolvedTarget>;

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
    const child = Bun.spawn([...argv], { cwd: options.cwd, stdout: "pipe", stderr: "pipe" });
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

async function execute(runner: ArgvRunner, argv: readonly string[], cwd: string): Promise<ArgvResult> {
  let result: ArgvResult;
  try {
    result = await runner(argv, { cwd });
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
      const status = code.startsWith("A") ? "added" : code.startsWith("D") ? "deleted" : code.startsWith("R") ? "renamed" : code.startsWith("M") ? "modified" : "unknown";
      const first = fields[index++] ?? "";
      const second = status === "renamed" ? fields[index++] : undefined;
      const basePath = status === "added" ? undefined : first;
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
  const output = await execute(runner, ["git", "diff", "--name-status", "--find-renames", "-z", `${base}...${head}`], root);
  return parseGitNameStatus(output.stdout);
}

function analyzableChangeFiles(changes: readonly TargetChange[]): string[] {
  return [...new Set(changes.flatMap((change) => change.headPath ? [change.headPath] : []))].sort((left, right) => left.localeCompare(right));
}

async function snapshotFiles(runner: ArgvRunner, root: string, ref: string): Promise<string[]> {
  const tree = await execute(runner, ["git", "ls-tree", "-r", "--name-only", ref], root);
  return [...new Set(cleanOutput(tree.stdout))].sort((left, right) => left.localeCompare(right));
}

async function resolveWorkingTree(root: string, runner: ArgvRunner): Promise<ResolvedTarget> {
  const resolvedRoot = ensureRoot(root);
  const [unstaged, staged, untracked] = await Promise.all([
    git(runner, resolvedRoot, ["diff", "--name-only"]),
    git(runner, resolvedRoot, ["diff", "--cached", "--name-only"]),
    git(runner, resolvedRoot, ["ls-files", "--others", "--exclude-standard"]),
  ]);
  const files = uniqueExistingFiles(resolvedRoot, [...cleanOutput(unstaged), ...cleanOutput(staged), ...cleanOutput(untracked)]);
  const head = await immutableRef(runner, resolvedRoot, "HEAD");
  return { kind: "working-tree", label: "uncommitted changes", root: resolvedRoot, files, baseRef: head, immutableRef: head, materialization: "in-place" };
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
      const base = await immutableRef(runner, root, `${head}^`);
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

export type TemporaryCheckoutLease = {
  readonly directory: string;
  readonly immutableRef: string;
  release(): void;
};

export async function createTemporaryCheckout(
  repository: string,
  ref: string,
  runner: ArgvRunner = runArgv,
  fullHistory = false,
): Promise<TemporaryCheckoutLease> {
  if (!isImmutableRef(ref)) throw new TargetResolutionError("invalid-ref", "Temporary checkout requires a full commit SHA");
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
    await execute(runner, ["git", "clone", "--no-checkout", "--", source, directory], directory);
    if (!local && fullHistory) {
      await execute(runner, ["git", "-C", directory, "fetch", "--force", "--tags", "origin"], directory);
      await execute(runner, ["git", "-C", directory, "fetch", "--force", "origin", ref], directory);
    } else if (!local) {
      await execute(runner, ["git", "-C", directory, "fetch", "--depth=1", "origin", ref], directory);
    }
    await execute(runner, ["git", "-C", directory, "checkout", "--detach", ref], directory);
    const resolved = await execute(runner, ["git", "-C", directory, "rev-parse", "--verify", "HEAD^{commit}"], directory);
    const immutable = resolved.stdout.trim().toLowerCase();
    if (!isImmutableRef(immutable) || immutable !== ref.toLowerCase()) throw new TargetResolutionError("invalid-ref", "Checkout did not produce the requested immutable commit");
    return { directory: ensureRoot(directory), immutableRef: immutable, release };
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

export type ResolvedTargetLease = {
  readonly target: ResolvedTarget;
  release(): void;
};

export async function resolveTargetLease(request: TargetRequest, runner: ArgvRunner = runArgv, providerResolver?: ProviderTargetResolver, materializer?: ProviderTargetMaterializer): Promise<ResolvedTargetLease> {
  const resolved = await resolveTarget(request, runner, providerResolver);
  if (resolved.materialization === "in-place") return { target: validateResolvedTarget(resolved), release: () => undefined };
  const immutable = resolved.immutableRef ?? resolved.headRef;
  if (!immutable || !isImmutableRef(immutable)) throw new TargetResolutionError("invalid-ref", "Resolved target lacks a full commit SHA");
  const checkout = await createTemporaryCheckout(resolved.repository ?? resolved.root, immutable, runner, resolved.kind === "history" || resolved.kind === "release");
  try {
    if (!materializer) throw new TargetResolutionError("invalid-target", "Provider target materialization is unavailable in this host");
    const materialized = await materializer({ ...resolved, root: checkout.directory, immutableRef: checkout.immutableRef, headRef: checkout.immutableRef }, runner);
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
