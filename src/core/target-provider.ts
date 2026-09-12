import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import {
  type ArgvResult,
  type ArgvRunner,
  type HistoryWindow,
  isImmutableRef,
  parseGitNameStatus,
  type ResolvedTarget,
  redactTransportValues,
  resolveTarget as resolveLocalTarget,
  resolveTargetLease as resolveLocalTargetLease,
  runArgv,
  type TargetChange,
  type TargetRequest,
  TargetResolutionError,
  validateGitOperand,
  validateRepository,
  withResolvedTarget as withLocalResolvedTarget,
} from "./target.ts";

export type ProviderName = "github" | "gitlab" | "generic-git";

export type ProviderDetection = {
  readonly provider: ProviderName;
  readonly repository: string;
  readonly cli: "gh" | "glab" | "git";
};

export type RemoteRelease = {
  readonly provider: Exclude<ProviderName, "generic-git">;
  readonly repository: string;
  readonly tag: string;
  readonly commit: string;
  readonly previousTag?: string;
  readonly url?: string;
};

function outputText(result: ArgvResult): string {
  return redactTransportValues(`${result.stdout}\n${result.stderr}`.trim());
}

function isAuthFailure(result: ArgvResult): boolean {
  return /(?:not logged in|authentication|unauthori[sz]ed|forbidden|token|credentials|401|403)/i.test(outputText(result));
}

function isMissingCli(result: ArgvResult): boolean {
  return result.code === 127 || /(?:command not found|no such file[^\n]*(?:gh|glab|git)|cannot find executable)/i.test(outputText(result));
}

function spawnFailureCode(error: unknown): "missing-cli" | "command-failure" {
  if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return "missing-cli";
  const message = error instanceof Error ? error.message : String(error);
  return /(?:command not found|no such file|cannot find executable)/i.test(message) ? "missing-cli" : "command-failure";
}

function parseJson(result: ArgvResult, context: string): unknown {
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new TargetResolutionError("command-failure", `${context} returned invalid JSON`, { details: outputText(result) });
  }
}

function objectValue(value: unknown, context: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TargetResolutionError("command-failure", `${context} returned an invalid object`);
  }
  return value as Record<string, unknown>;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function repositorySlug(repository: string): string {
  const value = validateRepository(repository).replace(/\.git$/, "");
  const scp = value.match(/^git@[^:]+:(.+)$/);
  if (scp?.[1]) return scp[1];
  const parsed = new URL(value);
  return parsed.pathname.replace(/^\/+/, "");
}

function providerFromRepository(repository: string): Exclude<ProviderName, "generic-git"> | "generic-git" {
  const value = validateRepository(repository);
  const scpHost = value.match(/^git@([^:]+):/)?.[1]?.toLowerCase();
  const hostname = scpHost ?? new URL(value).hostname.toLowerCase();
  if (hostname === "github.com") return "github";
  if (hostname === "gitlab.com") return "gitlab";
  return "generic-git";
}

function validateNumericId(value: string | number, label: string): string {
  const text = String(value);
  if (!/^[1-9]\d*$/.test(text)) throw new TargetResolutionError("invalid-target", `${label} must be a positive integer`);
  return text;
}

function validateDate(value: string): string {
  const date = validateGitOperand(value, "History date");
  if (!/^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:\d{2})?)?$/.test(date) || Number.isNaN(Date.parse(date))) {
    throw new TargetResolutionError("invalid-target", "History date must be an ISO 8601 date or timestamp");
  }
  return date;
}

export async function detectProvider(repository: string, runner: ArgvRunner): Promise<ProviderDetection> {
  const safeRepository = validateRepository(repository);
  const provider = providerFromRepository(safeRepository);
  const cli = provider === "github" ? "gh" : provider === "gitlab" ? "glab" : "git";
  const providerName = provider === "generic-git" ? "git" : provider;
  let probe: ArgvResult;
  try {
    probe = await runner([cli, "--version"]);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    const code = spawnFailureCode(error);
    throw new TargetResolutionError(code, code === "missing-cli" ? `${cli} is not installed` : `${cli} process failed to start`, { provider: providerName, details: detail });
  }
  if (probe.code !== 0) {
    const missing = isMissingCli(probe);
    throw new TargetResolutionError(missing ? "missing-cli" : "command-failure", missing ? `${cli} is not installed` : `${cli} version probe failed`, { provider: providerName, details: outputText(probe) });
  }
  return { provider, repository: safeRepository, cli };
}

async function providerCommand(runner: ArgvRunner, provider: ProviderDetection, argv: readonly string[]): Promise<ArgvResult> {
  let result: ArgvResult;
  try {
    result = await runner(argv);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    const code = spawnFailureCode(error);
    throw new TargetResolutionError(code, code === "missing-cli" ? `${provider.cli} is not installed` : `${provider.cli} process failed to start`, { provider: provider.provider === "generic-git" ? "git" : provider.provider, details: detail });
  }
  if (result.code === 0) return result;
  if (isMissingCli(result)) throw new TargetResolutionError("missing-cli", `${provider.cli} is not installed`, { provider: provider.provider === "generic-git" ? "git" : provider.provider, details: outputText(result) });
  if (isAuthFailure(result)) throw new TargetResolutionError("authentication-failure", `${provider.cli} rejected authentication`, { provider: provider.provider === "generic-git" ? "git" : provider.provider, details: outputText(result) });
  throw new TargetResolutionError("command-failure", `${provider.cli} command failed`, { provider: provider.provider === "generic-git" ? "git" : provider.provider, details: outputText(result) });
}

function parseCommit(value: unknown, context: string): string {
  if (typeof value !== "string" || !isImmutableRef(value)) throw new TargetResolutionError("invalid-ref", `${context} did not provide an immutable commit SHA`);
  return value.toLowerCase();
}

async function releaseMetadataCommand(
  runner: ArgvRunner,
  provider: ProviderDetection,
  argv: readonly string[],
): Promise<ArgvResult> {
  let result: ArgvResult;
  try {
    result = await runner(argv);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    const code = spawnFailureCode(error);
    throw new TargetResolutionError(code, code === "missing-cli" ? `${provider.cli} is not installed` : `${provider.cli} release lookup failed`, { provider: provider.provider === "generic-git" ? "git" : provider.provider, details: detail });
  }
  if (result.code === 0) return result;
  if (isMissingCli(result)) throw new TargetResolutionError("missing-cli", `${provider.cli} is not installed`, { provider: provider.provider === "generic-git" ? "git" : provider.provider, details: outputText(result) });
  if (isAuthFailure(result)) throw new TargetResolutionError("authentication-failure", `${provider.cli} release lookup requires authentication`, { provider: provider.provider === "generic-git" ? "git" : provider.provider, details: outputText(result) });
  if (/(?:not found|does not exist|404)/i.test(outputText(result))) throw new TargetResolutionError("absent-release", "The requested release does not exist", { provider: provider.provider === "generic-git" ? "git" : provider.provider, details: outputText(result) });
  throw new TargetResolutionError("command-failure", `${provider.cli} release lookup failed`, { provider: provider.provider === "generic-git" ? "git" : provider.provider, details: outputText(result) });
}

async function resolveGitHubPullRequest(request: Extract<TargetRequest, { kind: "pr" }>, runner: ArgvRunner): Promise<ResolvedTarget> {
  const provider = await detectProvider(request.repository, runner);
  if (provider.provider !== "github") throw new TargetResolutionError("invalid-target", "A PR target must use a GitHub repository", { provider: "github" });
  const slug = repositorySlug(provider.repository);
  const number = validateNumericId(request.number, "Pull request number");
  const details = await providerCommand(runner, provider, ["gh", "pr", "view", number, "--repo", slug, "--json", "headRefOid,baseRefOid,headRefName,baseRefName,files,url"]);
  const metadata = objectValue(parseJson(details, "GitHub PR metadata"), "GitHub PR metadata");
  const head = parseCommit(metadata.headRefOid, "GitHub PR head");
  const base = parseCommit(metadata.baseRefOid, "GitHub PR base");
  const entries = Array.isArray(metadata.files) ? metadata.files : [];
  const changes = entries.flatMap((entry): TargetChange[] => {
    const object = objectValue(entry, "GitHub PR file");
    const path = stringValue(object.path);
    if (!path) return [];
    const rawStatus = stringValue(object.status);
    const status = rawStatus === "added" ? "added" : rawStatus === "removed" ? "deleted" : rawStatus === "renamed" ? "renamed" : rawStatus === "modified" ? "modified" : "unknown";
    return [{ path, status, ...(status === "added" ? {} : { basePath: path }), ...(status === "deleted" ? {} : { headPath: path }) }];
  }).sort((left, right) => left.path.localeCompare(right.path));
  return { kind: "pr", label: `GitHub PR #${number}`, root: resolve("."), files: changes.flatMap((change) => change.headPath ? [change.headPath] : []), changes, baseRef: base, headRef: head, immutableRef: head, repository: provider.repository, materialization: "temporary-checkout" };
}

async function resolveGitLabMergeRequest(request: Extract<TargetRequest, { kind: "mr" }>, runner: ArgvRunner): Promise<ResolvedTarget> {
  const provider = await detectProvider(request.repository, runner);
  if (provider.provider !== "gitlab") throw new TargetResolutionError("invalid-target", "An MR target must use a GitLab repository", { provider: "gitlab" });
  const slug = repositorySlug(provider.repository);
  const iid = validateNumericId(request.iid, "Merge request IID");
  const details = await providerCommand(runner, provider, ["glab", "mr", "view", iid, "--repo", slug, "--output", "json"]);
  const metadata = objectValue(parseJson(details, "GitLab MR metadata"), "GitLab MR metadata");
  const refs = objectValue(metadata.diff_refs, "GitLab MR refs");
  const head = parseCommit(refs.head_sha ?? metadata.sha, "GitLab MR head");
  const base = parseCommit(refs.base_sha, "GitLab MR base");
  const entries = Array.isArray(metadata.changes) ? metadata.changes : [];
  const changes = entries.flatMap((entry): TargetChange[] => {
    const object = objectValue(entry, "GitLab MR file");
    const oldPath = stringValue(object.old_path);
    const newPath = stringValue(object.new_path);
    const deleted = object.deleted_file === true;
    const added = object.new_file === true;
    const renamed = object.renamed_file === true;
    const path = deleted ? oldPath : (newPath ?? oldPath);
    if (!path) return [];
    const status = deleted ? "deleted" : added ? "added" : renamed ? "renamed" : "modified";
    return [{ path, status, ...(oldPath && !added ? { basePath: oldPath } : {}), ...(newPath && !deleted ? { headPath: newPath } : {}) }];
  }).sort((left, right) => left.path.localeCompare(right.path));
  return { kind: "mr", label: `GitLab MR !${iid}`, root: resolve("."), files: changes.flatMap((change) => change.headPath ? [change.headPath] : []), changes, baseRef: base, headRef: head, immutableRef: head, repository: provider.repository, materialization: "temporary-checkout" };
}

async function dereferenceGitHubTag(provider: ProviderDetection, slug: string, tag: string, runner: ArgvRunner): Promise<string> {
  let result = await providerCommand(runner, provider, ["gh", "api", `repos/${slug}/git/ref/tags/${encodeURIComponent(tag)}`]);
  let data = objectValue(parseJson(result, "GitHub release tag ref"), "GitHub release tag ref");
  let object = objectValue(data.object, "GitHub release tag object");
  for (let depth = 0; depth < 8; depth += 1) {
    const sha = stringValue(object.sha);
    const type = stringValue(object.type);
    if (type === "commit") return parseCommit(sha, "GitHub release tag");
    if (type !== "tag" || !sha || !isImmutableRef(sha)) throw new TargetResolutionError("invalid-ref", "GitHub release tag does not resolve to a commit");
    result = await providerCommand(runner, provider, ["gh", "api", `repos/${slug}/git/tags/${sha}`]);
    data = objectValue(parseJson(result, "GitHub annotated tag"), "GitHub annotated tag");
    object = objectValue(data.object, "GitHub annotated tag object");
  }
  throw new TargetResolutionError("invalid-ref", "GitHub annotated tag chain is too deep");
}

export async function resolveGitHubRelease(repository: string, tag: string, runner: ArgvRunner, previousTag?: string): Promise<RemoteRelease> {
  const safeTag = validateGitOperand(tag, "Release tag");
  const safePrevious = previousTag ? validateGitOperand(previousTag, "Previous release tag") : undefined;
  const provider = await detectProvider(repository, runner);
  if (provider.provider !== "github") throw new TargetResolutionError("invalid-target", "A GitHub release requires a github.com repository", { provider: "github" });
  const slug = repositorySlug(provider.repository);
  const details = await releaseMetadataCommand(runner, provider, ["gh", "release", "view", safeTag, "--repo", slug, "--json", "tagName,targetCommitish,url"]);
  const metadata = objectValue(parseJson(details, "GitHub release metadata"), "GitHub release metadata");
  if (metadata.tagName !== safeTag) throw new TargetResolutionError("ambiguous-release", "GitHub release lookup did not resolve the exact tag", { provider: "github" });
  const commit = await dereferenceGitHubTag(provider, slug, safeTag, runner);
  return { provider: "github", repository: provider.repository, tag: safeTag, commit, previousTag: safePrevious, url: stringValue(metadata.url) };
}

export async function resolveGitLabRelease(repository: string, tag: string, runner: ArgvRunner, previousTag?: string): Promise<RemoteRelease> {
  const safeTag = validateGitOperand(tag, "Release tag");
  const safePrevious = previousTag ? validateGitOperand(previousTag, "Previous release tag") : undefined;
  const provider = await detectProvider(repository, runner);
  if (provider.provider !== "gitlab") throw new TargetResolutionError("invalid-target", "A GitLab release requires a gitlab.com repository", { provider: "gitlab" });
  const slug = repositorySlug(provider.repository);
  const details = await releaseMetadataCommand(runner, provider, ["glab", "release", "view", safeTag, "--repo", slug, "--output", "json"]);
  const metadata = objectValue(parseJson(details, "GitLab release metadata"), "GitLab release metadata");
  const resolvedTag = stringValue(metadata.tag_name) ?? stringValue(metadata.tagName);
  if (resolvedTag !== safeTag) throw new TargetResolutionError("ambiguous-release", "GitLab release lookup did not resolve the exact tag", { provider: "gitlab" });
  const commitObject = objectValue(metadata.commit, "GitLab release commit");
  const links = metadata._links ? objectValue(metadata._links, "GitLab release links") : undefined;
  return { provider: "gitlab", repository: provider.repository, tag: safeTag, commit: parseCommit(commitObject.id, "GitLab release tag"), previousTag: safePrevious, url: links ? stringValue(links.self) : undefined };
}

async function resolveGenericRepository(request: Extract<TargetRequest, { kind: "repository" }>, runner: ArgvRunner): Promise<ResolvedTarget> {
  const repository = validateRepository(request.repository);
  const provider: ProviderDetection = { provider: "generic-git", repository, cli: "git" };
  const version = await providerCommand(runner, provider, ["git", "--version"]);
  if (version.code !== 0) throw new TargetResolutionError("missing-cli", "git is not installed", { provider: "git", details: outputText(version) });
  const ref = validateGitOperand(request.ref ?? "HEAD", "Repository ref");
  const probe = await providerCommand(runner, provider, ["git", "ls-remote", "--", repository, ref, `${ref}^{}`]);
  const rows = probe.stdout.trim().split(/\r?\n/).filter(Boolean).map((row) => {
    const [object, name] = row.split(/\s+/, 2);
    return { object: parseCommit(object, "Repository ref"), name: name ?? "" };
  });
  if (rows.length === 0 || rows.length > 2) throw new TargetResolutionError("ambiguous-release", `Repository ref resolved to ${rows.length} refs`, { provider: "git" });
  const peeled = rows.find(({ name }) => name.endsWith("^{}"));
  if (rows.length === 2 && !peeled) throw new TargetResolutionError("ambiguous-release", "Repository ref resolved to multiple non-commit objects", { provider: "git" });
  const immutable = (peeled ?? rows[0])?.object;
  if (!immutable) throw new TargetResolutionError("invalid-ref", "Repository ref did not resolve to a commit");
  return { kind: "repository", label: repository, root: resolve("."), files: [], headRef: immutable, immutableRef: immutable, repository, materialization: "temporary-checkout" };
}

function requestedHistoryHead(window: HistoryWindow): string {
  if (window.kind === "refs") return validateGitOperand(window.head, "History head");
  if (window.head) return validateGitOperand(window.head, "History head");
  if (window.kind === "previous-release" && window.release) return validateGitOperand(window.release, "Release tag");
  return "HEAD";
}

async function capturedRemoteRef(repository: string, ref: string, runner: ArgvRunner): Promise<string> {
  const target = await resolveGenericRepository({ kind: "repository", repository, ref }, runner);
  if (!target.immutableRef) throw new TargetResolutionError("invalid-ref", "Remote history ref did not resolve to a commit");
  return target.immutableRef;
}

async function captureHistoryWindow(repository: string, window: HistoryWindow, runner: ArgvRunner): Promise<HistoryWindow> {
  if (window.kind === "refs") {
    const [base, head] = await Promise.all([
      capturedRemoteRef(repository, window.base, runner),
      capturedRemoteRef(repository, window.head, runner),
    ]);
    return { kind: "refs", base, head };
  }
  const head = await capturedRemoteRef(repository, requestedHistoryHead(window), runner);
  if (window.kind === "since-date") return { ...window, head };
  if (window.kind === "last-commits") return { ...window, head };
  if (window.kind === "since-release") return { ...window, release: await capturedRemoteRef(repository, window.release, runner), head };
  if (window.kind === "previous-release") {
    const release = window.release ? await capturedRemoteRef(repository, window.release, runner) : undefined;
    return { ...window, ...(release ? { release } : {}), head };
  }
  return { ...window, head };
}

export async function resolveProviderTarget(request: TargetRequest, runner: ArgvRunner): Promise<ResolvedTarget> {
  if (request.kind === "pr") return resolveGitHubPullRequest(request, runner);
  if (request.kind === "mr") return resolveGitLabMergeRequest(request, runner);
  if (request.kind === "repository") return resolveGenericRepository(request, runner);
  if (request.kind === "release") {
    const provider = providerFromRepository(request.repository);
    const release = provider === "github"
      ? await resolveGitHubRelease(request.repository, request.tag, runner, request.previousTag)
      : provider === "gitlab"
        ? await resolveGitLabRelease(request.repository, request.tag, runner, request.previousTag)
        : (() => { throw new TargetResolutionError("invalid-target", "Release resolution requires a GitHub or GitLab repository"); })();
    const previousRef = release.previousTag ? await capturedRemoteRef(release.repository, release.previousTag, runner) : undefined;
    return {
      kind: "release",
      label: `${release.provider} release ${release.tag}`,
      root: resolve("."),
      files: [],
      headRef: release.commit,
      immutableRef: release.commit,
      repository: release.repository,
      release: { tag: release.tag, previousTag: release.previousTag, ...(previousRef ? { previousRef } : {}), deltaFiles: [], snapshotFiles: [] },
      materialization: "temporary-checkout",
    };
  }
  if (request.kind === "history") {
    const local = existsSync(resolve(request.rootOrRepository));
    if (local) return resolveHistoryAtRoot(resolve(request.rootOrRepository), request.window, runner);
    const repository = validateRepository(request.rootOrRepository);
    const capturedWindow = await captureHistoryWindow(repository, request.window, runner);
    const head = requestedHistoryHead(capturedWindow);
    if (!isImmutableRef(head)) throw new TargetResolutionError("invalid-ref", "Remote history head was not captured as a commit SHA");
    return {
      kind: "history",
      label: `history ${request.window.kind}`,
      root: resolve("."),
      files: [],
      headRef: head,
      immutableRef: head,
      repository,
      history: { window: request.window, capturedWindow, commits: [] },
      materialization: "temporary-checkout",
    };
  }
  throw new TargetResolutionError("invalid-target", `Unsupported provider target ${request.kind}`);
}

export async function resolveTarget(request: TargetRequest, runner: ArgvRunner = runArgv): Promise<ResolvedTarget> {
  return request.kind === "whole-repo" || request.kind === "working-tree" || request.kind === "files" || request.kind === "directory" || request.kind === "module" || request.kind === "commit" || request.kind === "range" || request.kind === "branch" || request.kind === "ref"
    ? resolveLocalTarget(request, runner)
    : resolveProviderTarget(request, runner);
}

export async function resolveTargetLease(request: TargetRequest, runner: ArgvRunner = runArgv) {
  return resolveLocalTargetLease(request, runner, resolveProviderTarget, materializeProviderTarget);
}

export async function withResolvedTarget<T>(request: TargetRequest, callback: (target: ResolvedTarget) => T | Promise<T>, runner: ArgvRunner = runArgv): Promise<T> {
  return withLocalResolvedTarget(request, callback, runner, resolveProviderTarget, materializeProviderTarget);
}

async function runGit(runner: ArgvRunner, root: string, args: readonly string[], failure: string): Promise<ArgvResult> {
  let result: ArgvResult;
  try {
    result = await runner(["git", ...args], { cwd: root });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new TargetResolutionError("command-failure", failure, { provider: "git", details: detail });
  }
  if (result.code !== 0) throw new TargetResolutionError(result.code === 127 ? "missing-cli" : "command-failure", failure, { provider: "git", details: outputText(result) });
  return result;
}

async function localCommit(root: string, ref: string, runner: ArgvRunner): Promise<string> {
  const safeRef = validateGitOperand(ref, "Git ref");
  const result = await runGit(runner, root, ["rev-parse", "--verify", `${safeRef}^{commit}`], "Git ref resolution failed");
  return parseCommit(result.stdout.trim().split(/\s+/)[0], "Git ref");
}

function commitRows(result: ArgvResult): string[] {
  const commits = result.stdout.split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
  if (commits.some((commit) => !isImmutableRef(commit))) throw new TargetResolutionError("invalid-ref", "History returned a non-immutable commit");
  return commits.map((commit) => commit.toLowerCase());
}

async function historyDiff(root: string, base: string, head: string, runner: ArgvRunner): Promise<TargetChange[]> {
  const result = await runGit(runner, root, ["diff", "--name-status", "--find-renames", "-z", `${base}...${head}`], "History diff failed");
  return parseGitNameStatus(result.stdout);
}

async function logRange(root: string, args: readonly string[], runner: ArgvRunner): Promise<string[]> {
  return commitRows(await runGit(runner, root, ["log", "--format=%H", ...args], "History lookup failed"));
}

async function baseBeforeOldest(root: string, commits: readonly string[], head: string, runner: ArgvRunner): Promise<string> {
  const oldest = commits.at(-1) ?? head;
  try {
    return await localCommit(root, `${oldest}^`, runner);
  } catch (error) {
    if (error instanceof TargetResolutionError && error.code !== "missing-cli") return oldest;
    throw error;
  }
}

export async function resolveHistoryAtRoot(root: string, window: HistoryWindow, runner: ArgvRunner): Promise<ResolvedTarget> {
  let head: string;
  let base: string;
  let commits: string[];
  switch (window.kind) {
    case "refs":
      base = await localCommit(root, window.base, runner);
      head = await localCommit(root, window.head, runner);
      commits = await logRange(root, [`${base}..${head}`], runner);
      break;
    case "since-date":
      {
        const date = validateDate(window.date);
        head = await localCommit(root, window.head ?? "HEAD", runner);
        commits = await logRange(root, [`--since=${date}`, head], runner);
      }
      base = await baseBeforeOldest(root, commits, head, runner);
      break;
    case "last-commits":
      if (!Number.isSafeInteger(window.count) || window.count < 1 || window.count > 100_000) throw new TargetResolutionError("invalid-target", "History commit count must be between 1 and 100000");
      head = await localCommit(root, window.head ?? "HEAD", runner);
      commits = await logRange(root, ["-n", String(window.count), head], runner);
      base = await baseBeforeOldest(root, commits, head, runner);
      break;
    case "since-release":
      base = await localCommit(root, window.release, runner);
      head = await localCommit(root, window.head ?? "HEAD", runner);
      commits = await logRange(root, [`${base}..${head}`], runner);
      break;
    case "previous-release": {
      const requestedHead = window.head ?? window.release ?? "HEAD";
      head = await localCommit(root, requestedHead, runner);
      let release = window.release;
      if (!release) {
        const current = await runGit(runner, root, ["describe", "--tags", "--abbrev=0", head], "Current release lookup failed");
        release = validateGitOperand(current.stdout.trim(), "Current release tag");
      }
      const previous = await runGit(runner, root, ["describe", "--tags", "--abbrev=0", `${validateGitOperand(release, "Release tag")}^`], "Previous release lookup failed");
      base = await localCommit(root, previous.stdout.trim(), runner);
      commits = await logRange(root, [`${base}..${head}`], runner);
      break;
    }
    case "context-aware-default":
      head = await localCommit(root, window.head ?? "HEAD", runner);
      commits = await logRange(root, ["-n", "1", head], runner);
      base = await baseBeforeOldest(root, commits, head, runner);
      break;
  }
  const changes = await historyDiff(root, base, head, runner);
  const files = [...new Set(changes.flatMap((change) => change.headPath ? [change.headPath] : []))].sort();
  return {
    kind: "history",
    label: `history ${window.kind}`,
    root,
    files,
    changes,
    baseRef: base,
    headRef: head,
    immutableRef: head,
    history: { window, capturedWindow: { kind: "refs", base, head }, commits },
    materialization: "temporary-checkout",
  };
}

export async function materializeProviderTarget(target: ResolvedTarget, runner: ArgvRunner): Promise<ResolvedTarget> {
  if (target.kind === "history" && target.history) {
    const window = target.history.capturedWindow ?? target.history.window;
    const history = await resolveHistoryAtRoot(target.root, window, runner);
    if (!history.history) throw new TargetResolutionError("invalid-target", "Materialized history target omitted history metadata");
    return {
      ...history,
      repository: target.repository,
      history: { ...history.history, window: target.history.window },
      materialization: "temporary-checkout",
    };
  }
  if (target.kind === "release" && target.release && target.immutableRef) {
    const snapshot = await runGit(runner, target.root, ["ls-tree", "-r", "--name-only", target.immutableRef], "Release snapshot lookup failed");
    const snapshotFiles = [...new Set(snapshot.stdout.split(/\r?\n/).map((value) => value.trim()).filter(Boolean))].sort();
    let deltaFiles = snapshotFiles;
    let changes: TargetChange[] | undefined;
    let baseRef: string | undefined;
    if (target.release.previousRef) {
      baseRef = await localCommit(target.root, target.release.previousRef, runner);
      changes = await historyDiff(target.root, baseRef, target.immutableRef, runner);
      deltaFiles = changes.map((change) => change.path);
    }
    return { ...target, files: snapshotFiles, ...(changes ? { changes } : {}), baseRef, release: { ...target.release, snapshotFiles, deltaFiles } };
  }
  if (target.kind === "repository" && target.immutableRef) {
    const snapshot = await runGit(runner, target.root, ["ls-tree", "-r", "--name-only", target.immutableRef], "Repository snapshot lookup failed");
    return { ...target, files: [...new Set(snapshot.stdout.split(/\r?\n/).map((value) => value.trim()).filter(Boolean))].sort() };
  }
  return target;
}

export function providerFingerprint(provider: ProviderDetection): string {
  return createHash("sha256").update(`${provider.provider}:${provider.repository}:${provider.cli}`).digest("hex");
}
