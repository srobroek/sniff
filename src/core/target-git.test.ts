import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type ArgvRunner, createTemporaryCheckout, resolveTarget, runArgv } from "./target.ts";
import { resolveHistoryAtRoot } from "./target-provider.ts";

const temporary: string[] = [];
afterEach(() => {
  for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true });
});

function repo() {
  const root = mkdtempSync(join(tmpdir(), "sniff-git-names-"));
  temporary.push(root);
  const git = (...args: string[]) => {
    const result = Bun.spawnSync(["git", ...args], { cwd: root, stdout: "pipe", stderr: "pipe" });
    if (result.exitCode !== 0) throw new Error(result.stderr.toString());
    return result.stdout.toString().trim();
  };
  git("init", "-q");
  git("config", "user.email", "sniff@example.invalid");
  git("config", "user.name", "Sniff Test");
  git("config", "commit.gpgsign", "false");
  git("config", "core.hooksPath", "/dev/null");
  return { root, git };
}

const AWKWARD = ["ok.ts", "café.ts", " lead.ts", "trail.ts ", "new\nline\ttab.ts"];

describe("git filename handling", () => {
  test("whole-repo, commit and range keep non-ASCII, padded and control-character names", async () => {
    const { root, git } = repo();
    writeFileSync(join(root, "seed.ts"), "x\n");
    git("add", ".");
    git("commit", "-q", "-m", "seed");
    const base = git("rev-parse", "HEAD");
    for (const name of AWKWARD) writeFileSync(join(root, name), "x\n");
    git("add", ".");
    git("commit", "-q", "-m", "names");

    const whole = await resolveTarget({ kind: "whole-repo", root });
    expect([...whole.files].sort()).toEqual([...AWKWARD, "seed.ts"].sort());
    const range = await resolveTarget({ kind: "range", root, base, head: "HEAD" });
    expect([...range.files].sort()).toEqual([...AWKWARD].sort());
  });

  test("working-tree keeps awkward names and records deletions and renames", async () => {
    const { root, git } = repo();
    writeFileSync(join(root, "gone.ts"), "gone\n");
    writeFileSync(join(root, "old.ts"), "a rather long body so rename detection is stable\n".repeat(5));
    writeFileSync(join(root, "keep.ts"), "keep\n");
    git("add", ".");
    git("commit", "-q", "-m", "seed");
    rmSync(join(root, "gone.ts"));
    renameSync(join(root, "old.ts"), join(root, "café renamed.ts"));
    git("add", "-A");
    writeFileSync(join(root, "keep.ts"), "edited\n");
    for (const name of AWKWARD) writeFileSync(join(root, name), "x\n");

    const target = await resolveTarget({ kind: "working-tree", root });
    expect([...target.files].sort()).toEqual([...AWKWARD, "café renamed.ts", "keep.ts"].sort());
    expect(target.changes).toContainEqual({ path: "gone.ts", status: "deleted", basePath: "gone.ts" });
    expect(target.changes).toContainEqual({ path: "café renamed.ts", status: "renamed", basePath: "old.ts", headPath: "café renamed.ts" });
    expect(target.changes).toContainEqual({ path: "keep.ts", status: "modified", basePath: "keep.ts", headPath: "keep.ts" });
    expect(target.files).not.toContain("gone.ts");
  });

  test("unstaged deletion yields a change and no files", async () => {
    const { root, git } = repo();
    writeFileSync(join(root, "gone.ts"), "gone\n");
    git("add", ".");
    git("commit", "-q", "-m", "seed");
    rmSync(join(root, "gone.ts"));
    const target = await resolveTarget({ kind: "working-tree", root });
    expect(target.files).toEqual([]);
    expect(target.changes).toEqual([{ path: "gone.ts", status: "deleted", basePath: "gone.ts" }]);
  });

  test("since-date window with zero commits is empty", async () => {
    const { root, git } = repo();
    writeFileSync(join(root, "a.ts"), "a\n");
    git("add", ".");
    git("commit", "-q", "-m", "one");
    writeFileSync(join(root, "b.ts"), "b\n");
    git("add", ".");
    git("commit", "-q", "-m", "two");
    const head = git("rev-parse", "HEAD");
    const target = await resolveHistoryAtRoot(root, { kind: "since-date", date: "2099-01-01" }, runArgv);
    expect(target.files).toEqual([]);
    expect(target.changes).toEqual([]);
    expect(target.baseRef).toBe(head);
    expect(target.history?.commits).toEqual([]);
  });

  test("temporary checkouts disable hooks and LFS smudge", async () => {
    const { root, git } = repo();
    writeFileSync(join(root, "a.ts"), "a\n");
    git("add", ".");
    git("commit", "-q", "-m", "one");
    const head = git("rev-parse", "HEAD");
    const seen: { argv: readonly string[]; env?: Readonly<Record<string, string>> }[] = [];
    const runner: ArgvRunner = (argv, options) => {
      seen.push({ argv, env: options?.env });
      return runArgv(argv, options);
    };
    const lease = await createTemporaryCheckout(root, head, runner);
    lease.release();
    expect(seen.length).toBeGreaterThanOrEqual(3);
    for (const call of seen.filter((entry) => ["clone", "fetch", "checkout"].some((verb) => entry.argv.includes(verb)))) {
      expect(call.argv).toContain("core.hooksPath=/dev/null");
      expect(call.env?.GIT_LFS_SKIP_SMUDGE).toBe("1");
      expect(call.env?.GIT_CONFIG_GLOBAL).toBeUndefined();
    }
    expect(seen.some((entry) => entry.argv.includes("clone"))).toBe(true);
    expect(seen.some((entry) => entry.argv.includes("checkout"))).toBe(true);
  });
});
