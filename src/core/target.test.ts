import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type ArgvRunner, resolveTarget, runArgv } from "./target.ts";
import { resolveTargetLease } from "./target-provider.ts";

const temporary: string[] = [];

afterEach(() => {
  for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true });
});

function repository(): { readonly root: string; readonly git: (...args: string[]) => string } {
  const root = mkdtempSync(join(tmpdir(), "sniff-whole-repo-"));
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

function commitFixture() {
  const fixture = repository();
  writeFileSync(join(fixture.root, "fixture.ts"), "export const value = 'committed';\n");
  fixture.git("add", "fixture.ts");
  fixture.git("commit", "-q", "-m", "fixture");
  return { ...fixture, head: fixture.git("rev-parse", "HEAD") };
}

describe("whole-repo targets", () => {
  test("resolves committed files at an immutable HEAD", async () => {
    const { root, head } = commitFixture();
    writeFileSync(join(root, "working-tree.ts"), "export const value = 'uncommitted';\n");

    const target = await resolveTarget({ kind: "whole-repo", root });

    expect(target).toMatchObject({
      root: realpathSync(root),
      files: ["fixture.ts"],
      headRef: head,
      immutableRef: head,
      materialization: "temporary-checkout",
    });
  });

  test("materializes the resolved commit even after source edits", async () => {
    const { root, head } = commitFixture();
    let changedSource = false;
    const runner: ArgvRunner = async (argv, options) => {
      const result = await runArgv(argv, options);
      if (!changedSource && argv[1] === "ls-tree") {
        changedSource = true;
        writeFileSync(join(root, "fixture.ts"), "export const value = 'changed';\n");
        writeFileSync(join(root, "working-tree.ts"), "export const value = 'uncommitted';\n");
      }
      return result;
    };

    const lease = await resolveTargetLease({ kind: "whole-repo", root }, runner);
    const checkout = lease.target.root;
    try {
      expect(lease.target.kind).toBe("whole-repo");
      expect(lease.target.files).toEqual(["fixture.ts"]);
      expect(lease.target.immutableRef).toBe(head);
      expect(readFileSync(join(checkout, "fixture.ts"), "utf8")).toBe("export const value = 'committed';\n");
      expect(existsSync(join(checkout, "working-tree.ts"))).toBe(false);
    } finally {
      lease.release();
    }
    expect(existsSync(checkout)).toBe(false);
  });

  test("releases a whole-repo checkout exactly once", async () => {
    const { root } = commitFixture();
    const lease = await resolveTargetLease({ kind: "whole-repo", root });
    const checkout = lease.target.root;

    expect(existsSync(checkout)).toBe(true);
    lease.release();
    expect(existsSync(checkout)).toBe(false);
    expect(() => lease.release()).not.toThrow();
  });
});
