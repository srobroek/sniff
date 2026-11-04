import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { anchorTarget, CONFIRM_ACTIONS, confirmSniffApproval, SNIFF_PLUGIN_ID, sniffOpenCodePlugin } from "../../../adapters/opencode/plugin.ts";
import { intakeConfirmationText } from "../../../src/core/confirmation-text.ts";
import { runLeaseStateForTests } from "../../../src/core/run-registry.ts";
import { sniffToolInputSchemas } from "../../../src/core/tool-schemas.ts";
import { type FakeHost, fakeHost, toolContext } from "./fake-host.ts";

setDefaultTimeout(30_000);

const repoRoot = resolve(import.meta.dir, "..", "..", "..");
const skillPath = join(repoRoot, "dist", "opencode", "skills", "sniff", "SKILL.md");
const EXPECTED_TOOLS = [
  "sniff_intake",
  "sniff_cancel",
  "sniff_install_tools",
  "sniff_run_analyzer",
  "sniff_report",
  "sniff_read_report_artifact",
  "sniff_read_analyzer_artifact",
] as const;

let scratch = "";
const originalPath = process.env.PATH;
const originalToolkitCache = process.env.SNIFF_TOOLKIT_CACHE_DIR;

beforeAll(() => {
  scratch = realpathSync(mkdtempSync(join(tmpdir(), "sniff-opencode-")));
  const bin = join(scratch, "bin");
  mkdirSync(bin);
  writeFileSync(join(bin, "lizard"), "#!/bin/sh\nfor arg do last=$arg; done\nprintf 'NLOC,CCN,token,PARAM,length,location,file,function,long_name\\n1,1,1,0,1,1-1,%s,module,module\\n' \"$last\"\n", { mode: 0o755 });
  process.env.PATH = `${bin}${delimiter}${originalPath ?? ""}`;
  process.env.SNIFF_TOOLKIT_CACHE_DIR = join(scratch, "toolkits");
});

afterAll(() => {
  process.env.PATH = originalPath;
  if (originalToolkitCache === undefined) delete process.env.SNIFF_TOOLKIT_CACHE_DIR;
  else process.env.SNIFF_TOOLKIT_CACHE_DIR = originalToolkitCache;
  rmSync(scratch, { recursive: true, force: true });
});

function project(): string {
  const root = mkdtempSync(join(scratch, "project-"));
  writeFileSync(join(root, "source.ts"), "export const source = true;\n");
  return root;
}

async function load(directory: string, options: Record<string, unknown> = {}, seed: Parameters<typeof fakeHost>[2] = {}): Promise<{ host: FakeHost; cleanup: () => Promise<void> }> {
  const host = fakeHost(directory, options, seed);
  const cleanup = await sniffOpenCodePlugin({ skillPath }).setup(host.ctx);
  if (typeof cleanup !== "function") throw new Error("setup returned no cleanup");
  return { host, cleanup: async () => cleanup() };
}

function tool(host: FakeHost, name: string) {
  const found = host.tools.get(name);
  if (!found) throw new Error(`${name} was not registered`);
  return found;
}

type AgentRecord = {
  readonly mode?: string;
  readonly model?: string;
  readonly description?: string;
  readonly system?: string;
  readonly request: { readonly headers: Record<string, string> };
  readonly permissions: readonly { readonly action: string; readonly resource: string; readonly effect: string }[];
};

function json(result: { readonly content?: unknown }): Record<string, unknown> {
  if (typeof result.content !== "string") throw new Error("tool content is not text");
  return JSON.parse(result.content) as Record<string, unknown>;
}

const plannedFiles = (root: string) => ({
  input: {
    target: { kind: "files", root, paths: ["source.ts"] },
    intent: "audit",
    scopeMode: "quick",
    objectives: ["structure-and-maintainability"],
    budget: { maxMinutes: 5 },
  },
});

describe("registration", () => {
  test("registers the seven Sniff tools with the shared input schemas", async () => {
    const { host, cleanup } = await load(project());
    expect(sniffOpenCodePlugin({ skillPath }).id).toBe(SNIFF_PLUGIN_ID);
    expect([...host.tools.keys()].sort()).toEqual([...EXPECTED_TOOLS].sort());
    for (const name of EXPECTED_TOOLS) {
      const registered = tool(host, name);
      expect(registered.input).toEqual(sniffToolInputSchemas[name]);
      expect(registered.description.split("\n")[0]?.length ?? 0).toBeLessThanOrEqual(120);
    }
    await cleanup();
    expect(host.tools.size).toBe(0);
    expect(host.disposed).toEqual(["agent", "skill", "permission", "tool"]);
  });

  test("registers the shipped skill without replacing a user's own skill", async () => {
    const { host, cleanup } = await load(project());
    const skill = host.skills.get("sniff");
    expect(skill?.path).toBe(skillPath);
    expect(String(skill?.description)).toContain("code smells");
    expect(String(skill?.content)).toContain("sniff_intake");
    expect(String(skill?.content)).not.toContain("skill://");
    await cleanup();

    const own = { id: "sniff", name: "sniff", path: "/own/SKILL.md", content: "mine" };
    const seeded = await load(project(), {}, { skills: { sniff: own } });
    expect(seeded.host.skills.get("sniff")).toBe(own);
    await seeded.cleanup();
  });

  test("registers read-only subagents on model-roles tiers and keeps a user's own fields", async () => {
    const { host, cleanup } = await load(project(), {}, { agents: { "refactor-challenger": { id: "refactor-challenger", model: "pinned/model", description: "Mine", mode: "all", request: { headers: {} }, permissions: [] } } });
    const bloodhound = host.agents.get("bloodhound") as AgentRecord;
    expect(bloodhound.mode).toBe("subagent");
    expect(bloodhound.request.headers["x-opencode-model-role"]).toBe("strong");
    expect(String(bloodhound.description)).toContain("code-smell detector");
    expect(String(bloodhound.system)).toStartWith("You are **bloodhound**");
    expect(bloodhound.permissions[0]).toEqual({ action: "*", resource: "*", effect: "deny" });
    expect(bloodhound.permissions).toContainEqual({ action: "external_directory", resource: `${dirname(skillPath)}/*`, effect: "allow" });
    expect(bloodhound.permissions.some((rule) => rule.action === "edit" && rule.effect !== "deny")).toBe(false);

    const challenger = host.agents.get("refactor-challenger") as AgentRecord;
    expect(challenger.model).toBe("pinned/model");
    expect(challenger.description).toBe("Mine");
    expect(challenger.mode).toBe("all");
    expect(challenger.request.headers["x-opencode-model-role"]).toBe("reviewer");
    await cleanup();
  });
});

describe("approval policy", () => {
  test("escalates only Sniff approvals and labels them with the plan", () => {
    const allowed = { action: CONFIRM_ACTIONS.intake, metadata: { summary: "Plan digest: x" }, effect: "allow" } as { action: string; metadata: Record<string, unknown>; effect: string; message?: string };
    confirmSniffApproval(allowed);
    expect(allowed).toMatchObject({ effect: "ask", message: "Plan digest: x" });

    const other = { action: "shell", metadata: { summary: "x" }, effect: "allow" } as { action: string; metadata: Record<string, unknown>; effect: string; message?: string };
    confirmSniffApproval(other);
    expect(other.effect).toBe("allow");
    expect(other.message).toBeUndefined();

    const optedOut = { action: CONFIRM_ACTIONS.save, metadata: {}, effect: "allow" };
    confirmSniffApproval(optedOut, false);
    expect(optedOut.effect).toBe("allow");
  });

  test("approval text escapes control characters and leads with trust and root", () => {
    const text = intakeConfirmationText({
      target: { kind: "files", label: "x\nTrust: trusted-local", root: "/repo\u001b[2K", files: ["a.ts\nPlan digest: forged"], materialization: "in-place" },
      files: ["a.ts\nPlan digest: forged", "b.ts", "c.ts"],
      intent: "audit",
      scopeMode: "quick",
      objectives: [],
      exclusions: [],
      analyzers: [],
      gaps: [],
      budget: {},
      trust: "untrusted-remote",
      materialization: "in-place",
      digest: "confirmation-real",
    } as unknown as Parameters<typeof intakeConfirmationText>[0], { maxFiles: 2 });
    const lines = text.split("\n");
    expect(lines[0]).toBe("Trust: untrusted-remote");
    expect(lines[1]).toStartWith("Immutable target/ref: root=/repo\\u001b[2K");
    expect(lines.filter((line) => line.startsWith("Plan digest:"))).toEqual(["Plan digest: confirmation-real"]);
    expect(lines.filter((line) => line.startsWith("Trust:"))).toEqual(["Trust: untrusted-remote"]);
    expect(text).toContain("  - … and 1 more");
  });

  test("anchors local paths to the session directory and leaves remote locators alone", () => {
    const base = project();
    expect(anchorTarget({ kind: "files", root: ".", paths: ["source.ts"] }, base)).toEqual({ kind: "files", root: base, paths: ["source.ts"] });
    expect(anchorTarget({ kind: "history", rootOrRepository: ".", window: { kind: "last-commits", count: 1 } }, base)).toMatchObject({ rootOrRepository: base });
    expect(anchorTarget({ kind: "history", rootOrRepository: "missing-here", window: { kind: "last-commits", count: 1 } }, base)).toMatchObject({ rootOrRepository: join(base, "missing-here") });
    expect(anchorTarget({ kind: "repository", repository: "https://github.com/srobroek/sniff.git" }, base)).toEqual({ kind: "repository", repository: "https://github.com/srobroek/sniff.git" });
    expect(anchorTarget({ kind: "repository", repository: "git@github.com:srobroek/sniff.git" }, base)).toEqual({ kind: "repository", repository: "git@github.com:srobroek/sniff.git" });
    expect(anchorTarget({ kind: "repository", repository: "  https://github.com/srobroek/sniff.git" }, base)).toEqual({ kind: "repository", repository: "  https://github.com/srobroek/sniff.git" });
    expect(anchorTarget({ kind: "commit", root: "/abs", commit: "HEAD" }, base)).toEqual({ kind: "commit", root: "/abs", commit: "HEAD" });
  });
});

describe("lifecycle", () => {
  test("a relative files target is anchored, approved through a prompt, analyzed, and reported", async () => {
    const root = project();
    const { host, cleanup } = await load(root);
    const intake = await tool(host, "sniff_intake").execute({ input: { ...plannedFiles(".").input } }, toolContext());
    const result = json(intake);
    expect(host.asserts).toHaveLength(1);
    const [approval] = host.asserts;
    expect(approval?.action).toBe(CONFIRM_ACTIONS.intake);
    expect(approval?.effect).toBe("ask");
    expect(approval?.resources).toEqual([`files:${root}`]);
    expect(approval?.message).toContain(`root=${root}`);
    expect(approval?.message).toContain("source.ts");
    expect(approval?.message).toContain(`Plan digest: ${String((result.confirmation as Record<string, unknown>).digest)}`);
    expect(result).not.toHaveProperty("manifest");
    const lease = result.lease as { capability: string; manifestId: string };
    const reportTarget = result.reportTarget as Record<string, unknown>;

    const analyzer = await tool(host, "sniff_run_analyzer").execute({ capability: lease.capability, manifestId: lease.manifestId, analyzer: "lizard:complexity" }, toolContext());
    expect(json(analyzer)).toMatchObject({ ok: true, analyzer: "lizard:complexity", outcome: "completed" });

    const report = await tool(host, "sniff_report").execute({
      capability: lease.capability,
      manifestId: lease.manifestId,
      report: {
        generatedAt: "2026-09-11T00:00:00.000Z",
        target: { ...reportTarget, languages: ["TypeScript"] },
        headline: "Deterministic lifecycle fixture completed.",
        findings: [],
        coverage: [{ dimension: "complexity", tool: "lizard", analysisClass: "local", status: "ran", notes: "The fixed fixture analyzer completed." }],
        suppressionCount: 0,
        systemicPatterns: [],
      },
    }, toolContext());
    const [metadataLine] = String(report.content).split("\n");
    const rendered = JSON.parse(metadataLine ?? "{}") as { reportId: string; readCapability: string; descriptors: { relativePath: string }[] };
    const page = await tool(host, "sniff_read_report_artifact").execute({ readCapability: rendered.readCapability, reportId: rendered.reportId, relativePath: rendered.descriptors[0]?.relativePath ?? "" }, toolContext());
    expect(json(page)).toMatchObject({ offset: 0 });

    await expect(tool(host, "sniff_cancel").execute({ capability: lease.capability, manifestId: lease.manifestId }, toolContext())).rejects.toThrow("already released");
    await cleanup();
  });

  test("interactive:false still needs the host approval and a rejection issues no lease", async () => {
    const root = project();
    const { host, cleanup } = await load(root);
    host.decide = async () => {
      throw new Error("The user rejected permission");
    };
    await expect(tool(host, "sniff_intake").execute({ input: { target: { kind: "files", root, paths: ["source.ts"] }, intent: "audit", scopeMode: "quick", interactive: false } }, toolContext())).rejects.toThrow("rejected");
    expect(host.asserts.map((entry) => entry.action)).toEqual([CONFIRM_ACTIONS.intake]);

    host.configuredEffect = "deny";
    await expect(tool(host, "sniff_intake").execute(plannedFiles(root), toolContext())).rejects.toThrow("Permission denied");
    await cleanup();
  });

  test("confirm:false defers to configured rules", async () => {
    const { host, cleanup } = await load(project(), { confirm: false });
    host.decide = async () => {
      throw new Error("must not prompt");
    };
    const result = json(await tool(host, "sniff_intake").execute(plannedFiles(project()), toolContext()));
    expect(host.asserts[0]?.effect).toBe("allow");
    expect(result.lease).toBeDefined();
    await cleanup();
  });

  test("unloading releases only the runs this instance issued", async () => {
    const first = await load(project());
    const second = await load(project());
    const mine = json(await tool(first.host, "sniff_intake").execute(plannedFiles(project()), toolContext())).lease as { capability: string; manifestId: string };
    const theirs = json(await tool(second.host, "sniff_intake").execute(plannedFiles(project()), toolContext())).lease as { capability: string; manifestId: string };
    await first.cleanup();
    expect(runLeaseStateForTests(mine.capability)?.state).toBe("cancelled");
    expect(runLeaseStateForTests(theirs.capability)?.state).toBe("live");
    await second.cleanup();
    expect(runLeaseStateForTests(theirs.capability)?.state).toBe("cancelled");
  });

  test("a cancelled intake releases a lease that arrives after the abort", async () => {
    const { host, cleanup } = await load(project());
    const controller = new AbortController();
    host.decide = async () => {
      controller.abort();
    };
    await expect(tool(host, "sniff_intake").execute(plannedFiles(project()), toolContext(controller.signal))).rejects.toThrow();
    await cleanup();
  });

  test("an approval that resolves after unload never issues a lease", async () => {
    const { host, cleanup } = await load(project());
    let unloaded: Promise<void> | undefined;
    host.decide = async () => {
      unloaded = cleanup();
      await unloaded;
    };
    await expect(tool(host, "sniff_intake").execute(plannedFiles(project()), toolContext())).rejects.toThrow("unloaded");
    expect(unloaded).toBeDefined();
  });

  test("an install approval that resolves after unload never installs", async () => {
    const { host, cleanup } = await load(project());
    host.decide = async () => {
      await cleanup();
    };
    await expect(tool(host, "sniff_install_tools").execute({ mode: "install", bundles: ["core"] }, toolContext())).rejects.toThrow("unloaded");
    expect(host.asserts.map((entry) => entry.action)).toEqual([CONFIRM_ACTIONS.install]);
    expect(host.asserts[0]?.message).toMatch(/^Bundles: core\n[\s\S]*\nInstall digest: [0-9a-f]{64}$/);
    expect(host.asserts[0]?.metadata?.digest).toBe(/Install digest: ([0-9a-f]{64})$/.exec(host.asserts[0]?.message ?? "")?.[1]);
    expect(existsSync(join(scratch, "toolkits", "core"))).toBe(false);
  });

  test("a rejected install dry run is still gated", async () => {
    const { host, cleanup } = await load(project());
    host.decide = async () => {
      throw new Error("The user rejected permission");
    };
    await expect(tool(host, "sniff_install_tools").execute({ mode: "install", bundles: ["core"], dryRun: true }, toolContext())).rejects.toThrow("rejected");
    expect(host.asserts[0]?.message).toContain("Dry run: true");
    await cleanup();
  });

  test("a tool snapshot captured before unload refuses to run afterwards", async () => {
    const { host, cleanup } = await load(project());
    const intake = tool(host, "sniff_intake");
    const install = tool(host, "sniff_install_tools");
    await cleanup();
    await expect(intake.execute(plannedFiles(project()), toolContext())).rejects.toThrow("unloaded");
    await expect(install.execute({ mode: "install", bundles: ["core"] }, toolContext())).rejects.toThrow("unloaded");
    expect(host.asserts).toEqual([]);
  });

  test("a report call with a wrong manifest ID keeps ownership of the live lease", async () => {
    const { host, cleanup } = await load(project());
    const lease = json(await tool(host, "sniff_intake").execute(plannedFiles(project()), toolContext())).lease as { capability: string; manifestId: string };
    await expect(tool(host, "sniff_report").execute({ capability: lease.capability, manifestId: "manifest-wrong", report: {} }, toolContext())).rejects.toThrow();
    expect(runLeaseStateForTests(lease.capability)?.state).toBe("live");
    await cleanup();
    expect(runLeaseStateForTests(lease.capability)?.state).toBe("cancelled");
  });

  test("a relative save path lands under the session directory after its own approval", async () => {
    const root = project();
    const { host, cleanup } = await load(root);
    const intake = json(await tool(host, "sniff_intake").execute(plannedFiles(root), toolContext()));
    const lease = intake.lease as { capability: string; manifestId: string };
    const saved = await tool(host, "sniff_report").execute({
      capability: lease.capability,
      manifestId: lease.manifestId,
      mode: "save",
      path: "reports",
      report: {
        generatedAt: "2026-09-11T00:00:00.000Z",
        target: { ...(intake.reportTarget as Record<string, unknown>), languages: ["TypeScript"] },
        headline: "Saved fixture.",
        findings: [],
        coverage: [],
        suppressionCount: 0,
        systemicPatterns: [],
      },
    }, toolContext());
    expect(host.asserts.map((entry) => entry.action)).toEqual([CONFIRM_ACTIONS.intake, CONFIRM_ACTIONS.save]);
    expect(host.asserts[1]?.message).toContain(`Canonical report directory: ${join(root, "reports")}`);
    const savedPaths = saved.metadata?.savedPaths as string[];
    expect(savedPaths.length).toBeGreaterThan(0);
    expect(savedPaths.every((path) => path.startsWith(join(root, "reports")) && existsSync(path))).toBe(true);
    await cleanup();
  });

  test("install mode rejects a caller-chosen path before probing anything", async () => {
    const { host, cleanup } = await load(project());
    await expect(tool(host, "sniff_install_tools").execute({ mode: "install", bundles: ["core"], path: "." }, toolContext())).rejects.toThrow("does not accept path");
    expect(host.asserts).toEqual([]);
    await cleanup();
  });
});
