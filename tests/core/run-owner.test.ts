import { afterEach, describe, expect, test, vi } from "bun:test";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAnalyzerArtifacts, readAnalyzerArtifact, registerAnalyzerArtifacts } from "../../src/core/analyzer-artifact-registry.ts";
import { runSniffAnalyzer } from "../../src/core/install.ts";
import { createRunManifest, type RunManifest } from "../../src/core/intake.ts";
import { canonicalReportTargetIdentity, runSniffIntakeTool } from "../../src/core/intake-use-case.ts";
import { buildSniffReport, createReportArtifacts, type ReportInput } from "../../src/core/report.ts";
import { MAX_REPORT_ARTIFACT_REGISTRY_ENTRIES, readReportArtifact, registerReportArtifacts } from "../../src/core/report-artifact-registry.ts";
import { runSniffReportTool } from "../../src/core/report-use-case.ts";
import { createSniffRunOwner, MAX_LIVE_LEASES_PER_OWNER, type SniffRunOwner } from "../../src/core/run-owner.ts";
import {
  abandonAnalyzerReservation,
  assertRunReport,
  authorizeAnalyzerRun,
  beginRunReport,
  cancelRunLease,
  completeAnalyzerReservation,
  endRunReport,
  finalizeRunLease,
  issueRunLease,
  prepareAnalyzerSpawn,
  readRunManifest,
  registerActiveProcess,
  releaseAllRunLeases,
  releaseRunLease,
  runLeaseStateForTests,
  unregisterActiveProcess,
  validateReportCoverage,
  validateReportManifest,
} from "../../src/core/run-registry.ts";
import { validateResolvedTarget } from "../../src/core/target.ts";

const temporary: string[] = [];
const owners: SniffRunOwner[] = [];

afterEach(async () => {
  await Promise.allSettled(owners.splice(0).map((owner) => owner.dispose()));
  for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true });
});

function owner(label: string): SniffRunOwner {
  const created = createSniffRunOwner({ label });
  owners.push(created);
  return created;
}

function targetRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "sniff-owner-target-"));
  temporary.push(root);
  writeFileSync(join(root, "a.ts"), "export const value = 1;\n");
  return root;
}

function lease(runOwner: SniffRunOwner, options: { readonly onRelease?: () => void } = {}) {
  const root = targetRoot();
  const manifest = createRunManifest({ target: validateResolvedTarget({ kind: "files", label: "a.ts", root, files: ["a.ts"], materialization: "in-place" }), intent: "audit", scopeMode: "full" });
  let releases = 0;
  const receipt = issueRunLease(manifest, { target: manifest.resolvedTarget, release: () => { releases += 1; options.onRelease?.(); } }, { owner: runOwner });
  return { manifest, receipt, capability: receipt.capability, manifestId: receipt.manifestId, releases: () => releases };
}

function reportInput(manifest: RunManifest, headline = "No retained findings."): ReportInput {
  return {
    generatedAt: "2026-09-11T00:00:00Z",
    target: { ...canonicalReportTargetIdentity(manifest.resolvedTarget, manifest.scopeMode), languages: ["TypeScript"] },
    headline,
    findings: [],
    coverage: [],
    suppressionCount: 0,
    systemicPatterns: [],
  };
}

function reportArtifacts(headline: string) {
  return createReportArtifacts(buildSniffReport({ generatedAt: "2026-09-11T00:00:00Z", target: { kind: "files", label: "selected files", scopeMode: "full", languages: [], filesAnalyzed: 1 }, headline, findings: [], coverage: [], suppressionCount: 0, systemicPatterns: [] }));
}

function errorOf(action: () => unknown): string {
  try {
    action();
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  return "<no error>";
}

async function rejectionOf(action: () => Promise<unknown>): Promise<string> {
  try {
    await action();
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  return "<no error>";
}

const UNKNOWN_CAPABILITY = "A".repeat(43);

describe("owner-scoped run leases", () => {
  test("every lease lookup rejects another owner's capability exactly like an unknown one", async () => {
    const mine = owner("project-a");
    const theirs = owner("project-b");
    const run = lease(mine);
    const { capability, manifestId } = run;
    const sameAsUnknown = (call: (capability: string) => unknown) => {
      const crossOwner = errorOf(() => call(capability));
      expect(crossOwner).toBe(errorOf(() => call(UNKNOWN_CAPABILITY)));
      expect(crossOwner).toBe("Unknown Sniff run capability");
    };
    sameAsUnknown((cap) => authorizeAnalyzerRun(cap, manifestId, "lizard:complexity", theirs));
    sameAsUnknown((cap) => prepareAnalyzerSpawn(cap, manifestId, "lizard:complexity", "reservation", theirs));
    sameAsUnknown((cap) => abandonAnalyzerReservation(cap, manifestId, "lizard:complexity", "reservation", theirs));
    sameAsUnknown((cap) => completeAnalyzerReservation(cap, manifestId, "lizard:complexity", "reservation", theirs));
    sameAsUnknown((cap) => beginRunReport(cap, manifestId, theirs));
    sameAsUnknown((cap) => assertRunReport(cap, manifestId, "claim", theirs));
    sameAsUnknown((cap) => readRunManifest(cap, manifestId, theirs));
    sameAsUnknown((cap) => validateReportManifest(cap, manifestId, run.manifest, theirs));
    sameAsUnknown((cap) => validateReportCoverage(cap, manifestId, [], theirs));
    sameAsUnknown((cap) => releaseRunLease(cap, manifestId, theirs));
    sameAsUnknown((cap) => cancelRunLease(cap, manifestId, theirs));
    // A wrong manifest ID under the wrong owner reveals nothing about the manifest either.
    expect(errorOf(() => readRunManifest(capability, "manifest-wrong", theirs))).toBe("Unknown Sniff run capability");

    // The no-op paths leave the issuing owner's lease untouched.
    const kill = vi.spyOn(process, "kill").mockImplementation((() => true) as typeof process.kill);
    try {
      sameAsUnknown((cap) => registerActiveProcess(cap, manifestId, { pid: 987_001, exited: Promise.resolve() }, theirs));
      expect(kill).toHaveBeenCalledWith(-987_001, "SIGTERM");
    } finally {
      kill.mockRestore();
    }
    unregisterActiveProcess(capability, manifestId, 987_001, theirs);
    endRunReport(capability, manifestId, "claim", theirs);
    await finalizeRunLease(capability, manifestId, theirs);
    expect(run.releases()).toBe(0);

    const reservation = authorizeAnalyzerRun(capability, manifestId, "lizard:complexity", mine);
    expect(errorOf(() => prepareAnalyzerSpawn(capability, manifestId, "lizard:complexity", reservation.reservationId, theirs))).toBe("Unknown Sniff run capability");
    const claim = beginRunReport(capability, manifestId, mine);
    expect(errorOf(() => assertRunReport(capability, manifestId, claim, theirs))).toBe("Unknown Sniff run capability");
    endRunReport(capability, manifestId, claim, mine);

    // Terminal state is scoped too: the other owner never learns the lease was cancelled.
    await cancelRunLease(capability, manifestId, mine);
    expect(errorOf(() => readRunManifest(capability, manifestId, mine))).toContain("already cancelled");
    expect(errorOf(() => readRunManifest(capability, manifestId, theirs))).toBe("Unknown Sniff run capability");
  });

  test("the analyzer and report use cases reject another owner's run", async () => {
    const mine = owner("project-a");
    const theirs = owner("project-b");
    const run = lease(mine);
    const analyzed = await runSniffAnalyzer({ capability: run.capability, manifestId: run.manifestId, analyzer: "lizard:complexity", owner: theirs });
    expect(analyzed).toMatchObject({ ok: false, outcome: "not-run", report: "sniff analyzer authorization blocked: Unknown Sniff run capability" });
    expect(await rejectionOf(() => runSniffReportTool({ capability: run.capability, manifestId: run.manifestId, report: reportInput(run.manifest), owner: theirs }))).toBe("Unknown Sniff run capability");

    const rendered = await runSniffReportTool({ capability: run.capability, manifestId: run.manifestId, report: reportInput(run.manifest), owner: mine });
    const { readCapability, reportId } = rendered.publicArtifacts;
    expect(run.releases()).toBe(1);
    expect(readReportArtifact({ capability: readCapability, reportId, relativePath: "index.json" }, undefined, mine).offset).toBe(0);
    const crossOwner = errorOf(() => readReportArtifact({ capability: readCapability, reportId, relativePath: "index.json" }, undefined, theirs));
    expect(crossOwner).toBe("Unknown Sniff report artifact capability");
    expect(crossOwner).toBe(errorOf(() => readReportArtifact({ capability: UNKNOWN_CAPABILITY, reportId, relativePath: "index.json" }, undefined, theirs)));
  });

  test("analyzer artifacts are readable only through the issuing owner", () => {
    const mine = owner("project-a");
    const theirs = owner("project-b");
    const artifacts = createAnalyzerArtifacts("lizard:complexity", [{ path: "a.ts", start: { line: 1, column: 1 }, ruleId: "ccn", message: "complex", severity: "warning" }]);
    const capability = registerAnalyzerArtifacts(artifacts, undefined, mine);
    const read = (runOwner: SniffRunOwner, cap = capability) => readAnalyzerArtifact({ capability: cap, analyzerResultId: artifacts.analyzerResultId, relativePath: "index.json" }, undefined, runOwner);
    expect(read(mine).relativePath).toBe("index.json");
    expect(errorOf(() => read(theirs))).toBe("Unknown Sniff analyzer artifact capability");
    expect(errorOf(() => read(theirs))).toBe(errorOf(() => read(theirs, UNKNOWN_CAPABILITY)));
  });
});

describe("per-owner budgets", () => {
  test("one owner filling its report artifact budget never evicts another owner's artifacts", () => {
    const busy = owner("busy");
    const quiet = owner("quiet");
    const kept = reportArtifacts("quiet report");
    const keptCapability = registerReportArtifacts(kept, 1_000, quiet);
    const busyArtifacts = reportArtifacts("busy report");
    const busyCapabilities = Array.from({ length: MAX_REPORT_ARTIFACT_REGISTRY_ENTRIES + 4 }, () => registerReportArtifacts(busyArtifacts, 1_000, busy));
    const read = (capability: string, artifacts: typeof kept, runOwner: SniffRunOwner) => readReportArtifact({ capability, reportId: artifacts.report.reportId, relativePath: "report.json" }, 1_000, runOwner);
    expect(read(keptCapability, kept, quiet).totalBytes).toBeGreaterThan(0);
    // The busy owner's own oldest entries were evicted to make room within its own budget.
    expect(errorOf(() => read(busyCapabilities[0] ?? "", busyArtifacts, busy))).toBe("Unknown Sniff report artifact capability");
    expect(read(busyCapabilities.at(-1) ?? "", busyArtifacts, busy).totalBytes).toBeGreaterThan(0);
  });

  test("one owner filling its analyzer byte budget never evicts another owner's artifacts", () => {
    const busy = owner("busy");
    const quiet = owner("quiet");
    const small = createAnalyzerArtifacts("lizard:complexity", [{ path: "a.ts", start: { line: 1, column: 1 }, ruleId: "ccn", message: "small", severity: "warning" }]);
    const keptCapability = registerAnalyzerArtifacts(small, 1_000, quiet);
    // Each large artifact is over half the per-owner byte budget, so a second one evicts the first.
    const large = createAnalyzerArtifacts("lizard:complexity", Array.from({ length: 1_100 }, (_, index) => ({ path: `src/f-${index}.ts`, start: { line: 1, column: 1 }, ruleId: "ccn", message: "x".repeat(16_000), severity: "warning" })));
    const first = registerAnalyzerArtifacts(large, 1_000, busy);
    const second = registerAnalyzerArtifacts(large, 1_000, busy);
    const read = (capability: string, artifacts: typeof small, runOwner: SniffRunOwner) => readAnalyzerArtifact({ capability, analyzerResultId: artifacts.analyzerResultId, relativePath: "index.json" }, 1_000, runOwner);
    expect(errorOf(() => read(first, large, busy))).toBe("Unknown Sniff analyzer artifact capability");
    expect(read(second, large, busy).relativePath).toBe("index.json");
    expect(read(keptCapability, small, quiet).relativePath).toBe("index.json");
  });

  test("an owner holds at most MAX_LIVE_LEASES_PER_OWNER live leases and other owners are unaffected", async () => {
    const full = owner("full");
    const other = owner("other");
    const runs = Array.from({ length: MAX_LIVE_LEASES_PER_OWNER }, () => lease(full));
    expect(MAX_LIVE_LEASES_PER_OWNER).toBe(8);
    let released = false;
    expect(() => lease(full, { onRelease: () => { released = true; } })).toThrow(`at most ${MAX_LIVE_LEASES_PER_OWNER} live Sniff runs`);
    // A refused issuance still releases the materialized target it was handed.
    expect(released).toBe(true);
    expect(lease(other).capability).toBeString();
    await cancelRunLease(runs[0]?.capability ?? "", runs[0]?.manifestId ?? "", full);
    expect(lease(full).capability).toBeString();
  });

  test("intake refuses an owner at its lease cap before resolving any target", async () => {
    const full = owner("full");
    for (let index = 0; index < MAX_LIVE_LEASES_PER_OWNER; index += 1) lease(full);
    let commands = 0;
    const runner = async () => {
      commands += 1;
      throw new Error("the runner must not be reached");
    };
    const failure = await rejectionOf(() => runSniffIntakeTool({ input: { target: { kind: "whole-repo", root: targetRoot() }, intent: "audit", scopeMode: "full", objectives: ["structure-and-maintainability"], budget: {} } }, { runner, owner: full, confirmInteractive: async (request) => ({ acceptedDigest: request.digest }) }));
    expect(failure).toContain(`at most ${MAX_LIVE_LEASES_PER_OWNER} live Sniff runs`);
    expect(commands).toBe(0);
  });
});

describe("owner disposal", () => {
  test("dispose releases only its own leases and waits for its own analyzer children", async () => {
    const mine = owner("project-a");
    const theirs = owner("project-b");
    const myRun = lease(mine);
    const theirRun = lease(theirs);
    const myHome = authorizeAnalyzerRun(myRun.capability, myRun.manifestId, "lizard:complexity", mine).home;
    const theirHome = authorizeAnalyzerRun(theirRun.capability, theirRun.manifestId, "lizard:complexity", theirs).home;
    const myExit = Promise.withResolvers<number>();
    const theirExit = Promise.withResolvers<number>();
    const kill = vi.spyOn(process, "kill").mockImplementation((() => true) as typeof process.kill);
    try {
      registerActiveProcess(myRun.capability, myRun.manifestId, { pid: 987_101, exited: myExit.promise }, mine);
      registerActiveProcess(theirRun.capability, theirRun.manifestId, { pid: 987_202, exited: theirExit.promise }, theirs);
      let settled = false;
      const disposal = mine.dispose().finally(() => {
        settled = true;
      });
      expect(mine.disposed).toBe(true);
      expect(kill.mock.calls.map(([pid]) => Math.abs(pid))).toEqual([987_101]);
      await Bun.sleep(20);
      // The target and home outlive the child: nothing is released until it exited.
      expect(settled).toBe(false);
      expect(myRun.releases()).toBe(0);
      expect(existsSync(myHome)).toBe(true);
      myExit.resolve(0);
      await disposal;
      expect(myRun.releases()).toBe(1);
      expect(existsSync(myHome)).toBe(false);
      expect(kill.mock.calls.some(([pid]) => Math.abs(pid) === 987_202)).toBe(false);
      expect(theirRun.releases()).toBe(0);
      expect(existsSync(theirHome)).toBe(true);
      expect(readRunManifest(theirRun.capability, theirRun.manifestId, theirs).manifestId).toBe(theirRun.manifestId);
    } finally {
      kill.mockRestore();
      myExit.resolve(0);
      theirExit.resolve(0);
    }
  });

  test("dispose waits for a cancel already in progress whose child ignores SIGTERM", async () => {
    const mine = owner("project-a");
    const run = lease(mine);
    const home = authorizeAnalyzerRun(run.capability, run.manifestId, "lizard:complexity", mine).home;
    const exit = Promise.withResolvers<number>();
    const signals: string[] = [];
    // The child ignores SIGTERM and exits only once the escalation timer sends SIGKILL.
    const kill = vi.spyOn(process, "kill").mockImplementation(((_pid: number, signal?: string | number) => {
      signals.push(String(signal));
      if (signal === "SIGKILL") setTimeout(() => exit.resolve(0), 30);
      return true;
    }) as typeof process.kill);
    try {
      registerActiveProcess(run.capability, run.manifestId, { pid: 987_303, exited: exit.promise }, mine);
      const cancel = cancelRunLease(run.capability, run.manifestId, mine);
      let disposed = false;
      const disposal = mine.dispose().then(() => {
        disposed = true;
      });
      await Bun.sleep(20);
      expect(signals).toEqual(["SIGTERM"]);
      expect(disposed).toBe(false);
      expect(run.releases()).toBe(0);
      expect(existsSync(home)).toBe(true);
      await disposal;
      expect(signals).toEqual(["SIGTERM", "SIGKILL"]);
      expect(run.releases()).toBe(1);
      expect(existsSync(home)).toBe(false);
      await cancel;
    } finally {
      kill.mockRestore();
      exit.resolve(0);
    }
  });

  test("a disposed owner refuses further use, keeps nothing, and disposing again is a no-op", async () => {
    const mine = owner("project-a");
    const run = lease(mine);
    const artifacts = reportArtifacts("disposed report");
    const readCapability = registerReportArtifacts(artifacts, undefined, mine);
    const analyzer = createAnalyzerArtifacts("lizard:complexity", []);
    const analyzerCapability = registerAnalyzerArtifacts(analyzer, undefined, mine);
    const first = mine.dispose();
    const second = mine.dispose();
    await Promise.all([first, second]);
    await mine.dispose();
    expect(run.releases()).toBe(1);
    expect(errorOf(() => readRunManifest(run.capability, run.manifestId, mine))).toBe("Sniff run owner was disposed");
    expect(errorOf(() => lease(mine))).toBe("Sniff run owner was disposed");
    expect(errorOf(() => registerReportArtifacts(artifacts, undefined, mine))).toBe("Sniff run owner was disposed");
    expect(errorOf(() => readReportArtifact({ capability: readCapability, reportId: artifacts.report.reportId, relativePath: "index.json" }, undefined, mine))).toBe("Sniff run owner was disposed");
    // Nothing the disposed owner held survives, and an ownerless call never saw it in the first place.
    expect(errorOf(() => readReportArtifact({ capability: readCapability, reportId: artifacts.report.reportId, relativePath: "index.json" }))).toBe("Unknown Sniff report artifact capability");
    expect(errorOf(() => readAnalyzerArtifact({ capability: analyzerCapability, analyzerResultId: analyzer.analyzerResultId, relativePath: "index.json" }))).toBe("Unknown Sniff analyzer artifact capability");
    expect(errorOf(() => readRunManifest(run.capability, run.manifestId))).toBe("Unknown Sniff run capability");
    expect(runLeaseStateForTests(run.capability)).toEqual({ state: "cancelled", reason: "run owner disposed", ownerId: mine.id });
  });

  test("an ownerless call sees only the process owner's runs and artifacts", async () => {
    const plugin = owner("plugin");
    const owned = lease(plugin);
    expect(errorOf(() => readRunManifest(owned.capability, owned.manifestId))).toBe("Unknown Sniff run capability");
    expect(errorOf(() => cancelRunLease(owned.capability, owned.manifestId))).toBe("Unknown Sniff run capability");
    expect(runLeaseStateForTests(owned.capability)).toEqual({ state: "live", ownerId: plugin.id });
    const report = reportArtifacts("plugin-owned report");
    const reportCapability = registerReportArtifacts(report, undefined, plugin);
    expect(errorOf(() => readReportArtifact({ capability: reportCapability, reportId: report.report.reportId, relativePath: "index.json" }))).toBe("Unknown Sniff report artifact capability");
    const analyzer = createAnalyzerArtifacts("lizard:complexity", []);
    const analyzerCapability = registerAnalyzerArtifacts(analyzer, undefined, plugin);
    expect(errorOf(() => readAnalyzerArtifact({ capability: analyzerCapability, analyzerResultId: analyzer.analyzerResultId, relativePath: "index.json" }))).toBe("Unknown Sniff analyzer artifact capability");

    // An ownerless issuance belongs to the process owner, which ownerless calls see and others do not.
    const root = targetRoot();
    const manifest = createRunManifest({ target: validateResolvedTarget({ kind: "files", label: "a.ts", root, files: ["a.ts"], materialization: "in-place" }), intent: "audit", scopeMode: "full" });
    const processRun = issueRunLease(manifest, { target: manifest.resolvedTarget, release: () => undefined });
    expect(readRunManifest(processRun.capability, processRun.manifestId).manifestId).toBe(processRun.manifestId);
    expect(errorOf(() => readRunManifest(processRun.capability, processRun.manifestId, plugin))).toBe("Unknown Sniff run capability");
    await cancelRunLease(processRun.capability, processRun.manifestId);
    expect(errorOf(() => readRunManifest(processRun.capability, processRun.manifestId))).toContain("already cancelled");
  });

  test("an object that is not an issued owner is refused", () => {
    const forged = { id: "forged", label: "forged", disposed: false, dispose: async () => undefined } as SniffRunOwner;
    expect(errorOf(() => readRunManifest(UNKNOWN_CAPABILITY, "manifest-x", forged))).toBe("Unknown Sniff run owner");
  });

  test("no lease timer survives its owner's disposal", async () => {
    const created: unknown[] = [];
    const cleared = new Set<unknown>();
    const originalSetTimeout = globalThis.setTimeout;
    const originalClearTimeout = globalThis.clearTimeout;
    const setSpy = vi.spyOn(globalThis, "setTimeout").mockImplementation(((...args: Parameters<typeof setTimeout>) => {
      const handle = originalSetTimeout(...args);
      created.push(handle);
      return handle;
    }) as typeof setTimeout);
    const clearSpy = vi.spyOn(globalThis, "clearTimeout").mockImplementation(((handle: Parameters<typeof clearTimeout>[0]) => {
      cleared.add(handle);
      originalClearTimeout(handle);
    }) as typeof clearTimeout);
    try {
      const mine = owner("timers");
      lease(mine);
      lease(mine);
      expect(created.length).toBe(2);
      await mine.dispose();
      expect(created.every((handle) => cleared.has(handle))).toBe(true);
    } finally {
      setSpy.mockRestore();
      clearSpy.mockRestore();
    }
  });

  test("process shutdown disposes every owner even when one release fails", async () => {
    const first = owner("first");
    const second = owner("second");
    const failing = lease(first, { onRelease: () => { throw new Error("release exploded"); } });
    const healthy = lease(second);
    await expect(releaseAllRunLeases("SIGTERM: shutdown")).resolves.toBeUndefined();
    expect(first.disposed).toBe(true);
    expect(second.disposed).toBe(true);
    expect(failing.releases()).toBe(1);
    expect(healthy.releases()).toBe(1);
    expect(runLeaseStateForTests(healthy.capability)).toEqual({ state: "cancelled", reason: "SIGTERM: shutdown", ownerId: second.id });
  });
});
