import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, fstatSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRunManifest } from "../../src/core/intake.ts";
import { canonicalReportTargetIdentity } from "../../src/core/intake-use-case.ts";
import { reportRenderContent } from "../../src/core/model-content.ts";
import { readReportArtifact } from "../../src/core/report-artifact-registry.ts";
import { openReportDirectory, type ReportSaveEntry, reportPersistenceSupported, saveReportEntriesAt, setReportFsyncForTests } from "../../src/core/report-native-persistence.ts";
import { runSniffReportTool } from "../../src/core/report-use-case.ts";
import { createSniffRunOwner } from "../../src/core/run-owner.ts";
import { issueRunLease, readRunManifest } from "../../src/core/run-registry.ts";
import { validateResolvedTarget } from "../../src/core/target.ts";

const temporary: string[] = [];
afterEach(() => {
  setReportFsyncForTests(undefined);
  for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true });
});

type SyncRecord = { readonly ino: number; readonly directory: boolean; readonly size: number; readonly published: boolean };

const entries: readonly ReportSaveEntry[] = [
  ["index.json", '{"index":true}\n'],
  ["report.json", '{"report":true}\n'],
  ["files/a.json", '{"a":1}\n'],
  ["files/b.json", '{"b":22}\n'],
];

describe.skipIf(!reportPersistenceSupported())("durable report saves", () => {
  test("fsyncs every file, then the files and staging directories, publishes, then fsyncs the parent", () => {
    const parent = realpathSync(mkdtempSync(join(tmpdir(), "sniff-durable-")));
    temporary.push(parent);
    const reportId = "report-0123456789abcdef";
    const published = join(parent, reportId);
    const synced: SyncRecord[] = [];
    setReportFsyncForTests((fd) => {
      const stat = fstatSync(fd);
      synced.push({ ino: stat.ino, directory: stat.isDirectory(), size: stat.size, published: existsSync(published) });
    });
    const opened = openReportDirectory(parent);
    try {
      expect(saveReportEntriesAt(opened, reportId, entries)).toEqual({ savedPaths: entries.map(([relativePath]) => `${parent}/${reportId}/${relativePath}`) });
    } finally {
      opened.close();
    }
    const inode = (path: string) => statSync(path).ino;
    const fileInodes = entries.map(([relativePath]) => inode(join(published, relativePath)));
    expect(synced.map((record) => record.ino)).toEqual([...fileInodes, inode(join(published, "files")), inode(published), inode(parent)]);
    // Each file was synced with its complete contents, and only the parent sync follows the publish.
    expect(synced.slice(0, entries.length).map((record) => record.size)).toEqual(entries.map(([, content]) => Buffer.byteLength(content)));
    expect(synced.map((record) => record.directory)).toEqual([false, false, false, false, true, true, true]);
    expect(synced.map((record) => record.published)).toEqual([false, false, false, false, false, false, true]);
  });

  test("a failed fsync before publishing removes the staging tree and publishes nothing", () => {
    const parent = realpathSync(mkdtempSync(join(tmpdir(), "sniff-durable-fail-")));
    temporary.push(parent);
    let calls = 0;
    setReportFsyncForTests((fd) => {
      calls += 1;
      if (fstatSync(fd).isDirectory()) throw new Error("simulated EIO");
    });
    const opened = openReportDirectory(parent);
    try {
      expect(() => saveReportEntriesAt(opened, "report-fedcba9876543210", entries)).toThrow("simulated EIO");
    } finally {
      opened.close();
    }
    expect(calls).toBe(entries.length + 1);
    expect(readdirSync(parent)).toEqual([]);
  });

  test("a parent fsync failure after publishing reports a published but not durable save", () => {
    const parent = realpathSync(mkdtempSync(join(tmpdir(), "sniff-durable-parent-")));
    temporary.push(parent);
    const parentInode = statSync(parent).ino;
    setReportFsyncForTests((fd) => {
      if (fstatSync(fd).ino === parentInode) throw new Error("simulated parent EIO");
    });
    const reportId = "report-00112233445566ff";
    const opened = openReportDirectory(parent);
    let result: ReturnType<typeof saveReportEntriesAt>;
    try {
      result = saveReportEntriesAt(opened, reportId, entries);
    } finally {
      opened.close();
    }
    expect(result.savedPaths).toEqual(entries.map(([relativePath]) => `${parent}/${reportId}/${relativePath}`));
    expect(result.durabilityWarning).toContain("simulated parent EIO");
    expect(result.durabilityWarning).toContain(`${parent}/${reportId}`);
    expect(readFileSync(join(parent, reportId, "files", "b.json"), "utf8")).toBe('{"b":22}\n');
  });

  test("the report use case finalizes the run and returns the saved report with the durability warning", async () => {
    const owner = createSniffRunOwner({ label: "durable-save" });
    const root = realpathSync(mkdtempSync(join(tmpdir(), "sniff-durable-target-")));
    const output = realpathSync(mkdtempSync(join(tmpdir(), "sniff-durable-output-")));
    temporary.push(root, output);
    writeFileSync(join(root, "a.ts"), "export const value = 1;\n");
    const manifest = createRunManifest({ target: validateResolvedTarget({ kind: "files", label: "a.ts", root, files: ["a.ts"], materialization: "in-place" }), intent: "audit", scopeMode: "full" });
    const lease = issueRunLease(manifest, { target: manifest.resolvedTarget, release: () => undefined }, { owner });
    const outputInode = statSync(output).ino;
    setReportFsyncForTests((fd) => {
      if (fstatSync(fd).ino === outputInode) throw new Error("simulated parent EIO");
    });
    try {
      const result = await runSniffReportTool({
        capability: lease.capability,
        manifestId: lease.manifestId,
        owner,
        mode: "save",
        path: output,
        report: { generatedAt: "2026-09-11T00:00:00Z", target: { ...canonicalReportTargetIdentity(manifest.resolvedTarget, manifest.scopeMode), languages: [] }, headline: "Durability fixture.", findings: [], coverage: [], suppressionCount: 0, systemicPatterns: [] },
        runtime: { authorizeSave: async (request) => ({ acceptedDigest: request.digest }) },
      });
      const reportId = result.publicArtifacts.reportId;
      expect(result.savedPaths).toContain(`${output}/${reportId}/index.json`);
      expect(existsSync(join(output, reportId, "receipt.json"))).toBe(true);
      expect(result.durabilityWarning).toContain("simulated parent EIO");
      expect(result.publicArtifacts.durabilityWarning).toBe(result.durabilityWarning);
      // Adapters render this metadata line, so the model sees the warning next to the saved paths.
      expect(JSON.parse(reportRenderContent(result.publicArtifacts).split("\n")[0] ?? "{}").durabilityWarning).toBe(result.durabilityWarning);
      // The report exists, so the run is over rather than left open for a retry that would collide.
      expect(() => readRunManifest(lease.capability, lease.manifestId, owner)).toThrow("already released");
      expect(readReportArtifact({ capability: result.publicArtifacts.readCapability, reportId, relativePath: "index.json" }, undefined, owner).offset).toBe(0);
    } finally {
      await owner.dispose();
    }
  });
});
