import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, fstatSync, mkdtempSync, readdirSync, realpathSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openReportDirectory, type ReportSaveEntry, reportPersistenceSupported, saveReportEntriesAt, setReportFsyncForTests } from "../../src/core/report-native-persistence.ts";

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
      saveReportEntriesAt(opened, reportId, entries);
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
});
