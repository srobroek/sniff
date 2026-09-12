import { describe, expect, test } from "bun:test";
import {
  ANALYZER_ARTIFACT_CHUNK_BYTES,
  ANALYZER_ARTIFACT_TTL_MS,
  clearAnalyzerArtifactRegistryForTests,
  createAnalyzerArtifacts,
  projectAnalyzerObservations,
  publicAnalyzerDescriptors,
  readAnalyzerArtifact,
  registerAnalyzerArtifacts,
} from "./analyzer-artifact-registry.ts";
import { parseOpenGrepOutput } from "./opengrep.ts";

type Observation = { ruleId: string; path: string; start: { line: number; column: number }; message: string; severity: string };
const observation = (index: number, path = "src/example.ts"): Observation => ({ ruleId: "rule/test", path, start: { line: index + 1, column: 1 }, message: `finding ${index}`, severity: "WARNING" });

describe("analyzer artifact registry", () => {
  test("persists complete large output while projecting a bounded preview", () => {
    const observations = Array.from({ length: 11_128 }, (_, index) => observation(index, index % 2 ? "src/b.ts" : "src/a.ts"));
    const artifacts = createAnalyzerArtifacts("opengrep:test", observations);
    const capability = registerAnalyzerArtifacts(artifacts);
    const preview = projectAnalyzerObservations(artifacts.observations);
    expect(preview.preview).toEqual({ total: 11_128, returned: expect.any(Number), truncated: true });
    expect(Buffer.byteLength(JSON.stringify(preview.observations))).toBeLessThanOrEqual(96 * 1024);
    expect(publicAnalyzerDescriptors(artifacts).descriptorCount).toBe(3);
    expect(readAnalyzerArtifact({ capability, analyzerResultId: artifacts.analyzerResultId, relativePath: "index.json" }).content).toContain('"totalObservations": 11128');
  });

  test("supports source lookup and UTF-8-safe paging", () => {
    const observations = Array.from({ length: 1_000 }, (_, index) => ({ ...observation(index), message: `é finding ${index}` }));
    const artifacts = createAnalyzerArtifacts("lizard:complexity", observations);
    const capability = registerAnalyzerArtifacts(artifacts);
    const first = readAnalyzerArtifact({ capability, analyzerResultId: artifacts.analyzerResultId, sourcePath: "src/example.ts" });
    expect(first.bytes).toBeLessThanOrEqual(ANALYZER_ARTIFACT_CHUNK_BYTES);
    expect(Buffer.from(first.content).toString("utf8")).toBe(first.content);
    const second = readAnalyzerArtifact({ capability, analyzerResultId: artifacts.analyzerResultId, sourcePath: "src/example.ts", offset: first.nextOffset });
    expect(second.offset).toBe(first.nextOffset);
  });

  test("rejects wrong capabilities and stale entries", () => {
    const artifacts = createAnalyzerArtifacts("test", [observation(0)]);
    const capability = registerAnalyzerArtifacts(artifacts, 1_000);
    expect(() => readAnalyzerArtifact({ capability: "wrong", analyzerResultId: artifacts.analyzerResultId, relativePath: "index.json" }, 1_001)).toThrow("Unknown Sniff analyzer artifact capability");
    expect(() => readAnalyzerArtifact({ capability, analyzerResultId: artifacts.analyzerResultId, relativePath: "index.json" }, 1_000 + ANALYZER_ARTIFACT_TTL_MS + 1)).toThrow("Unknown Sniff analyzer artifact capability");
  });

  test("keeps malformed, truncated, and hard-overflow captures incomplete", () => {
    const root = process.cwd();
    const finding = { check_id: "r", path: "src/example.ts", start: { line: 1, col: 1 }, extra: { message: "x", severity: "WARNING" } };
    const valid = JSON.stringify({ results: [finding] });
    expect(parseOpenGrepOutput(valid, root).capture.incomplete).toBe(false);
    expect(parseOpenGrepOutput(valid.slice(0, -1), root).capture.incomplete).toBe(true);
    expect(parseOpenGrepOutput(valid, root, true).capture.incomplete).toBe(true);
    const overflow = JSON.stringify({ results: Array.from({ length: 50_001 }, (_, index) => ({ check_id: "r", path: "missing.ts", start: { line: index + 1, col: 1 }, extra: { message: "x", severity: "WARNING" } })) });
    expect(parseOpenGrepOutput(overflow, root).capture.incomplete).toBe(true);
  });

  test("clears registry state between tests", () => {
    clearAnalyzerArtifactRegistryForTests();
    expect(() => readAnalyzerArtifact({ capability: "cleared", analyzerResultId: "x", relativePath: "index.json" })).toThrow();
  });
});
