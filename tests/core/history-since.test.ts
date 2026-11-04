import { describe, expect, test } from "bun:test";
import { historySinceInstant } from "../../src/core/target.ts";

describe("since-date windows are host-independent", () => {
  test("a bare date is midnight UTC", () => {
    expect(historySinceInstant("2020-01-06")).toBe("2020-01-06T00:00:00.000Z");
  });

  test("a timestamp keeps its offset and one without an offset is UTC", () => {
    expect(historySinceInstant("2020-01-06T12:30:00+04:00")).toBe("2020-01-06T08:30:00.000Z");
    expect(historySinceInstant("2020-01-06T12:30:00Z")).toBe("2020-01-06T12:30:00.000Z");
    expect(historySinceInstant("2020-01-06T12:30")).toBe("2020-01-06T12:30:00.000Z");
  });

  test("rejects unsafe or unparseable values", () => {
    expect(() => historySinceInstant("--upload-pack=x")).toThrow("not a safe Git operand");
    expect(() => historySinceInstant("not-a-date")).toThrow("ISO 8601");
  });
});
