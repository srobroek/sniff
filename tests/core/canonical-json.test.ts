import { describe, expect, test } from "bun:test";
import { canonicalJson, canonicalValue, compareCodeUnits, stableJson } from "../../src/core/canonical-json.ts";

describe("canonical JSON", () => {
  test("orders keys by UTF-16 code unit, not by locale", () => {
    // localeCompare would put "a" before "B" and "_" before letters; code-unit order does neither.
    expect(stableJson({ a: 1, B: 2, _: 3, "-": 4, "1": 5 })).toBe('{"1":5,"-":4,"B":2,"_":3,"a":1}');
    expect(["b", "B", "a", "_"].sort(compareCodeUnits)).toEqual(["B", "_", "a", "b"]);
  });

  test("sorts nested objects, keeps array order, and drops undefined members like JSON.stringify", () => {
    const value = { z: { y: 1, x: [{ b: 1, a: 2 }, undefined, 3] }, gone: undefined, a: null };
    expect(stableJson(value)).toBe('{"a":null,"z":{"x":[{"a":2,"b":1},null,3],"y":1}}');
    expect(Object.keys(canonicalValue(value) as object)).toEqual(["a", "z"]);
  });

  test("canonicalJson is the two-space, newline-terminated form of the same value", () => {
    const value = { b: [1], a: "x" };
    expect(canonicalJson(value)).toBe(`${JSON.stringify({ a: "x", b: [1] }, null, 2)}\n`);
  });

  test("matches JSON.stringify for primitives", () => {
    for (const value of ["text", 1, true, null]) expect(stableJson(value)).toBe(JSON.stringify(value));
  });
});
