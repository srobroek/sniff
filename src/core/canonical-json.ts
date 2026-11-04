/**
 * The one canonical JSON encoding behind every Sniff identity and digest: object keys in UTF-16
 * code-unit order at every depth, `undefined` members dropped as `JSON.stringify` drops them, and
 * array order preserved. Code-unit order is locale-independent, so a digest never depends on the
 * host's ICU data.
 */

export function compareCodeUnits(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

/** A structurally equal value whose object keys are in canonical order. */
export function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, entry]) => entry !== undefined)
        .sort(([left], [right]) => compareCodeUnits(left, right))
        .map(([key, entry]) => [key, canonicalValue(entry)]),
    );
  }
  return value;
}

/** Compact canonical JSON, the input of every identity hash. */
export function stableJson(value: unknown): string {
  return JSON.stringify(canonicalValue(value));
}

/** Two-space, newline-terminated canonical JSON, the on-disk and artifact form. */
export function canonicalJson(value: unknown): string {
  return `${JSON.stringify(canonicalValue(value), null, 2)}\n`;
}
