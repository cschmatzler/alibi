/** Serialize SDK Date objects without discarding observable fields or values. */
export function normalizeClientValue(value: unknown): unknown {
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return value.map(normalizeClientValue);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [key, normalizeClientValue(child)]),
    );
  }
  return value;
}

/** Retain every field and array element while describing primitive types. */
export function jsonShape(value: unknown): unknown {
  if (value === null) return "null";
  if (value instanceof Date) return "string";
  if (Array.isArray(value)) return value.map(jsonShape);
  if (typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, jsonShape(child)]));
  }
  return typeof value;
}
