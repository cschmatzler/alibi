/** Bounded numeric profiles configure the real pinned plugins; callbacks remain unchanged. */
export const numericModes = [
  "length-zero",
  "length-fraction",
  "length-negative",
  "length-nan",
  "length-negative-infinity",
  "attempts-zero",
  "attempts-fraction",
  "attempts-negative",
  "attempts-nan",
  "attempts-infinity",
  "attempts-negative-infinity",
  "lifetime-zero",
  "lifetime-fraction",
  "lifetime-negative",
  "lifetime-nan",
  "lifetime-infinity",
  "lifetime-negative-infinity",
] as const;
export function numericOptions(name: string) {
  const mode = name.split("-numeric-")[1];
  if (!mode) return {};
  const [kind, ...parts] = mode.split("-");
  const values: Record<string, number> = {
    zero: 0,
    fraction: kind === "length" || kind === "attempts" ? 1.5 : 30.0005,
    negative: -1,
    nan: NaN,
    infinity: Infinity,
    "negative-infinity": -Infinity,
  };
  const value = values[parts.join("-")];
  if (value === undefined) throw new Error("Unknown numeric fixture mode");
  return kind === "length"
    ? { otpLength: value }
    : kind === "attempts"
      ? { allowedAttempts: value }
      : { expiresIn: value };
}
