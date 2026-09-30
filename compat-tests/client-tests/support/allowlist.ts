/** Every exception must name an exact scenario and leaf, with an upstream explanation. */
export type RawDiffAllowance = {
  readonly scenario: RegExp;
  readonly path: RegExp;
  readonly reason: string;
};

/** No currently accepted raw-wire deviations from the pinned runtime. */
export const RAW_DIFF_ALLOWLIST: readonly RawDiffAllowance[] = [];
