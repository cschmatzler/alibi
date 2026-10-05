import { ARTIFACT_ROOT } from "./artifacts";
import type { TraceEntry } from "./trace";

/**
 * Identical output from both runtimes proves nothing when the reference itself
 * did not exercise the behavior: a mistyped path is an empty 404 on both
 * servers, and a fixture control that turns any thrown error into one generic
 * 500 hides which error was thrown. These checks run on the reference traces
 * after a passing comparison.
 */
export type OracleExpectations = {
  /** Why the scenario deliberately requests auth paths the reference does not route. */
  readonly unroutedRequests?: string;
  /**
   * Why the scenario accepts a fixture control that reports a thrown error as
   * the generic `{"message":"Internal server error"}`. Both runtimes then agree
   * on the status only, not on which error occurred.
   */
  readonly collapsedFixtureErrors?: string;
};

/** Passing scenarios record here whether each declared expectation was needed. */
export const ORACLE_RECEIPTS = new URL("oracle/", ARTIFACT_ROOT);

const authRoute = /^(?:\/__test\/profiles\/[a-z0-9-]+)?\/api\/auth(?:\/|$)/;

function pathname(trace: TraceEntry) {
  return new URL(trace.path, "http://compat.local").pathname;
}

function isCollapsedFixtureError(trace: TraceEntry) {
  const body = trace.responseErrorBody;
  return (
    trace.responseStatus === 500 &&
    !!body &&
    typeof body === "object" &&
    Object.keys(body).length === 1 &&
    (body as { message?: unknown }).message === "Internal server error"
  );
}

/** Reasons the reference traces cannot support a parity claim; empty when they can. */
export function oracleFindings(
  traces: readonly TraceEntry[],
  expectations: OracleExpectations = {},
): string[] {
  if (!traces.length) {
    return ["the scenario made no request to the reference server"];
  }

  const findings: string[] = [];

  for (const trace of traces) {
    const route = `${trace.method} ${trace.path}`;

    // better-call answers unrouted requests with an empty 404; endpoint
    // rejections such as USER_NOT_FOUND always carry a body.
    if (
      !expectations.unroutedRequests &&
      trace.responseStatus === 404 &&
      trace.responseErrorBody === null &&
      authRoute.test(pathname(trace))
    ) {
      findings.push(`${route}: the reference server has no such route (empty 404)`);
    }

    if (!expectations.collapsedFixtureErrors && isCollapsedFixtureError(trace)) {
      findings.push(`${route}: the fixture reported a thrown error as a generic 500`);
    }
  }

  return findings;
}
