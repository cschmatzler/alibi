# Collection callback scheduling (#332)

JavaScript promise reactions and Rust future polling do not guarantee the same
ordering between unrelated callback continuations and aggregate rejection.
An investigation of the pinned adapter factory showed that changing the number
of ready output fields could change which callbacks finished before rejection.
That runtime-specific ordering is not a compatibility contract.

The retained cases in `client-tests/tests/sessions/session.test.ts` exercise the
public SDK, HTTP responses and persisted state:

- Successful lists preserve row order, configured output and ownership while
  excluding expired sessions and private fields.
- Rejected lists leave storage unchanged and let started callbacks finish with
  their captured request context.
- Coordinated callbacks establish explicit causal order: a ready callback
  releases the rejecting sibling, and a separate held callback is released only
  after the client receives HTTP 500 and checks persisted state.

The comparator checks the complete observations and transport traces. The native
collection worker must retain pending siblings after rejection; cancellation or
premature completion fails these cases. No scheduler delay, fixed yield count or
comparison exception is used to make unrelated runtime scheduling agree.

The standalone factory probe and opt-in, deliberately failing microtask-order
scenario have been removed. They were investigation tools, not additional
behavioral coverage.
