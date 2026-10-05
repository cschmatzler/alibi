// The two adapter runs execute concurrently, but each must prove the complete
// capability inventory from its own passing scenarios and oracle receipts.
const namespace = process.env.COMPAT_ARTIFACT_NAMESPACE ?? "";
if (!["", "sqlx", "seaorm"].includes(namespace)) {
  throw new Error("COMPAT_ARTIFACT_NAMESPACE must be sqlx or seaorm");
}
export const ARTIFACT_ROOT = new URL(
  `../artifacts/${namespace ? `${namespace}/` : ""}`,
  import.meta.url,
);
