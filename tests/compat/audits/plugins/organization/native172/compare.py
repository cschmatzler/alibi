"""Compare the bounded saved raw traces; no server or Source mutation."""
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
source = json.loads((root / "source-workflow.json").read_text())["trace"][3:-1]

def normalized(trace):
    ids = {}
    def visit(value, key=""):
        if isinstance(value, dict):
            return {k: visit(v, k) for k, v in sorted(value.items())
                    if k not in {"createdAt", "updatedAt", "expiresAt"}
                    and not (v is None and k in {"logo", "teamId", "image", "name"})}
        if isinstance(value, list):
            return [visit(v) for v in value]
        if isinstance(value, str) and (key == "id" or key.endswith("Id")):
            if value not in ids:
                ids[value] = "ID" + str(len(ids))
            return ids[value]
        return value
    return [{"path": r["path"], "status": r["status"],
             "body": visit(json.loads(r["body"]))} for r in trace]

expected = normalized(source)
results = {}
for backend in ["without-database", "Sqlx", "SeaOrm"]:
    actual = normalized(json.loads((root / (backend + "-workflow.json")).read_text()))
    differences = [{"index": i, "source": s, "rust": r}
                   for i, (s, r) in enumerate(zip(expected, actual)) if s != r]
    results[backend] = {"sourceCount": len(expected), "rustCount": len(actual),
                        "differences": differences}
print(json.dumps(results, indent=2))
if any(r["differences"] or r["sourceCount"] != r["rustCount"] for r in results.values()):
    sys.exit(1)
