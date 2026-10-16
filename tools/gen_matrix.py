"""Generate policy/authority_matrix.json and docs/03-authority-matrix.md from matrix_def.py."""
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from halvard.relay.matrix_def import MATRIX, ROLES, CLASSES


def render():
    js = json.dumps({"version": 1, "classes": CLASSES, "roles": ROLES, "actions": MATRIX}, indent=2, sort_keys=True) + "\n"
    md = ["# Authority matrix: Relay, Signet, Courier, Atlas and Glass", "",
          "Generated from `src/halvard/relay/matrix_def.py` by `tools/gen_matrix.py`. Do not edit by hand; "
          "`tests/test_authority.py` fails if this file is stale.", "",
          "**Levels:** `auto` runs alone · `notify` runs and tells a named role · `approve` one role must approve first · "
          "`two_person` two different people must approve.", "",
          "**Rules:** a customer may tighten any cell. A customer may loosen a cell only down to its *floor*. "
          "Destructive actions on production, clinical and privileged assets never go below `approve`. "
          "Keeper: `within_auto` = may run only where the cell is `auto`/`notify` or a customer approver approved; "
          "`propose_only` = prepares, a customer approver runs; `never` = Keeper may not do this at all. "
          "Humans on staff or Keeper always use just-in-time elevation. No action has a shared superuser path.", "",
          "## Roles", ""]
    md += [f"- **{k}**: {v}" for k, v in ROLES.items()]
    for mod in ("Relay", "Signet", "Courier", "Atlas", "Glass", "Lumen", "Hearth", "Harbor"):
        md += ["", f"## {mod}", "",
               "| Action | Features | Standard | Production | Clinical | Privileged | Floor (S/P/C/X) | Reversal | Cannot undo | Request | Approve | Keeper |",
               "|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for a in MATRIX:
            if a["module"] != mod:
                continue
            ap, fl = a["approval"], a["floor"]
            md.append("| `{k}` {l} | {f} | {s} | {p} | {c} | {x} | {fs}/{fp}/{fc}/{fx} | {r} | {cu} | {rq} | {aq} | {kp} |".format(
                k=a["key"], l="— " + a["label"], f=a["features"], s=ap["standard"], p=ap["production"],
                c=ap["clinical"], x=ap["privileged"], fs=fl["standard"], fp=fl["production"], fc=fl["clinical"],
                fx=fl["privileged"], r=a["reversal"], cu="; ".join(a["cannot_undo"]) or "—",
                rq=", ".join(a["request_roles"]), aq=", ".join(a["approve_roles"]), kp=a["keeper"]))
        notes = [f"- `{a['key']}`: {a['note']}" for a in MATRIX if a["module"] == mod and a["note"]]
        if notes:
            md += ["", "Notes:", ""] + notes
    return js, "\n".join(md) + "\n"


if __name__ == "__main__":
    js, md = render()
    (ROOT / "policy").mkdir(exist_ok=True)
    (ROOT / "policy" / "authority_matrix.json").write_text(js, encoding="utf-8")
    (ROOT / "docs" / "03-authority-matrix.md").write_text(md, encoding="utf-8")
    print("wrote policy/authority_matrix.json and docs/03-authority-matrix.md")
