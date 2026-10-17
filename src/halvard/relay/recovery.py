"""Recovery note (F046): what was restored, what was not, and what the business should check."""

def recovery_note(rep):
    restored, lost, changed = len(rep.restored), rep.not_restorable, rep.skipped_changed_after
    checks = []
    if lost:
        checks.append("Restore the files listed as not restorable from your backup (Halvard can signal your backup product).")
    if changed:
        checks.append("Open the files that changed after the incident and decide which version to keep; Halvard left them untouched.")
    checks.append("Spot-check the folders your team uses most before declaring the work restored.")
    from .journal import _file_statements
    files = list(getattr(rep, "files", None) or _file_statements(rep))
    return {"headline": f"Restored {restored} file(s); removed {len(rep.removed_created)} file(s) the incident created."
                        + ("" if rep.complete else f" {len(lost)} could not be restored and {len(changed)} were left as-is."),
            "restored": restored, "not_restored": [{"path": p, "reason": r} for p, r in lost],
            "left_as_is_changed_after": changed, "files": files, "what_to_check": checks, "complete": rep.complete}
