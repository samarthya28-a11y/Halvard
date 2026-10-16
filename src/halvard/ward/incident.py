"""The one-page incident view in plain language (F115, section 7): what is happening, what Halvard already did,
what needs a person, what the business impact is. Numbers come from the incident record; nothing is estimated."""

STATUS_WORDS = {"executed": "done", "pending_approval": "waiting for approval",
                "pending_pattern_acceptance": "prepared, waiting for you to accept this automation",
                "deferred": "delayed by a maintenance window", "blocked": "held back", "denied": "refused"}
DOING = {"stop_process": "Stopped the program", "isolate_host": "Cut this computer off the network (Halvard stays connected)",
         "journal_rollback": "Restored files from Halvard's own journal"}


def render(inc, device, asset_class="standard"):
    L = [f"Incident on {device}: a program was scrambling files", "",
         "WHAT IS HAPPENING",
         f"  {inc['process']} overwrote files with unreadable data. Confidence {inc['confidence']:.0%}.",
         "  Evidence: " + "; ".join(inc["reasons"]) + ".",
         f"  Halvard decided this on the computer itself ({'no connection to Halvard at the time' if not inc['online'] else 'connected'}).",
         "", "WHAT HALVARD ALREADY DID"]
    if inc["mode"] != "enforce":
        L.append("  Nothing. This rule is in audit-only mode. " + inc.get("note", ""))
    else:
        L.append("  Froze the program's file access immediately, so no further files could be changed.")
        for name, status, msg, _ in inc["results"]:
            if status == "executed":
                L.append(f"  {DOING.get(name, name)}. {msg}")
    waiting = [(n, s, m) for n, s, m, _ in inc["results"] if s != "executed"]
    L += ["", "WHAT NEEDS A PERSON"]
    if not waiting:
        L.append("  Nothing urgent. Spot-check the folders your team uses most.")
    for n, s, m in waiting:
        L.append(f"  {DOING.get(n, n)}: {STATUS_WORDS.get(s, s)}. {m}")
    L += ["", "BUSINESS IMPACT",
          f"  This is a {asset_class} system. {inc['files_at_detection']} file(s) had been changed when Halvard stopped it.",
          ]
    rec = inc.get("recovery")
    if rec:
        L.append(f"  Recovery note: {rec['headline']}")
        for item in rec["not_restored"]:
            L.append(f"    Not restored: {item['reason']}")
        for c in rec["what_to_check"]:
            L.append(f"  - {c}")
    else:
        L.append("  No recovery note yet: files have not been restored.")
    return "\n".join(L)
