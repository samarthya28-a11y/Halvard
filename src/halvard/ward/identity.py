"""Program identity: publisher plus image hash.

A name-only row is the reference stand-in and matches only a process that presents no image hash.
Once a hash is present, the row must carry the same publisher and the same image hash.
A file name that matches and a hash that does not is not that program.
"""


def _hash(entry):
    if isinstance(entry, dict):
        return entry.get("image_hash") or entry.get("sha256") or entry.get("exe_sha256")
    return None


def allows(entries, *, name, publisher, image_hash):
    for entry in entries or []:
        if isinstance(entry, str):
            if entry == name and not image_hash and not publisher:
                return True
            continue
        want = _hash(entry)
        if want and entry.get("publisher") and image_hash == want and publisher == entry.get("publisher"):
            return True
    return False


def blocks(entry, *, name, publisher, image_hash):
    """True when this blocked-app row is this program. Identity rows ignore the file name."""
    want = _hash(entry)
    if want or entry.get("publisher"):
        return bool(want and entry.get("publisher") and image_hash == want and publisher == entry.get("publisher"))
    app = (entry.get("app") or "")
    return bool(app) and app.lower() == (name or "").lower()
