"""Program identity: publisher plus image hash, or a hash alone when no publisher is known.

`blocks` matches a name-only row by program name. `allows` matches a name-only row only when the process presents no image hash and no publisher.
A row that names a publisher still needs that publisher and the same image hash.
A row that names only an image hash matches that hash in `blocks`. A publisher with no hash does not match by name.
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
    if not isinstance(entry, dict):
        return False
    want = _hash(entry)
    pub = entry.get("publisher")
    if want and not pub:
        return bool(image_hash) and image_hash == want
    if want or pub:
        return bool(want and pub and image_hash == want and publisher == pub)
    app = (entry.get("app") or "")
    return bool(app) and app.lower() == (name or "").lower()
