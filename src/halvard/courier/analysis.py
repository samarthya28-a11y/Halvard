"""Attachment and link analysis (F063).

HONEST SCOPE: nothing here executes anything. Attachments get STATIC analysis (type by content, macro and script indicators,
container tricks, known-bad hashes) and links are "detonated" against an OFFLINE MODEL of the web (ReferenceWeb) that returns
the redirect chain and final page. A real deployment needs an isolated dynamic sandbox and an isolated fetcher; the
`Sandbox`/`Fetcher` seams are where they plug in. Until then F063 is only partly met, and verdicts say which evidence they rest on.
"""
import hashlib, io, re, zipfile
from dataclasses import dataclass, field
from urllib.parse import urlparse

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
DOWNLOADER = [b"powershell", b"-enc", b"invoke-webrequest", b"downloadstring", b"downloadfile", b"bitsadmin", b"certutil -urlcache", b"mshta", b"wscript.shell", b"cmd /c", b"frombase64string", b"urldownloadtofile"]
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}
CONTAINER_EXT = {".iso", ".img", ".vhd", ".lnk", ".hta", ".scr", ".js", ".jse", ".vbs", ".wsf", ".ps1", ".exe", ".msi", ".jar"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "rebrand.ly", "cutt.ly"}
BRANDS = {"microsoft": {"microsoft.com", "office.com", "live.com", "microsoftonline.com"}, "google": {"google.com", "gmail.com"}, "docusign": {"docusign.com", "docusign.net"}, "dropbox": {"dropbox.com"}}


@dataclass
class Verdict:
    decision: str                 # allow | suspicious | malicious
    score: float                  # rule-assigned, 0..1, not a probability
    reasons: list = field(default_factory=list)
    evidence: str = "static"      # static | reputation | offline-web-model
    indicators: dict = field(default_factory=dict)

    @staticmethod
    def of(score, reasons, evidence="static", **ind):
        d = "malicious" if score >= 0.85 else "suspicious" if score >= 0.4 else "allow"
        return Verdict(d, round(min(score, 1.0), 2), reasons, evidence, ind)


class Intel:
    """Customer + feed reputation: known-bad hashes, domain ages. Updating it is how a message that was fine at delivery becomes malicious later."""
    def __init__(self): self.bad_hashes, self.domain_age_days, self.bad_domains = {}, {}, set()
    def add_bad_hash(self, h, why="reported by threat intelligence"): self.bad_hashes[h] = why


def sniff(data: bytes):
    if data[:4] == b"PK\x03\x04": return "zip"
    if data[:2] == b"MZ": return "pe"
    if data[:4] == b"\x7fELF": return "elf"
    if data[:4] == b"%PDF": return "pdf"
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": return "ole"
    if data[:5].lower() in (b"<html", b"<!doc"): return "html"
    return "text" if all(9 <= b <= 13 or 32 <= b < 127 for b in data[:200]) else "binary"


class AttachmentAnalyzer:
    def __init__(self, intel: Intel): self.intel = intel

    def analyze(self, name: str, data: bytes) -> Verdict:
        sha = hashlib.sha256(data).hexdigest(); ext = "." + name.lower().rsplit(".", 1)[-1] if "." in name else ""
        score, why, ind = 0.0, [], {"sha256": sha, "type": sniff(data), "name_ext": ext}
        if sha in self.intel.bad_hashes or EICAR in data:
            return Verdict.of(1.0, [self.intel.bad_hashes.get(sha, "matches a known-bad file")], "reputation", **ind)
        t = ind["type"]; blob = data.lower()
        if t == "zip":
            try:
                z = zipfile.ZipFile(io.BytesIO(data)); infos = z.infolist()
                if any(i.flag_bits & 0x1 for i in infos):
                    score = max(score, 0.55); why.append("encrypted archive: contents cannot be inspected, a common way to hide malware")
                else:
                    names = [i.filename.lower() for i in infos]; inner = b""
                    for i in infos:
                        if i.file_size < 5 << 20: inner += z.read(i).lower()
                    macro = any(n.endswith("vbaproject.bin") for n in names)
                    hits = [d.decode() for d in DOWNLOADER if d in inner]
                    ind["macro"] = macro; ind["downloader_strings"] = hits
                    if macro: score = max(score, 0.45); why.append("document contains macros")
                    if macro and len(hits) >= 2: score = max(score, 0.9); why.append("macro code looks like a downloader (" + ", ".join(hits[:3]) + ")")
                    if any(n.rsplit(".", 1)[-1] in {e[1:] for e in CONTAINER_EXT} for n in names if "." in n) and not macro:
                        score = max(score, 0.5); why.append("archive contains a runnable file")
            except zipfile.BadZipFile: score = max(score, 0.3); why.append("damaged archive")
        elif t in ("pe", "elf"): score = max(score, 0.6); why.append("program file sent as an attachment")
        elif t == "html" and b"atob(" in blob and b"blob" in blob and b"download" in blob:
            score = max(score, 0.88); why.append("web page that builds and saves a file on opening (HTML smuggling)")
        else:
            hits = [d.decode() for d in DOWNLOADER if d in blob]
            if len(hits) >= 2 and t in ("text", "html"): score = max(score, 0.85); why.append("script contains download-and-run commands (" + ", ".join(hits[:3]) + ")")
        if ext in MACRO_EXT and not ind.get("macro") and t == "zip": score = max(score, 0.3); why.append("macro-enabled file type")
        if ext in CONTAINER_EXT: score = max(score, 0.5); why.append(f"{ext} files can run code when opened")
        if re.search(r"\.(pdf|docx?|xlsx?|jpg|png)\.(exe|scr|js|vbs|lnk|hta)$", name.lower()): score = max(score, 0.8); why.append("double file extension disguises a program as a document")
        return Verdict.of(score, why or ["nothing suspicious found by static analysis"], "static", **ind)


# ---------------- links ----------------
class ReferenceWeb:
    """Offline model of the internet for link analysis: url -> {"redirect": url} | {"html": str, "status": int}. No real network access."""
    def __init__(self, pages=None): self.pages = pages or {}
    def fetch(self, url, max_hops=5):
        chain = [url]
        for _ in range(max_hops):
            p = self.pages.get(chain[-1])
            if p is None: return {"chain": chain, "final": chain[-1], "html": None, "status": 404}
            if "redirect" in p: chain.append(p["redirect"]); continue
            return {"chain": chain, "final": chain[-1], "html": p.get("html", ""), "status": p.get("status", 200)}
        return {"chain": chain, "final": chain[-1], "html": None, "status": 310}


def _host(url): return (urlparse(url).hostname or "").lower()


def edit_distance(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1): cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


CONFUSABLES = {"0": "o", "3": "e", "5": "s", "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ѕ": "s", "ο": "o", "ı": "i", "α": "a", "ε": "e", "ρ": "p", "ν": "v", "τ": "t", "κ": "k", "ι": "i", "β": "b", "η": "n", "μ": "u", "ω": "w"}


def skeletons(domain):
    """Spellings a reader could mistake for each other. '1' can pass for l or i, so both are tried."""
    out = set()
    for one in ("l", "i"):
        d = domain.lower().replace("1", one)
        for k, v in CONFUSABLES.items(): d = d.replace(k, v)
        out.add(d.replace("rn", "m").replace("vv", "w").replace("-", ""))
    return out


def _wildcard_match(d, p):
    """A domain with letters outside ASCII (an internationalised name) that matches a protected one wherever it is ASCII, with each foreign letter standing for any one character.
    This catches homoglyphs that no table lists. Plain ASCII domains never take this path."""
    try: d = d.encode("ascii").decode("idna") if "xn--" in d else d
    except UnicodeError: pass
    if all(ord(c) < 128 for c in d) or len(d) != len(p): return False
    return all(ord(c) >= 128 or c == q for c, q in zip(d, p)) and sum(ord(c) >= 128 for c in d) >= 1


def lookalike_of(domain, protected):
    """Return the protected domain this one imitates, or None. An exact match or a real subdomain is not a look-alike."""
    d = domain.lower(); dl = d.split(".")[0]
    for p in protected:
        p = p.lower(); pl = p.split(".")[0]
        if d == p or d.endswith("." + p): continue
        if skeletons(d) & skeletons(p): return p
        if _wildcard_match(d, p): return p
        if len(p) >= 6 and edit_distance(d, p) <= 2: return p
        if len(pl) >= 4 and pl in dl.split("-") and dl != pl: return p        # acme-payments.com, secure-acme.net
        if dl == pl and d.rsplit(".", 1)[-1] != p.rsplit(".", 1)[-1]: return p   # acme.co for acme.com
    return None


class LinkAnalyzer:
    def __init__(self, intel: Intel, web: ReferenceWeb, protected_domains=()):
        self.intel, self.web, self.protected = intel, web, set(protected_domains)

    def analyze(self, text: str, href: str) -> Verdict:
        u = urlparse(href); host = _host(href); score, why, ind = 0.0, [], {"host": host}
        if host in self.intel.bad_domains: return Verdict.of(1.0, ["domain is on a block list"], "reputation", **ind)
        shown = re.search(r"([a-z0-9-]+\.)+[a-z]{2,}", (text or "").lower())
        if shown and _host("http://" + shown.group(0)) != host and not host.endswith("." + shown.group(0)): score = max(score, 0.6); why.append(f"the link text shows {shown.group(0)} but goes to {host}")
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host): score = max(score, 0.6); why.append("address is a raw IP number")
        if "xn--" in host: score = max(score, 0.6); why.append("address uses look-alike international characters")
        if u.username: score = max(score, 0.6); why.append("address hides its real destination behind a username")
        look = lookalike_of(host, self.protected)
        if look: score = max(score, 0.75); why.append(f"{host} imitates {look}")
        age = self.intel.domain_age_days.get(host)
        if age is not None and age < 30: score = max(score, 0.5); why.append(f"the domain was registered {age} days ago")
        ev = "static"
        if host in SHORTENERS or score >= 0.4 or True:
            r = self.web.fetch(href); ind["chain"] = r["chain"]; ev = "offline-web-model"
            fh = _host(r["final"]); ind["final_host"] = fh
            if len(r["chain"]) > 2: score = max(score, 0.5); why.append(f"redirects through {len(r['chain']) - 1} hops")
            html = (r["html"] or "").lower()
            if 'type="password"' in html or "type='password'" in html:
                brand = next((b for b in BRANDS if b in html), None)
                at_brand = brand and any(fh == d or fh.endswith("." + d) for d in BRANDS[brand])
                if brand and not at_brand: score = max(score, 0.92); why.append(f"the page asks for a password and looks like {brand}, but is hosted on {fh}")
                elif not brand and not any(fh == d or fh.endswith("." + d) for d in self.protected): score = max(score, 0.55); why.append(f"the page asks for a password on {fh}")
            if r["html"] and re.search(r"\.(exe|msi|scr|js|iso)\b", html) and "download" in html: score = max(score, 0.7); why.append("the page offers a program download")
        return Verdict.of(score, why or ["nothing suspicious found"], ev, **ind)
