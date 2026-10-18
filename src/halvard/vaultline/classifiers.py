"""Content classifiers (F083). They count and label; they never return, store or log the matched values.

Every detector validates, not just pattern-matches: card numbers must pass the Luhn check and have a plausible length and prefix,
IBANs must pass mod-97, Indian Aadhaar numbers must pass the Verhoeff check, US SSNs must not use the ranges that are never issued.
That is what keeps a spreadsheet of order numbers from being called regulated data. Confidence is rule-assigned and says why.
"""
import io, re, unicodedata, zipfile, zlib
from dataclasses import dataclass, field

# every way people and exports separate the groups of a card number: space, dash, dot, no-break and thin spaces, new line, tab, comma, slash,
# underscore, colon, middle dot, ideographic space
SEP = r"[ \-.\u00a0\u2009\u202f\r\n\t,/_:\u00b7\u3000\u2000-\u200a]"
CARD = re.compile(rf"(?<![\d-])(?:\d+{SEP}?){{1,60}}(?![\d-])")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{2,4}){3,8}\b")
SSN = re.compile(r"(?<![\d-])(\d{3})-(\d{2})-(\d{4})(?![\d-])")
AADHAAR = re.compile(r"(?<![\d-])([2-9]\d{3})[ -]?(\d{4})[ -]?(\d{4})(?![\d-])")
PAN = re.compile(r"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b")
AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")
GENERIC_SECRET = re.compile(r"(?i)\b(?:api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=_\-]{20,})")
CARD_CONTEXT = re.compile(r"(?i)\b(card|visa|mastercard|amex|expiry|exp\.?|cvv|cvc|pan|payment)\b")
IBAN_LEN = {"GB": 22, "DE": 22, "FR": 27, "ES": 24, "IT": 27, "NL": 18, "IE": 22, "CH": 21, "BE": 16, "PL": 28}

_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def luhn_ok(num: str) -> bool:
    s, alt = 0, False
    for ch in reversed(num):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9: d -= 9
        s += d; alt = not alt
    return s % 10 == 0


def cards_in(run: str) -> int:
    """Count valid card numbers inside a run of digit groups. Windows are taken only at the spaces and dashes that were already there,
    so a long unbroken number such as an order id is never sliced into lucky pieces."""
    groups = [g for g in re.split(SEP + "+", run) if g]; found, i = 0, 0
    while i < len(groups):
        if len(groups[i]) < 4: i += 1; continue      # no card format starts with a group of fewer than four digits: skipping these keeps number-heavy CSVs fast
        for j in range(min(len(groups), i + 5), i, -1):
            if j - i > 1 and any(len(g) > 6 for g in groups[i:j]): continue      # a card written in groups has short groups (4-4-4-4, 4-6-5); two long numbers side by side are not one card
            if card_plausible("".join(groups[i:j])): found += 1; i = j; break
        else: i += 1
    return found


def card_plausible(n: str) -> bool:
    if not (13 <= len(n) <= 19) or len(set(n)) == 1 or not luhn_ok(n): return False
    return (n[0] == "4" and len(n) in (13, 16, 19)) or (n[:2] in {"51", "52", "53", "54", "55"} and len(n) == 16) or (2221 <= int(n[:4]) <= 2720 and len(n) == 16) \
        or (n[:2] in {"34", "37"} and len(n) == 15) or (n[:4] == "6011" or n[:2] == "65") and len(n) in (16, 19) or (n[:2] in {"30", "36", "38", "39"} and len(n) in (14, 16)) or (3528 <= int(n[:4]) <= 3589 and len(n) == 16)


def iban_ok(s: str) -> bool:
    s = s.replace(" ", "")
    if not 15 <= len(s) <= 34 or (s[:2] in IBAN_LEN and len(s) != IBAN_LEN[s[:2]]): return False
    return int("".join(str(int(c, 36)) for c in s[4:] + s[:4])) % 97 == 1


def count_ibans(text: str) -> int:
    """IBANs in any letter case. The pattern can run on into following words ("... 5432 PLEASE"), so the longest prefix of whole groups that passes the checksum is the IBAN."""
    n = 0
    for m in IBAN.finditer(text.upper()):
        parts = m.group(0).split(" ")
        for k in range(len(parts), 0, -1):
            if iban_ok(" ".join(parts[:k])): n += 1; break
    return n


def verhoeff_ok(num: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(num)): c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(num: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(num)): c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


def ssn_ok(a, g, s): return a not in ("000", "666") and not a.startswith("9") and g != "00" and s != "0000"


def entropy_bits(s):
    import math
    from collections import Counter
    return -sum(c / len(s) * math.log2(c / len(s)) for c in Counter(s).values())


@dataclass
class Classification:
    labels: dict = field(default_factory=dict)        # label -> {"count": n, "confidence": c, "why": str}
    sensitivity: str = "internal"
    scanned_bytes: int = 0
    unscannable: str | None = None                     # honest reason when the content could not be read

    def has(self, label, min_conf=0.0): return self.labels.get(label, {}).get("confidence", 0) >= min_conf


LABEL_SENSITIVITY = {"pci_card": "regulated", "iban": "confidential", "us_ssn": "regulated", "in_aadhaar": "regulated", "in_pan": "confidential", "secret_key": "regulated", "secret_generic": "confidential", "custom": "confidential"}


def ascii_digits(text: str) -> str:
    """Digits of any script (fullwidth, Arabic-Indic, Devanagari ...) become 0-9, so the checksum and prefix rules see what a person sees."""
    if text.isascii(): return text
    return "".join(str(unicodedata.decimal(ch)) if ord(ch) > 127 and unicodedata.category(ch) == "Nd" else ch for ch in text)


_PDF_STREAM = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.S)
_PDF_LIT = re.compile(rb"\(((?:\\.|[^\\()])*)\)", re.S)
_PDF_HEX = re.compile(rb"<([0-9A-Fa-f\s]{4,})>")
_PDF_ESC = {ord("n"): b"\n", ord("r"): b"\r", ord("t"): b"\t", ord("b"): b"\b", ord("f"): b"\f", ord("("): b"(", ord(")"): b")", 0x5C: b"\\"}


def _pdf_unescape(b: bytes) -> bytes:
    out, i = bytearray(), 0
    while i < len(b):
        if b[i] == 0x5C and i + 1 < len(b):
            nxt = b[i + 1]
            if nxt in _PDF_ESC: out += _PDF_ESC[nxt]; i += 2; continue
            if 0x30 <= nxt <= 0x37:
                j = i + 1
                while j < len(b) and j < i + 4 and 0x30 <= b[j] <= 0x37: j += 1
                out.append(int(b[i + 1:j], 8) & 0xFF); i = j; continue
            i += 1; continue
        out.append(b[i]); i += 1
    return bytes(out)


def pdf_text(data: bytes):
    """Best-effort text of a PDF: the text strings of every content stream (inflated when compressed). Fonts that map codes to other characters, scans and
    encrypted files are NOT readable this way; for those the caller still reports 'unscannable'. Returns the text, or None when nothing readable was found."""
    chunks = [data]
    for m in _PDF_STREAM.finditer(data):
        body = m.group(1)
        if len(body) > 20 << 20: continue
        try: chunks.append(zlib.decompress(body))
        except zlib.error:
            try: chunks.append(zlib.decompressobj(-15).decompress(body))
            except zlib.error: pass
    parts = []
    for c in chunks:
        for m in _PDF_LIT.finditer(c):
            t = _pdf_unescape(m.group(1))
            if len(t) >= 2 and sum(32 <= b < 127 for b in t) / len(t) > 0.8: parts.append(t.decode("latin-1"))
        for m in _PDF_HEX.finditer(c):
            h = re.sub(rb"\s+", b"", m.group(1))
            if len(h) % 2: continue
            raw = bytes.fromhex(h.decode())
            t = raw.decode("utf-16-be", "ignore") if raw[:2] == b"\xfe\xff" else raw.decode("latin-1")
            if len(t) >= 2 and sum(32 <= ord(ch) < 127 for ch in t) / len(t) > 0.8: parts.append(t)
    text = "\n".join(parts)
    return text if re.search(r"[A-Za-z0-9]{3,}", text) else None


_MEDIA_EXT = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".ico", ".webp", ".mp3", ".mp4", ".wav", ".mov", ".avi", ".emf", ".wmf", ".ttf", ".otf", ".woff")
MAX_DEPTH = 3


def extract_text(name: str, data: bytes, depth: int = 0):
    """(text, reason_if_unreadable). Plain text, CSV/JSON/XML, PDF (best effort) and OOXML (docx/xlsx/pptx, every part, nested documents too) are read; other formats are reported, not guessed."""
    n = name.lower()
    if data[:4] == b"PK\x03\x04":
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
            if any(i.flag_bits & 0x1 for i in z.infolist()): return "", "encrypted archive"
            parts, budget = [], 40 << 20
            for i in z.infolist():
                if i.file_size > 20 << 20 or budget <= 0 or i.filename.endswith("/"): continue
                fn = i.filename.lower()
                if fn.endswith(_MEDIA_EXT): continue                       # pictures, sound and fonts hold no text we could read
                raw = z.read(i); budget -= len(raw)
                if raw[:4] == b"PK\x03\x04" or raw[:4] == b"%PDF":         # a document inside the document: look inside it too, a few levels deep
                    if depth < MAX_DEPTH:
                        t, _ = extract_text(fn, raw, depth + 1); parts.append(t)
                elif fn.endswith((".xml", ".rels")) or "sharedstrings" in fn: parts.append(re.sub(r"<[^>]+>", " ", raw.decode("utf-8", "ignore")))
                else: parts.append(raw.decode("utf-8", "ignore") + "\n" + raw.decode("utf-16-le", "ignore"))      # any other part (.bin, .txt, .csv, embedded objects)
            return "\n".join(parts), None
        except zipfile.BadZipFile: return "", "damaged archive"
    if data[:4] == b"%PDF":
        t = pdf_text(data)
        return (t, None) if t is not None else ("", "PDF text could not be read (scanned image, unusual font encoding or encrypted)")
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": return "", "legacy Office format is not read"
    if b"\x00" in data[:4096] and not n.endswith((".txt", ".csv")): return "", "binary format"
    return data.decode("utf-8", "ignore"), None


class Classifier:
    def __init__(self, custom=None, max_bytes=20 << 20):
        self.custom = custom or []          # [{"label": "project_atlas", "regex": "...", "min_count": 1}] customer-defined, validated by the customer's own pattern
        self.max_bytes = max_bytes

    def classify(self, name: str, data: bytes) -> Classification:
        text, why = extract_text(name, data[: self.max_bytes]); text = ascii_digits(text); out = Classification(scanned_bytes=min(len(data), self.max_bytes))
        if why: out.unscannable = why; out.sensitivity = "confidential"; return out      # a file Halvard could not read is NOT known to be harmless: it is treated as confidential and says so
        L = out.labels
        cards = 0
        for m in CARD.finditer(text): cards += cards_in(m.group(0))
        ctx = bool(CARD_CONTEXT.search(text))
        if cards: L["pci_card"] = {"count": cards, "confidence": round(min(0.99, (0.9 if cards >= 5 else 0.7) + (0.08 if ctx else 0)), 2),
                                    "why": f"{cards} number(s) pass the card checksum and have a real card prefix and length" + ("; card words appear nearby" if ctx else "")}
        ib = count_ibans(text)
        if ib: L["iban"] = {"count": ib, "confidence": 0.9, "why": f"{ib} bank account number(s) pass the IBAN checksum"}
        ss = sum(1 for m in SSN.finditer(text) if ssn_ok(*m.groups()))
        if ss: L["us_ssn"] = {"count": ss, "confidence": round(min(0.95, 0.6 + 0.08 * ss), 2), "why": f"{ss} value(s) in the format of a US social security number, excluding never-issued ranges"}
        aa = sum(1 for m in AADHAAR.finditer(text) if verhoeff_ok("".join(m.groups())))
        if aa: L["in_aadhaar"] = {"count": aa, "confidence": round(min(0.95, 0.6 + 0.1 * aa), 2), "why": f"{aa} 12-digit number(s) pass the Aadhaar checksum"}
        pa = len(PAN.findall(text))
        if pa: L["in_pan"] = {"count": pa, "confidence": 0.8, "why": f"{pa} value(s) in the format of an Indian PAN"}
        keys = len(AWS_KEY.findall(text)) + len(PRIVATE_KEY.findall(text))
        if keys: L["secret_key"] = {"count": keys, "confidence": 0.97, "why": "cloud access key id or private key block"}
        gen = sum(1 for m in GENERIC_SECRET.finditer(text) if entropy_bits(m.group(1)) >= 3.5)
        if gen: L["secret_generic"] = {"count": gen, "confidence": 0.7, "why": f"{gen} assignment(s) of a high-randomness value to a name like key, secret or password"}
        for c in self.custom:
            n = len(re.findall(c["regex"], text))
            if n >= c.get("min_count", 1): L["custom:" + c["label"]] = {"count": n, "confidence": 0.9, "why": f"matches the customer-defined pattern '{c['label']}'"}
        rank = {"public": 0, "internal": 1, "confidential": 2, "regulated": 3}
        out.sensitivity = max([LABEL_SENSITIVITY.get(k, "confidential") for k in L] or ["internal"], key=rank.get)
        return out
