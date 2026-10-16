"""Canary tokens (F110): a unique web address (or name) placed in a document or a repository the customer chooses. Nobody has a reason to use it;
if it is fetched, the document or repository was opened somewhere it should not have been.

Honest limits, shown with every token: a document beacon fires only when the file is opened by software that fetches remote images or links AND has
network access; many viewers and mail gateways block that. A token that does not fire is not proof that nothing was read.
The callback service here is a reference model; the real one is a Halvard-hosted endpoint that records time, source address and agent string only.
"""
import hashlib, io, secrets, zipfile
from dataclasses import dataclass

BASE = "https://canary.halvard.example/t/"
LIMITS = "Fires only if the file is opened by software that loads remote content and has network access. Silence is not proof that nothing was read."


@dataclass
class Token:
    id: str
    kind: str          # doc_url | repo_url
    label: str
    placed_in: str
    created_by: str
    created_at: float

    @property
    def url(self): return f"{BASE}{self.id}"


class CanaryService:
    def __init__(self, clock): self.clock, self.tokens, self.log = clock, {}, []

    def mint(self, kind, label, placed_in, by):
        t = Token("c" + secrets.token_hex(8), kind, label, placed_in, by, self.clock.now()); self.tokens[t.id] = t; return t

    def hit(self, token_id, ip, user_agent):
        """The callback endpoint. Unknown tokens are ignored (internet noise); known ones are recorded with time, address and agent string only."""
        if token_id not in self.tokens: return False
        self.log.append({"ts": self.clock.now(), "source": "canary", "kind": "canary_hit", "token": token_id, "ip": ip, "user_agent": user_agent}); return True

    def events_since(self, cursor): return self.log[cursor:], len(self.log)


def embed_text(token: Token, text: str, fmt="html"):
    """Return the text with the beacon added: an invisible image for HTML, a link line for markdown or plain text."""
    if fmt == "html": return text + f'\n<img src="{token.url}.png" width="1" height="1" alt="">\n'
    return text + f"\n[ref]({token.url})\n"


def canary_docx(token: Token, paragraphs):
    """A minimal Word document whose package carries an external image reference to the token. Built from the standard parts only."""
    ct = '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
    rels = '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'
    body = "".join(f"<w:p><w:r><w:t>{p}</w:t></w:r></w:p>" for p in paragraphs)
    doc = f'<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>{body}<w:p><w:r><w:drawing><a:blip xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" r:link="rId2"/></w:drawing></w:r></w:p></w:body></w:document>'
    drels = f'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="{token.url}.png" TargetMode="External"/></Relationships>'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct); z.writestr("_rels/.rels", rels); z.writestr("word/document.xml", doc); z.writestr("word/_rels/document.xml.rels", drels)
    return buf.getvalue()
