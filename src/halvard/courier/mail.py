"""Reference mail platform: the contract Courier codes against (a Graph-API / Gmail-API style integration).

Courier works AFTER delivery through the platform's API, with no change to mail routing. That is deliberate: it keeps working
if Halvard is unreachable, and it means there is always a window between delivery and verdict. The model records both times so
the window is measured, never assumed. Message bodies live here, in the customer's mail system; Courier reads them in memory to
analyse and stores only verdicts, hashes and header facts.
"""
from ..addr import domain_of
from ..fabric.connector_auth import seal
import hashlib, secrets
from dataclasses import dataclass, field


@dataclass
class Attachment:
    name: str
    data: bytes

    @property
    def sha256(self): return hashlib.sha256(self.data).hexdigest()


@dataclass
class Message:
    id: str
    ts: float
    sender: str
    display_name: str
    subject: str
    body: str
    to: list
    reply_to: str | None = None
    attachments: list = field(default_factory=list)
    links: list = field(default_factory=list)            # (display text, href)
    auth: dict = field(default_factory=lambda: {"spf": "pass", "dkim": "pass", "dmarc": "pass"})
    forwarded_from: str | None = None
    campaign: str | None = None                          # set by the sender simulation only to group fixtures; Courier derives its own key

    @property
    def sender_domain(self): return domain_of(self.sender)


@dataclass
class Mailbox:
    addr: str
    owner_upn: str | None
    folders: dict = field(default_factory=lambda: {"inbox": [], "quarantine": [], "deleted": []})
    rules: list = field(default_factory=list)
    forwarding: str | None = None
    delegates: list = field(default_factory=list)
    state: dict = field(default_factory=dict)            # msg_id -> set(read, attachment_opened, clicked, replied, forwarded)


class ReferenceMail:
    def __init__(self, domain, clock):
        self.domain, self.clock = domain, clock
        self.mailboxes, self.messages, self.log, self.blocked = {}, {}, [], set()
        self.outbound_hook = None      # callable(msg) -> decision dict; set by Vaultline. None = no outbound control

    def add_mailbox(self, addr, owner_upn=None): self.mailboxes[addr] = Mailbox(addr, owner_upn); return self.mailboxes[addr]

    def _ev(self, kind, mailbox, msg_id=None, **extra):
        e = {"ts": self.clock.now(), "source": "mail", "kind": kind, "mailbox": mailbox, "msg_id": msg_id, **extra}; self.log.append(seal(e)); return e

    def events_since(self, cursor): return self.log[cursor:], len(self.log)

    # ---------------- flow ----------------
    def deliver(self, msg: Message):
        self.messages[msg.id] = msg
        for r in msg.to:
            mb = self.mailboxes.get(r)
            if not mb: continue
            if msg.sender_domain in self.blocked:
                mb.folders["quarantine"].append(msg.id); self._ev("blocked", r, msg.id, sender=msg.sender); continue
            self._apply_rules(mb, msg)
            self._ev("delivered", r, msg.id, sender=msg.sender, delivered_at=self.clock.now())
        return msg

    def _apply_rules(self, mb, msg):
        folder = "inbox"
        for rule in [r for r in mb.rules if not r["removed"]]:
            w, t = rule["when"], rule["then"]
            if (not w.get("subject_contains") or any(k.lower() in msg.subject.lower() for k in w["subject_contains"])) and (not w.get("from") or msg.sender == w["from"]):
                if t.get("forward_to"): self._send_copy(mb.addr, msg, t["forward_to"], via_rule=True)
                if t.get("delete"): folder = "deleted"
                if t.get("move_to"): folder = t["move_to"]
                if t.get("mark_read"): mb.state.setdefault(msg.id, set()).add("read")
        mb.folders.setdefault(folder, []).append(msg.id)
        if mb.forwarding: self._send_copy(mb.addr, msg, mb.forwarding, via_rule=False)

    def _send_copy(self, from_mbx, msg, to, via_rule):
        fid = "FWD-" + secrets.token_hex(4)
        cp = Message(fid, self.clock.now(), from_mbx, from_mbx, "FW: " + msg.subject, msg.body, [to], attachments=msg.attachments, links=msg.links, forwarded_from=msg.id)
        self.messages[fid] = cp
        self._ev("auto_forward", from_mbx, msg.id, to=to, via_rule=via_rule, external=domain_of(to) != self.domain)
        if to in self.mailboxes: self.mailboxes[to].folders["inbox"].append(fid)

    def send_outbound(self, from_addr, msg: Message):
        """A user sends mail. If Vaultline is watching, regulated data going outside is held BEFORE it leaves, never after."""
        msg.sender = from_addr; self.messages[msg.id] = msg
        d = self.outbound_hook(msg) if self.outbound_hook else {"action": "allow"}
        if d["action"] in ("block", "justify"):
            self.mailboxes[from_addr].folders.setdefault("held", []).append(msg.id)
            self._ev("outbound_held", from_addr, msg.id, rule=d.get("rule"), action=d["action"], message=d.get("message"), labels=d.get("labels", {})); return {"status": "held", **d}
        return self._release_out(from_addr, msg, d)

    def _release_out(self, from_addr, msg, d):
        for r in msg.to:
            self._ev("sent", from_addr, msg.id, to=r, external=domain_of(r) != self.domain, warned=d.get("action") == "warn")
            if r in self.mailboxes: self.mailboxes[r].folders["inbox"].append(msg.id)
        return {"status": "sent", **d}

    def release_held(self, from_addr, msg_id):
        mb = self.mailboxes[from_addr]
        if msg_id not in mb.folders.get("held", []): return None
        mb.folders["held"].remove(msg_id); return self._release_out(from_addr, self.messages[msg_id], {"action": "allow", "released": True})

    def discard_held(self, from_addr, msg_id):
        mb = self.mailboxes[from_addr]
        if msg_id in mb.folders.get("held", []): mb.folders["held"].remove(msg_id); self._ev("outbound_discarded", from_addr, msg_id); return True
        return False

    # ---------------- user actions ----------------
    def read(self, addr, msg_id, device_id=None): self.mailboxes[addr].state.setdefault(msg_id, set()).add("read"); self._ev("read", addr, msg_id, device_id=device_id)

    def open_attachment(self, addr, msg_id, name, device_id=None):
        self.mailboxes[addr].state.setdefault(msg_id, set()).add("attachment_opened")
        att = next(a for a in self.messages[msg_id].attachments if a.name == name)
        self._ev("attachment_open", addr, msg_id, name=name, sha256=att.sha256, device_id=device_id); return att

    def click(self, addr, msg_id, url, device_id=None):
        self.mailboxes[addr].state.setdefault(msg_id, set()).add("clicked"); self._ev("link_click", addr, msg_id, url=url, device_id=device_id)

    def reply(self, addr, msg_id): self.mailboxes[addr].state.setdefault(msg_id, set()).add("replied"); self._ev("reply", addr, msg_id)

    def forward(self, addr, msg_id, to):
        self.mailboxes[addr].state.setdefault(msg_id, set()).add("forwarded"); self._send_copy(addr, self.messages[msg_id], to, via_rule=False)

    def report(self, addr, msg_id): self._ev("user_report", addr, msg_id)

    def add_rule(self, addr, when, then, actor, ip=None, device_id=None):
        rid = "RULE-" + secrets.token_hex(3); self.mailboxes[addr].rules.append({"id": rid, "when": when, "then": then, "removed": False})
        self._ev("rule_create", addr, None, rule=rid, when=when, then=then, actor=actor, ip=ip, device_id=device_id); return rid

    def set_forwarding(self, addr, to, actor, ip=None):
        self.mailboxes[addr].forwarding = to
        self._ev("forwarding_set", addr, None, to=to, actor=actor, ip=ip, external=domain_of(to) != self.domain)

    def add_delegate(self, addr, delegate, actor): self.mailboxes[addr].delegates.append(delegate); self._ev("delegate_add", addr, None, delegate=delegate, actor=actor)

    # ---------------- admin surface used by Courier actions ----------------
    def copies(self, key):
        """Every (mailbox, message) copy matching an attachment hash, message id, or a forwarded descendant of it."""
        out = []
        for a, mb in self.mailboxes.items():
            for f, ids in mb.folders.items():
                for mid in ids:
                    m = self.messages[mid]
                    if key == mid or key == m.forwarded_from or any(att.sha256 == key for att in m.attachments): out.append((a, mid, f))
        return out

    def quarantine(self, addr, msg_id):
        mb = self.mailboxes[addr]
        for f, ids in mb.folders.items():
            if msg_id in ids and f != "quarantine": ids.remove(msg_id); mb.folders["quarantine"].append(msg_id); self._ev("quarantined", addr, msg_id, from_folder=f); return f
        return None

    def restore(self, addr, msg_id):
        mb = self.mailboxes[addr]
        if msg_id in mb.folders["quarantine"]: mb.folders["quarantine"].remove(msg_id); mb.folders["inbox"].append(msg_id); self._ev("restored", addr, msg_id); return True
        return False

    def purge(self, addr, msg_id):
        mb = self.mailboxes[addr]
        if msg_id in mb.folders["quarantine"]: mb.folders["quarantine"].remove(msg_id); self._ev("purged", addr, msg_id); return True
        return False

    def remove_rule(self, addr, rid):
        for r in self.mailboxes[addr].rules:
            if r["id"] == rid and not r["removed"]: r["removed"] = True; self._ev("rule_removed", addr, None, rule=rid); return True
        return False

    def restore_rule(self, addr, rid):
        for r in self.mailboxes[addr].rules:
            if r["id"] == rid: r["removed"] = False; return True
        return False

    def block_sender(self, domain): self.blocked.add(domain.lower())
    def unblock_sender(self, domain): self.blocked.discard(domain.lower())

    def active_rules(self, addr): return [r for r in self.mailboxes[addr].rules if not r["removed"]]
