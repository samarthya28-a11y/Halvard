"""Tell the right person, on a channel the customer approved, without using the channel an attacker may hold (F058).

Rules: the recipient is the person's manager from HR; the channel must be on the customer's approved list; the message never
travels through a mailbox or chat belonging to an identity that is part of the incident; the text is a fixed plain-language
template with no technical detail an attacker could use. The ledger records template, channel kind and role, not the text.
"""
TEMPLATE = ("{employee}'s account was locked down as a precaution at {when}. We saw sign-in activity on it that did not look like {employee}. "
            "Their devices and access are protected. What you can do: please let {employee} know to expect a call from IT, "
            "and ask them to use a different device or phone to reach IT. Nothing is needed from you beyond that.")


class Channel:
    def __init__(self, kind, owner_identity_of=None):
        self.kind, self.sent, self.owner_identity_of = kind, [], owner_identity_of or (lambda addr: None)

    def deliver(self, address, text): self.sent.append((address, text)); return True


class Notifier:
    def __init__(self, hr, approved_channels, clock):
        self.hr, self.channels, self.clock = hr, list(approved_channels), clock

    def notify_manager(self, person, compromised_identities=()):
        rec = self.hr.records.get(person)
        if not rec: return {"status": "failed", "message": f"no HR record for {person}"}
        mgr = self.hr.manager_of(person)
        if not mgr or not mgr.email: return {"status": "no_recipient", "message": f"{rec.name} has no manager with an address on file. Call the department head."}
        if not self.channels: return {"status": "no_approved_channel", "message": "No approved notification channel is configured. Call the manager instead."}
        compromised = set(compromised_identities)
        for ch in self.channels:
            owner = ch.owner_identity_of(mgr.email)
            if owner in compromised: continue          # never send through a channel owned by an affected identity
            text = TEMPLATE.format(employee=rec.name, when=__import__("time").strftime("%H:%M UTC", __import__("time").gmtime(self.clock.now())))
            ch.deliver(mgr.email, text)
            return {"status": "sent", "channel": ch.kind, "recipient_role": "manager", "address": mgr.email, "template": "manager-lockdown-v1"}
        return {"status": "no_safe_channel", "message": "Every approved channel belongs to an affected account. Call the manager instead."}
