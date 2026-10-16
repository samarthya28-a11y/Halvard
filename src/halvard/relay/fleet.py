"""Control plane -> devices. Delivers signed commands now if the device is reachable, queues them if not (store-and-forward),
and says plainly which it did. An expired queued command is dropped and reported, never run late."""
from . import commands


class Fleet:
    def __init__(self, key: bytes, clock, ledger=None):
        self.key, self.clock, self.ledger = key, clock, ledger
        self.agents, self.queue, self.history, self.pending_policy = {}, {}, [], {}

    def register(self, agent): self.agents[agent.device_id] = agent

    def send(self, device_id, action, params, reason, case, approvals, rule, issuer="controlplane", ttl=6 * 3600):
        cmd = commands.sign(self.key, device=device_id, action=action, params=params, reason=reason, case=case,
                            approvals=[{"id": a.id, "role": a.role} for a in approvals], rule=rule, issuer=issuer, now=self.clock.now(), ttl=ttl)
        agent = self.agents.get(device_id)
        if agent is None:
            res = {"status": "unknown_device", "message": f"{device_id} is not enrolled", "command": cmd["id"]}
        elif not agent.online:
            self.queue.setdefault(device_id, []).append(cmd)
            res = {"status": "queued", "message": f"{device_id} is offline; the command waits (valid until it expires) and runs when the device reconnects", "command": cmd["id"]}
        else:
            r = agent.execute_command(cmd, self.key); res = {**r, "command": cmd["id"]}
        self.history.append((device_id, action, res["status"]))
        if self.ledger:
            self.ledger.append("relay.command_sent", issuer, "system", device_id, {"action": action, "command_id": cmd["id"], "result": res["status"], "rule": rule, "approvers": len(approvals)},
                               controls=("RELAY.COMMAND_CHANNEL",))
        return res

    def push_policy(self, device_id, bundle: dict):
        """Signed policy bundle (e.g. new known-bad hashes). Offline devices get only the newest bundle when they return."""
        agent = self.agents[device_id]
        if not agent.online:
            self.pending_policy[device_id] = bundle; return {"status": "queued"}
        ok = agent.apply_bundle(bundle, self.key); return {"status": "applied" if ok else "rejected"}

    def reconnect(self, device_id):
        """The device is back: deliver what is still valid, report what expired."""
        agent = self.agents[device_id]; agent.set_online(True); out = []
        if device_id in self.pending_policy:
            ok = agent.apply_bundle(self.pending_policy.pop(device_id), self.key); out.append({"action": "policy", "status": "applied" if ok else "rejected", "message": ""})
        for cmd in self.queue.pop(device_id, []):
            r = agent.execute_command(cmd, self.key); out.append({**r, "command": cmd["id"], "action": cmd["action"]})
        return out
