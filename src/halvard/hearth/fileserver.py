"""Reference file server (the contract Hearth's decoy shares code against): shares, files and an access log with who, from where, and what they did."""


class ReferenceFileServer:
    def __init__(self, clock):
        self.clock, self.shares, self.log = clock, {}, []

    def add_share(self, name, files=None, readers=("*",)): self.shares[name] = {"files": dict(files or {}), "readers": set(readers)}

    def _ev(self, kind, account, src_ip, workstation, share, path, ok):
        e = {"ts": self.clock.now(), "source": "fileserver", "kind": kind, "account": account, "src_ip": src_ip, "workstation": workstation, "share": share, "path": path, "ok": ok}; self.log.append(e); return e

    def _allowed(self, account, share): r = self.shares[share]["readers"]; return "*" in r or account in r

    def list(self, account, src_ip, workstation, share, path="/"):
        ok = share in self.shares and self._allowed(account, share); self._ev("smb_list", account, src_ip, workstation, share, path, ok)
        if not ok: raise PermissionError("access denied")
        return sorted(self.shares[share]["files"])

    def read(self, account, src_ip, workstation, share, path):
        ok = share in self.shares and self._allowed(account, share) and path in self.shares[share]["files"]; self._ev("smb_open", account, src_ip, workstation, share, path, ok)
        if not ok: raise PermissionError("access denied")
        return self.shares[share]["files"][path]

    def events_since(self, cursor): return self.log[cursor:], len(self.log)
