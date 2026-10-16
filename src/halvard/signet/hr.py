"""HR feed: the source of truth for who works here, in which role, under which manager (used by joiner/mover/leaver checks and notices)."""
from dataclasses import dataclass


@dataclass
class HRRecord:
    person: str                # "p:alice"
    name: str
    upn: str | None
    sam: str | None
    status: str                # active | terminated | leave
    dept: str
    manager: str | None        # person id
    start: float
    end: float | None = None
    email: str | None = None


class HR:
    def __init__(self): self.records = {}
    def add(self, r: HRRecord): self.records[r.person] = r; return r
    def manager_of(self, person): r = self.records.get(person); return self.records.get(r.manager) if r and r.manager else None
    def by_upn(self, upn): return next((r for r in self.records.values() if r.upn == upn), None)
    def by_sam(self, sam): return next((r for r in self.records.values() if r.sam == sam), None)
