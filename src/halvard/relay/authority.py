"""Authority matrix engine: decides what approval an action needs for an asset class, and validates policy."""
import json
from dataclasses import dataclass, field
from pathlib import Path

from .matrix_def import MATRIX, BY_KEY, CLASSES, ROLES

ORDER = {"auto": 0, "notify": 1, "approve": 2, "two_person": 3}


class PolicyError(ValueError):
    pass


@dataclass
class Requirement:
    level: str
    approve_roles: list
    approvals_needed: int
    notify: bool = False

    @property
    def needs_human(self):
        return self.level in ("approve", "two_person")


@dataclass
class CustomerPolicy:
    """Customer overrides: {action: {asset_class: level}}, plus accepted automation patterns."""
    overrides: dict = field(default_factory=dict)
    accepted_patterns: set = field(default_factory=set)       # F-"automation shows its work first"
    maintenance_windows: dict = field(default_factory=dict)   # entity_id -> (start_ts, end_ts)


class Authority:
    def __init__(self, policy: CustomerPolicy | None = None):
        self.policy = policy or CustomerPolicy()
        self.validate(self.policy)

    @staticmethod
    def validate(policy: CustomerPolicy):
        for action, cells in policy.overrides.items():
            a = BY_KEY.get(action)
            if not a:
                raise PolicyError(f"unknown action {action}")
            for cls, lvl in cells.items():
                if cls not in CLASSES or lvl not in ORDER:
                    raise PolicyError(f"{action}/{cls}: bad value {lvl}")
                if ORDER[lvl] < ORDER[a["floor"][cls]]:
                    raise PolicyError(f"{action} on {cls} assets cannot be set below '{a['floor'][cls]}' (asked '{lvl}')")

    def requirement(self, action, asset_class) -> Requirement:
        a = BY_KEY[action]
        lvl = self.policy.overrides.get(action, {}).get(asset_class, a["approval"][asset_class])
        # defence in depth: never below floor even if validate() was bypassed
        if ORDER[lvl] < ORDER[a["floor"][asset_class]]:
            lvl = a["floor"][asset_class]
        return Requirement(lvl, a["approve_roles"], 2 if lvl == "two_person" else (1 if lvl == "approve" else 0),
                           notify=(lvl == "notify"))

    @staticmethod
    def strictest(reqs):
        return max(reqs, key=lambda r: ORDER[r.level])
