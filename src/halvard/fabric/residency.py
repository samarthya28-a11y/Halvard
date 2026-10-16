"""Regional residency (F117): where a tenant's data lives, and which operations are refused because they would move it or expose it elsewhere.

A tenant has a home region and a set of regions its data may be stored or accessed in. Operations that cross regions are checked here:
  store/replicate   data copied to another region (backups, replicas)
  export            the customer's data export going to a destination in another region
  staff_access      Halvard staff or Keeper crew in another region looking at the tenant (follow-the-sun support is OFF unless the customer allows it)
  provider_access   a service provider in another region
The answer is plain, the refusal is recorded in the tenant's Ledger, and nothing moves.
"""
REGIONS = {"eu-west": "EU", "eu-central": "EU", "us-east": "US", "us-west": "US", "in-south": "IN", "ap-southeast": "APAC"}


class ResidencyRefused(PermissionError):
    pass


class ResidencyPolicy:
    def __init__(self, home, allowed=None, allow_staff_from=None):
        if home not in REGIONS: raise ValueError(f"unknown region {home}")
        self.home = home; self.allowed = set(allowed or [home]) | {home}; self.allow_staff_from = set(allow_staff_from or [])

    def check(self, operation, other_region):
        if other_region not in REGIONS: return False, f"{other_region} is not a known region, so {operation} is refused."
        if operation in ("store", "replicate", "export"):
            ok = other_region in self.allowed
            return ok, "" if ok else f"This company's data stays in {', '.join(sorted(self.allowed))}. {operation.capitalize()} to {other_region} is refused; nothing was copied."
        if operation in ("staff_access", "provider_access"):
            ok = other_region == self.home or other_region in self.allow_staff_from
            return ok, "" if ok else f"People in {other_region} may not access this company's data (home region {self.home}). The company can allow it explicitly; nothing was opened."
        return False, f"unknown operation {operation}"
