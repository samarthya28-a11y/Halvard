"""Mail address helpers. One place decides what a domain is, so no caller can disagree about it.

An address with anything other than exactly one '@' has NO domain here (empty string), which never equals the company's own domain.
That is the safe direction: a malformed or tricky address such as `victim@gmail.example@acme.com` is treated as outside, not inside.
"""


def domain_of(addr) -> str:
    a = (addr or "").strip().lower()
    return a.rsplit("@", 1)[-1] if a.count("@") == 1 else ""
