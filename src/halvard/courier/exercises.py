"""Short practice exercises built from incidents the customer actually saw (F068).

Safe by construction: the lure carries no live link, attachment or real sender; it imitates the TACTIC (wording, urgency, kind of
sender), never the victim. Results are for learning, not discipline: an individual sees their own result; managers see only
department totals, and only when at least MIN_GROUP people have answered, so no one can be singled out.
"""
from dataclasses import dataclass, field

MIN_GROUP = 5
TACTICS = {
    "lookalike_domain": ("Payment details for next week", "Hi, our bank details have changed. Please use the account below for the next payment. Thanks, Accounts.",
                         ["The sender's address is one letter different from a supplier you know", "It changes bank details, which a real supplier confirms by phone", "It reaches you out of the blue"], "Call the supplier on a number you already have."),
    "display_name_spoof": ("Quick favour", "I'm in a meeting and cannot talk. Can you buy some gift cards today? I will reimburse you. Do not mention it to anyone.",
                           ["The name is a colleague's but the address is not the company's", "It asks for secrecy and speed", "It asks for gift cards"], "Message the colleague on the company chat to check."),
    "credential_phish": ("Your mailbox is almost full", "Your mailbox storage is full. Sign in within 24 hours to avoid losing mail.",
                         ["The link goes somewhere other than the company's sign-in page", "It threatens loss to hurry you", "Your IT team never asks you to sign in from an email"], "Open the sign-in page yourself, not from the email."),
    "malicious_attachment": ("Invoice attached", "Please open the attached invoice and enable editing so you can read it.",
                             ["A document asking you to 'enable editing' or 'enable content'", "An invoice you did not expect", "The sender is new to you"], "Do not enable editing; ask the sender to confirm another way."),
}


@dataclass
class Exercise:
    id: str
    tactic: str
    subject: str
    body: str
    clues: list
    right_action: str
    audience: str
    results: dict = field(default_factory=dict)       # person -> list of answers


def build_from_finding(kind, audience_dept, n=1):
    tactic = {"lookalike_domain": "lookalike_domain", "bank_details_changed": "lookalike_domain", "display_name_spoof": "display_name_spoof", "credential_phish": "credential_phish",
              "malicious_attachment": "malicious_attachment"}.get(kind)
    if not tactic: return None
    s, b, clues, act = TACTICS[tactic]
    return Exercise(f"EX-{tactic}-{n}", tactic, s, b, clues, act, audience_dept)


def answer(ex: Exercise, person, spotted_clues: int, took_right_action: bool):
    ex.results[person] = {"clues": spotted_clues, "right_action": took_right_action}
    return {"you_spotted": f"{spotted_clues} of {len(ex.clues)} clues", "what_to_do": ex.right_action, "clues": ex.clues}


def department_summary(ex: Exercise):
    n = len(ex.results)
    if n < MIN_GROUP: return {"shown": False, "message": f"Results appear once at least {MIN_GROUP} people have finished; so far {n}."}
    ok = sum(1 for r in ex.results.values() if r["right_action"])
    return {"shown": True, "people": n, "took_right_action_pct": round(100 * ok / n), "avg_clues": round(sum(r["clues"] for r in ex.results.values()) / n, 1)}
