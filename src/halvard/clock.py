import time


class Clock:
    def now(self) -> float:
        return time.time()


class ManualClock(Clock):
    """Deterministic clock for tests and workday traces."""

    def __init__(self, start: float = 1_760_000_000.0):
        self.t = start

    def now(self) -> float:
        return self.t

    def advance(self, seconds: float) -> float:
        self.t += seconds
        return self.t
