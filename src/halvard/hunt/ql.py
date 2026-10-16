"""Halvard query language (HQL): one filter grammar shared by hunt, custom detections and device-side evaluation.

    kind=process AND proc~"powershell*" AND cmdline contains "-enc" | count by device | where count > 3 | head 20

Filter operators: =  !=  ~ (glob, * and ?)  contains  startswith  endswith  in (a,b)  >  >=  <  <=  with AND OR NOT ( ).
Stages after '|': count [by f,..] | head N | sort [-]f | table f,.. | dedup f | where count OP N.
Safety: field names are whitelisted, values are always bound parameters, result size is capped. The SQL path (store
queries) and the Python path (device-side rule evaluation) implement the same semantics; tests compare them.
"""
import fnmatch, re
from dataclasses import dataclass

FIELDS = {"ts": "num", "device": "str", "kind": "str", "op": "str", "pid": "num", "ppid": "num", "proc": "str",
          "exe_sha256": "str", "cmdline": "str", "user": "str", "path": "str", "dst_path": "str", "dst_ip": "str",
          "dst_port": "num", "signals": "str", "file_sha256": "str", "parent_proc": "str"}
MAX_ROWS = 50_000
_TOK = re.compile(r'''\s*(?:(?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|(?P<op>>=|<=|!=|=|~|>|<)|(?P<p>[(),|])|(?P<w>[^\s(),|=!~<>"']+))''')
KEYWORDS = {"and", "or", "not", "contains", "startswith", "endswith", "in"}


class QLError(ValueError):
    pass


def tokenize(s):
    out, i = [], 0
    s = s.strip()
    while i < len(s):
        m = _TOK.match(s, i)
        if not m or m.end() == i:
            raise QLError(f"cannot read the query near: {s[i:i+20]!r}")
        i = m.end()
        if m.group("str") is not None:
            q = m.group("str"); out.append(("str", re.sub(r"\\(.)", r"\1", q[1:-1])))
        elif m.group("op"): out.append(("op", m.group("op")))
        elif m.group("p"): out.append(("p", m.group("p")))
        else:
            w = m.group("w"); out.append(("kw", w.lower()) if w.lower() in KEYWORDS else ("w", w))
    return out


@dataclass
class Query:
    ast: tuple | None
    stages: list


class _P:
    def __init__(self, toks): self.t, self.i = toks, 0
    def peek(self): return self.t[self.i] if self.i < len(self.t) else (None, None)
    def next(self): tok = self.peek(); self.i += 1; return tok
    def eat(self, kind, val=None):
        k, v = self.peek()
        if k == kind and (val is None or v == val): self.i += 1; return True
        return False
    def expect(self, kind, val=None):
        if not self.eat(kind, val): raise QLError(f"expected {val or kind} but found {self.peek()[1] or 'end of query'}")

    def or_(self):
        n = self.and_()
        while self.eat("kw", "or"): n = ("or", n, self.and_())
        return n

    def and_(self):
        n = self.not_()
        while self.eat("kw", "and"): n = ("and", n, self.not_())
        return n

    def not_(self):
        if self.eat("kw", "not"): return ("not", self.not_())
        if self.eat("p", "("):
            n = self.or_(); self.expect("p", ")"); return n
        return self.cmp()

    def value(self):
        k, v = self.next()
        if k in ("str", "w", "kw"): return v
        raise QLError("expected a value")

    def cmp(self):
        k, f = self.next()
        if k != "w" or f.lower() not in FIELDS:
            raise QLError(f"unknown field {f!r}. Fields: {', '.join(sorted(FIELDS))}")
        f = f.lower(); k, op = self.next()
        if k == "kw" and op in ("contains", "startswith", "endswith"):
            return ("cmp", f, op, self.value())
        if k == "kw" and op == "in":
            self.expect("p", "("); vals = [self.value()]
            while self.eat("p", ","): vals.append(self.value())
            self.expect("p", ")"); return ("cmp", f, "in", vals)
        if k == "op":
            v = self.value()
            if FIELDS[f] == "num" or op in (">", ">=", "<", "<="):
                if FIELDS[f] != "num": raise QLError(f"{f} is text; use = ~ contains")
                try: v = float(v)
                except ValueError: raise QLError(f"{f} needs a number, got {v!r}")
            return ("cmp", f, op, v)
        raise QLError(f"expected an operator after {f}")


def parse(text) -> Query:
    # quoted strings are single tokens, so every ('p','|') token is a real stage separator
    toks = tokenize(text); segs, cur = [], []
    for t in toks:
        if t == ("p", "|"): segs.append(cur); cur = []
        else: cur.append(t)
    segs.append(cur)
    ast = None
    if segs[0]:
        p = _P(segs[0]); ast = p.or_()
        if p.i != len(segs[0]): raise QLError(f"unexpected {p.peek()[1]!r}")
    stages = []
    for seg in segs[1:]:
        if not seg: raise QLError("empty stage after |")
        name, args = seg[0][1].lower(), [t[1] for t in seg[1:]]
        if name == "count":
            by = []
            if args:
                if args[0].lower() != "by": raise QLError("use: count by field,field")
                by = [a.lower() for a in args[1:] if a != ","]
                for b in by:
                    if b not in FIELDS: raise QLError(f"unknown field {b!r}")
            stages.append(("count", by))
        elif name == "head":
            try: stages.append(("head", int(args[0])))
            except (IndexError, ValueError): raise QLError("use: head N")
        elif name == "sort":
            f = (args[0] if args else "").lstrip("-").lower()
            if f not in FIELDS and f != "count": raise QLError("sort needs a field")
            stages.append(("sort", f, args[0].startswith("-")))
        elif name == "table":
            fs = [a.lower() for a in args if a != ","]
            for f in fs:
                if f not in FIELDS: raise QLError(f"unknown field {f!r}")
            stages.append(("table", fs))
        elif name == "dedup":
            if not args or args[0].lower() not in FIELDS: raise QLError("use: dedup field")
            stages.append(("dedup", args[0].lower()))
        elif name == "where":
            if len(args) != 3 or args[0].lower() != "count" or args[1] not in (">", ">=", "<", "<=", "=", "!="):
                raise QLError("use: where count > N")
            stages.append(("where", args[1], float(args[2])))
        else:
            raise QLError(f"unknown stage {name!r}")
    return Query(ast, stages)


# ---------------- SQL path ----------------
def _glob_to_like(v):
    out = []
    for ch in v:
        if ch in "%_\\": out.append("\\" + ch)
        elif ch == "*": out.append("%")
        elif ch == "?": out.append("_")
        else: out.append(ch)
    return "".join(out)


def _esc(v): return re.sub(r"([%_\\])", r"\\\1", v)


def to_sql(ast):
    """Returns (where_sql, params). Only whitelisted field names are ever interpolated."""
    if ast is None: return "1=1", []
    k = ast[0]
    if k in ("and", "or"):
        a, pa = to_sql(ast[1]); b, pb = to_sql(ast[2]); return f"({a} {k.upper()} {b})", pa + pb
    if k == "not":
        a, pa = to_sql(ast[1]); return f"(NOT {a})", pa
    _, f, op, v = ast
    assert f in FIELDS
    num = FIELDS[f] == "num"; col = f if num else f"COALESCE({f},'')"
    if op == "=": return (f"{f} = ?", [v]) if num else (f"{col} = ? COLLATE NOCASE", [v])
    if op == "!=": return (f"({f} IS NULL OR {f} != ?)", [v]) if num else (f"{col} != ? COLLATE NOCASE", [v])
    if op in (">", ">=", "<", "<="): return f"{f} {op} ?", [v]
    if op == "~": return f"{col} LIKE ? ESCAPE '\\'", [_glob_to_like(v)]
    if op == "contains": return f"{col} LIKE ? ESCAPE '\\'", [f"%{_esc(v)}%"]
    if op == "startswith": return f"{col} LIKE ? ESCAPE '\\'", [f"{_esc(v)}%"]
    if op == "endswith": return f"{col} LIKE ? ESCAPE '\\'", [f"%{_esc(v)}"]
    if op == "in":
        return f"{col} IN ({','.join('?' * len(v))}) COLLATE NOCASE" if not num else f"{f} IN ({','.join('?' * len(v))})", list(v)
    raise QLError(op)


# ---------------- Python path (device-side) ----------------
_ASCII = {i: i + 32 for i in range(65, 91)}


def _lo(s):
    """ASCII-only lowercase: matches SQLite NOCASE/LIKE so the two paths agree on every input."""
    return str(s).translate(_ASCII)


def _g(e, f):
    v = e.get(f)
    if f == "signals" and isinstance(v, (list, tuple)): v = " ".join(v)
    return v


def matches(ast, e) -> bool:
    if ast is None: return True
    k = ast[0]
    if k == "and": return matches(ast[1], e) and matches(ast[2], e)
    if k == "or": return matches(ast[1], e) or matches(ast[2], e)
    if k == "not": return not matches(ast[1], e)
    _, f, op, v = ast
    x = _g(e, f); num = FIELDS[f] == "num"
    if num:
        if x is None: return op == "!="
        return {"=": x == v, "!=": x != v, ">": x > v, ">=": x >= v, "<": x < v, "<=": x <= v}.get(op) if op != "in" else x in [float(i) for i in v]
    x = "" if x is None else _lo(x)
    if op == "in": return x in [_lo(i) for i in v]
    v = _lo(v)
    if op == "=": return x == v
    if op == "!=": return x != v
    if op == "~": return re.fullmatch(fnmatch.translate(v.replace("[", "[[]")), x, re.S) is not None
    if op == "contains": return v in x
    if op == "startswith": return x.startswith(v)
    if op == "endswith": return x.endswith(v)
    raise QLError(op)


# ---------------- stages ----------------
def run_stages(rows, stages):
    truncated = False
    for st in stages:
        n = st[0]
        if n == "count":
            by = st[1]
            if not by: rows = [{"count": len(rows)}]
            else:
                agg = {}
                for r in rows:
                    key = tuple(r.get(b) for b in by); agg[key] = agg.get(key, 0) + 1
                rows = [dict(zip(by, k), count=c) for k, c in agg.items()]
                rows.sort(key=lambda r: -r["count"])
        elif n == "head": rows = rows[: st[1]]
        elif n == "sort": rows = sorted(rows, key=lambda r: (r.get(st[1]) is None, r.get(st[1])), reverse=st[2])
        elif n == "table": rows = [{f: r.get(f) for f in st[1]} for r in rows]
        elif n == "dedup":
            seen, out = set(), []
            for r in rows:
                if r.get(st[1]) not in seen: seen.add(r.get(st[1])); out.append(r)
            rows = out
        elif n == "where":
            op, val = st[1], st[2]
            rows = [r for r in rows if {">": r.get("count", 0) > val, ">=": r.get("count", 0) >= val, "<": r.get("count", 0) < val,
                                         "<=": r.get("count", 0) <= val, "=": r.get("count", 0) == val, "!=": r.get("count", 0) != val}[op]]
    return rows
