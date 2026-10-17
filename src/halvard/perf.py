"""Agent performance test (F127): runs a deterministic workday trace and checks it against policy/perf_budget.json."""
import json, os, random, shutil, statistics, tempfile, time, tracemalloc
from pathlib import Path
from .paths import policy_dir

BUDGET = json.loads((policy_dir() / "perf_budget.json").read_text(encoding="utf-8"))


def _trace(n, rnd):
    """Office-worker mix. Returns list of (op, key)."""
    ops = []
    for i in range(n):
        r = rnd.random()
        if r < 0.25: ops.append(("autosave", rnd.randrange(150)))
        elif r < 0.55: ops.append(("cache_write", rnd.randrange(40)))
        elif r < 0.70: ops.append(("create_tmp", i))
        elif r < 0.80: ops.append(("save_as", i))
        elif r < 0.90: ops.append(("delete_tmp", i))
        elif r < 0.95: ops.append(("backup_copy", i))
        else: ops.append(("photo_export", rnd.randrange(150)))
    return ops


def run_trace(n_events=20000, seed=11):
    from halvard.clock import ManualClock
    from halvard.relay.host import SimHost
    from halvard.ward.agent import WardAgent, ProtectedFS
    from halvard.ward.policy import PolicyBundle
    tmp = Path(tempfile.mkdtemp(prefix="halvard-perf-"))
    try:
        rnd = random.Random(seed)
        ops = _trace(n_events, rnd)
        work = tmp / "work"; work.mkdir()
        doc = lambda k: (b"Meeting notes %d. " % k) * 400
        cache = tmp / "appdata" / "local" / "browser"; cache.mkdir(parents=True)
        for k in range(40): (cache / f"c{k}.db").write_bytes(b"cache %d " % k * 300)
        for k in range(150):
            (work / f"doc{k}.txt").write_bytes(doc(k)); (work / f"img{k}.jpg").write_bytes(b"\xff\xd8\xff" + bytes(range(256)) * 20)

        def play(fs, clock, pid_for):
            lat = []
            tmpset = {}
            for i, (op, key) in enumerate(ops):
                clock.advance(BUDGET["assumptions"]["workday_seconds"] / n_events)
                pid = pid_for(op)
                t0 = time.perf_counter_ns()
                if op == "cache_write": fs.overwrite(pid, cache / f"c{key}.db", doc(key + i % 5))
                elif op == "autosave": fs.overwrite(pid, work / f"doc{key}.txt", doc(key + i % 7))
                elif op == "create_tmp": p = work / f"tmp{key}.dat"; fs.create(pid, p, b"temp %d" % key * 50); tmpset[key] = p
                elif op == "save_as":
                    p = work / f"saveas{key}.tmp"; fs.create(pid, p, doc(key)); fs.rename(pid, p, work / f"saveas{key}.txt")
                elif op == "delete_tmp" and tmpset:
                    k, p = tmpset.popitem(); fs.delete(pid, p)
                elif op == "backup_copy": fs.create(pid, work / f"bak{key}.txt", doc(key))
                elif op == "photo_export": fs.overwrite(pid, work / f"img{key}.jpg", b"\xff\xd8\xff" + bytes(range(256)) * 20 + bytes([i % 256]))
                lat.append((time.perf_counter_ns() - t0) / 1000)
            return lat

        class RawFS:   # same operations without Ward, to isolate agent overhead
            def overwrite(s, pid, p, d): Path(p).write_bytes(d)
            def create(s, pid, p, d): Path(p).write_bytes(d)
            def rename(s, pid, a, b): os.replace(a, b)
            def delete(s, pid, p): os.remove(p)

        # baseline
        shutil.copytree(work, tmp / "work_base"); base_work = work
        work = tmp / "work_base"; base_cache = cache; cache = tmp / "work_base_cache"; shutil.copytree(base_cache, cache)
        c0 = ManualClock(); b0 = time.process_time(); lat_raw = play(RawFS(), c0, lambda op: 1); base_cpu = time.process_time() - b0
        work = base_work; cache = base_cache
        clock = ManualClock()
        host = SimHost("PERF", tmp / "host"); host.spawn(1, "office-app")
        from halvard.ward.agent import WardAgent
        b = PolicyBundle(tenant="perf", version=1).sign(b"k" * 32)
        agent = WardAgent("PERF", tmp / "agent", b, host, clock, b"d" * 32, b"u" * 32)
        agent.install_files({"ward.exe": b"x" * 1024})
        fs = ProtectedFS(agent)
        tracemalloc.start()
        c1 = time.process_time(); lat = play(fs, clock, lambda op: 1); hooked_cpu = time.process_time() - c1
        _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
        overhead_s = max(hooked_cpu - base_cpu, 0.0)
        per_event_us = overhead_s / n_events * 1e6
        a = BUDGET["assumptions"]
        day_cpu = per_event_us / 1e6 * a["write_class_events_per_workday"] * a["slow_machine_factor"]
        cpu_pct = day_cpu / a["workday_seconds"] * 100
        delta = sorted(max(h - r, 0.0) for h, r in zip(lat, lat_raw)); p99 = delta[int(len(delta) * 0.99)] * a["slow_machine_factor"]
        journal_mb = agent.journal.used / 1e6 * (a["write_class_events_per_workday"] / n_events)
        footprint = sum(f.stat().st_size for f in (tmp / "agent" / "install").rglob("*") if f.is_file()) / 1e6
        res = {"events": n_events, "agent_overhead_us_per_event": round(per_event_us, 1),
               "cpu_percent_of_one_core_workday_est": round(cpu_pct, 3),
               "added_latency_p99_us_scaled": round(p99, 0),
               "memory_peak_mb": round(peak / 1e6, 2), "journal_mb_per_workday_est": round(journal_mb, 1),
               "install_footprint_mb": round(footprint, 3), "blocked_processes": len(agent.blocked),
               "incidents": len(agent.incidents)}
        res["checks"] = {
            "cpu": cpu_pct <= BUDGET["cpu_average_percent_of_one_core_max"],
            "latency_p99": p99 <= BUDGET["added_latency_p99_microseconds_max"],
            "memory": res["memory_peak_mb"] <= BUDGET["memory_mb_max"],
            "journal_disk": journal_mb <= BUDGET["journal_disk_mb_per_workday_max"],
            "footprint": footprint <= BUDGET["install_footprint_mb_max"],
            "no_false_positive_stop": len(agent.incidents) == 0,
        }
        res["pass"] = all(res["checks"].values())
        return res
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_median(n_events=4000, repeats=3):
    """Median-of-N by estimated CPU, to damp noise on shared CI machines."""
    runs = sorted((run_trace(n_events, seed=11 + i) for i in range(repeats)),
                  key=lambda r: r["cpu_percent_of_one_core_workday_est"])
    res = dict(runs[len(runs) // 2])
    res["runs_cpu_percent"] = [r["cpu_percent_of_one_core_workday_est"] for r in runs]
    # correctness checks must hold in every run, not just the median
    res["checks"]["no_false_positive_stop"] = all(r["checks"]["no_false_positive_stop"] for r in runs)
    res["pass"] = all(res["checks"].values())
    return res
