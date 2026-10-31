#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A/B benchmark of cold-cache recursive DNS latency for two Lumen binaries.

Each trial starts a fresh daemon (empty caches) per variant, waits a settle
period, times one cold pass over a shuffled name list, a warm repeat, a
coalescing burst and an optional DNSSEC check. Trials are interleaved ABBA so
network drift hits both variants equally. Statistics are pure standard library.
"""

from __future__ import annotations

import argparse
import atexit
import bisect
import datetime
import hashlib
import json
import math
import os
import platform
import random
import secrets
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

DEFAULT_NAMES = """example.com wikipedia.org github.com mozilla.org debian.org kernel.org
python.org rust-lang.org openbsd.org archlinux.org nixos.org ietf.org icann.org iana.org
eff.org torproject.org gnu.org apache.org bund.de bbc.co.uk gov.uk europa.eu admin.ch
nic.cz nic.fr sidn.nl switch.ch afnic.fr denic.de ripe.net arin.net internic.net
wikimedia.org openstreetmap.org libreoffice.org videolan.org""".split()

BURST_NAMES = ["www.w3.org", "www.postgresql.org", "www.kde.org"]
BURST_SIZE = 32

DEFAULT_CANDIDATE_EXTRA = "[resolver.warm]\nenabled = true\n[resolver.prefetch]\nenabled = true\n"

CONFIG_TEMPLATE = """schema_version = 1
metrics = "127.0.0.1:{metrics_port}"

[web]
http = []
https = []

[listen]
udp = ["127.0.0.1:{dns_port}"]
tcp = ["127.0.0.1:{dns_port}"]
allow_clients = ["127.0.0.0/8"]

[resolver]
mode = "recursive"
dnssec = true

[limits]
queries_per_second = 1000
"""

CATEGORIES = ["cold_first", "cold_all", "warm_all", "burst"]
ALPHA = 0.05

# ---------------------------------------------------------------- statistics


def percentile(sorted_vals, p):
    """Linear-interpolated percentile (p in 0..100), numpy 'linear' method."""
    n = len(sorted_vals)
    if n == 0:
        return float("nan")
    if n == 1:
        return sorted_vals[0]
    pos = (n - 1) * p / 100.0
    lo = int(math.floor(pos))
    hi = min(lo + 1, n - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (pos - lo)


def mean(vals):
    return sum(vals) / len(vals) if vals else float("nan")


def median(vals):
    return percentile(sorted(vals), 50)


def summarize(vals, failures=0):
    s = sorted(vals)
    return {
        "n": len(s), "mean": mean(s), "median": percentile(s, 50),
        "p50": percentile(s, 50), "p90": percentile(s, 90),
        "p95": percentile(s, 95), "p99": percentile(s, 99),
        "min": s[0] if s else float("nan"), "max": s[-1] if s else float("nan"),
        "failures": failures,
    }


def midranks(values):
    """Return (ranks, tie_group_sizes) with average ranks for ties."""
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    ties = []
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        r = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = r
        ties.append(j - i + 1)
        i = j + 1
    return ranks, ties


def norm_two_sided(z):
    return math.erfc(abs(z) / math.sqrt(2.0))


def mann_whitney(x, y):
    """Two-sided Mann-Whitney U (U of x), tie-corrected normal approx with
    continuity correction. Returns (U_x, p)."""
    n1, n2 = len(x), len(y)
    if n1 == 0 or n2 == 0:
        return float("nan"), float("nan")
    ranks, ties = midranks(list(x) + list(y))
    u1 = sum(ranks[:n1]) - n1 * (n1 + 1) / 2.0
    n = n1 + n2
    mu = n1 * n2 / 2.0
    tie_term = sum(t ** 3 - t for t in ties)
    var = n1 * n2 / 12.0 * ((n + 1) - tie_term / (n * (n - 1))) if n > 1 else 0.0
    if var <= 0:
        return u1, 1.0
    d = abs(u1 - mu) - 0.5
    z = max(d, 0.0) / math.sqrt(var)
    return u1, min(1.0, norm_two_sided(z))


def wilcoxon_signed_rank(a, b):
    """Two-sided Wilcoxon signed-rank on paired a-b. Exact enumeration when
    <=20 non-zero pairs, else normal approx with tie and continuity correction.
    Returns (W_plus, n_nonzero, p, method)."""
    diffs = [ai - bi for ai, bi in zip(a, b) if ai != bi]
    n = len(diffs)
    if n == 0:
        return 0.0, 0, 1.0, "none"
    ranks, ties = midranks([abs(d) for d in diffs])
    wplus = sum(r for r, d in zip(ranks, diffs) if d > 0)
    if n <= 20:
        rint = [int(round(2 * r)) for r in ranks]
        total = sum(rint)
        counts = {0: 1}
        for r in rint:
            nxt = dict(counts)
            for s, c in counts.items():
                nxt[s + r] = nxt.get(s + r, 0) + c
            counts = nxt
        w2 = int(round(2 * wplus))
        # sums are in doubled units; mean is total/2, so compare |2*s - total|
        obs = abs(2 * w2 - total)
        tail = sum(c for s, c in counts.items() if abs(2 * s - total) >= obs)
        return wplus, n, min(1.0, tail / float(2 ** n)), "exact"
    mu = n * (n + 1) / 4.0
    var = n * (n + 1) * (2 * n + 1) / 24.0 - sum(t ** 3 - t for t in ties) / 48.0
    if var <= 0:
        return wplus, n, 1.0, "normal"
    z = max(abs(wplus - mu) - 0.5, 0.0) / math.sqrt(var)
    return wplus, n, min(1.0, norm_two_sided(z)), "normal"


def cliffs_delta(cand, base):
    """P(cand > base) - P(cand < base); positive means candidate slower."""
    if not cand or not base:
        return float("nan")
    sb = sorted(base)
    gt = lt = 0
    for c in cand:
        lt += bisect.bisect_left(sb, c)            # base < c
        gt += len(sb) - bisect.bisect_right(sb, c)  # base > c
    # gt counts base>c i.e. cand<base ; lt counts base<c i.e. cand>base
    return (lt - gt) / float(len(cand) * len(base))


def cliffs_label(d):
    a = abs(d)
    if a < 0.147:
        return "negligible"
    if a < 0.33:
        return "small"
    if a < 0.474:
        return "medium"
    return "large"


def hodges_lehmann(cand, base, rng, sample=2_000_000):
    """Median of all pairwise (cand - base) differences; exact if pooled n<=3000."""
    if not cand or not base:
        return float("nan")
    if len(cand) + len(base) <= 3000:
        return median([c - b for c in cand for b in base])
    diffs = [rng.choice(cand) - rng.choice(base) for _ in range(sample)]
    return median(diffs)


STAT_FUNCS = {
    "median": lambda s: percentile(s, 50),
    "mean": mean,
    "p95": lambda s: percentile(s, 95),
    "p99": lambda s: percentile(s, 99),
}


def bootstrap_ci(base_trials, cand_trials, n_boot, seed, stats=("median", "mean", "p95", "p99")):
    """Cluster bootstrap: resample trial indices with replacement (same indices
    for both variants), pool latencies, recompute each statistic.
    Returns {stat: {point, diff_ci, pct_ci, base, cand}}."""
    n = min(len(base_trials), len(cand_trials))
    out = {}
    if n == 0:
        return out
    pb = sorted(v for t in base_trials[:n] for v in t)
    pc = sorted(v for t in cand_trials[:n] for v in t)
    rng = random.Random(seed)
    diffs = {s: [] for s in stats}
    pcts = {s: [] for s in stats}
    for _ in range(n_boot):
        idx = [rng.randrange(n) for _ in range(n)]
        sb = sorted(v for i in idx for v in base_trials[i])
        sc = sorted(v for i in idx for v in cand_trials[i])
        if not sb or not sc:
            continue
        for s in stats:
            b, c = STAT_FUNCS[s](sb), STAT_FUNCS[s](sc)
            diffs[s].append(c - b)
            if b != 0:
                pcts[s].append((c - b) / b * 100.0)
    for s in stats:
        b, c = STAT_FUNCS[s](pb), STAT_FUNCS[s](pc)

        def ci(v):
            v = sorted(v)
            return (percentile(v, 2.5), percentile(v, 97.5)) if v else (float("nan"),) * 2

        out[s] = {
            "base": b, "cand": c, "diff": c - b,
            "pct": (c - b) / b * 100.0 if b else float("nan"),
            "diff_ci": ci(diffs[s]), "pct_ci": ci(pcts[s]),
        }
    return out


def verdict(p, direction):
    """direction: >0 candidate slower, <0 candidate faster."""
    if p != p or p >= ALPHA or direction == 0:
        return f"no significant difference at alpha={ALPHA}"
    return "candidate slower" if direction > 0 else "candidate faster"


def compare(base_trials, cand_trials, n_boot, seed):
    """Full paired comparison for one category (lists of per-trial latency lists)."""
    n = min(len(base_trials), len(cand_trials))
    bt = [t for t in base_trials[:n]]
    ct = [t for t in cand_trials[:n]]
    pooled_b = [v for t in bt for v in t]
    pooled_c = [v for t in ct for v in t]
    res = {"trials": n, "n_base": len(pooled_b), "n_cand": len(pooled_c)}
    res["bootstrap"] = bootstrap_ci(bt, ct, n_boot, seed)
    u, p_mw = mann_whitney(pooled_c, pooled_b)
    res["mann_whitney"] = {"U_cand": u, "p": p_mw}
    mb = [median(t) for t in bt if t]
    mc = [median(t) for t in ct if t]
    wplus, nz, p_w, method = wilcoxon_signed_rank(mc, mb)
    res["wilcoxon"] = {"W_plus": wplus, "n_nonzero": nz, "p": p_w, "method": method,
                       "trial_median_diffs": [c - b for c, b in zip(mc, mb)]}
    d = cliffs_delta(pooled_c, pooled_b)
    res["cliffs_delta"] = {"delta": d, "label": cliffs_label(d) if d == d else "n/a"}
    res["hodges_lehmann"] = hodges_lehmann(pooled_c, pooled_b, random.Random(seed + 7))
    nd = nz and (wplus - (nz * (nz + 1) / 2.0 - wplus))
    res["verdict_primary"] = verdict(p_w, nd)
    direction_mw = (res["hodges_lehmann"] > 0) - (res["hodges_lehmann"] < 0) if d == d else 0
    res["verdict_mw"] = verdict(p_mw, direction_mw)
    return res


def self_test():
    assert percentile([1, 2, 3, 4], 50) == 2.5
    assert abs(percentile([1, 2, 3, 4], 90) - 3.7) < 1e-12
    assert percentile([5], 99) == 5 and percentile([1, 2, 3], 0) == 1 and percentile([1, 2, 3], 100) == 3
    u, p = mann_whitney([1, 2, 3], [4, 5, 6])
    assert u == 0.0, u
    assert abs(p - 0.0809) < 0.001, p  # hand: sigma=sqrt(5.25), z=4/2.2913=1.746
    u, _ = mann_whitney([1, 2], [2, 3])
    assert u == 0.5, u  # ranks 1,2.5,2.5,4 -> R1=3.5, U=3.5-3
    u, p = mann_whitney([1, 2, 3], [1, 2, 3])
    assert u == 4.5 and p == 1.0
    w, n, p, m = wilcoxon_signed_rank([1, 2, 3, 4, 5], [0] * 5)
    assert (w, n, m) == (15.0, 5, "exact") and abs(p - 2 / 32) < 1e-12, (w, n, p)
    w, n, p, m = wilcoxon_signed_rank([1, -2, 3], [0, 0, 0])
    assert w == 4.0 and abs(p - 0.75) < 1e-12, (w, p)
    w, n, p, m = wilcoxon_signed_rank([1, 1, 1], [1, 1, 1])
    assert n == 0 and p == 1.0
    big_a = [i + 0.5 for i in range(30)]
    w, n, p, m = wilcoxon_signed_rank(big_a, [0.0] * 30)
    assert m == "normal" and p < 0.001
    assert cliffs_delta([4, 5, 6], [1, 2, 3]) == 1.0
    assert cliffs_delta([1, 2, 3], [4, 5, 6]) == -1.0
    assert cliffs_delta([1, 2], [1, 2]) == 0.0
    assert cliffs_label(0.1) == "negligible" and cliffs_label(0.2) == "small"
    assert cliffs_label(-0.4) == "medium" and cliffs_label(0.9) == "large"
    assert hodges_lehmann([4, 5, 6], [1, 2, 3], random.Random(1)) == 3
    base = [[10, 12, 11], [9, 10, 14], [11, 11, 13], [10, 15, 12]]
    cand = [[x + 2 for x in t] for t in base]
    r1 = bootstrap_ci(base, cand, 300, 42)
    r2 = bootstrap_ci(base, cand, 300, 42)
    r3 = bootstrap_ci(base, cand, 300, 43)
    assert r1 == r2 and r1 != r3
    assert abs(r1["median"]["diff"] - 2) < 1e-12
    lo, hi = r1["mean"]["diff_ci"]
    assert abs(lo - 2) < 1e-9 and abs(hi - 2) < 1e-9  # constant shift
    c = compare(base, cand, 200, 1)
    assert c["cliffs_delta"]["delta"] > 0 and c["hodges_lehmann"] == 2
    assert c["wilcoxon"]["p"] == 0.125 and "no significant" in c["verdict_primary"]  # n=4 exact floor 2/16
    print("self-test OK")


# ---------------------------------------------------------------- DNS wire


def build_query(name, qtype=1, ident=None):
    ident = secrets.randbelow(65536) if ident is None else ident
    labels = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.rstrip(".").split(".") if p)
    header = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 1)
    question = labels + b"\0" + struct.pack("!HH", qtype, 1)
    opt = b"\0" + struct.pack("!HHIH", 41, 1232, 0, 0)  # EDNS0, 1232 payload, DO=0
    return ident, header + question + opt


def dns_query(port, name, timeout, qtype=1, sock=None):
    """Send one UDP query. Returns (latency_ms, rcode or None, failed)."""
    ident, packet = build_query(name, qtype)
    own = sock is None
    if own:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("127.0.0.1", port))
        start = time.perf_counter()
        deadline = start + timeout
        sock.send(packet)
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                return timeout * 1000.0, None, True
            sock.settimeout(remaining)
            try:
                data = sock.recv(4096)
            except (socket.timeout, BlockingIOError):
                return timeout * 1000.0, None, True
            except OSError:
                # e.g. ECONNREFUSED from ICMP; treat as failure now
                return (time.perf_counter() - start) * 1000.0, None, True
            elapsed = (time.perf_counter() - start) * 1000.0
            if len(data) >= 12 and struct.unpack("!H", data[:2])[0] == ident and data[2] & 0x80:
                return elapsed, data[3] & 0x0F, False
    finally:
        if own:
            sock.close()


def burst(port, name, timeout):
    results = [None] * BURST_SIZE
    barrier = threading.Barrier(BURST_SIZE)

    def worker(i):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("127.0.0.1", port))
            barrier.wait(timeout=30)
            results[i] = dns_query(port, name, timeout, sock=s)
        except Exception:  # noqa: BLE001 - recorded as failure
            results[i] = (timeout * 1000.0, None, True)
        finally:
            s.close()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(BURST_SIZE)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return [{"name": name, "ms": r[0], "rcode": r[1], "fail": r[2]} for r in results]


# ---------------------------------------------------------------- daemon

CHILDREN: list = []


def kill_children():
    for proc in list(CHILDREN):
        stop_daemon(proc)


atexit.register(kill_children)


def _raise_term(signum, frame):
    raise KeyboardInterrupt


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def free_udp_tcp_port():
    for _ in range(50):
        p = free_port()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
                u.bind(("127.0.0.1", p))
            return p
        except OSError:
            continue
    raise RuntimeError("no free port")


def read_text(path):
    return Path(path).read_text(encoding="utf-8") if path else ""


def make_config(directory, dns_port, metrics_port, extra):
    text = CONFIG_TEMPLATE.format(dns_port=dns_port, metrics_port=metrics_port)
    if extra.strip():
        # Leading bare keys belong to [resolver]; anything from the first table header on is appended.
        lines = extra.strip().splitlines()
        split = next((i for i, line in enumerate(lines) if line.lstrip().startswith("[")), len(lines))
        head, tail = "\n".join(lines[:split]).strip(), "\n".join(lines[split:]).strip()
        if head:
            text = text.replace('dnssec = true\n', 'dnssec = true\n' + head + "\n", 1)
        if tail:
            text += "\n" + tail + "\n"
    path = Path(directory) / "lumen.toml"
    path.write_text(text, encoding="utf-8")
    return path, text


def check_config(binary, path):
    r = subprocess.run([binary, "--config", str(path), "--check"], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError(f"{binary} rejected config {path}: {r.stderr.strip() or r.stdout.strip()}")


def stop_daemon(proc):
    if proc.poll() is None:
        try:
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        except OSError:
            pass
    if proc in CHILDREN:
        CHILDREN.remove(proc)


def wait_ready(proc, port, timeout=30.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if proc.poll() is not None:
            raise RuntimeError(f"daemon exited early with code {proc.returncode}")
        _, rcode, failed = dns_query(port, ".", 1.0, qtype=2)
        if not failed and rcode is not None:
            return
        time.sleep(0.1)
    raise RuntimeError("daemon did not answer health check in time")


def scrape_metrics(port):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=3) as r:
            return r.read().decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - metrics are optional
        return None


def run_trial(binary, extra, names, order_seed, args, workdir):
    dns_port = free_udp_tcp_port()
    metrics_port = free_port()
    cfg, _ = make_config(workdir, dns_port, metrics_port, extra)
    check_config(binary, cfg)
    log = open(Path(workdir) / "daemon.log", "wb")
    proc = subprocess.Popen([binary, "--config", str(cfg)], stdout=log, stderr=log, stdin=subprocess.DEVNULL)
    CHILDREN.append(proc)
    try:
        t0 = time.monotonic()
        wait_ready(proc, dns_port)
        startup = time.monotonic() - t0
        time.sleep(args.settle)
        order = list(names)
        random.Random(order_seed).shuffle(order)
        timeout = args.per_query_timeout
        cold, warm = [], []
        for seq, name in enumerate(order):
            ms, rc, fail = dns_query(dns_port, name, timeout)
            cold.append({"name": name, "seq": seq, "ms": ms, "rcode": rc, "fail": fail})
        for seq, name in enumerate(order):
            ms, rc, fail = dns_query(dns_port, name, timeout)
            warm.append({"name": name, "seq": seq, "ms": ms, "rcode": rc, "fail": fail})
        bursts = []
        for name in BURST_NAMES:
            bursts.extend(burst(dns_port, name, timeout))
        dnssec = None
        if not args.skip_dnssec_check:
            _, rc_bad, f1 = dns_query(dns_port, "dnssec-failed.org", timeout)
            _, rc_ok, f2 = dns_query(dns_port, "example.com", timeout)
            dnssec = {"dnssec_failed_rcode": rc_bad, "example_rcode": rc_ok,
                      "pass": (not f1 and rc_bad == 2 and not f2 and rc_ok == 0)}
        metrics = scrape_metrics(metrics_port)
        return {"startup_s": startup, "cold": cold, "warm": warm, "burst": bursts,
                "dnssec": dnssec, "metrics": metrics}
    finally:
        stop_daemon(proc)
        log.close()


# ---------------------------------------------------------------- environment


def run_cmd(*cmd, cwd=None):
    try:
        return subprocess.check_output(cmd, cwd=cwd, text=True, stderr=subprocess.STDOUT, timeout=15).strip()
    except Exception:  # noqa: BLE001
        return None


def cpu_model():
    if platform.system() == "Darwin":
        return run_cmd("sysctl", "-n", "machdep.cpu.brand_string") or platform.processor() or "unknown"
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text(errors="replace").splitlines():
            if line.lower().startswith("model name") and ":" in line:
                return line.split(":", 1)[1].strip()
    return platform.processor() or "unknown"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def binary_info(path):
    real = str(Path(path).resolve())
    return {
        "path": real,
        "version": run_cmd(real, "--version"),
        "sha256": sha256_file(real),
        "git_commit": run_cmd("git", "-C", str(Path(real).parent), "rev-parse", "HEAD"),
    }


def environment(args, names, baseline, candidate):
    return {
        "cpu": cpu_model(), "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "python": sys.version.split()[0], "date": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "baseline": baseline, "candidate": candidate, "trials": args.trials,
        "names": len(names), "settle_s": args.settle, "seed": args.seed,
        "per_query_timeout_s": args.per_query_timeout, "bootstrap": args.bootstrap,
    }


# ---------------------------------------------------------------- analysis/report


def category_trials(data, variant, category):
    """Per-trial latency lists (ms) for a variant and category, ordered by trial index."""
    rows = sorted((t for t in data if t["variant"] == variant), key=lambda t: t["trial"])
    out = []
    for t in rows:
        if category == "cold_first":
            out.append([t["cold"][0]["ms"]] if t["cold"] else [])
        elif category == "cold_all":
            out.append([q["ms"] for q in t["cold"]])
        elif category == "warm_all":
            out.append([q["ms"] for q in t["warm"]])
        else:
            out.append([q["ms"] for q in t["burst"]])
    return out


def category_failures(data, variant, category):
    n = 0
    for t in data:
        if t["variant"] != variant:
            continue
        if category == "cold_first":
            n += int(bool(t["cold"] and t["cold"][0]["fail"]))
        elif category == "cold_all":
            n += sum(q["fail"] for q in t["cold"])
        elif category == "warm_all":
            n += sum(q["fail"] for q in t["warm"])
        else:
            n += sum(q["fail"] for q in t["burst"])
    return n


def analyze(data, n_boot, seed):
    summaries = {}
    for v in ("baseline", "candidate"):
        summaries[v] = {}
        for c in CATEGORIES:
            vals = [x for t in category_trials(data, v, c) for x in t]
            summaries[v][c] = summarize(vals, category_failures(data, v, c))
    comparisons = {}
    for c in ("cold_first", "cold_all"):
        comparisons[c] = compare(category_trials(data, "baseline", c), category_trials(data, "candidate", c),
                                 n_boot, seed)
    return {"summaries": summaries, "comparisons": comparisons}


def f(x, d=1):
    return "n/a" if x != x else f"{x:.{d}f}"


def fp(x):
    return "n/a" if x != x else ("<0.0001" if x < 1e-4 else f"{x:.4f}")


def render_report(env, data, analysis):
    L = []
    L.append("# Lumen recursion A/B benchmark\n")
    L.append("## Environment\n")
    L.append(f"- Date: {env['date']}")
    L.append(f"- CPU: {env['cpu']}")
    L.append(f"- OS: {env['os']}")
    L.append(f"- Python: {env['python']}")
    for v in ("baseline", "candidate"):
        b = env[v]
        L.append(f"- {v.capitalize()}: `{b['path']}`")
        L.append(f"  - version: {b['version']}")
        L.append(f"  - sha256: `{b['sha256']}`")
        L.append(f"  - git commit: {b['git_commit'] or 'n/a'}")
    L.append(f"- Trials: {env['trials']} (fresh daemon per trial per variant, interleaved ABBA)")
    L.append(f"- Names: {env['names']}; settle: {env['settle_s']} s; per-query timeout: {env['per_query_timeout_s']} s")
    L.append(f"- Seed: {env['seed']}; bootstrap resamples: {env['bootstrap']}")
    L.append("")
    L.append("## Per-variant latency (ms)\n")
    L.append("Percentiles use linear interpolation between order statistics (index (n-1)p). "
             "Timeouts are right-censored at the timeout value and included.\n")
    L.append("| Variant | Category | n | mean | median | p90 | p95 | p99 | min | max | failures |")
    L.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for v in ("baseline", "candidate"):
        for c in CATEGORIES:
            s = analysis["summaries"][v][c]
            L.append(f"| {v} | {c} | {s['n']} | {f(s['mean'])} | {f(s['median'])} | {f(s['p90'])} | "
                     f"{f(s['p95'])} | {f(s['p99'])} | {f(s['min'])} | {f(s['max'])} | {s['failures']} |")
    L.append("")
    L.append("Burst latencies are pooled across 3 names x 32 concurrent identical UDP queries per trial.\n")
    L.append("## Paired comparison (candidate minus baseline)\n")
    L.append("Negative values mean the candidate is faster. 95% CIs are percentile bootstrap over "
             "TRIALS (cluster bootstrap; same resampled trials for both variants).\n")
    for c, r in analysis["comparisons"].items():
        L.append(f"### {c} ({r['trials']} paired trials; n_base={r['n_base']}, n_cand={r['n_cand']})\n")
        L.append("| Statistic | baseline | candidate | diff (ms) | diff 95% CI | change % | change 95% CI |")
        L.append("|---|---|---|---|---|---|---|")
        for s, b in r["bootstrap"].items():
            L.append(f"| {s} | {f(b['base'])} | {f(b['cand'])} | {f(b['diff'], 2)} | "
                     f"[{f(b['diff_ci'][0], 2)}, {f(b['diff_ci'][1], 2)}] | {f(b['pct'])}% | "
                     f"[{f(b['pct_ci'][0])}%, {f(b['pct_ci'][1])}%] |")
        w, mw, cd = r["wilcoxon"], r["mann_whitney"], r["cliffs_delta"]
        L.append("")
        L.append(f"- Wilcoxon signed-rank over per-trial medians (PRIMARY): W+={f(w['W_plus'], 1)}, "
                 f"non-zero pairs={w['n_nonzero']}, p={fp(w['p'])} ({w['method']})")
        L.append(f"- Mann-Whitney U on pooled latencies (secondary): U={f(mw['U_cand'], 1)}, p={fp(mw['p'])}")
        L.append(f"- Cliff's delta: {f(cd['delta'], 3)} ({cd['label']}); positive = candidate slower")
        L.append(f"- Hodges-Lehmann shift (cand - base): {f(r['hodges_lehmann'], 2)} ms")
        L.append(f"- **Verdict ({c}, Wilcoxon over trials, alpha={ALPHA}): {r['verdict_primary']}**")
        L.append(f"- Verdict ({c}, Mann-Whitney, anticonservative): {r['verdict_mw']}")
        L.append("")
    L.append("Burst category: compared descriptively only.\n")
    for v in ("baseline", "candidate"):
        s = analysis["summaries"][v]["burst"]
        L.append(f"- {v}: burst p50={f(s['p50'])} ms, p95={f(s['p95'])} ms, max={f(s['max'])} ms")
    L.append("")
    L.append("## DNSSEC check\n")
    if all(t["dnssec"] is None for t in data):
        L.append("Skipped (--skip-dnssec-check).\n")
    else:
        L.append("| Variant | trials passed | trials total |")
        L.append("|---|---|---|")
        for v in ("baseline", "candidate"):
            ts = [t["dnssec"] for t in data if t["variant"] == v and t["dnssec"] is not None]
            L.append(f"| {v} | {sum(1 for d in ts if d['pass'])} | {len(ts)} |")
        L.append("\nPass requires dnssec-failed.org A -> SERVFAIL and example.com A -> NOERROR.\n")
    L.append("## Failures\n")
    for v in ("baseline", "candidate"):
        parts = [f"{c}={analysis['summaries'][v][c]['failures']}" for c in CATEGORIES]
        L.append(f"- {v}: " + ", ".join(parts))
    L.append("")
    L.append("## Limitations\n")
    for item in [
        "Single machine and single network vantage point; results may not transfer elsewhere.",
        "Real-internet variance (routing, authoritative load, rate limiting) is not controlled; "
        "ABBA interleaving only mitigates slow drift.",
        "Authoritative-side caching can make 'cold' include warm authoritative caches, so absolute "
        "cold latencies are optimistic and depend on what other resolvers recently asked.",
        "Mann-Whitney treats queries as independent, which they are not (queries within a trial share "
        "delegation caches), so it is anticonservative; the trial-level Wilcoxon test and cluster "
        "bootstrap are the primary evidence.",
        "With few trials the exact Wilcoxon p-value has a coarse floor (2/2^n for n non-zero pairs).",
        "This is a latency comparison on a small name list, not a throughput or capacity claim.",
    ]:
        L.append(f"- {item}")
    L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------- main


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--baseline", help="baseline lumen binary")
    p.add_argument("--candidate", help="candidate lumen binary (may equal baseline for A/A)")
    p.add_argument("--trials", type=int, default=12)
    p.add_argument("--names", help="file with one domain per line")
    p.add_argument("--settle", type=float, default=8.0, help="idle seconds after health check")
    p.add_argument("--per-query-timeout", type=float, default=8.0)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--bootstrap", type=int, default=4000)
    p.add_argument("--out-dir", default="./recursion-bench-results")
    p.add_argument("--skip-dnssec-check", action="store_true")
    p.add_argument("--candidate-extra-toml", help="extra TOML appended to candidate config "
                   "(default enables [resolver.warm] and [resolver.prefetch])")
    p.add_argument("--baseline-extra-toml", help="extra TOML appended to baseline config (default empty)")
    p.add_argument("--self-test", action="store_true", help="run stats unit tests and exit")
    args = p.parse_args(argv)
    if not args.self_test and not (args.baseline and args.candidate):
        p.error("--baseline and --candidate are required")
    return args


def load_names(path):
    if not path:
        return list(DEFAULT_NAMES)
    names = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line.rstrip("."))
    if not names:
        raise SystemExit("names file is empty")
    return names


def main():
    args = parse_args()
    if args.self_test:
        self_test()
        return 0
    signal.signal(signal.SIGTERM, _raise_term)
    names = load_names(args.names)
    binaries = {"baseline": args.baseline, "candidate": args.candidate}
    extras = {
        "baseline": read_text(args.baseline_extra_toml) if args.baseline_extra_toml else "",
        "candidate": read_text(args.candidate_extra_toml) if args.candidate_extra_toml is not None
        else DEFAULT_CANDIDATE_EXTRA,
    }
    infos = {v: binary_info(b) for v, b in binaries.items()}
    env = environment(args, names, infos["baseline"], infos["candidate"])
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Verify both configs before any timing.
    with tempfile.TemporaryDirectory(prefix="rb-check-") as d:
        for v in binaries:
            cfg, _ = make_config(d, 15353, 19153, extras[v])
            check_config(binaries[v], cfg)

    data = []
    try:
        for trial in range(args.trials):
            order = ["baseline", "candidate"] if trial % 2 == 0 else ["candidate", "baseline"]
            for pos, v in enumerate(order):
                print(f"[trial {trial + 1}/{args.trials}] {v} (position {pos})", file=sys.stderr, flush=True)
                with tempfile.TemporaryDirectory(prefix=f"rb-{v}-") as d:
                    rec = run_trial(binaries[v], extras[v], names, args.seed * 1000 + trial, args, d)
                rec.update({"trial": trial, "variant": v, "position": pos})
                data.append(rec)
    except KeyboardInterrupt:
        print("interrupted; analyzing completed trials", file=sys.stderr)
    finally:
        kill_children()

    # Keep only trials where both variants completed.
    done = {}
    for t in data:
        done.setdefault(t["trial"], set()).add(t["variant"])
    data = [t for t in data if len(done[t["trial"]]) == 2]
    if not data:
        print("no complete trials", file=sys.stderr)
        return 1
    analysis = analyze(data, args.bootstrap, args.seed)
    report = render_report(env, data, analysis)
    (out_dir / "report.md").write_text(report, encoding="utf-8")
    (out_dir / "results.json").write_text(json.dumps({
        "parameters": env, "config_extras": extras, "trials": data, "analysis": analysis,
    }, indent=1, default=str), encoding="utf-8")
    print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
