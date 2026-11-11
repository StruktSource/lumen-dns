#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Measure Lumen latency, throughput, and resource use under local UDP load.

Scenarios run against a native release daemon on loopback:

* blocked  - names answered by the filter engine (no upstream, no cache)
* cached   - one real name, resolved once, then answered from the cache
* default  - the cached case under the shipped 100 queries/second per-IP limit

With `--console` the daemon also runs the web console on a loopback port with a
managed-mode state database (`--state`), as a normal home install does. Idle use is
sampled and the console's static page latency is measured before the DNS load.

Each scenario is closed-loop: every worker keeps a fixed window of queries
in flight. The per-IP limit is raised to its 10000 maximum except for the
`default` scenario, so one loopback client cannot exceed 10000 queries/second.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import select
import socket
import statistics
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / "target" / "release" / "lumen"


def packet(name: str, ident: int) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + labels + b"\0\0\1\0\1"


def worker(port: int, names: list[str], window: int, seconds: float, out: mp.Queue) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.connect(("127.0.0.1", port))
    sent_at: dict[int, float] = {}
    lat: list[float] = []
    rcodes: dict[int, int] = {}
    timeouts = 0
    ident = 0
    n = len(names)

    def send() -> None:
        nonlocal ident
        ident = (ident + 1) & 0xFFFF
        sent_at[ident] = time.perf_counter()
        try:
            sock.send(packet(names[ident % n], ident))
        except OSError:
            sent_at.pop(ident, None)

    end = time.perf_counter() + seconds
    for _ in range(window):
        send()
    while True:
        now = time.perf_counter()
        if now >= end:
            break
        ready, _, _ = select.select([sock], [], [], 0.05)
        if ready:
            for _ in range(256):
                try:
                    data = sock.recv(4096)
                except BlockingIOError:
                    break
                except OSError:
                    break
                if len(data) < 12:
                    continue
                rid = struct.unpack("!H", data[:2])[0]
                t0 = sent_at.pop(rid, None)
                if t0 is None:
                    continue
                lat.append((time.perf_counter() - t0) * 1000)
                rc = data[3] & 0x0F
                rcodes[rc] = rcodes.get(rc, 0) + 1
                if time.perf_counter() < end:
                    send()
        # Dropped queries (rate limit, overload) never answer: reap and replace.
        stale = time.perf_counter() - 1.0
        dead = [k for k, v in sent_at.items() if v < stale]
        for k in dead:
            del sent_at[k]
            timeouts += 1
            if time.perf_counter() < end:
                send()
    out.put({"lat": lat, "rcodes": rcodes, "timeouts": timeouts})


def pct(values: list[float], p: float) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, int(len(s) * p))]


class Sampler(threading.Thread):
    def __init__(self, pid: int) -> None:
        super().__init__(daemon=True)
        self.pid, self.cpu, self.rss, self.stop = pid, [], [], threading.Event()

    def run(self) -> None:
        while not self.stop.is_set():
            try:
                out = subprocess.check_output(["ps", "-o", "%cpu=,rss=", "-p", str(self.pid)], text=True).split()
                self.cpu.append(float(out[0]))
                self.rss.append(int(out[1]))
            except Exception:
                pass
            self.stop.wait(0.5)


def config(path: Path, port: int, qps: int, web_port: int | None = None) -> None:
    web = f'\n[web]\nhttp = ["127.0.0.1:{web_port}"]\n' if web_port else ""
    path.write_text(
        f'''schema_version = 1

[listen]
udp = ["127.0.0.1:{port}"]
tcp = ["127.0.0.1:{port}"]
allow_clients = ["127.0.0.0/8"]

{web}
[resolver]
mode = "recursive"
dnssec = true

[limits]
queries_per_second = {qps}

[filtering.rules]
block = ["blocked.example"]
''',
        encoding="utf-8",
    )


WEB_PORT: int | None = None


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start(qps: int, console: bool = False) -> tuple[subprocess.Popen[bytes], int]:
    global WEB_PORT
    port = free_port()
    WEB_PORT = free_port() if console else None
    directory = Path(tempfile.mkdtemp())
    cfg = directory / "lumen.toml"
    config(cfg, port, qps, WEB_PORT)
    extra = ["--state", str(directory / "state.db")] if console else []
    proc = subprocess.Popen([str(BINARY), "--config", str(cfg), *extra], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), 0.1).close()
            break
        except OSError:
            time.sleep(0.05)
    else:
        raise RuntimeError("daemon did not start")
    time.sleep(1.5)
    return proc, port


def run(proc: subprocess.Popen[bytes], port: int, names: list[str], procs: int, window: int, seconds: float) -> dict:
    q: mp.Queue = mp.Queue()
    sampler = Sampler(proc.pid)
    sampler.start()
    t0 = time.perf_counter()
    ws = [mp.Process(target=worker, args=(port, names, window, seconds, q)) for _ in range(procs)]
    for w in ws:
        w.start()
    results = [q.get() for _ in ws]
    for w in ws:
        w.join()
    elapsed = time.perf_counter() - t0
    sampler.stop.set()
    sampler.join()
    lat = [x for r in results for x in r["lat"]]
    rc: dict[int, int] = {}
    for r in results:
        for k, v in r["rcodes"].items():
            rc[k] = rc.get(k, 0) + v
    return {
        "answered": len(lat),
        "qps": len(lat) / seconds,
        "timeouts": sum(r["timeouts"] for r in results),
        "p50": statistics.median(lat) if lat else 0,
        "p95": pct(lat, 0.95) if lat else 0,
        "p99": pct(lat, 0.99) if lat else 0,
        "max": max(lat) if lat else 0,
        "cpu_mean": statistics.fmean(sampler.cpu) if sampler.cpu else 0,
        "cpu_peak": max(sampler.cpu) if sampler.cpu else 0,
        "rss_peak_mib": max(sampler.rss) / 1024 if sampler.rss else 0,
        "rcodes": rc,
        "elapsed": elapsed,
    }


def rss_now(pid: int) -> float:
    return int(subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)], text=True)) / 1024


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seconds", type=float, default=10)
    ap.add_argument("--output", type=Path)
    ap.add_argument("--cached-name", default="example.com")
    ap.add_argument("--console", action="store_true", help="also run the web console with a state database")
    args = ap.parse_args()

    report: dict = {}
    # (label, qps limit, names, procs, window)
    blocked = [f"h{i}.blocked.example" for i in range(64)]
    cached = [args.cached_name]
    scenarios = [
        ("blocked, window 1", 10000, blocked, 1, 1),
        ("blocked, window 8", 10000, blocked, 1, 8),
        ("blocked, window 64", 10000, blocked, 2, 32),
        ("cached, window 1", 10000, cached, 1, 1),
        ("cached, window 8", 10000, cached, 1, 8),
        ("cached, window 64", 10000, cached, 2, 32),
        ("cached, shipped 100 qps limit", 100, cached, 1, 8),
    ]
    proc, port = start(10000, args.console)
    current_qps = 10000
    try:
        report["idle_before_mib"] = rss_now(proc.pid)
        if args.console:
            idle = Sampler(proc.pid)
            idle.start()
            time.sleep(15)
            idle.stop.set()
            idle.join()
            report["console_idle"] = {"cpu_mean": statistics.fmean(idle.cpu), "cpu_peak": max(idle.cpu), "rss_mib": statistics.fmean(idle.rss) / 1024}
            times = []
            for _ in range(200):
                t0 = time.perf_counter()
                with socket.create_connection(("127.0.0.1", WEB_PORT), 2) as c:
                    c.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                    body = b""
                    while chunk := c.recv(65536):
                        body += chunk
                times.append((time.perf_counter() - t0) * 1000)
            report["console_page"] = {"status": body.split(b"\r\n", 1)[0].decode(), "bytes": len(body), "p50": statistics.median(times), "p99": pct(times, 0.99)}
        # Warm the cache once with a real recursive lookup and time that cold query.
        t = time.perf_counter()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(10)
        s.sendto(packet(args.cached_name, 1), ("127.0.0.1", port))
        try:
            s.recvfrom(4096)
            report["cold_ms"] = (time.perf_counter() - t) * 1000
        except OSError:
            report["cold_ms"] = None
        time.sleep(1)
        for label, qps, names, procs, window in scenarios:
            if qps != current_qps:
                proc.terminate()
                proc.wait(5)
                proc, port = start(qps, args.console)
                current_qps = qps
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(10)
                s.sendto(packet(args.cached_name, 2), ("127.0.0.1", port))
                s.recvfrom(4096)
                time.sleep(1.2)
            report[label] = run(proc, port, names, procs, window, args.seconds)
            print(label, json.dumps(report[label]), flush=True)
            time.sleep(1.2)
        time.sleep(5)
        report["idle_after_mib"] = rss_now(proc.pid)
    finally:
        proc.terminate()
        proc.wait(5)

    lines = ["| Scenario | Answered/s | p50 | p95 | p99 | Max | Dropped | Mean CPU | Peak CPU | Peak RSS |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for label, *_ in scenarios:
        r = report[label]
        lines.append(
            f"| {label} | {r['qps']:,.0f} | {r['p50']:.3f} ms | {r['p95']:.3f} ms | {r['p99']:.3f} ms | "
            f"{r['max']:.1f} ms | {r['timeouts']} | {r['cpu_mean']:.0f}% | {r['cpu_peak']:.0f}% | {r['rss_peak_mib']:.1f} MiB |"
        )
    cold = report["cold_ms"]
    lines += ["", f"Cold first lookup of `{args.cached_name}`: {cold:.0f} ms." if cold else "Cold lookup timed out.",
              f"RSS before load {report['idle_before_mib']:.2f} MiB, 5 s after load {report['idle_after_mib']:.2f} MiB."]
    if "console_idle" in report:
        ci, cp = report["console_idle"], report["console_page"]
        lines += ["", f"Console enabled (state database, web on loopback): idle {ci['rss_mib']:.2f} MiB RSS, {ci['cpu_mean']:.1f}% mean CPU ({ci['cpu_peak']:.1f}% peak) over 15 s.",
                  f"Console page `GET /` ({cp['status']}, {cp['bytes']:,} bytes): p50 {cp['p50']:.2f} ms, p99 {cp['p99']:.2f} ms over 200 requests."]
    text = "\n".join(lines) + "\n"
    print(text)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        args.output.with_suffix(".json").write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
