#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Record comparable native idle snapshots for Lumen."""

from __future__ import annotations

import argparse
import os
import platform
import socket
import statistics
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / "target" / "release" / "lumen"


@dataclass
class Snapshot:
    name: str
    cpu: list[float]
    rss_kib: list[int]
    process_time_first: str
    process_time_last: str


def command(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def sysctl(name: str, fallback: str) -> str:
    try:
        return command("sysctl", "-n", name)
    except (OSError, subprocess.CalledProcessError):
        return fallback


def machine_details() -> tuple[str, int, str]:
    system = platform.system()
    if system == "Darwin":
        cpu = sysctl("machdep.cpu.brand_string", platform.processor() or "Unknown CPU")
        memory = int(sysctl("hw.memsize", "0") or 0)
        try:
            version = command("sw_vers", "-productVersion")
            build = command("sw_vers", "-buildVersion")
            os_name = f"macOS {version} ({build}), {platform.machine()}"
        except (OSError, subprocess.CalledProcessError):
            os_name = f"Darwin {platform.release()} ({platform.machine()})"
        return cpu, memory, os_name
    if system == "Linux":
        cpu = platform.processor() or "Unknown CPU"
        cpuinfo = Path("/proc/cpuinfo")
        if cpuinfo.is_file():
            for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.lower().startswith("model name") and ":" in line:
                    cpu = line.split(":", 1)[1].strip()
                    break
        memory = 0
        meminfo = Path("/proc/meminfo")
        if meminfo.is_file():
            for line in meminfo.read_text(encoding="ascii", errors="replace").splitlines():
                if line.startswith("MemTotal:"):
                    memory = int(line.split()[1]) * 1024
                    break
        return cpu, memory, f"Linux {platform.release()} ({platform.machine()})"
    return platform.processor() or "Unknown CPU", 0, f"{system} {platform.release()} ({platform.machine()})"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_for_tcp(port: int, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Lumen exited with status {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("Lumen did not open its TCP listener within five seconds")


def filtered_config(directory: Path, port: int) -> Path:
    path = directory / "filtering.toml"
    path.write_text(
        f'''schema_version = 1

[listen]
udp = ["127.0.0.1:{port}"]
tcp = ["127.0.0.1:{port}"]
allow_clients = ["127.0.0.0/8"]

[resolver]
mode = "recursive"
dnssec = true

[filtering.rules]
allow = ["safe.ads.example"]
block = ["manual.example", "=exact.example"]

[[filtering.lists]]
id = "snapshot"
format = "domains"
text = """ads.example
tracker.example
adult.example"""
refresh_secs = 0
''',
        encoding="utf-8",
    )
    return path


def sample_process(pid: int) -> tuple[float, int, str]:
    output = command("ps", "-o", "%cpu=,rss=,time=", "-p", str(pid))
    fields = output.split()
    if len(fields) != 3:
        raise RuntimeError(f"unexpected ps output: {output!r}")
    return float(fields[0]), int(fields[1]), fields[2]


def run_snapshot(name: str, args: list[str], port: int, samples: int, interval: float, warmup: float) -> Snapshot:
    process = subprocess.Popen(
        [str(BINARY), *args],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    cpu: list[float] = []
    rss: list[int] = []
    process_times: list[str] = []
    try:
        wait_for_tcp(port, process)
        time.sleep(warmup)
        for index in range(samples):
            cpu_value, rss_value, process_time = sample_process(process.pid)
            cpu.append(cpu_value)
            rss.append(rss_value)
            process_times.append(process_time)
            if index + 1 < samples:
                time.sleep(interval)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    return Snapshot(name, cpu, rss, process_times[0], process_times[-1])


def mib(kib: float) -> float:
    return kib / 1024


def render(snapshots: list[Snapshot], samples: int, interval: float, warmup: float) -> str:
    commit = command("git", "rev-parse", "HEAD")
    rustc = command("rustc", "--version")
    cpu, memory_bytes, os_name = machine_details()
    logical = os.cpu_count() or 0
    memory = f"{memory_bytes / 1024**3:.0f} GiB" if memory_bytes else "Unknown"
    binary_bytes = BINARY.stat().st_size

    lines = [
        "# Lumen native idle performance snapshot",
        "",
        "| Environment | Value |",
        "| --- | --- |",
        f"| CPU | {cpu}, {logical} logical cores |",
        f"| Memory | {memory} |",
        f"| OS | {os_name} |",
        f"| Lumen | commit `{commit}` |",
        f"| Build | `cargo build --release --locked -p lumen`, {rustc} |",
        f"| Sampling | {samples} samples, {interval:g} second interval, after {warmup:g} seconds warm-up |",
        f"| Traffic | None; UDP/TCP listeners on loopback |",
        "",
        "| Scenario | Mean CPU | Peak CPU | Mean RSS | RSS range | Process CPU time |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for snapshot in snapshots:
        lines.append(
            f"| {snapshot.name} | {statistics.fmean(snapshot.cpu):.1f}% | "
            f"{max(snapshot.cpu):.1f}% | {mib(statistics.fmean(snapshot.rss_kib)):.2f} MiB | "
            f"{mib(min(snapshot.rss_kib)):.2f}–{mib(max(snapshot.rss_kib)):.2f} MiB | "
            f"{snapshot.process_time_first} → {snapshot.process_time_last} |"
        )
    lines.extend(
        [
            "",
            f"Release executable: **{binary_bytes / 1024**2:.2f} MiB** ({binary_bytes:,} bytes).",
            "",
            "CPU is process usage as reported by `ps`; 100% equals one logical core. "
            "RSS includes resident shared memory. This local idle snapshot is not a "
            "throughput, latency, or capacity benchmark.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--warmup", type=float, default=2.0)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.samples < 1 or args.interval <= 0 or args.warmup < 0:
        parser.error("samples must be positive; interval must be > 0; warmup must be >= 0")

    if not args.skip_build:
        subprocess.run(
            ["cargo", "build", "--release", "--locked", "-p", "lumen"],
            cwd=ROOT,
            check=True,
        )
    if not BINARY.is_file():
        raise FileNotFoundError(f"release binary missing: {BINARY}")

    with tempfile.TemporaryDirectory(prefix="lumen-performance-") as temp:
        baseline_port = free_port()
        filtering_port = free_port()
        config = filtered_config(Path(temp), filtering_port)
        snapshots = [
            run_snapshot(
                "Phase 2 binary / filtering disabled",
                ["--bind", f"127.0.0.1:{baseline_port}"],
                baseline_port,
                args.samples,
                args.interval,
                args.warmup,
            ),
            run_snapshot(
                "Phase 2 binary / filtering enabled",
                ["--config", str(config)],
                filtering_port,
                args.samples,
                args.interval,
                args.warmup,
            ),
        ]
    report = render(snapshots, args.samples, args.interval, args.warmup)
    if args.output:
        args.output.write_text(report, encoding="utf-8")
    print(report, end="")


if __name__ == "__main__":
    main()
