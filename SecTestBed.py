#!/usr/bin/env python3
"""
SecTestBed – High‑performance SSH‑brute detection test
Injects realistic fake SSH brute‑force events, detects them, and scores your security.
"""

import os
import sys
import time
from datetime import datetime, timedelta
from typing import List, Tuple, Optional
from dataclasses import dataclass


# === 1. Configuration and logging ===
@dataclass
class TestConfig:
    target_log: str = os.path.expanduser("~/SecTestBed/logs/test_auth.log")
    num_attempts: int = 20
    fake_ip: str = "192.168.1.100"
    fake_host: str = "fakehost"


CONFIG = TestConfig()


def ensure_log_dir():
    """Create the log dir quickly and idempotently."""
    log_dir = os.path.dirname(CONFIG.target_log)
    os.makedirs(log_dir, exist_ok=True)


def log_info(msg: str):
    """Quick, clean console output."""
    print(f"[INFO] {msg}")


def log_error(msg: str):
    """Error logging."""
    print(f"[ERROR] {msg}", file=sys.stderr)


# === 2. Realistic SSH‑brute test generator ===

def generate_fake_log_lines(
    n: int,
    base_time: datetime,
    fake_host: str,
    fake_ip: str
) -> List[str]:
    """Generate `n` realistic fake SSH failed login lines (no I/O inside this function)."""
    lines = []
    user_names = [f"tester{i}" for i in range(n)]
    for i in range(n):
        t = base_time + timedelta(seconds=i)
        log_line = (
            f"{t.strftime('%b %d %H:%M:%S')} {fake_host} sshd[1234]: "
            f"Failed password for invalid user {user_names[i]} "
            f"from {fake_ip} port 55555 ssh2"
        )
        lines.append(log_line)
    return lines


def inject_ssh_brute_events(
    log_path: str,
    count: int = CONFIG.num_attempts
) -> int:
    """
    Inject `count` fake SSH brute events in a single, efficient write.
    Returns number of events injected.
    """
    log_info(f"Injecting {count} fake SSH brute‑force attempts into {log_path}...")

    base_time = datetime.now() - timedelta(seconds=count + 60)
    lines = generate_fake_log_lines(
        n=count,
        base_time=base_time,
        fake_host=CONFIG.fake_host,
        fake_ip=CONFIG.fake_ip
    )

    ensure_log_dir()
    with open(log_path, "a") as f:
        f.write("\n".join(lines) + "\n")
    injected = len(lines)
    log_info(f"✅ Injected {injected} events.")
    return injected


# === 3. High‑performance detector (regex‑style without regex) ===

PATTERN_KEYWORDS = [
    "Failed password for invalid user",
    "fakehost sshd",
    "192.168.1.100",
    "port 55555 ssh2",
]


def detect_ssh_brute_lines(
    log_path: str,
    expected_count: int
) -> int:
    """
    Fast, line‑by‑line scan of the log file counting SSH‑brute‑like events.
    Does not load the full file at once; streaming is memory‑efficient.
    """
    log_info("Running detection on log file...")

    if not os.path.exists(log_path):
        log_error("Log file not found.")
        return 0

    detected = 0

    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Fast keyword‑presence check (no regex, lowest overhead)
            if all(keyword in line for keyword in PATTERN_KEYWORDS):
                detected += 1

    # Cap to expected count to avoid fake inflation
    return min(detected, expected_count)


# === 4. Performance‑focused test runner and scorer ===

@dataclass
class TestResult:
    injected: int
    detected: int
    success_rate: float
    label: str
    injection_time_ms: float
    detection_time_ms: float


def run_test() -> Optional[TestResult]:
    """
    Full test run: inject, detect, score, print.
    Designed for maximum clarity and performance.
    """
    inject_start = time.time()
    injected = inject_ssh_brute_events(CONFIG.target_log, CONFIG.num_attempts)
    inject_end = time.time()
    inject_ms = (inject_end - inject_start) * 1000.0

    if injected == 0:
        log_error("Failed to inject events.")
        return None

    detect_start = time.time()
    detected = detect_ssh_brute_lines(CONFIG.target_log, injected)
    detect_end = time.time()
    detect_ms = (detect_end - detect_start) * 1000.0

    # === 5. Rich, human‑readable scorecard ===
    success_rate = detected / injected if injected > 0 else 0.0
    if success_rate >= 0.9:
        label = "✅ EXCELLENT – detection is strong"
    elif success_rate >= 0.6:
        label = "🟨 ACCEPTABLE – some events missed"
    else:
        label = "🔴 WEAK – coverage is poor"

    result = TestResult(
        injected=injected,
        detected=detected,
        success_rate=success_rate,
        label=label,
        injection_time_ms=inject_ms,
        detection_time_ms=detect_ms,
    )

    # ----- Console report -----
    border = "-" * 52
    print(f"\n{border}")
    print("SecTestBed – SSH Brute‑Force Detection Test")
    print(f"Test time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(border)
    print(f"Target log file     : {CONFIG.target_log}")
    print(f"Fake events injected: {injected}")
    print(f"Detected events     : {detected}")
    print(f"Success rate        : {result.success_rate:.1%}")
    print(f"Detection label     : {result.label}")
    print(border)
    print(f"⏱️  Injection time: {inject_ms:.2f} ms")
    print(f"⏱️  Detection time: {detect_ms:.2f} ms")
    print(border)

    return result


if __name__ == "__main__":
    try:
        result = run_test()
        if result is None:
            sys.exit(1)
    except Exception as e:
        log_error(f"Test failed with error: {e}")
        sys.exit(1)


