"""
Stop GPU jobs when the laptop's GPU memory runs hot.

The RTX 4060 Laptop does not report its GDDR6 junction temperature through
nvidia-smi / NVML ("Memory Current Temp: N/A"), so this reads it from HWiNFO's
sensor log: in HWiNFO (sensors-only) press "Start Logging" and save to the
--csv path. Every --interval seconds the newest row is read; the job is
stopped when

  * the memory junction exceeds --limit (default 85 C), or
  * the log has not been written for --stale seconds (HWiNFO closed, logging
    stopped): a watchdog that cannot see the temperature must not let the
    job run as if it could.

Stopping sends SIGTERM to run_ablation.sh and to the GPU Python jobs of this
repo. train_qlora.py saves a checkpoint every 10% of the run, so the same
./run_ablation.sh command resumes it later.

    nohup .venv/bin/python -u gpu_watchdog.py --csv /mnt/c/Users/<you>/hwinfo.csv > logs/gpu_watchdog.log 2>&1 &
"""

import argparse
import csv
import io
import os
import re
import signal
import subprocess
import sys
import time

JOBS = ["run_ablation.sh", "train_qlora.py", "pick_checkpoint.py",
        "hallucination_check.py", "run_eval.py"]


def last_row(path):
    """Header and newest complete row of an HWiNFO CSV. HWiNFO writes the
    header first and appends one row per poll; it repeats the header as the
    file's last line only when logging stops cleanly."""
    with open(path, "rb") as f:
        head = f.readline()
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - 65536))
        tail = f.read().splitlines()
    dec = lambda b: b.decode("utf-8", "replace") if b.startswith(b"\xef\xbb\xbf") or b"\xc2\xb0" in b \
        else b.decode("cp1252", "replace")
    header = next(csv.reader(io.StringIO(dec(head).lstrip("﻿"))))
    for line in reversed(tail):
        row = next(csv.reader(io.StringIO(dec(line))), [])
        if len(row) >= len(header) - 1 and row and row[0] != header[0]:
            return header, row
    return header, None


def gpu_core_temp():
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader"],
                             capture_output=True, text=True, timeout=10).stdout.strip()
        return float(out.splitlines()[0])
    except Exception:
        return None


def stop_jobs(reason):
    print(f"{time.strftime('%H:%M:%S')} STOP: {reason}", flush=True)
    me = os.getpid()
    for name in JOBS:
        pids = subprocess.run(["pgrep", "-f", name], capture_output=True, text=True).stdout.split()
        for pid in map(int, pids):
            if pid == me:
                continue
            try:
                os.kill(pid, signal.SIGTERM)
                print(f"  sent SIGTERM to {pid} ({name})", flush=True)
            except ProcessLookupError:
                pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv")
    ap.add_argument("--stop", action="store_true", help="stop the GPU jobs now and exit")
    ap.add_argument("--column", default=r"memory junction",
                    help="regex for the HWiNFO column to watch")
    ap.add_argument("--limit", type=float, default=85.0)
    ap.add_argument("--warn", type=float, default=82.0)
    ap.add_argument("--stale", type=float, default=120.0)
    ap.add_argument("--interval", type=float, default=10.0)
    ap.add_argument("--report-every", type=float, default=600.0)
    args = ap.parse_args()
    if args.stop:
        return stop_jobs("requested")
    if not args.csv:
        ap.error("--csv is required")

    header, _ = last_row(args.csv)
    cols = [i for i, h in enumerate(header) if re.search(args.column, h, re.I)]
    if not cols:
        sys.exit(f"no column matching /{args.column}/ in {args.csv}; "
                 f"GPU-looking columns: {[h for h in header if 'GPU' in h][:15]}")
    print(f"watching {[header[i] for i in cols]}  limit {args.limit}  stale {args.stale}s", flush=True)

    peak, last_report, last_good = 0.0, 0.0, time.time()
    while True:
        age = time.time() - os.path.getmtime(args.csv)
        if age > args.stale:
            stop_jobs(f"HWiNFO log not written for {age:.0f}s; cannot see the memory temperature")
            return
        _, row = last_row(args.csv)
        vals = []
        for i in cols:
            try:
                vals.append(float(row[i].strip().replace(",", ".")))
            except (TypeError, ValueError, IndexError):
                pass
        if not vals:
            if time.time() - last_good > args.stale:
                stop_jobs(f"no readable memory temperature for {args.stale:.0f}s")
                return
            time.sleep(args.interval)
            continue
        last_good = time.time()
        mem, core = max(vals), gpu_core_temp()
        peak = max(peak, mem)
        now = time.time()
        if mem > args.limit:
            stop_jobs(f"memory junction {mem:.0f} C > {args.limit:.0f} C (core {core})")
            return
        if mem >= args.warn:
            print(f"{time.strftime('%H:%M:%S')} WARN memory junction {mem:.0f} C (core {core})", flush=True)
        if now - last_report >= args.report_every:
            print(f"{time.strftime('%H:%M:%S')} ok  memory junction {mem:.0f} C  peak {peak:.0f} C  "
                  f"core {core}", flush=True)
            last_report = now
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
