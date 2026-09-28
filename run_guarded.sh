#!/usr/bin/env bash
# Run a GPU job under gpu_watchdog.py.
#
#   ./run_guarded.sh <hwinfo.csv> <command...>
#   nohup ./run_guarded.sh /mnt/c/Users/<you>/hwinfo.csv ./run_ablation.sh v6-strict > logs/gpu_chain.log 2>&1 &
#
# Waits until HWiNFO is logging to <hwinfo.csv> (start it with a fresh file:
# the watchdog reads the column layout from the first line), starts the
# watchdog, then runs the command. If the watchdog exits for any reason (it
# stopped the job, or it crashed), the job is stopped too: nothing runs on the
# GPU without something watching the memory temperature.
set -uo pipefail
cd "$(dirname "$0")"
CSV=$1; shift
PY=.venv/bin/python
echo "$(date +%T) waiting for a live HWiNFO log at $CSV"
until [ -f "$CSV" ] && [ $(( $(date +%s) - $(stat -c %Y "$CSV") )) -lt 30 ]; do sleep 15; done
nohup $PY -u gpu_watchdog.py --csv "$CSV" > logs/gpu_watchdog.log 2>&1 &
WD=$!
sleep 20
if ! kill -0 $WD 2>/dev/null; then echo "$(date +%T) watchdog did not start:"; cat logs/gpu_watchdog.log; exit 1; fi
echo "$(date +%T) watchdog up: $(head -1 logs/gpu_watchdog.log)"
"$@" &
JOB=$!
while kill -0 $JOB 2>/dev/null; do
  if ! kill -0 $WD 2>/dev/null; then
    echo "$(date +%T) watchdog exited: $(tail -1 logs/gpu_watchdog.log)"
    $PY gpu_watchdog.py --stop > /dev/null
    break
  fi
  sleep 30
done
wait $JOB 2>/dev/null; rc=$?
kill $WD 2>/dev/null
echo "$(date +%T) finished (exit $rc)"
