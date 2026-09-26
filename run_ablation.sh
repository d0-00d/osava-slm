#!/usr/bin/env bash
# Train and score one v6 configuration. Each differs from `v6` in exactly one
# thing, so the severity regression v5 showed can be attributed:
#
#   v6         v5 + span-quoted indicators + logon rows (the candidate)
#   v6-seed2   v6 with another training seed: the noise floor. Read this one
#              before any other difference.
#   v6-strict  v6 on the `strict` prompt and v1 threatType vocabulary
#   v6-noquar  v6 without the action quarantine (compare on clean events only)
#
#   ./run_ablation.sh v6 [v6-seed2 v6-strict v6-noquar]   # ~2.5 h each on a 4060
#   python3 compare_runs.py v5=logs/v5/ckpt_step460.json v6=logs/v6/ckpt_v6.json ...
#
# A run whose final sweep exists is skipped, so after an interruption the same
# command carries on. Training settings are v3's and v5's: 4 epochs, severity
# token weight 20.
set -euo pipefail
cd "$(dirname "$0")"
PY=.venv/bin/python

for name in "$@"; do
  variant=strict2; seed=1337; extra=()
  case $name in
    v6) ;;
    v6-seed2) seed=2 ;;
    v6-strict) variant=strict ;;
    v6-noquar) extra=(--no-action-quarantine) ;;
    *) echo "unknown run: $name" >&2; exit 2 ;;
  esac
  if [[ -f logs/$name/ckpt_$name.json ]]; then echo "$name: done, skipping"; continue; fi
  mkdir -p logs/$name
  echo "$name: building SFT set ($variant)"
  $PY build_sft.py --variant $variant --eval-set eval_set_v3.jsonl --out-prefix sft_$name \
      "${extra[@]}" > logs/$name/build_sft.log 2>&1
  resume=()
  [[ -d adapters/$name ]] && ls adapters/$name | grep -q '^checkpoint-' && resume=(--resume)
  echo "$name: training (seed $seed) ${resume[*]}"
  $PY -u train_qlora.py --train sft_${name}_train.jsonl --val sft_${name}_val.jsonl \
      --out adapters/$name --epochs 4 --sev-weight 20 --seed $seed "${resume[@]}" \
      >> logs/train_$name.log 2>&1
  echo "$name: sweeping checkpoints"
  $PY -u pick_checkpoint.py --adapter-dir adapters/$name --eval-set eval_set_v3.jsonl \
      --out-dir logs/$name --variant $variant > logs/$name/sweep.log 2>&1
  tail -12 logs/$name/sweep.log
done
