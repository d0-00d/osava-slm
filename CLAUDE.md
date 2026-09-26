# osava-ft (SENTRI-Classifier)

QLoRA fine-tune of SmolLM3-3B that classifies one Windows Sysmon / Security
event as none/low/medium/high and explains why in JSON. README.md has the
pipeline and module map; this file is the working state and the rules.

## What runs where

This repo is also worked on from cloud sessions, which have **no GPU** and none
of the gitignored artefacts (`adapters/`, `dist/`, `*.evtx`, `sft_*.jsonl`).

| Runs anywhere (CPU) | Needs the local GPU machine |
|---|---|
| `targets.py`, `build_sft.py`, `export_contract.py` (downloads the SmolLM3 tokenizer) | `train_qlora.py` (~2.5 h on an 8 GB 4060) |
| `hallucination_check.py --responses <file>` | `pick_checkpoint.py`, `run_eval.py`, `merge_export.py` |
| `report.py` over committed `logs/` | `hallucination_check.py` without `--responses` |

Install with `pip install -r requirements.txt` (the torch pin is the CUDA build
used locally; CPU torch is fine for everything in the left column).

Check every training target against the seven hallucination gates (must stay
at 0 failures; this is how target-extractor changes are validated):

    python3 -c "import json,targets; rows=[json.loads(l) for l in open('train_final.jsonl')]; json.dump({r['id']: json.dumps(targets.build(r,'v2')) for r in rows}, open('/tmp/t.json','w'))"
    python3 hallucination_check.py --eval-set train_final.jsonl --responses /tmp/t.json --variant strict2 --out /tmp/t_check.json

## Current state (2026-09-26)

**Deployed: v3 checkpoint-282**, Ollama `osava-smollm` Q4_K_M, GGUF sha256
`9ab1eba2…3d51`, prompt variant `strict` (threatType vocabulary v1,
prompt_sha256 `8906351f…`). `contract.json` is bound to it.

**v5 trained, not deployed.** Tier-1 target rewrite + action quarantine +
`strict2` prompt. Scored with the same 4-bit+adapter method
(`logs/v3/ckpt_step282.json`, `logs/v5/ckpt_step460.json`):

| | v3 step282 | v5 step460 |
|---|---|---|
| accuracy (138 held-out) | 92.0% | 86.2% |
| malicious recall | 100% | 85.7% (8 malicious -> medium) |
| suspicious recall | 46.7% | 60.0% |
| threats scored benign | 0 | 0 |
| unsupported alerts (`logs/hallucination_*.json`) | 49 | **1** |
| parse failures | 0 | 2 (M010, X021) |

The target rewrite fixed explanations. Most of the accuracy gap is not a
regression: at matched final checkpoints v3 and v5 both score 107/122 on the
events whose action is absent from training (`python3 compare_runs.py`); v3's
92% was the best of ten checkpoints picked on this eval set, and v5 lost 4 of
the 16 overlap events because the quarantine removed their training twins.
What is real: on clean malicious events v5's P(gold) fell from 0.79 to 0.67.

## v6 (in progress, started 2026-09-26)

Data changes, all validated by the gate check (0 failures on 2,070 targets):

1. Indicator values quote the span their rule matched (`-w hidden`,
   `FromBase64String`, the URL of a cradle), not the 120-char command-line
   prefix that v5 learned to copy until it ran out of tokens.
2. Logons: keys `interactive_logon`, `service_logon`, `kerberos_auth`
   (exculpatory) and `new_credentials_logon`, `remote_interactive_logon`,
   `failed_logon`; 53 rows from `gen_logons.py` (TL###) following the labels of
   the real logons. 4624 type 3 NTLM and types 7/11 Negotiate are eval-only
   actions and are not generated.

Severity ablation, one change per run (`./run_ablation.sh`, ~2.5 h each):
`v6` (candidate), `v6-seed2` (noise floor, read first), `v6-strict` (prompt),
`v6-noquar` (quarantine; compare on clean only). Compare with
`compare_runs.py v5=logs/v5/ckpt_step460.json v6=logs/v6/ckpt_v6.json ...`.

After any target change: rerun the gate check above, then `build_sft.py
--variant strict2 --eval-set eval_set_v3.jsonl`, then train locally.

## Rules

- **The repo is public.** Never commit raw telemetry: `*.evtx`, or the output
  of `parity/make_fixture.py` (it refuses to write inside the repo). Training
  data here comes from EVTX-ATTACK-SAMPLES and synthetic generators only.
- When a model is deployed, regenerate the contract for it:
  `python3 export_contract.py --out contract.json --model-sha256 <gguf sha> --model-bytes <n> [--variant strict2]`.
  Canaries (M011, X074, B025) are a claim about that model; confirm them on it
  before shipping, or OSAVA refuses to start the model.
- Read every benign row a new target rule fires on; rules must match the verb,
  not the path.
- New synthetic rows need an id prefix no other file uses (`TB###` is taken).

## Consumers of contract.json

- **OSAVA** (`d0-00d/osava`, branch `feat/behaviour-classifier`): llama-server
  sidecar, copy at `backend/src/services/behaviour/contract.json`. Held-out:
  124/138 on the deployed Q4, byte parity with this repo's converter on 5,267
  records.
- **HIRA** (`Basith-S/HIRA`, PR #1): Ollama path. Known bugs: `buildContractPrompt`
  uses string `.replace`, so `$&`/`$'` in an event corrupt the prompt; its
  renderer lacks the Signed/Signer backfill.
