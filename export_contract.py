"""
Emit the classifier contract as one machine-readable artefact.

    python3 export_contract.py --out contract.json

The problem this solves: the contract is authored in Python (prompt.py,
contract.py, indicators.py) and consumed in TypeScript (HIRA). Every shared
fact -- the input field order, the severity scale, the bucketing, the
escalation rule, the output schema -- was independently restated on the
TypeScript side, and the restatements had already drifted:

  * HIRA's VALID_SEVERITIES still carried `critical`, dropped from this tier
    on evidence (R5).
  * parseClassification() required `confidence`, removed by R7, so every
    response failed validation and fell back to "benign".
  * promptBuilder's few-shot examples demonstrate the pre-R4 seven-field
    schema with severity fourth, contradicting what the model was trained on.

A contract that is restated is a contract that drifts. This file is the only
place it is written down; HIRA reads the JSON and checks `prompt_sha256`
against the deployed Modelfile at startup, so drift fails loudly instead of
silently degrading classification.
"""

import argparse
import hashlib
import re
import json
from pathlib import Path

import prompt as P
from contract import FIELD_ORDER, MAX_CMDLINE, TRUNC_MARKER
import evtx_to_contract as EVTX
import contract as C
from indicators import INDICATORS
from targets import BENIGN_KEYS

# Input types this model can actually classify. It was trained on Windows
# Sysmon telemetry rendered into FIELD_ORDER and nothing else; on anything
# else it returns "none" with high confidence, which is the worst possible
# failure for an intake tier. Anything outside this set must not be routed
# here -- see HIRA cascadeRouter.
SUPPORTED_INPUT_TYPES = ["log_lines", "process_list", "registry_entry"]

# threatType values that force escalation regardless of severity. Restores the
# rule the pre-R7 Modelfile stated, now evaluated host-side.
ESCALATE_THREAT_TYPES = [
    "lateral_movement", "data_exfiltration", "ransomware",
    "privilege_escalation", "supply_chain", "rce", "zero_day",
]


def trained_event_ids(train="train_final.jsonl"):
    """EventIDs the model has actually seen. Derived from the training data,
    not listed by hand: the parser accepts 13 EventIDs but training only ever
    contained 8, and a live Sysmon feed produces the other five (DNS queries,
    process access, remote threads) in volume. Those are out of distribution,
    and out of distribution this model answers "none" rather than declining."""
    ids = set()
    for line in Path(train).read_text().splitlines():
        if line.strip():
            ids.add(int(json.loads(line)["event"].split("\n", 1)[0].split(":")[1]))
    return sorted(ids)


def prompt_template(variant, scale):
    """The EXACT string the model was trained on, with {body} for the event.

    Rendered through the real tokenizer's chat template, so a runtime that
    takes a raw prompt (llama-server /completion) sends byte-identical input
    to training -- no second templating layer, no injected date header."""
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained("HuggingFaceTB/SmolLM3-3B")
    mark = "\u0000BODY\u0000"
    s = P.build_prompt(tok, mark, variant, scale)
    assert s.count(mark) == 1
    return s.replace(mark, "{body}")


# Held-out events with a known answer, run by the host every time it starts
# the model. A checksum proves the file is the file; it does not prove the
# file is the classifier (an untrained SmolLM3 of the same size and
# architecture once passed for it). Chosen so the untrained base gets them
# wrong: M011 and X074 are attacks the base model rates "none", and B025 is a
# plain signed-DLL load that catches a model which flags everything.
# Public (EVTX-ATTACK-SAMPLES) or synthetic only -- never local telemetry.
CANARIES = ["M011", "X074", "B025"]


def canaries(ids, eval_set):
    """Canary bodies and expected buckets, taken from the eval set rather than
    restated. Every id must have been confirmed against the GGUF this contract
    is bound to: the expectation is the gold label, and a canary the model
    gets wrong would block every start."""
    rows = {r["id"]: r for r in map(json.loads, Path(eval_set).read_text().splitlines())}
    return [{"id": i, "body": rows[i]["event"], "expect": rows[i]["gold"]} for i in ids]


def build(variant="strict", scale="4way", model=None, canary_rows=None):
    system = P.system_prompt(variant, scale, override=True)
    return {
        "schema_version": "2.1.0",
        "base": "HuggingFaceTB/SmolLM3-3B",
        "generated_by": "osava-ft/export_contract.py",

        # R1 -- the frozen input contract. Order is load-bearing: the model
        # was trained on exactly this sequence.
        "input": {
            "field_order": FIELD_ORDER,
            "max_cmdline": MAX_CMDLINE,
            "truncation_marker": TRUNC_MARKER,
            "user_message_template": "Event:\n{body}\n\nClassify.",
            "supported_input_types": SUPPORTED_INPUT_TYPES,
            "supported_event_ids": trained_event_ids(),
        },

        # How a raw Sysmon / Security record becomes a contract body. Every
        # entry is copied from the code that built the training data
        # (evtx_to_contract.parse_record, contract.render): a runtime that
        # converts events any other way is feeding the model a different
        # distribution than it learned from.
        "conversion": {
            "event_types": {str(k): v for k, v in C.EVENT_TYPES.items()},
            "field_map": EVTX.FIELD_MAP,
            "null_values": ["-", "N/A", "0x0"],
            "percent_unescape": ["%%", "%"],
            # Signed/Signer are backfilled from the image path on these
            # EventIDs and stripped from every other one -- the training data
            # had them on process creation and image load, and nowhere else.
            "signature_eids": [1, 7, 4688],
            "signature_backfill": {
                "vendor_signers": C.VENDOR_SIGNERS,
                "microsoft_signer": C.MS_SIGNER,
                "system_dirs": list(C.SYSTEM_DIRS),
                "writable_windows_dirs": list(C.WRITABLE_WINDOWS_DIRS),
                "unsigned_prefixes": ["c:\\users\\public"],
            },
        },

        "prompt": {
            "template": prompt_template(variant, scale),
            # prefilled so the first generated token IS the severity: its
            # probabilities give the R7 margin, which Ollama never exposed
            "prefill": P.PREFIX,
            "stop": ["<|im_end|>"],
        },
        "model": model or {},
        "canaries": canary_rows or [],

        # R4/R5 -- severity first, four-way. `critical` is accepted on input
        # for backward compatibility and folded into `high`.
        "severity": {
            "scale": P.SCALES[scale],
            "accepted_on_input": P.SCALES["5way"],
            "bucket": P.BUCKET,
            "classes": P.CLASSES,
            "score_prefix": P.PREFIX,
        },

        # R7 -- routing is the host's decision, not the model's.
        "routing": {
            "escalate_severities": ["high", "critical"],
            "escalate_threat_types": ESCALATE_THREAT_TYPES,
            "confidence_reported_by_model": False,
            "confidence_from_severity": {
                "none": 0.05, "low": 0.2, "medium": 0.5,
                "high": 0.85, "critical": 0.95,
            },
        },

        # R6 -- closed indicator vocabulary.
        "indicators": sorted(INDICATORS),
        # Indicators that argue FOR normality. A threat verdict citing only
        # these is unsupported: the evidence shown does not explain it.
        "exculpatory_indicators": sorted(BENIGN_KEYS),
        "threat_types": P.threat_types(variant),

        "output_fields": ["severity", "isThreat", "threatType",
                          "indicators", "reasoning"],

        # Drift detector. HIRA compares this against the SYSTEM block of the
        # Modelfile it deployed; a mismatch means the model is being prompted
        # differently from how it was trained, which is invisible otherwise.
        "prompt_sha256": hashlib.sha256(system.encode()).hexdigest(),
        "prompt_variant": variant,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="contract.json")
    ap.add_argument("--variant", choices=list(P.TAIL), default="strict")
    ap.add_argument("--scale", choices=list(P.SCALES), default="4way")
    ap.add_argument("--model-sha256", default=None,
                    help="sha256 of the GGUF this contract belongs to")
    ap.add_argument("--model-bytes", type=int, default=None)
    ap.add_argument("--model-name", default="osava-smollm")
    ap.add_argument("--canaries", nargs="*", default=CANARIES,
                    help="eval ids run at startup; only emitted with --model-sha256")
    ap.add_argument("--eval-set", default="eval_set_v3.jsonl")
    ap.add_argument("--also", nargs="*", default=[],
                    help="additional paths to write the same artefact to "
                         "(e.g. HIRA/backend/src/ollama/contract.json)")
    args = ap.parse_args()

    model = ({"name": args.model_name, "gguf_sha256": args.model_sha256,
              "gguf_bytes": args.model_bytes, "quantisation": "Q4_K_M"}
             if args.model_sha256 else None)
    # Canaries are a claim about one specific model, so they ride with it.
    doc = build(args.variant, args.scale, model,
                canaries(args.canaries, args.eval_set) if model else None)
    # The host guard resets any threatType not on this list, so a wrong list
    # silently rewrites every answer. Check it against the prompt the model
    # actually reads, not against the source that produced it.
    system = P.system_prompt(args.variant, args.scale, override=True)
    tt = doc["threat_types"]
    assert "unknown" in tt and len(tt) >= 10, tt
    assert all(re.search(rf"\b{t}\b", system) for t in tt), tt
    text = json.dumps(doc, indent=2) + "\n"
    for p in [args.out, *args.also]:
        Path(p).write_text(text)
        print(f"wrote {p}")
    print(f"\nschema_version   {doc['schema_version']}")
    print(f"prompt_sha256    {doc['prompt_sha256'][:16]}…")
    print(f"input fields     {len(doc['input']['field_order'])}")
    print(f"supported types  {', '.join(doc['input']['supported_input_types'])}")
    print(f"indicators       {len(doc['indicators'])}")


if __name__ == "__main__":
    main()
