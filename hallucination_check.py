"""
Measure hallucination in the classifier's generated output.

Accuracy measures `severity` only. Severity is drawn from a closed set of four
words: it can be wrong, but it cannot be invented. The fields that CAN be
invented are the explanation -- indicator keys, indicator values, threatType,
and reasoning -- and nothing in the eval harness looked at them. This does.

Every check is against the input event, never against a gold label: the
question is not "is the model right" but "is everything it says actually
there".

    python3 hallucination_check.py                          # generate with bf16, score
    python3 hallucination_check.py --responses q4_raw.json  # score Ollama output

Checks, per event:
  parse         output is valid JSON
  severity      value in the contract's scale
  threat_type   value in the prompt's threatType list
  key_vocab     every indicator key is in the closed vocabulary (R6)
  grounded      every indicator value is actually present in the event
  verdict       the reasoning's verdict sentence agrees with the severity
  supported     a threat verdict cites at least one incriminating indicator, or
                says honestly (context_dependent) that no single field does.
                Reassuring evidence presented as the reason is what fails.
"""

import argparse
import json
import re
from collections import Counter
from pathlib import Path

import prompt as P
from indicators import INDICATORS
from targets import BENIGN_KEYS, VERDICT, VERDICT_CONTEXT

THREAT_TYPES = set(P.threat_types("strict"))     # reset from --variant in main()
SCALE = set(P.SCALES["4way"])


def norm(s):
    return re.sub(r"\s+", " ", str(s)).strip().lower()


def grounded(value, event):
    """Is this indicator value actually in the event?

    targets.py writes values in a few derived shapes, all of which are
    checked: a verbatim field, `parent -> child`, `ip:port`, a lowercased
    directory, and text clipped with a trailing ellipsis. `-` is the
    no-evidence sentinel and is not a claim."""
    v = str(value).strip()
    if v in ("", "-"):
        return True
    v = v.rstrip("\u2026").rstrip()
    ev = norm(event)
    parts = re.split(r"\s*->\s*", v) if "->" in v else [v]
    for p in parts:
        p = norm(p)
        if not p or p in ev:
            continue
        m = re.fullmatch(r"(.+):(\d+)", p)
        if m and m.group(1) in ev and m.group(2) in ev:
            continue
        return False
    return True


def verdict_of(reasoning):
    r = reasoning.lower()
    for table in (VERDICT, VERDICT_CONTEXT):
        for cls, sentence in table.items():
            if sentence[:40].lower() in r:
                return cls
    return None


def extract_json(text):
    a, b = text.find("{"), text.rfind("}")
    if a < 0 or b <= a:
        raise ValueError("no JSON object")
    return json.loads(text[a:b + 1])


def check(event, raw):
    rec = {"parse": True, "severity": True, "threat_type": True, "key_vocab": True,
           "grounded": True, "verdict": True, "supported": True,
           "bad_keys": [], "ungrounded": [], "raw": raw}
    try:
        out = extract_json(raw)
    except Exception:
        rec.update(parse=False)
        return rec
    sev = out.get("severity")
    rec["severity_value"] = sev
    rec["severity"] = sev in SCALE
    tt = out.get("threatType")
    rec["threat_type"] = tt is None or tt in THREAT_TYPES
    ind = out.get("indicators") or {}
    if not isinstance(ind, dict):
        ind = {}
    rec["bad_keys"] = [k for k in ind if k not in INDICATORS]
    rec["key_vocab"] = not rec["bad_keys"]
    rec["ungrounded"] = [(k, v) for k, v in ind.items() if not grounded(v, event)]
    rec["grounded"] = not rec["ungrounded"]
    bucket = P.BUCKET.get(sev)
    said = verdict_of(str(out.get("reasoning", "")))
    rec["verdict"] = said is None or said == bucket
    rec["context_dependent"] = "context_dependent" in ind
    if bucket in ("malicious", "suspicious"):
        rec["supported"] = any(k not in BENIGN_KEYS for k in ind)
    return rec


VARIANT = "strict"


def generate(model_path, rows, max_new):
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(model_path)
    m = AutoModelForCausalLM.from_pretrained(
        model_path, dtype=torch.bfloat16, device_map="cuda:0",
        attn_implementation="sdpa").eval()
    out = {}
    for i, r in enumerate(rows, 1):
        p = P.build_prompt(tok, r["event"], VARIANT, "4way")
        ids = tok(p, return_tensors="pt", add_special_tokens=False).input_ids.to("cuda:0")
        with torch.no_grad():
            g = m.generate(ids, max_new_tokens=max_new, do_sample=False,
                           pad_token_id=tok.eos_token_id)
        out[r["id"]] = tok.decode(g[0, ids.shape[1]:], skip_special_tokens=True)
        print(f"  {i:>3}/{len(rows)}  {r['id']}", flush=True)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="dist/sentri-v1")
    ap.add_argument("--eval-set", default="eval_set_v3.jsonl")
    ap.add_argument("--responses", default=None,
                    help="JSON {id: raw_text} from another runtime, e.g. Ollama")
    ap.add_argument("--max-new", type=int, default=240)
    ap.add_argument("--out", default="logs/hallucination.json")
    ap.add_argument("--variant", default="strict", choices=list(P.TAIL),
                    help="prompt variant: sets the threatType list checked against")
    args = ap.parse_args()
    THREAT_TYPES.clear()
    THREAT_TYPES.update(P.threat_types(args.variant))
    global VARIANT
    VARIANT = args.variant

    rows = [json.loads(l) for l in Path(args.eval_set).read_text().splitlines() if l.strip()]
    if args.responses:
        raw = json.loads(Path(args.responses).read_text(encoding="utf-8-sig"))
    else:
        raw = generate(args.model, rows, args.max_new)

    recs = {r["id"]: check(r["event"], raw[r["id"]]) for r in rows if r["id"] in raw}
    n = len(recs)
    Path(args.out).write_text(json.dumps(recs, indent=2))

    names = ["parse", "severity", "threat_type", "key_vocab", "grounded", "verdict", "supported"]
    print(f"\n{n} outputs checked\n")
    for k in names:
        bad = [i for i, r in recs.items() if not r[k]]
        print(f"  {k:<12} {n-len(bad):>4}/{n} ok   {len(bad):>3} failing  {bad[:6]}")
    keys = Counter(k for r in recs.values() for k in r["bad_keys"])
    if keys:
        print(f"\ninvented indicator keys: {dict(keys.most_common(8))}")
    cd = sum(1 for r in recs.values() if r.get("context_dependent"))
    print(f"\n  context_dependent (honestly unexplained): {cd}/{n}")
    ug = [(i, k, v) for i, r in recs.items() for k, v in r["ungrounded"]]
    if ug:
        print(f"\nungrounded indicator values ({len(ug)}):")
        for i, k, v in ug[:10]:
            print(f"  {i:<6}{k:<26}{str(v)[:70]}")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
