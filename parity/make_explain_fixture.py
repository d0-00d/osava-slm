"""
Expected explanations, for parity-testing a reimplementation of targets.py
(OSAVA's explain.ts, which computes a verdict's indicators, threatType and
reasoning on the host instead of having the model generate them).

For every event body, under each of the three severity classes, it records
what targets.build() produces. A reimplementation must reproduce every field
byte for byte, including indicator order.

Bodies come from train_final and the eval set, and optionally from the
conversion fixture (parity/make_fixture.py), which holds real telemetry -- so
the output is written outside the repository, like that fixture.

    python3 parity/make_explain_fixture.py --out /tmp/explain.json [--real /tmp/fixture.json]
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import targets  # noqa: E402

CLASSES = ("benign", "suspicious", "malicious")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--real", help="conversion fixture from make_fixture.py")
    ap.add_argument("--vocab", default="v2")
    args = ap.parse_args()
    repo = Path(__file__).resolve().parent.parent
    if Path(args.out).resolve().is_relative_to(repo):
        sys.exit(f"refusing to write inside the repository: {args.out}")

    bodies = []
    for f in ("train_final.jsonl", "eval_set_v3.jsonl"):
        bodies += [json.loads(l)["event"] for l in (repo / f).read_text().splitlines() if l.strip()]
    if args.real:
        bodies += [c["body"] for c in json.loads(Path(args.real).read_text()) if c.get("body")]
    bodies = list(dict.fromkeys(bodies))

    cases = []
    for body in bodies:
        for cls in CLASSES:
            t = targets.build({"event": body, "gold": cls, "severity": None}, args.vocab)
            cases.append({"body": body, "cls": cls, "isThreat": t["isThreat"],
                          "threatType": t["threatType"],
                          "indicators": list(t["indicators"].items()),
                          "reasoning": t["reasoning"]})
    Path(args.out).write_text(json.dumps(cases, ensure_ascii=False))
    print(f"{len(bodies)} bodies x {len(CLASSES)} classes = {len(cases)} cases -> {args.out}")


if __name__ == "__main__":
    main()
