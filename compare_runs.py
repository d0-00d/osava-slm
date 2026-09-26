"""
Compare trained runs on the held-out eval set, per event.

    python3 compare_runs.py v3=logs/v3/ckpt_step282.json v5=logs/v5/ckpt_step460.json ...

Accuracy on 138 events moves in steps of 0.7 points, and one run's checkpoints
already swing by 6 (v3: 86-92%), so two single runs differing by four events
say little. Next to accuracy this reports the model's probability on the gold
class, averaged per class -- continuous, so it moves before a prediction flips
-- and splits the set into events whose action appears in train_final
("overlap", which the action quarantine removes from training) and the rest
("clean"). A run trained without the quarantine is only comparable on clean.
"""

import json
import sys
from pathlib import Path

from boundary import pblind

CLASSES = ("benign", "suspicious", "malicious")


def load(path):
    return {r["id"]: r for r in json.loads(Path(path).read_text())}


def main():
    runs = [a.split("=", 1) for a in sys.argv[1:]]
    if not runs:
        raise SystemExit(__doc__)
    ev = [json.loads(l) for l in Path("eval_set_v3.jsonl").read_text().splitlines() if l.strip()]
    tr_act = {pblind(json.loads(l)) for l in Path("train_final.jsonl").read_text().splitlines()
              if l.strip()}
    overlap = {e["id"] for e in ev if pblind(e) in tr_act}
    ids = [e["id"] for e in ev]
    gold = {e["id"]: e["gold"] for e in ev}
    data = {name: load(p) for name, p in runs}

    def acc(d, sub):
        sub = [i for i in sub if i in d]
        return sum(d[i]["pred"] == gold[i] for i in sub), len(sub)

    clean = [i for i in ids if i not in overlap]
    print(f"{len(clean)} clean events, {len(overlap)} overlap; P(gold|class) is over clean events\n")
    head = f"{'run':<14}{'all':>13}{'clean':>13}{'overlap':>9}  " + \
           "".join(f"P(gold|{c[:4]})".rjust(14) for c in CLASSES) + "  threat->benign"
    print(head)
    for name, d in data.items():
        a, n = acc(d, ids)
        c, cn = acc(d, clean)
        o, on = acc(d, overlap)
        pg = []
        for cls in CLASSES:
            xs = [d[i]["class_probs"][cls] for i in clean if gold[i] == cls and i in d]
            pg.append(sum(xs) / len(xs))
        missed = sum(1 for i in ids if i in d and gold[i] != "benign" and d[i]["pred"] == "benign")
        print(f"{name:<14}{f'{a}/{n}':>8} {a/n:4.0%}{f'{c}/{cn}':>8} {c/cn:4.0%}{f'{o}/{on}':>9}  "
              + "".join(f"{p:14.3f}" for p in pg) + f"{missed:>16}")

    names = list(data)
    print(f"\nevents where the runs disagree (gold, then each run; * = overlap):")
    for i in ids:
        preds = [data[n][i]["pred"] if i in data[n] else "-" for n in names]
        if len(set(preds)) > 1:
            print(f"  {'*' if i in overlap else ' '}{i:<6}{gold[i]:<12}"
                  + "".join(f"{n}={p:<12}" for n, p in zip(names, preds)))


if __name__ == "__main__":
    main()
