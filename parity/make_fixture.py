"""
Build a conversion fixture from real EVTX records, for parity-testing any
reimplementation of the event -> contract conversion (OSAVA's TypeScript).

For each record it stores what a runtime reading the Windows event log gets --
the EventID and the raw EventData Name->text map -- and what the Python that
built the training data turns it into: contract.render(parse_record(xml)) and
its behaviour signature. A reimplementation must reproduce `body` and
`signature` byte for byte.

The output contains real telemetry from the capture machine. It is written
outside the repository on purpose; never commit it.

    python3 parity/make_fixture.py --out /tmp/fixture.json
"""
import argparse
import sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
import json
import random
from pathlib import Path
from xml.etree import ElementTree as ET

from Evtx.Evtx import Evtx

import contract as C
import evtx_to_contract as E
import targets
from signature import signature

NS = E.NS


def records(path):
    with Evtx(str(path)) as log:
        for rec in log.records():
            try:
                yield rec.xml()
            except Exception:
                continue


def raw_view(xml):
    """What PowerShell's Get-WinEvent gives a runtime: EventID + Name->text."""
    root = ET.fromstring(xml)
    eid = int(root.find(f"{NS}System").find(f"{NS}EventID").text)
    data = {}
    blk = root.find(f"{NS}EventData")
    if blk is not None:
        for d in blk.findall(f"{NS}Data"):
            if d.get("Name"):
                data[d.get("Name")] = d.text
    return eid, data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign", default="sysmon-benign.evtx")
    ap.add_argument("--attack-dir", default=str(Path.home() / "evtx-samples"))
    ap.add_argument("--per-file", type=int, default=40)
    ap.add_argument("--benign-n", type=int, default=2500)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    repo = Path(__file__).resolve().parent.parent
    if Path(args.out).resolve().is_relative_to(repo):
        sys.exit(f"refusing to write real telemetry inside the repository: {args.out}")

    rng = random.Random("osava-parity")
    xmls = []
    b = list(records(args.benign))
    xmls += rng.sample(b, min(args.benign_n, len(b)))
    for f in sorted(Path(args.attack_dir).rglob("*.evtx")):
        got = list(records(f))
        xmls += rng.sample(got, min(args.per_file, len(got)))

    cases, skipped = [], 0
    for xml in xmls:
        try:
            eid, data = raw_view(xml)
        except Exception:
            skipped += 1
            continue
        fields = E.parse_record(xml)
        if fields is None:
            cases.append({"eid": eid, "data": data, "body": None, "signature": None})
            continue
        body = C.render(fields, "backfill")
        cases.append({"eid": eid, "data": data, "body": body,
                      "signature": signature(targets.parse(body))})
    Path(args.out).write_text(json.dumps(cases, ensure_ascii=False))
    conv = sum(1 for c in cases if c["body"])
    longc = sum(1 for c in cases if c["body"] and C.TRUNC_MARKER in c["body"])
    print(f"{len(cases)} records ({conv} convert, {len(cases)-conv} rejected, "
          f"{skipped} unreadable); {longc} exercise truncation")


if __name__ == "__main__":
    main()
