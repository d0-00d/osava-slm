"""
Logon events (4624/4625) the corpus barely has.

26 of 2,017 training rows were logons, most with no indicator at all, and v5
invented keys for them (`negotiate_auth`, `ntlm_auth`) because nothing in its
training showed what to say about a logon. A logon carries four fields --
User, LogonType, AuthPackage and the source address -- so the rows below vary
exactly those, as contrasts: the same LogonType or AuthPackage with the account
or the outcome changed.

Labels follow the policy of the human-labelled real logons already in
train_final, not a new one:

    none        console (2), service (5), batch (4), system (0), Kerberos network (3)
    low         a failed console or service logon; a failed network logon by an
                ordinary account (stale credentials)
    medium      NewCredentials (9: runas /netonly, pass-the-hash), RDP (10) over
                loopback (tunnelled), a failed NTLM network logon against
                Administrator or Guest (the account password spraying targets)

Only field combinations Windows actually emits: interactive and service logons
report `Negotiate`; Kerberos appears on network logons; a failed network logon
reports `NTLM` (Kerberos pre-auth failures are 4771 on the DC, not 4625).

Combinations whose action (boundary.pblind: EventID, LogonType, AuthPackage)
belongs to an eval event are not generated -- build_sft.py's quarantine would
drop them anyway. That rules out 4624 type 3 NTLM, type 7 and type 11
Negotiate: the eval tests those, and the model must generalise to them.

    # ids are TL###
    python3 gen_logons.py --append train_final.jsonl train_final_5way.jsonl
"""

import argparse
import json
from pathlib import Path

from boundary import pblind
from contract import DOMAIN, HOSTS, LOCAL_USERS, SERVERS, render, stable_rng
from signature import signature
import targets

SYS = "NT AUTHORITY\\SYSTEM"
SERVICE_ACCTS = [SYS, "NT AUTHORITY\\LOCAL SERVICE", "NT AUTHORITY\\NETWORK SERVICE",
                 f"{DOMAIN}\\svc-deploy", f"{DOMAIN}\\svc-backup"]


def internal_ip(r):
    return f"10.14.{r.randint(7, 30)}.{r.randint(2, 250)}"


def user(r, kind):
    if kind == "domain":
        return f"{DOMAIN}\\{r.choice(LOCAL_USERS)}"
    return f"{r.choice(HOSTS)}\\{r.choice(LOCAL_USERS)}"


def families(r):
    host = r.choice(HOSTS + SERVERS)
    loop = r.choice(["127.0.0.1", "::1"])
    return [
        # --- benign
        ("console logon", "benign", "none", "-", dict(
            EventID=4624, User=user(r, r.choice(["local", "domain"])),
            DestinationIp=r.choice([None, "127.0.0.1"]), LogonType=2, AuthPackage="Negotiate")),
        ("service logon", "benign", "none", "-", dict(
            EventID=4624, User=r.choice(SERVICE_ACCTS), LogonType=5, AuthPackage="Negotiate")),
        ("scheduled task logon", "benign", "none", "-", dict(
            EventID=4624, User=r.choice([f"{DOMAIN}\\svc-backup", f"{DOMAIN}\\svc-deploy",
                                         user(r, "domain")]),
            LogonType=4, AuthPackage="Negotiate")),
        ("system logon at boot", "benign", "none", "-", dict(
            EventID=4624, User=SYS, LogonType=0)),
        ("Kerberos network logon", "benign", "none", "-", dict(
            EventID=4624, User=r.choice([user(r, "domain"), f"{DOMAIN}\\{host}$"]),
            DestinationIp=internal_ip(r), LogonType=3, AuthPackage="Kerberos")),
        ("failed console logon", "benign", "low", "-", dict(
            EventID=4625, User=user(r, r.choice(["local", "domain"])),
            DestinationIp=r.choice([None, "127.0.0.1"]), LogonType=2, AuthPackage="Negotiate")),
        ("failed service logon", "benign", "low", "-", dict(
            EventID=4625, User=r.choice([f"{DOMAIN}\\svc-backup", f"{DOMAIN}\\svc-deploy"]),
            LogonType=5, AuthPackage="Negotiate")),
        ("failed network logon, ordinary account", "benign", "low", "-", dict(
            EventID=4625, User=user(r, "domain"), DestinationIp=internal_ip(r),
            LogonType=3, AuthPackage="NTLM")),
        # --- suspicious
        ("new credentials logon", "suspicious", "medium", "T1550.002", dict(
            EventID=4624, User=user(r, r.choice(["local", "domain"])),
            DestinationIp=loop, LogonType=9, AuthPackage="Negotiate")),
        ("RDP logon over loopback", "suspicious", "medium", "T1572", dict(
            EventID=4624, User=user(r, r.choice(["local", "domain"])),
            DestinationIp=loop, LogonType=10, AuthPackage="Negotiate")),
        ("failed network logon, privileged or guest account", "suspicious", "medium", "T1110.003", dict(
            EventID=4625, User=r.choice([f"{r.choice(HOSTS)}\\Administrator",
                                         f"{DOMAIN}\\Administrator", f"{r.choice(HOSTS)}\\Guest"]),
            DestinationIp=r.choice([internal_ip(r), f"185.220.101.{r.randint(2, 250)}"]),
            LogonType=3, AuthPackage="NTLM")),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-family", type=int, default=6)
    ap.add_argument("--eval-set", default="eval_set_v3.jsonl")
    ap.add_argument("--append", nargs="*", default=[])
    ap.add_argument("--out", default="train_logons.jsonl")
    args = ap.parse_args()

    ev_act = {pblind(json.loads(l)) for l in Path(args.eval_set).read_text().splitlines() if l.strip()}
    rows, n, seen = [], 0, set()
    for i in range(args.per_family):
        r = stable_rng(f"logon-{i}")
        for name, gold, sev, attck, fields in families(r):
            fields = {k: v for k, v in fields.items() if v is not None}
            body = render(fields)
            if body in seen:                       # same account drawn twice
                continue
            seen.add(body)
            n += 1
            row = {"id": f"TL{n:03d}", "name": name, "gold": gold, "severity": sev, "event": body,
                   "provenance": {"source": "synthetic:gen_logons",
                                  "signature": signature(targets.parse(body)),
                                  "attck": attck, "family": name,
                                  "label_rule": "generator, following the human labels on real logons",
                                  "rationale": f"logon contrast: {name}"}}
            assert pblind(row) not in ev_act, f"{name} recreates an eval action: {pblind(row)}"
            rows.append(row)
    Path(args.out).write_text("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in rows))
    print(f"wrote {args.out}: {len(rows)} rows")

    for path in args.append:
        p = Path(path)
        have = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
        ids = {x["id"] for x in have}
        assert not any(x["id"].startswith("TL") and x["id"] not in {y["id"] for y in rows}
                       for x in have), "unexpected TL ids already present"
        new = [x for x in rows if x["id"] not in ids]      # idempotent
        p.write_text("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in have + new))
        print(f"  {path}: +{len(new)} (now {len(have) + len(new)})")


if __name__ == "__main__":
    main()
