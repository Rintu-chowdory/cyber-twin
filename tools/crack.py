"""Wordlist attack against user credentials.

    python3 -m tools.crack [--report] [--world world.json]

Runs a common-password wordlist against every user account. Weak,
reused passwords crack; strong ones don't. With --report, cracked
credentials are submitted to the control API as attacker findings
(proof included, so they score) - unless the defender rotated them
already, in which case the claim is rejected.
"""
from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path

from world.schema import World
from world.seed import WEAK_PASSWORDS


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--world", default="world.json")
    ap.add_argument("--api", default="http://localhost:8000")
    ap.add_argument("--report", action="store_true",
                    help="submit cracked creds as attacker findings")
    args = ap.parse_args()

    world = World.load(args.world)
    user_creds = [c for c in world.credentials if c.owner]

    cracked = []
    for c in user_creds:
        if c.password in WEAK_PASSWORDS:
            cracked.append(c)

    print(f"== wordlist attack: {len(WEAK_PASSWORDS)} passwords x "
          f"{len(user_creds)} accounts ==")
    for c in cracked:
        emp = next((e for e in world.employees if e.id == c.owner), None)
        who = emp.name if emp else "?"
        print(f"  CRACKED {c.id}  {c.username:<28} ({who})  -> '{c.password}'")
    strong = len(user_creds) - len(cracked)
    print(f"\n{len(cracked)} cracked, {strong} resisted "
          f"({len(cracked) * 100 // max(1, len(user_creds))}% hit rate)")

    if not args.report:
        print("\n(use --report to submit findings to the control API)")
        return

    if not cracked:
        return
    ok = 0
    for c in cracked:
        body = json.dumps({"kind": "credential", "id": c.id,
                           "proof": c.password}).encode()
        req = urllib.request.Request(f"{args.api}/report", data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                res = json.loads(r.read())
            if res.get("ok"):
                ok += 1
                print(f"  reported {c.id}: +{res['awarded']} pts")
            else:
                print(f"  reported {c.id}: {res}")
        except urllib.error.HTTPError as e:
            print(f"  reported {c.id}: REJECTED ({e.code}) "
                  "- defender already rotated it?")
    print(f"\nsubmitted {ok} scoring findings")


if __name__ == "__main__":
    main()
