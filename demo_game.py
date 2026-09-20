"""Play a scripted demo game so the scoreboard page has real content.

Seed -> drift days -> attacker claims findings via the control API ->
defender remediates some incidents (and eats one collateral event) ->
score. Reproducible with --seed.
"""
from __future__ import annotations

import argparse
import json
import random
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

API = "http://localhost:8001"


def call(method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        API + path, data=data, method=method,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": e.code, "body": e.read().decode()}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--days", type=int, default=5)
    args = ap.parse_args()

    rng = random.Random(args.seed)

    # fresh world
    for f in ("world.json", "control/state.json"):
        Path(f).unlink(missing_ok=True)
    subprocess.run(["rm", "-rf", "history"], check=True)
    subprocess.run(["python3", "-m", "world.seed", "--seed", str(args.seed),
                    "--out", "world.json"], check=True, capture_output=True)

    world = json.loads(Path("world.json").read_text())
    weak = next(c for c in world["credentials"]
                if c["owner"] and c["strength"] < 0.5)
    strong = next(c for c in world["credentials"]
                  if c["owner"] and c["strength"] >= 0.9)
    db = next(c for c in world["credentials"]
              if "db-prod-01" in c["grants"])
    hr = next(c for c in world["credentials"] if "db-hr-01" in c["grants"])

    # drift
    for day in range(1, args.days + 1):
        subprocess.run(["python3", "-m", "tick", "--world", "world.json",
                        "--random", "--seed", str(args.seed * 100 + day)],
                       check=True, capture_output=True)

    # attacker claims (using REAL proof values from the world)
    print("attacker:", call("POST", "/report",
          {"kind": "credential", "id": weak["id"], "proof": weak["password"]}))
    print("attacker:", call("POST", "/report",
          {"kind": "credential", "id": strong["id"], "proof": strong["password"]}))
    print("attacker:", call("POST", "/report",
          {"kind": "asset_access", "id": "db-prod-01",
           "credential": db["id"], "proof": db["password"]}))
    print("attacker stale-proof (defender rotated):",
          call("POST", "/report",
               {"kind": "asset_access", "id": "db-hr-01",
                "credential": hr["id"], "proof": "wrong-password"}))

    # defender remediates what it can see
    state = json.loads(Path("control/state.json").read_text())
    # remediate all but the most recent incident - leave one OPEN on the board
    for inc in state["incidents"][:-1]:
        for t in inc["targets"]:
            if t.startswith("s"):
                r = call("POST", "/act", {"action": "rotate_secret", "target": t})
            elif t.startswith("e"):
                r = call("POST", "/act", {"action": "revoke_admin", "target": t})
            elif t.startswith("v") or t.startswith("ws") or t.startswith("web"):
                r = call("POST", "/act", {"action": "isolate_host", "target": t})
            else:
                r = call("POST", "/act", {"action": "rotate_credential", "target": t})
            if r.get("ok"):
                print("defender:", r["result"])

    sc = call("GET", "/score")
    print(f"\nattacker {sc['attacker']['score']} pts | defender {sc['defender']['score']} pts")


if __name__ == "__main__":
    main()
