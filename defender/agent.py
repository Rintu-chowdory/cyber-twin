"""Defender agent skeleton.

Polls the control API, pulls fresh logs and the world diff, and leaves a
clearly marked hook where the LLM (the actual defender brain) decides
which actions to spend the daily budget on.

Run:  python -m defender.agent --api http://localhost:8000
"""
from __future__ import annotations

import argparse
import json
import time
import urllib.parse
import urllib.request


class Control:
    """Thin client for the control API (stdlib only)."""

    def __init__(self, base: str):
        self.base = base.rstrip("/")

    def get(self, path: str, **params) -> dict:
        qs = urllib.parse.urlencode(params)
        url = f"{self.base}{path}" + (f"?{qs}" if qs else "")
        with urllib.request.urlopen(url, timeout=10) as r:
            return json.loads(r.read())

    def act(self, action: str, target: str, param: str | None = None,
            note: str | None = None) -> dict:
        body = json.dumps({"action": action, "target": target,
                           "param": param, "note": note}).encode()
        req = urllib.request.Request(f"{self.base}/act", data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            return {"ok": False, "error": e.read().decode()}


def observe(api: Control) -> dict:
    return {
        "state": api.get("/state"),
        "diff": api.get("/diff"),
        "logs": api.get("/logs", limit=25),
    }


def decide(observation: dict, api: Control) -> list[dict]:
    """LLM HOOK: this is where the defender brain goes.

    Receives the full observation (state, diff, recent log lines) and
    returns a list of actions: [{"action": ..., "target": ..., "param": ...}].
    Must respect the budget - check observation["state"]["budget_remaining"].
    """
    # placeholder policy: do nothing yet
    return []


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://localhost:8000")
    ap.add_argument("--interval", type=float, default=60.0)
    args = ap.parse_args()

    api = Control(args.api)
    while True:
        obs = observe(api)
        for a in decide(obs, api):
            print(api.act(**a))
        print(json.dumps(obs["state"]))
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
