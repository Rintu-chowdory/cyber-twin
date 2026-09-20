"""Cyber Twin defender control API.

The defender's entire action space, priced in points so it can't just
nuke everything. Collateral damage (locking an employee out) is recorded.

Run from the repo root:

    uvicorn control.api:app --port 8000     # local
    docker compose up defender-api           # in the lab

Actions (POST /act, JSON body {"action", "target", "param", "note"}):

    block_ip          1 pt   target = attacker IPv4
    isolate_host      3 pts   target = asset id (collateral if workstation)
    rotate_credential 2 pts   target = credential id
    rotate_secret     2 pts   target = secret id (kills exposed copies)
    patch_service     5 pts   target = asset id, param = vuln id
    restore_backup   20 pts   target = asset id (rebuild from backup)

Budget: 100 pts per day; reset by the daily tick.
"""
from __future__ import annotations

import json
import os
import re
import secrets as pysecrets
import string
import threading
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from score import compute_scores
from world.schema import World

WORLD_PATH = Path(os.environ.get("WORLD_PATH", "world.json"))
STATE_PATH = Path(os.environ.get("STATE_PATH", "control/state.json"))
HISTORY_DIR = Path(os.environ.get("HISTORY_DIR", "history"))
LOG_ROOT = Path(os.environ.get("LOG_ROOT", "/mnt"))

DAILY_BUDGET = 100
COSTS = {
    "block_ip": 1,
    "isolate_host": 3,
    "rotate_credential": 2,
    "rotate_secret": 2,
    "patch_service": 5,
    "restore_backup": 20,
    "revoke_admin": 2,
}

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

from score import ATTACKER_POINTS  # noqa: E402

app = FastAPI(title="cyber-twin control plane")
_LOCK = threading.Lock()


# ------------------------------------------------------------------ state

def _load_state() -> dict:
    state = {"day": 0, "budget_used": 0, "blocked_ips": [],
             "actions": [], "collateral": [], "incidents": [], "findings": []}
    if STATE_PATH.exists():
        state.update(json.loads(STATE_PATH.read_text()))
    state.setdefault("incidents", [])
    state.setdefault("findings", [])
    return state


def _save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2))


def _strong_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(pysecrets.choice(alphabet) for _ in range(20))


# ------------------------------------------------------------------ reads

@app.get("/state")
def get_state():
    with _LOCK:
        state = _load_state()
        world = World.load(WORLD_PATH)
    return {
        "org": world.org,
        "day": world.day,
        "budget_used": state["budget_used"],
        "budget_remaining": DAILY_BUDGET - state["budget_used"],
        "blocked_ips": state["blocked_ips"],
        "actions_taken": len(state["actions"]),
        "collateral_events": len(state["collateral"]),
    }


@app.get("/assets")
def get_assets():
    world = World.load(WORLD_PATH)
    return [
        {"id": a.id, "kind": a.kind, "hostname": a.hostname, "ip": a.ip,
         "net": a.net, "services": a.services, "vulns": a.vulns,
         "isolated": a.isolated, "crown_jewel": a.crown_jewel,
         "owner": a.owner}
        for a in world.assets
    ]


@app.get("/secrets")
def get_secrets():
    world = World.load(WORLD_PATH)
    # never return secret values - location and exposure only
    return [
        {"id": s.id, "kind": s.kind, "location": s.location,
         "exposure": s.exposure, "unlocks": s.unlocks}
        for s in world.secrets
    ]


@app.get("/logs")
def get_logs(source: str = "", q: str = "", limit: int = 50):
    """Search real service logs. In compose, log volumes mount at /mnt/logs-*."""
    if not LOG_ROOT.exists():
        return {"note": f"no logs at {LOG_ROOT} - run under compose, or set LOG_ROOT"}
    hits = []
    dirs = [LOG_ROOT / f"logs-{source}"] if source else sorted(LOG_ROOT.iterdir())
    for d in dirs:
        if not d.is_dir():
            continue
        for f in sorted(d.rglob("*")):
            if not f.is_file():
                continue
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if (not q or q in line) and line.strip():
                    hits.append({"source": d.name, "file": f.name,
                                 "line": lineno, "text": line.strip()})
                    if len(hits) >= limit:
                        return {"hits": hits, "truncated": True}
    return {"hits": hits, "truncated": False}


@app.get("/diff")
def get_diff():
    """What changed since yesterday's snapshot (written by the tick)."""
    world = World.load(WORLD_PATH)
    prev_path = HISTORY_DIR / f"world-day-{world.day - 1}.json"
    if not prev_path.exists():
        return {"day": world.day, "changes": [],
                "note": "no snapshot yet - run the tick first"}

    prev = json.loads(prev_path.read_text())
    prev_secrets = {s["id"]: s for s in prev["secrets"]}
    prev_assets = {a["id"]: a for a in prev["assets"]}
    changes = []

    for s in world.secrets:
        p = prev_secrets.get(s.id)
        if p and (p["exposure"] != s.exposure or p["location"] != s.location):
            changes.append({"type": "secret", "id": s.id,
                            "exposure": [p["exposure"], s.exposure],
                            "location": [p["location"], s.location]})
    for a in world.assets:
        p = prev_assets.get(a.id)
        if p and p.get("isolated", False) != a.isolated:
            changes.append({"type": "isolation", "id": a.id,
                            "was": p.get("isolated", False), "now": a.isolated})
        if p and sorted(p["vulns"]) != sorted(a.vulns):
            changes.append({"type": "vulns", "id": a.id,
                            "was": p["vulns"], "now": a.vulns})
    return {"day": world.day, "changes": changes}


# ------------------------------------------------------------------ writes

class Action(BaseModel):
    action: str
    target: str
    param: Optional[str] = None
    note: Optional[str] = None


def _apply(world: World, state: dict, req: Action) -> dict:
    idx = world.index()

    if req.action == "block_ip":
        if not _IP_RE.match(req.target):
            raise HTTPException(400, "target must be an IPv4 address")
        if req.target in state["blocked_ips"]:
            return {"already_blocked": req.target}
        state["blocked_ips"].append(req.target)
        return {"blocked": req.target}

    if req.action == "isolate_host":
        asset = idx["assets"].get(req.target)
        if asset is None:
            raise HTTPException(404, f"unknown asset {req.target}")
        if asset.isolated:
            return {"already_isolated": req.target}
        asset.isolated = True
        if asset.kind == "workstation" and asset.owner:
            emp = idx["employees"].get(asset.owner)
            who = emp.name if emp else asset.owner
            state["collateral"].append(
                {"day": world.day, "asset": req.target,
                 "impact": f"{who} locked out of the network"})
        return {"isolated": req.target}

    if req.action == "rotate_credential":
        cred = idx["credentials"].get(req.target)
        if cred is None:
            raise HTTPException(404, f"unknown credential {req.target}")
        cred.password = _strong_password()
        cred.strength = 1.0
        return {"rotated": req.target, "old_value_is_dead": True}

    if req.action == "rotate_secret":
        s = idx["secrets"].get(req.target)
        if s is None:
            raise HTTPException(404, f"unknown secret {req.target}")
        s.exposure = 0.0
        s.location = "rotated by defender - old value is dead"
        return {"rotated": req.target, "exposure": 0.0}

    if req.action == "patch_service":
        asset = idx["assets"].get(req.target)
        if asset is None:
            raise HTTPException(404, f"unknown asset {req.target}")
        if not req.param or req.param not in asset.vulns:
            raise HTTPException(400, f"asset {req.target} has vulns {asset.vulns}")
        asset.vulns.remove(req.param)
        world.vulns = [v for v in world.vulns if v.id != req.param]
        return {"patched": req.param, "on": req.target}

    if req.action == "revoke_admin":
        emp = idx["employees"].get(req.target)
        if emp is None:
            raise HTTPException(404, f"unknown employee {req.target}")
        if not emp.admin:
            return {"already_revoked": req.target}
        emp.admin = False
        return {"revoked": req.target}

    if req.action == "restore_backup":
        asset = idx["assets"].get(req.target)
        if asset is None:
            raise HTTPException(404, f"unknown asset {req.target}")
        cleared = list(asset.vulns)
        asset.vulns = []
        asset.isolated = False
        world.vulns = [v for v in world.vulns if v.on != req.target]
        return {"restored": req.target, "vulns_cleared": cleared}

    raise HTTPException(400, f"unknown action - choose from {sorted(COSTS)}")


@app.post("/act")
def act(req: Action):
    with _LOCK:
        state = _load_state()
        cost = COSTS.get(req.action)
        if cost is None:
            raise HTTPException(400, f"unknown action - choose from {sorted(COSTS)}")
        if state["budget_used"] + cost > DAILY_BUDGET:
            raise HTTPException(
                402, f"budget exceeded: {DAILY_BUDGET - state['budget_used']} pts left today")

        world = World.load(WORLD_PATH)
        result = _apply(world, state, req)
        world.save(WORLD_PATH)

        state["budget_used"] += cost
        state["day"] = world.day
        state["actions"].append({
            "day": world.day, "action": req.action, "target": req.target,
            "param": req.param, "cost": cost, "note": req.note, "result": result,
        })
        _save_state(state)

    return {"ok": True, "cost": cost,
            "budget_remaining": DAILY_BUDGET - state["budget_used"],
            "result": result}


# ------------------------------------------------------- attacker reports

class Finding(BaseModel):
    kind: str          # "credential" | "asset_access"
    id: str            # credential id, or asset id for asset_access
    credential: Optional[str] = None   # for asset_access: the compromised cred
    proof: str         # the actual secret value (checked against the world)


@app.post("/report")
def report(req: Finding):
    """Attacker claims a finding with proof. No proof, no points.

    Wrong proof (e.g. an old, already-rotated password) scores nothing -
    the defender's rotate actions genuinely invalidate stolen creds.
    """
    with _LOCK:
        state = _load_state()
        world = World.load(WORLD_PATH)
        idx = world.index()

        if req.kind == "credential":
            cred = idx["credentials"].get(req.id)
            if cred is None:
                raise HTTPException(404, f"unknown credential {req.id}")
            asset_id = None
        elif req.kind == "asset_access":
            cred = idx["credentials"].get(req.credential or "")
            if cred is None:
                raise HTTPException(404, f"unknown credential {req.credential}")
            if req.id not in cred.grants:
                raise HTTPException(
                    400, f"credential {cred.id} does not grant access to {req.id}")
            asset_id = req.id
        else:
            raise HTTPException(400, "kind must be 'credential' or 'asset_access'")

        if req.proof != cred.password:
            raise HTTPException(
                400, "invalid proof - value does not match (maybe rotated)")

        if (req.kind, req.id) in {(f["kind"], f["id"]) for f in state["findings"]}:
            return {"ok": False, "already_claimed": True}

        if req.kind == "credential":
            key = "credential_strong" if cred.strength >= 0.9 else "credential_weak"
            label = f"compromised credential {cred.id} ({cred.username})"
        else:
            asset = idx["assets"][asset_id]
            if asset.crown_jewel:
                key = "crown_jewel"
                label = f"reached crown jewel {asset.id}"
            else:
                key = "asset_dmz" if asset.net == "dmz" else "asset_lan"
                label = f"reached {asset.id} ({asset.net})"
        points = ATTACKER_POINTS[key]

        finding = {"day": world.day, "kind": req.kind, "id": req.id,
                   "label": label, "points": points}
        state["findings"].append(finding)
        _save_state(state)

    return {"ok": True, "awarded": points, "finding": finding}


@app.get("/score")
def get_score():
    world = World.load(WORLD_PATH)
    with _LOCK:
        state = _load_state()
    return compute_scores(world, state)
