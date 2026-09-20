"""The daily tick: apply one scenario card to the world, save, recompile.

    python -m tick --list                                # show cards + weights
    python -m tick --scenario scenarios/phishing_upload.yaml
    python -m tick --random                              # weighted random pick
    python -m tick --random --seed 42                    # reproducible day

Cards are declarative mutation steps over the world model:

    mutate:
      - entity: secrets            # secrets | assets | credentials | employees
        where: {kind: api_key, exposure: 0.0}   # exact match, >=, <=, >, <,
        set: {exposure: 1.0}                    # "null" / "!=null" supported
        append: {data: some-label}             # append to a list field
      - add_vuln: {target: web-dmz-01, kind: sql_injection, severity: critical}
      - add_service: {target: web-dmz-01, service: "http-alt"}
      - add_data: {target: files-01, label: "backup.sql (unencrypted)"}

`target` accepts "$last.<attr>" to chain a step to whatever the previous
entity step picked (e.g. the workstation of the phished employee).
"""
from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path

import yaml

from world.schema import Vuln, World

SCENARIO_DIR = Path(__file__).parent / "scenarios"
_ENTITIES = ("secrets", "assets", "credentials", "employees")


# ---------------------------------------------------------------- matching

def _cmp(actual, op: str, val) -> bool:
    try:
        a, v = float(actual), float(val)
    except (TypeError, ValueError):
        return False
    return {">=": a >= v, "<=": a <= v, ">": a > v, "<": a < v}[op]


def _match(obj, where: dict | None) -> bool:
    for key, val in (where or {}).items():
        actual = getattr(obj, key, None)
        if val == "null":
            if actual is not None:
                return False
        elif val == "!=null":
            if actual is None:
                return False
        else:
            for op in (">=", "<=", ">", "<"):
                if key.endswith(op) and not _cmp(actual, op, val):
                    return False
            else:
                if actual != val:
                    return False
    return True


def _resolve_on(on, idx: dict, picked) -> str | None:
    if isinstance(on, str) and on.startswith("$last."):
        attr = on.split(".", 1)[1]
        return getattr(picked, attr, None) if picked is not None else None
    return on


# ---------------------------------------------------------------- engine

def apply_card(world: World, card: dict, rng: random.Random) -> list[str]:
    log: list[str] = []
    idx = world.index()
    picked = None

    for step in card.get("mutate", []):
        if "add_vuln" in step:
            spec = step["add_vuln"]
            on = _resolve_on(spec.get("target"), idx, picked)
            asset = idx["assets"].get(on) if on else None
            if asset is None:
                log.append(f"skip add_vuln: unknown asset {spec.get('target')}")
                continue
            if any(v.kind == spec["kind"] and v.on == asset.id for v in world.vulns):
                log.append(f"skip add_vuln: {asset.id} already has "
                           f"a '{spec['kind']}' vuln")
                continue
            vid = f"v{len(world.vulns) + 1:04d}"
            world.vulns.append(Vuln(
                id=vid, kind=spec["kind"], on=asset.id,
                severity=spec.get("severity", "medium"),
                cve=spec.get("cve"), grants=spec.get("grants", [])))
            asset.vulns.append(vid)
            log.append(f"new vuln {vid} ({spec['kind']}) on {asset.id}")
            continue

        if "add_service" in step:
            spec = step["add_service"]
            on = _resolve_on(spec.get("target"), idx, picked)
            asset = idx["assets"].get(on) if on else None
            if asset is None:
                log.append(f"skip add_service: unknown asset {spec.get('target')}")
                continue
            if spec["service"] not in asset.services:
                asset.services.append(spec["service"])
                log.append(f"{asset.id}: new service {spec['service']}")
            continue

        if "add_data" in step:
            spec = step["add_data"]
            on = _resolve_on(spec.get("target"), idx, picked)
            asset = idx["assets"].get(on) if on else None
            if asset is None:
                log.append(f"skip add_data: unknown asset {spec.get('target')}")
                continue
            if spec["label"] not in asset.data:
                asset.data.append(spec["label"])
                log.append(f"{asset.id}: new data {spec['label']}")
            continue

        entity = step.get("entity")
        if entity not in _ENTITIES:
            log.append(f"skip: unknown entity '{entity}'")
            continue
        pool = [o for o in getattr(world, entity) if _match(o, step.get("where"))]
        if not pool:
            log.append(f"skip {entity}: no eligible target {step.get('where')}")
            continue
        target = rng.choice(pool)
        picked = target
        for k, v in step.get("set", {}).items():
            setattr(target, k, v)
            log.append(f"{target.id}: {k} -> {v}")
        for k, v in step.get("append", {}).items():
            lst = getattr(target, k, None)
            if isinstance(lst, list) and v not in lst:
                lst.append(v)
                log.append(f"{target.id}: {k} += {v}")

    return log


# ---------------------------------------------------------------- cards

def load_cards() -> list[dict]:
    cards = []
    for f in sorted(SCENARIO_DIR.glob("*.yaml")):
        c = yaml.safe_load(f.read_text())
        c["_file"] = f.name
        cards.append(c)
    return cards


def _applied(log: list[str]) -> bool:
    return any(not line.startswith("skip") for line in log)


# ---------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--world", default="world.json")
    ap.add_argument("--scenario", help="path to a specific card")
    ap.add_argument("--random", action="store_true",
                    help="pick a card by weight")
    ap.add_argument("--seed", type=int, default=None,
                    help="deterministic card pick + target choice")
    ap.add_argument("--list", action="store_true", help="show cards + weights")
    args = ap.parse_args()

    cards = load_cards()

    if args.list:
        for c in cards:
            print(f"{c.get('weight', 1):>2}  {c['_file']:<28} {c.get('desc', '')}")
        return

    if not (args.random or args.scenario):
        ap.error("choose --random, --scenario, or --list")

    rng = random.Random(args.seed if args.seed is not None else time.time_ns())

    if args.random:
        # keep drawing until a card actually changes something
        for _ in range(len(cards)):
            weights = [c.get("weight", 1) for c in cards]
            card = rng.choices(cards, weights=weights, k=1)[0]
            world = World.load(args.world)
            log = apply_card(world, card, rng)
            if _applied(log):
                break
        else:
            print("no card could apply - the world is fully drifted")
            return
    else:
        card = yaml.safe_load(Path(args.scenario).read_text())
        world = World.load(args.world)
        log = apply_card(world, card, rng)
        if not _applied(log):
            print(f"card '{card.get('id')}' had no eligible target - "
                  "already applied or remediated")
            return

    # snapshot the pre-tick state so the defender API can serve /diff
    hist = Path("history")
    hist.mkdir(exist_ok=True)
    (hist / f"world-day-{world.day}.json").write_text(Path(args.world).read_text())

    # a new day resets the defender's action budget
    state_path = Path("control/state.json")
    if state_path.exists():
        state = json.loads(state_path.read_text())
        state["day"] = world.day + 1
        state["budget_used"] = 0
        state_path.write_text(json.dumps(state, indent=2))

    world.day += 1
    world.save(args.world)

    card_name = card.get("_file") or Path(args.scenario).name
    print(f"day {world.day}: applied '{card.get('id')}' ({card_name})")
    for line in log:
        print(f"  - {line}")


if __name__ == "__main__":
    main()
