"""The daily tick: apply one scenario card to the world, save, recompile.

Run:  python -m tick --scenario scenarios/leaked_api_key.yaml
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from world.schema import World


def apply_card(world: World, card: dict) -> list[str]:
    """Apply a scenario card's mutations. Returns a human-readable changelog."""
    log = []
    idx = world.index()

    for step in card.get("mutate", []):
        action = step.get("pick", "")
        if action.startswith("secrets"):
            for s in world.secrets:
                if f"kind={s.kind}" in action or action == "secrets":
                    for k, v in step.get("set", {}).items():
                        setattr(s, k, v)
                        log.append(f"{s.id}: {k} -> {v}")
                    break
        elif action.startswith("assets"):
            for a in world.assets:
                if a.id in action:
                    for k, v in step.get("set", {}).items():
                        setattr(a, k, v)
                        log.append(f"{a.id}: {k} -> {v}")
    return log


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--world", default="world.json")
    ap.add_argument("--scenario", required=True)
    args = ap.parse_args()

    world = World.load(args.world)
    card = yaml.safe_load(Path(args.scenario).read_text())

    changelog = apply_card(world, card)
    world.day += 1
    world.save(args.world)

    print(f"day {world.day}: applied '{card.get('id')}'")
    for line in changelog:
        print(f"  - {line}")


if __name__ == "__main__":
    main()
