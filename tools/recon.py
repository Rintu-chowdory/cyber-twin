"""Recon the org from the outside in - what's publicly visible.

    python3 -m tools.recon [--world world.json]

Purely passive: reads the world model and reports the public attack
surface the way an external attacker (or Shodan) would see it.
"""
from __future__ import annotations

import argparse
from collections import Counter

from world.schema import World


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--world", default="world.json")
    args = ap.parse_args()

    world = World.load(args.world)

    print(f"== recon: {world.org['name']} (day {world.day}) ==")

    # internet-facing assets
    dmz = [a for a in world.assets if a.net == "dmz"]
    print(f"\n[1] internet-facing hosts ({len(dmz)})")
    for a in dmz:
        vulns = [v for v in world.vulns if v.on == a.id]
        print(f"    {a.ip:<12} {a.hostname:<28} services: {', '.join(a.services) or '-'}"
              + (f"  (!) {len(vulns)} known vuln(s)" if vulns else ""))

    # secrets with public exposure
    leaked = [s for s in world.secrets if s.exposure > 0]
    print(f"\n[2] leaked material discoverable publicly ({len(leaked)})")
    for s in leaked:
        print(f"    {s.id} ({s.kind}) exposure={s.exposure}"
              f"  found at: {s.location}")
        for u in s.unlocks:
            print(f"        unlocks -> {u}")

    # weak credentials (breach-dump / spraying candidates)
    weak = [c for c in world.credentials if c.owner and c.strength <= 0.3]
    print(f"\n[3] weak credential candidates ({len(weak)} of "
          f"{sum(1 for c in world.credentials if c.owner)} user accounts)")
    for c in weak[:10]:
        print(f"    {c.username:<28} strength={c.strength}")
    if len(weak) > 10:
        print(f"    ... and {len(weak) - 10} more (tools/crack.py will find them)")

    # org chart via "OSINT"
    by_dept = Counter(e.dept for e in world.employees)
    print(f"\n[4] headcount by department ({len(world.employees)} employees)")
    for dept, n in by_dept.most_common():
        admins = sum(1 for e in world.employees if e.dept == dept and e.admin)
        print(f"    {dept:<12} {n:>3}" + ("  (admins present)" if admins else ""))

    print("\nnext steps: tools/crack.py  |  tools/attack_paths.py")


if __name__ == "__main__":
    main()
