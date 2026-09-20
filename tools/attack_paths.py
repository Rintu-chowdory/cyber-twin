"""Map every viable attack path from the internet to the crown jewels.

    python3 -m tools.attack_paths [--max 5] [--world world.json]

Builds a graph over the world model and BFS-searches from the
attacker's entry points (DMZ hosts + anything publicly leaked) to
each crown jewel. This is the defender's worst nightmare, printed
in one screen: every chain of credentials, secrets and vulns that
walks an outsider into the database.
"""
from __future__ import annotations

import argparse
from collections import defaultdict, deque

from world.schema import World


def build_graph(world: World):
    idx = world.index()
    edges: dict[str, set[str]] = defaultdict(set)
    why: dict[tuple[str, str], str] = {}

    def link(src: str, dst: str, reason: str):
        if src and dst and src != dst and dst not in edges[src]:
            edges[src].add(dst)
            why[(src, dst)] = reason

    # owning a workstation = controlling its user's credentials
    emp_by_id = idx["employees"]
    asset_by_owner = {a.owner: a.id for a in world.assets if a.owner}
    for c in world.credentials:
        if c.owner in emp_by_id:
            src = asset_by_owner.get(c.owner)
            for g in c.grants:
                link(src, g, f"cred {c.id} ({emp_by_id[c.owner].name})")

    # exploiting a vuln moves you onto what it grants
    for v in world.vulns:
        for g in v.grants:
            link(v.on, g, f"vuln {v.id} ({v.kind})")

    # secrets live on an asset and unlock others
    for s in world.secrets:
        loc = s.location.split(":")[0] if ":" in s.location else None
        for u in s.unlocks:
            link(loc, u, f"secret {s.id} ({s.kind})")
            # a publicly leaked secret is an entry point in itself
            if s.exposure > 0:
                link("__internet__", u, f"LEAKED secret {s.id} @ {s.location}")
                if loc:
                    link("__internet__", loc, f"LEAKED secret {s.id} @ {s.location}")

    # a foothold on an asset hands you whatever it holds
    for a in world.assets:
        for held in a.holds:
            c = idx["credentials"].get(held)
            if c:
                for g in c.grants:
                    link(a.id, g, f"loot: cred {c.id} on {a.id}")
            s = idx["secrets"].get(held)
            if s:
                for u in s.unlocks:
                    link(a.id, u, f"loot: secret {s.id} on {a.id}")

    # the internet can reach every DMZ host
    for a in world.assets:
        if a.net == "dmz":
            link("__internet__", a.id, "internet-facing")

    return edges, why


def shortest_paths(world: World, edges, why, max_paths: int):
    goals = [a.id for a in world.assets if a.crown_jewel]
    idx = world.index()
    paths = {}

    for goal in goals:
        # BFS from the internet to this goal
        prev: dict[str, str] = {}
        q = deque([("__internet__", None)])
        seen = {"__internet__"}
        found = False
        while q and not found:
            node, _ = q.popleft()
            for nxt in edges.get(node, ()):
                if nxt in seen:
                    continue
                seen.add(nxt)
                prev[nxt] = node
                if nxt == goal:
                    found = True
                    break
                q.append((nxt, nxt))

        if goal in prev:
            chain, cur = [], goal
            while cur != "__internet__":
                chain.append(cur)
                cur = prev[cur]
            chain.reverse()
            paths[goal] = chain

    return goals, paths, idx


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--world", default="world.json")
    ap.add_argument("--max", type=int, default=5,
                    help="max entry points shown per path")
    args = ap.parse_args()

    world = World.load(args.world)
    edges, why = build_graph(world)
    goals, paths, idx = shortest_paths(world, edges, why, args.max)

    print(f"== attack paths to crown jewels ({len(goals)} jewels) ==")
    if not paths:
        print("\nno path from the internet to a crown jewel.")
        print("(unusual - check for a fully remediated world)")
        return

    for goal, chain in paths.items():
        jewel = idx["assets"][goal]
        print(f"\n--> {goal} [{jewel.data}]")
        step = "__internet__"
        for hop in chain:
            print(f"    {step:<14} --{why[(step, hop)]}-->  {hop}")
            step = hop

    total = len(paths)
    print(f"\n{total} of {len(goals)} crown jewels reachable from outside.")
    print("defender homework: cut the cheapest link in each chain first.")


if __name__ == "__main__":
    main()
