"""Materialize the world model into a REAL, runnable docker-compose stack.

    python -m compiler.materialize --world world.json --out runtime/generated \
        [--workstations 12]

Everything the tools attack is real here: live sshd with the world's
credentials, a Flask web tier whose logins check those same passwords,
real Postgres instances seeded with the org's data, a git-over-ssh
server holding the leaked repo. Docker network segmentation enforces
the zones: dmz (internet-facing), corp (everything internal), mgmt.
The web tier is dual-homed dmz+corp - its SSRF is the pivot.
"""
from __future__ import annotations

import argparse
import secrets
from pathlib import Path

import yaml

from world.schema import World

CORE = ["gitea-01", "db-prod-01", "db-hr-01", "jump-01"]


def _pick_workstations(world: World, limit: int) -> list:
    ws_all = [a for a in world.assets if a.kind == "workstation"]
    wifi_clients = {c for w in world.wifi_networks for c in w.clients}
    cracked = {"ws-eng-00", "ws-eng-03"}
    must = {a.id for a in ws_all if a.id in (wifi_clients | cracked)}
    selected, seen = [], set()
    # relevant ones first: wifi clients + cracked workstations
    for a in ws_all:
        if a.id in must and a.id not in seen:
            selected.append(a)
            seen.add(a.id)
    # then one per department
    depts_done = set()
    for a in ws_all:
        if a.id in seen:
            continue
        dept = a.id.split("-")[1][:3]
        if dept not in depts_done:
            selected.append(a)
            seen.add(a.id)
            depts_done.add(dept)
    # then fill alphabetically
    for a in ws_all:
        if a.id not in seen:
            selected.append(a)
            seen.add(a.id)
    return selected[: max(limit, len(must))]


def _cred_for(world: World, asset_id: str):
    for c in world.credentials:
        if asset_id in c.grants and c.owner is None:
            return c
    return None


def materialize(world: World, out: Path, workstations: int) -> None:
    profiles = out / "profiles"
    (profiles / "web").mkdir(parents=True, exist_ok=True)
    (profiles / "git" / "seed" / "billing-api").mkdir(parents=True, exist_ok=True)
    (profiles / "db-prod").mkdir(parents=True, exist_ok=True)
    (profiles / "db-hr").mkdir(parents=True, exist_ok=True)
    (profiles / "jump").mkdir(parents=True, exist_ok=True)
    (profiles / "ws").mkdir(parents=True, exist_ok=True)

    emp_by_id = {e.id: e for e in world.employees}

    def dept_of(c):
        return emp_by_id[c.owner].dept if c.owner in emp_by_id else "-"

    # ---- web: login directory (user:pass:dept for every employee cred) ----
    with open(profiles / "web" / "users.txt", "w") as f:
        for c in world.credentials:
            if c.owner:
                f.write(f"{c.username}:{c.password}:{dept_of(c)}\n")

    # ---- web: the leaked public-fork .env (day-0 incident) ----
    db = _cred_for(world, "db-prod-01")
    hr = _cred_for(world, "db-hr-01")
    assert db, "world has no service credential for db-prod-01"
    aws_key = "AKIA" + secrets.token_hex(8).upper()
    aws_secret = secrets.token_hex(20)
    (profiles / "web" / "leaked.env").write_text(
        f"# billing-api - fork, last touched 2026\n"
        f"AWS_ACCESS_KEY_ID={aws_key}\n"
        f"AWS_SECRET_ACCESS_KEY={aws_secret}\n"
        f"DATABASE_URL=postgresql://postgres:{db.password}@10.20.1.20:5432/prod\n")

    # same file committed in the private repo on the git server
    (profiles / "git" / "seed" / "billing-api" / ".env").write_text(
        (profiles / "web" / "leaked.env").read_text())
    (profiles / "git" / "seed" / "billing-api" / "README.md").write_text(
        "# billing-api\nInternal billing service. Do NOT commit .env.\n")

    # ---- jump-01 users ----
    jump = _cred_for(world, "jump-01")
    (profiles / "jump" / "users.txt").write_text(
        f"{jump.username}:{jump.password}:-\n" if jump else "")

    # ---- workstations: owner credentials become real ssh users ----
    ws_assets = _pick_workstations(world, workstations)
    for a in ws_assets:
        (profiles / "ws" / a.id).mkdir(exist_ok=True)
        lines = [f"{c.username}:{c.password}:{dept_of(c)}\n"
                 for c in world.credentials if c.owner == a.owner]
        (profiles / "ws" / a.id / "users.txt").write_text("".join(lines))

    # ---- db-prod: real customer PII ----
    customers = [(f"Customer {i:03d} GmbH",
                  f"billing{i:03d}@customer.example",
                  f"DE893704004405320{i:07d}",
                  ("enterprise", "standard", "trial")[i % 3])
                 for i in range(1, 26)]
    rows = ",\n".join(f"  ('{n}', '{e}', '{i}', '{p}')" for n, e, i, p in customers)
    (profiles / "db-prod" / "init.sql").write_text(f"""
CREATE TABLE customers (
  id serial PRIMARY KEY, name text, email text, iban text, plan text);
INSERT INTO customers (name, email, iban, plan) VALUES
{rows};
""")

    # ---- db-hr: the actual org chart from the world model ----
    emp_rows = ",\n".join(
        f"  ('{e.id}', '{e.name}', '{e.email}', '{e.dept}', '{e.title}', "
        f"{40000 + 400 * (hash(e.id) % 200)})" for e in world.employees)
    (profiles / "db-hr" / "init.sql").write_text(f"""
CREATE TABLE employees (
  id text PRIMARY KEY, name text, email text, dept text, title text,
  salary integer);
INSERT INTO employees (id, name, email, dept, title, salary) VALUES
{emp_rows};
""")

    # ---- intranet page (what a logged-in employee sees) ----
    git = _cred_for(world, "gitea-01")
    lines = ["Nimbus Dynamics - internal directory",
             "gitea-01   10.20.1.10   git clone git@gitea-01:/srv/git/billing-api.git",
             "db-prod-01 10.20.1.20   postgres (billing/customer data)",
             "db-hr-01   10.20.1.21   postgres (hr records)",
             "jump-01    10.20.1.40   ssh (ops only)",
             "", "workstations:"]
    lines += [f"  {a.id}  {a.ip}  ssh {dept_of(next(c for c in world.credentials if c.owner == a.owner)) if False else ''}".rstrip()
              for a in ws_assets]
    (profiles / "web" / "intranet.txt").write_text("\n".join(lines) + "\n")

    # ---- compose ----
    rel = lambda p: str(Path(p).as_posix())  # noqa: E731
    sshd_ctx = "../../runtime/images/sshd"

    services = {
        "web-dmz-01": {
            "build": {"context": "../../runtime/images/web"},
            "networks": {"dmz": {"ipv4_address": "10.10.0.10"},
                         "corp": {"ipv4_address": "10.20.0.10"}},
            "ports": ["127.0.0.1:${WEB_PORT:-18080}:8080"],
            "volumes": ["./profiles/web:/provision:ro"],
            "restart": "unless-stopped"},
        "gitea-01": {
            "build": {"context": "../../runtime/images/gitserver"},
            "networks": {"corp": {"ipv4_address": "10.20.1.10"}},
            "volumes": ["./profiles/git:/provision:ro"],
            "environment": {"GIT_PASS": git.password if git else "changeme"},
            "restart": "unless-stopped"},
        "db-prod-01": {
            "image": "postgres:16-alpine",
            "networks": {"corp": {"ipv4_address": "10.20.1.20"}},
            "environment": {"POSTGRES_PASSWORD": db.password},
            "volumes": ["dbprod_data:/var/lib/postgresql/data",
                        "./profiles/db-prod/init.sql:/docker-entrypoint-initdb.d/init.sql:ro"],
            "restart": "unless-stopped"},
        "db-hr-01": {
            "image": "postgres:16-alpine",
            "networks": {"corp": {"ipv4_address": "10.20.1.21"}},
            "environment": {"POSTGRES_PASSWORD": hr.password},
            "volumes": ["dbhr_data:/var/lib/postgresql/data",
                        "./profiles/db-hr/init.sql:/docker-entrypoint-initdb.d/init.sql:ro"],
            "restart": "unless-stopped"},
        "api": {
            "build": {"context": "../..", "dockerfile": "runtime/images/api/Dockerfile"},
            "networks": {"mgmt": {"ipv4_address": "10.30.0.5"},
                         "corp": {"ipv4_address": "10.20.0.5"}},
            "ports": ["127.0.0.1:${API_PORT:-18000}:8000"],
            "volumes": ["../../world.json:/app/world.json:ro",
                        "../../control:/app/control",
                        "../../history:/app/history"],
            "restart": "unless-stopped"},
        "jump-01": {
            "build": {"context": rel(sshd_ctx)},
            "networks": {"corp": {"ipv4_address": "10.20.1.40"}},
            "volumes": ["./profiles/jump:/provision:ro"],
            "restart": "unless-stopped"},
    }
    for a in ws_assets:
        services[a.id] = {
            "build": {"context": rel(sshd_ctx)},
            "networks": {"corp": {"ipv4_address": a.ip}},
            "volumes": [f"./profiles/ws/{a.id}:/provision:ro"],
            "restart": "unless-stopped"}

    services["attacker"] = {
        "image": "kalilinux/kali-rolling",
        "networks": ["dmz"], "command": "sleep infinity", "tty": True,
        "profiles": ["attacker"]}
    services["attacker-corp"] = {
        "image": "kalilinux/kali-rolling",
        "networks": ["corp"], "command": "sleep infinity", "tty": True,
        "profiles": ["onnet"]}

    compose = {
        "name": "cybertwin",
        "services": services,
        "networks": {
            "dmz": {"ipam": {"config": [{"subnet": "10.10.0.0/24"}]}},
            "corp": {"ipam": {"config": [{"subnet": "10.20.0.0/16"}]}},
            "mgmt": {"ipam": {"config": [{"subnet": "10.30.0.0/24"}]}},
        },
        "volumes": {"dbprod_data": {}, "dbhr_data": {}},
    }
    (out / "docker-compose.yml").write_text(
        "# generated by python -m compiler.materialize - do not edit\n"
        + yaml.safe_dump(compose, sort_keys=False))

    print(f"wrote {out/'docker-compose.yml'}")
    print(f"  services: {len(services)} (workstations materialized: {len(ws_assets)})")
    print(f"  attacker modes: --profile attacker (dmz) | --profile onnet (corp)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--world", default="world.json")
    ap.add_argument("--out", default="runtime/generated")
    ap.add_argument("--workstations", type=int, default=12)
    args = ap.parse_args()
    world = World.load(args.world)
    materialize(world, Path(args.out), args.workstations)


if __name__ == "__main__":
    main()
