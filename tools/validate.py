"""Live-stack validator: does the running lab actually match the world model?

    python -m tools.validate --world world.json [--full] \
        [--web-base http://localhost:18080] [--api-base http://localhost:18000]

This is the tool that makes Cyber Twin an actual security-posture
exercise instead of a data model with a pretty dashboard. It answers
one question per check: is this claim TRUE right now, on the
containers that are actually running?

Modes:
  host mode (default) - runs from outside the stack (your laptop/Kali
    host). Only checks what's actually published: the web tier and
    the defender API.
  --full - run this INSIDE the corp network (e.g. the attacker-corp /
    onnet profile, or `docker compose exec`) to also validate SSH
    logins, database contents, and git-over-ssh - the things that
    aren't published to the host on purpose.

Exit code is 0 only if every check passed. CI-friendly.
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from world.schema import World
from tools.attack_paths import build_graph, shortest_paths


@dataclass
class Check:
    area: str
    name: str
    ok: bool
    detail: str


RESULTS: list[Check] = []


def record(area: str, name: str, ok: bool, detail: str = "") -> bool:
    RESULTS.append(Check(area, name, ok, detail))
    return ok


def port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


import http.cookiejar
import urllib.parse


class WebProbe:
    """A tiny session: keeps cookies across requests, like a browser
    would. Plain urllib.request.urlopen has no cookie jar attached, so
    a login test using it will authenticate successfully and then
    immediately lose the session on the very next request - that
    looks exactly like a broken login even when the app is fine."""

    def __init__(self, base: str):
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def get(self, path: str, timeout: float = 5.0):
        req = urllib.request.Request(self.base + path)
        try:
            with self.opener.open(req, timeout=timeout) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers)

    def post_form(self, path: str, fields: dict, timeout: float = 5.0):
        body = urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(
            self.base + path, data=body, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with self.opener.open(req, timeout=timeout) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers)


def http_get(url: str, timeout: float = 5.0, headers: Optional[dict] = None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


# ---------------------------------------------------------------- web tier
def check_web(world: World, base: str) -> None:
    db_cred = next((c for c in world.credentials
                     if "db-prod-01" in c.grants and c.owner is None), None)
    good_cred = next((c for c in world.credentials if c.owner), None)
    probe = WebProbe(base)

    try:
        status, body, _ = probe.get("/")
        record("web", "homepage reachable", status == 200,
               f"GET / -> {status}")
    except Exception as e:  # noqa: BLE001
        record("web", "homepage reachable", False, str(e))
        return  # nothing else on web will work either

    try:
        status, _, _ = probe.post_form("/login", {"u": "nobody", "p": "wrong"})
        record("web", "bad login rejected", status == 401,
               f"expected 401, got {status}")
    except Exception as e:  # noqa: BLE001
        record("web", "bad login rejected", False, str(e))

    if good_cred:
        try:
            # cookie jar means the session survives the redirect, so a
            # real success actually lands on /intranet with content
            status, body, _ = probe.post_form(
                "/login", {"u": good_cred.username, "p": good_cred.password})
            ok = status == 200 and b"intranet" in body.lower()
            record("web", f"real login works ({good_cred.username})", ok,
                   f"world-model password for {good_cred.username} -> {status}, "
                   f"landed on intranet: {b'intranet' in body.lower()}")
        except Exception as e:  # noqa: BLE001
            record("web", "real login works", False, str(e))

    try:
        status, body, _ = probe.get("/fetch?url=http://db-prod-01:5432/")
        # a closed/refused port still proves the SSRF reached the corp network;
        # a DNS failure means the pivot itself is broken
        dns_broken = b"not known" in body.lower() or b"name resolution" in body.lower()
        reached = status in (200, 502) and not dns_broken
        record("web", "SSRF reaches corp network", reached,
               f"/fetch -> {status}: {body[:120]!r}")
    except Exception as e:  # noqa: BLE001
        record("web", "SSRF reaches corp network", False, str(e))

    if db_cred:
        try:
            status, body, _ = probe.get("/fork-billing-api/.env")
            has_pw = db_cred.password.encode() in body
            record("web", "leaked .env matches real db-prod password",
                   status == 200 and has_pw,
                   f"-> {status}, password present: {has_pw}")
        except Exception as e:  # noqa: BLE001
            record("web", "leaked .env matches real db-prod password", False, str(e))


# ---------------------------------------------------------------- api
def check_api(world: World, base: str) -> None:
    try:
        status, body = http_get(f"{base}/state")
        data = json.loads(body)
        has_budget = "budget" in data or "action_budget" in json.dumps(data).lower()
        record("api", "/state reachable and JSON", status == 200, f"-> {status}")
    except Exception as e:  # noqa: BLE001
        record("api", "/state reachable and JSON", False, str(e))


# ---------------------------------------------------------------- --full
def check_ssh_logins(world: World, sample: int) -> None:
    try:
        import paramiko
    except ImportError:
        record("ssh", "paramiko available", False,
               "pip install paramiko  (skipped all ssh checks)")
        return

    ws = [a for a in world.assets if a.kind == "workstation"]
    creds_by_asset = {}
    for c in world.credentials:
        for g in c.grants:
            creds_by_asset.setdefault(g, c)

    tested = [a for a in ws if a.id in creds_by_asset][:sample]
    for a in tested:
        c = creds_by_asset[a.id]
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(a.id, username=c.username, password=c.password,
                            timeout=5, banner_timeout=5, auth_timeout=5)
            record("ssh", f"login {c.username}@{a.id}", True, "authenticated")
        except Exception as e:  # noqa: BLE001
            record("ssh", f"login {c.username}@{a.id}", False, str(e))
        finally:
            client.close()

    jump = next((a for a in world.assets if a.id == "jump-01"), None)
    jc = creds_by_asset.get("jump-01")
    if jump and jc:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect("jump-01", username=jc.username, password=jc.password,
                            timeout=5, banner_timeout=5, auth_timeout=5)
            record("ssh", "login jump-01", True, "authenticated")
        except Exception as e:  # noqa: BLE001
            record("ssh", "login jump-01", False, str(e))
        finally:
            client.close()


def check_git(world: World) -> None:
    try:
        import paramiko
    except ImportError:
        return  # already reported under check_ssh_logins
    git_cred = next((c for c in world.credentials if "gitea-01" in c.grants), None)
    if not git_cred:
        return
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect("gitea-01", username=git_cred.username,
                        password=git_cred.password, timeout=5,
                        banner_timeout=5, auth_timeout=5)
        record("git", "gitea-01 ssh auth", True, "authenticated (git-shell)")
    except Exception as e:  # noqa: BLE001
        record("git", "gitea-01 ssh auth", False, str(e))
    finally:
        client.close()


def check_databases(world: World) -> None:
    try:
        import psycopg2
    except ImportError:
        record("db", "psycopg2 available", False,
               "pip install psycopg2-binary  (skipped db checks)")
        return

    checks = [
        ("db-prod-01", "customers", len(getattr(world, "_expected_customers", [])) or 25),
        ("db-hr-01", "employees", len(world.employees)),
    ]
    for host, table, expected_min in checks:
        cred = next((c for c in world.credentials if host in c.grants), None)
        if not cred:
            record("db", f"{host} credential in world model", False, "no service credential found")
            continue
        try:
            conn = psycopg2.connect(host=host, port=5432, user="postgres",
                                     password=cred.password, dbname="postgres",
                                     connect_timeout=5)
            cur = conn.cursor()
            cur.execute(f"SELECT count(*) FROM {table}")
            n = cur.fetchone()[0]
            record("db", f"{host}.{table} row count", n >= expected_min,
                   f"{n} rows (expected >= {expected_min})")
            conn.close()
        except Exception as e:  # noqa: BLE001
            record("db", f"{host} reachable with world-model password", False, str(e))


# ---------------------------------------------- attack-path cross-check
def check_attack_paths_are_real(world: World) -> None:
    """The dashboard's attack paths are only meaningful if the ports
    they claim are open actually ARE open. Cross-check every hop."""
    edges, why = build_graph(world)
    goals, paths, idx = shortest_paths(world, edges, why, max_paths=99)
    assets_by_id = idx["assets"]

    if not paths:
        record("attack-paths", "at least one path to a crown jewel exists",
               False, "no path found - either the lab is unrealistically locked down, or the graph is broken")
        return

    checked_edges = set()
    for goal, chain in paths.items():
        prev = "__internet__"
        for hop in chain:
            key = (prev, hop)
            if key not in checked_edges:
                checked_edges.add(key)
                asset = assets_by_id.get(hop)
                if asset and asset.services:
                    # confirm the asset it claims to land on has *something* listening
                    svc_map = {"http": 80, "https": 443, "ssh": 22,
                               "postgres": 5432, "smtp": 25, "imap": 143,
                               "wireguard": 51820}
                    reachable = any(
                        port_open(asset.id, svc_map.get(s, 0))
                        for s in asset.services if svc_map.get(s, 0))
                    record("attack-paths", f"{prev} -> {hop} ({why.get(key, '?')[:40]})",
                           reachable, f"{asset.id} services={asset.services}")
            prev = hop
        record("attack-paths", f"reachable crown jewel: {goal}", True,
               " -> ".join(["internet"] + chain))


def print_report() -> bool:
    by_area: dict[str, list[Check]] = {}
    for r in RESULTS:
        by_area.setdefault(r.area, []).append(r)

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r.ok)
    print(f"\n{'=' * 70}\nCYBER TWIN - LIVE STACK VALIDATION\n{'=' * 70}")
    for area, checks in by_area.items():
        print(f"\n[{area}]")
        for c in checks:
            mark = "PASS" if c.ok else "FAIL"
            print(f"  {mark:4}  {c.name}" + (f"  ({c.detail})" if c.detail else ""))
    print(f"\n{'-' * 70}\n{passed}/{total} checks passed")
    failed = [r for r in RESULTS if not r.ok]
    if failed:
        print(f"\n{len(failed)} FAILURE(S):")
        for r in failed:
            print(f"  - [{r.area}] {r.name}: {r.detail}")
    print(f"{'=' * 70}\n")
    return not failed


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--world", default="world.json")
    ap.add_argument("--web-base", default="http://web-dmz-01:8080",
                     help="use http://localhost:18080 in host mode")
    ap.add_argument("--api-base", default="http://api:8000",
                     help="use http://localhost:18000 in host mode")
    ap.add_argument("--full", action="store_true",
                     help="also check ssh logins, db contents, git auth "
                          "(requires running on the corp network)")
    ap.add_argument("--ssh-sample", type=int, default=6,
                     help="how many workstations to spot-check ssh logins on")
    args = ap.parse_args()

    world = World.load(args.world)

    check_web(world, args.web_base)
    check_api(world, args.api_base)
    check_attack_paths_are_real(world)

    if args.full:
        check_ssh_logins(world, args.ssh_sample)
        check_git(world)
        check_databases(world)
    else:
        record("info", "full mode", True,
               "run with --full (and --web-base/--api-base pointed at "
               "container hostnames) from inside the corp network for "
               "ssh/db/git checks - see runtime/images/validator")

    ok = print_report()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
