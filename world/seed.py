"""Generate a coherent fictional org. Deterministic given --seed."""
from __future__ import annotations

import argparse
import random
from pathlib import Path

from world.schema import (World, Employee, Asset, Credential, Secret, Vuln,
                          ServiceAccount)

FIRST = [
    "Priya", "Marcus", "Elena", "Tomas", "Aisha", "Jonas", "Mei", "Diego",
    "Sofia", "Ravi", "Nadia", "Owen", "Yuki", "Hassan", "Clara", "Ivan",
    "Leila", "Bruno", "Ingrid", "Kofi", "Anya", "Pedro", "Sanne", "Viktor",
    "Noor", "Felix", "Camila", "Arjun", "Greta", "Malik", "Rosa", "Tariq",
    "Iris", "Dmitri", "Hana", "Luca", "Zara", "Emil", "Bianca", "Soren",
]
LAST = [
    "Raman", "Voss", "Kovac", "Silva", "Okafor", "Lindqvist", "Chen", "Alvarez",
    "Petrov", "Nair", "Haddad", "Brennan", "Tanaka", "Farouk", "Moreau", "Novak",
    "Bennani", "Rossi", "Larsen", "Mensah", "Volkov", "Ferreira", "de Vries",
    "Sokolov", "Rahman", "Weber", "Duarte", "Iyer", "Fischer", "Diallo",
    "Marchetti", "Aziz", "Nakamura", "Orlov", "Kim", "Bianchi", "Kaur",
    "Halvorsen", "Costa", "Adeyemi",
]

DEPTS = {
    "engineering": {"headcount": 38, "subnet": "10.20.10"},
    "finance":     {"headcount": 14, "subnet": "10.20.20"},
    "hr":          {"headcount": 9,  "subnet": "10.20.30"},
    "sales":       {"headcount": 24, "subnet": "10.20.40"},
    "marketing":   {"headcount": 16, "subnet": "10.20.50"},
    "ops":         {"headcount": 12, "subnet": "10.20.60"},
    "exec":        {"headcount": 7,  "subnet": "10.20.70"},
}

TITLES = {
    "engineering": ["Software Engineer", "Senior Engineer", "SRE", "QA Engineer", "Eng Manager"],
    "finance":     ["Accountant", "AP Specialist", "Controller", "CFO"],
    "hr":          ["Recruiter", "HR Generalist", "HR Director"],
    "sales":       ["AE", "SDR", "Sales Manager", "VP Sales"],
    "marketing":   ["Content Lead", "Growth Marketer", "Designer", "CMO"],
    "ops":         ["IT Support", "Sysadmin", "IT Manager"],
    "exec":        ["CEO", "CTO", "COO", "General Counsel"],
}

WEAK_PASSWORDS = [
    "Summer2026!", "Company123", "Password1", "letmein123",
    "Nimbus!2026", "qwerty123", "Welcome1", "changeme",
]

OS_CHOICES = ["ubuntu-22.04", "ubuntu-24.04", "windows-11", "macos-14"]


def _name(rng: random.Random, used: set[str]) -> str:
    while True:
        n = f"{rng.choice(FIRST)} {rng.choice(LAST)}"
        if n not in used:
            used.add(n)
            return n


def build(seed: int = 1337) -> World:
    rng = random.Random(seed)

    employees: list[Employee] = []
    assets: list[Asset] = []
    credentials: list[Credential] = []
    secrets: list[Secret] = []
    vulns: list[Vuln] = []

    used_names: set[str] = set()
    emp_n = 0

    # ---------- employees + workstations ----------
    for dept, cfg in DEPTS.items():
        subnet = cfg["subnet"]
        for i in range(cfg["headcount"]):
            emp_n += 1
            eid = f"e{emp_n:04d}"
            name = _name(rng, used_names)
            first, last = name.split(" ", 1)
            email = f"{first.lower()}.{last.lower().replace(' ', '')}@nimbus.local"

            ws_id = f"ws-{dept[:3]}-{i:02d}"
            ws_ip = f"{subnet}.{10 + i}"

            is_admin = dept == "ops" and rng.random() < 0.25
            risk = round(min(1.0, max(0.0, rng.gauss(0.35, 0.22))), 2)

            emp = Employee(
                id=eid, name=name, email=email, dept=dept,
                title=rng.choice(TITLES[dept]),
                workstation=ws_id, risk=risk, admin=is_admin,
            )
            employees.append(emp)

            assets.append(Asset(
                id=ws_id, kind="workstation",
                hostname=f"{ws_id}.nimbus.local",
                ip=ws_ip, net="lan",
                os=rng.choice(OS_CHOICES),
                services=["ssh"] if rng.random() < 0.7 else [],
                owner=eid,
            ))

            # 1-2 credentials per employee
            for _ in range(rng.choice([1, 1, 2])):
                cid = f"c{len(credentials) + 1:05d}"
                weak = rng.random() < risk
                pw = rng.choice(WEAK_PASSWORDS) if weak else f"{rng.randrange(10**9):09d}"
                cred = Credential(
                    id=cid, username=email.split("@")[0],
                    password=pw, strength=0.2 if weak else 0.9,
                    owner=eid,
                    grants=[ws_id],
                )
                credentials.append(cred)
                emp.creds.append(cid)

    # ---------- core servers ----------
    servers = [
        # id, hostname, ip, net, services, data, crown_jewel
        ("web-dmz-01", "web-dmz-01.nimbus.local", "10.10.0.10", "dmz",
         ["http", "https"], ["public_site"], False),
        ("vpn-01", "vpn-01.nimbus.local", "10.10.0.20", "dmz",
         ["wireguard"], [], False),
        ("mail-01", "mail-01.nimbus.local", "10.10.0.30", "dmz",
         ["smtp", "imap"], ["mail_spool"], False),
        ("gitea-01", "gitea-01.nimbus.local", "10.20.1.10", "lan",
         ["http", "ssh"], ["source_code"], False),
        ("ci-runner-01", "ci-runner-01.nimbus.local", "10.20.1.11", "lan",
         ["ssh", "docker"], ["build_artifacts"], False),
        ("db-prod-01", "db-prod-01.nimbus.local", "10.20.1.20", "lan",
         ["postgres"], ["customer_pii", "billing"], True),
        ("db-hr-01", "db-hr-01.nimbus.local", "10.20.1.21", "lan",
         ["postgres"], ["employee_records"], True),
        ("files-01", "files-01.nimbus.local", "10.20.1.30", "lan",
         ["smb", "http"], ["shared_drive"], False),
        ("jump-01", "jump-01.nimbus.local", "10.20.1.40", "lan",
         ["ssh"], [], False),
        ("log-01", "log-01.nimbus.local", "10.30.0.10", "mgmt",
         ["http", "syslog"], ["audit_logs"], False),
    ]

    for sid, hostname, ip, net, svcs, data, jewel in servers:
        assets.append(Asset(
            id=sid, kind="server", hostname=hostname, ip=ip, net=net,
            os="ubuntu-24.04", services=svcs, data=data, crown_jewel=jewel,
        ))

    assets_by_id = {a.id: a for a in assets}

    # ---------- service credentials ----------
    svc_creds = [
        ("gitea-01", "git", "gitea"),
        ("db-prod-01", "postgres", "dbprod"),
        ("db-hr-01", "postgres", "dbhr"),
        ("ci-runner-01", "runner", "runner"),
        ("jump-01", "ops", "jump"),
    ]
    for asset_id, user, hint in svc_creds:
        cid = f"c{len(credentials) + 1:05d}"
        credentials.append(Credential(
            id=cid, username=user,
            password=f"{hint}-{rng.randrange(10**6):06d}",
            strength=0.8, owner=None, grants=[asset_id],
        ))
        assets_by_id[asset_id].holds.append(cid)

    # ---------- secrets ----------
    secret_defs = [
        ("api_key", "billing-api", ["db-prod-01"]),
        ("cloud_cred", "aws-prod", ["files-01", "db-prod-01"]),
        ("ssh_key", "deploy-key", ["ci-runner-01"]),
        ("db_password", "prod-db", ["db-prod-01"]),
        ("ssh_key", "backup-key", ["files-01"]),
    ]
    for kind, label, unlocks in secret_defs:
        sid = f"s{len(secrets) + 1:04d}"
        secrets.append(Secret(
            id=sid, kind=kind,
            location=f"gitea-01:infra/{label}/.env",
            unlocks=unlocks, exposure=0.0,
        ))

    # stash secrets on plausible hosts
    assets_by_id["gitea-01"].holds.extend(["s0001", "s0002", "s0003"])
    assets_by_id["ci-runner-01"].holds.append("s0004")
    assets_by_id["files-01"].holds.append("s0005")

    # ---------- vulnerabilities ----------
    vuln_defs = [
        ("v0001", "ssrf", "web-dmz-01", "high", None,
         [], ["lan"]),
        ("v0002", "weak_ssh_password", "jump-01", "medium", None,
         [], ["jump-01"]),
        ("v0003", "exposed_git_config", "gitea-01", "medium", None,
         ["v0001"], ["gitea-01"]),
        ("v0004", "docker_socket_mount", "ci-runner-01", "critical", None,
         [], ["ci-runner-01"]),
        ("v0005", "unpatched_postgres", "db-prod-01", "critical", None,
         [], ["db-prod-01"]),
        ("v0006", "vpn_no_mfa", "vpn-01", "high", None, [], ["vpn-01"]),
    ]
    for vid, kind, on, sev, cve, req, grants in vuln_defs:
        vulns.append(Vuln(
            id=vid, kind=kind, on=on, severity=sev,
            cve=cve, requires=req, grants=grants,
        ))
        assets_by_id[on].vulns.append(vid)

    # ---------- kubernetes cluster ----------
    k8s_assets = [
        Asset(id="ingress-01", kind="server", hostname="ingress-01.nimbus.local",
              ip="10.10.0.40", net="dmz", os="ubuntu-24.04", services=["http"],
              data=["ingress:billing-api-pod"]),
        Asset(id="billing-api-pod", kind="pod", hostname="billing-api-pod.nimbus.local",
              ip="10.25.0.11", net="k8s", os="container", services=["http"]),
        Asset(id="metrics-pod", kind="pod", hostname="metrics-pod.nimbus.local",
              ip="10.25.0.12", net="k8s", os="container"),
        Asset(id="k8s-node-01", kind="node", hostname="k8s-node-01.nimbus.local",
              ip="10.25.0.2", net="k8s", os="ubuntu-24.04", services=["kubelet"]),
    ]
    assets.extend(k8s_assets)

    # the pod's mounted service-account token (by design - every pod has one)
    secrets.append(Secret(
        id="s0006", kind="service_account_token",
        location="billing-api-pod:/var/run/secrets/kubernetes.io/serviceaccount/token",
        unlocks=[]))
    k8s_assets[1].holds.append("s0006")

    service_accounts = [
        ServiceAccount(id="sa-001", name="billing-api", namespace="payments",
                       permissions=["secrets.list", "pods.list"],
                       mounts=["billing-api-pod"], overprivileged=True,
                       escalates_to=["db-hr-01"]),
        ServiceAccount(id="sa-002", name="default", namespace="payments",
                       permissions=[], mounts=["metrics-pod"], overprivileged=False),
    ]

    # internet-facing billing API behind the ingress has an auth bypass
    vulns.append(Vuln(id="v0007", kind="api_auth_bypass", on="billing-api-pod",
                      severity="high", requires=[],
                      grants=["billing-api-pod"]))
    k8s_assets[1].vulns.append("v0007")

    # ---------- seed one accidental exposure (day-0 incident) ----------
    secrets[0].exposure = 1.0
    secrets[0].location = "public-github/fork-billing-api/.env"

    return World(
        org={"name": "Nimbus Dynamics", "domain": "nimbus.local"},
        employees=employees,
        assets=assets,
        credentials=credentials,
        secrets=secrets,
        vulns=vulns,
        service_accounts=service_accounts,
        day=0,
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--out", default="world.json")
    args = ap.parse_args()

    w = build(args.seed)
    w.save(args.out)

    print(f"wrote {args.out}")
    print(f"  employees:    {len(w.employees)}")
    print(f"  assets:       {len(w.assets)}")
    print(f"  credentials:  {len(w.credentials)}")
    print(f"  secrets:      {len(w.secrets)}")
    print(f"  vulns:        {len(w.vulns)}")
    print(f"  crown jewels: {sum(1 for a in w.assets if a.crown_jewel)}")


if __name__ == "__main__":
    main()
