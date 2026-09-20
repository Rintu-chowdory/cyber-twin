"""Compile world.json into a runnable docker-compose.yml.

Only server-class assets become containers by default (120 workstations
would melt a laptop). Workstations stay in the world model as attackable
metadata and can be opted in with --workstations N to materialize a sample.

Networks map 1:1 to the world model:
    dmz  -> 172.28.0.0/24   (attacker can reach these)
    lan  -> 10.20.0.0/24    (internal; requires a pivot)
    mgmt -> 10.30.0.0/24    (logging/control plane)
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

# world service -> compose service template
SERVICE_SPECS = {
    "web-dmz-01": {
        "image": "nginx:1.27-alpine",
        "networks": ["dmz"],
        "ports": ["8080:80"],
        "volumes": ["./volumes/web/html:/usr/share/nginx/html:ro",
                    "logs-web:/var/log/nginx"],
    },
    "vpn-01": {
        "image": "linuxserver/wireguard:latest",
        "networks": ["dmz"],
        "cap_add": ["NET_ADMIN", "SYS_MODULE"],
        "sysctls": ["net.ipv4.ip_forward=1"],
        "ports": ["51820:51820/udp"],
        "volumes": ["./volumes/wireguard:/config", "logs-vpn:/var/log"],
    },
    "mail-01": {
        "image": "nginx:1.27-alpine",  # placeholder: real SMTP lands in phase 2
        "networks": ["dmz"],
        "volumes": ["logs-mail:/var/log/nginx"],
    },
    "gitea-01": {
        "image": "gitea/gitea:1.21",
        "networks": ["lan"],
        "ports": ["3000:3000"],
        "volumes": ["./volumes/gitea:/data", "logs-gitea:/var/log"],
    },
    "ci-runner-01": {
        "image": "ubuntu:24.04",  # placeholder: gitlab-runner in phase 2
        "networks": ["lan"],
        "command": ["sleep", "infinity"],
        "volumes": ["logs-ci:/var/log"],
    },
    "db-prod-01": {
        "image": "postgres:16",
        "networks": ["lan"],
        "environment": ["POSTGRES_DB=prod",
                        "POSTGRES_PASSWORD_FILE=/run/secrets/db_prod_pw"],
        "volumes": ["db-prod:/var/lib/postgresql/data", "logs-db:/var/log"],
    },
    "db-hr-01": {
        "image": "postgres:16",
        "networks": ["lan"],
        "environment": ["POSTGRES_DB=hr",
                        "POSTGRES_PASSWORD_FILE=/run/secrets/db_hr_pw"],
        "volumes": ["db-hr:/var/lib/postgresql/data", "logs-hr:/var/log"],
    },
    "files-01": {
        "image": "nginx:1.27-alpine",
        "networks": ["lan"],
        "volumes": ["./volumes/files:/usr/share/nginx/html:ro",
                    "logs-files:/var/log/nginx"],
    },
    "jump-01": {
        "image": "linuxserver/openssh-server:latest",
        "networks": ["lan"],
        "volumes": ["logs-jump:/var/log"],
    },
    "log-01": {
        "image": "nginx:1.27-alpine",  # placeholder: loki in phase 2
        "networks": ["mgmt", "lan"],
        "volumes": ["logs-web:/mnt/logs-web:ro",
                    "logs-gitea:/mnt/logs-gitea:ro",
                    "logs-jump:/mnt/logs-jump:ro"],
    },
}

LOG_VOLUMES = [
    "logs-web", "logs-vpn", "logs-mail", "logs-gitea", "logs-ci",
    "logs-db", "logs-hr", "logs-files", "logs-jump",
]

NETWORKS = {
    "dmz": {"driver": "bridge", "ipam": {"config": [{"subnet": "172.28.0.0/24"}]}},
    "lan": {"driver": "bridge", "ipam": {"config": [{"subnet": "10.20.0.0/24"}]}},
    "mgmt": {"driver": "bridge", "ipam": {"config": [{"subnet": "10.30.0.0/24"}]}},
}

ATTACKER = {
    "attacker": {
        "image": "kalilinux/kali-rolling:latest",
        "networks": ["dmz"],
        "command": ["sleep", "infinity"],
        "cap_add": ["NET_ADMIN"],
    }
}


def compile_world(world_path: str, out_path: str, workstations: int = 0) -> None:
    world = json.loads(Path(world_path).read_text())

    services = dict(ATTACKER)
    for asset in world["assets"]:
        spec = SERVICE_SPECS.get(asset["id"])
        if spec:
            services[asset["id"]] = spec

    # opt-in sample of workstations on the lan
    ws = [a for a in world["assets"] if a["kind"] == "workstation"]
    for asset in ws[:workstations]:
        services[asset["id"]] = {
            "image": "linuxserver/openssh-server:latest",
            "networks": ["lan"],
            "volumes": [f"logs-{asset['id']}:/var/log"],
        }
        LOG_VOLUMES.append(f"logs-{asset['id']}")

    compose = {
        "name": "cyber-twin",
        "networks": NETWORKS,
        "volumes": {v: {} for v in LOG_VOLUMES} | {
            "db-prod": {}, "db-hr": {},
        },
        "services": services,
    }

    Path(out_path).write_text(
        "# AUTO-GENERATED from world.json - do not edit by hand.\n"
        "# Regenerate with: python -m compiler.materialize\n"
        + yaml.safe_dump(compose, sort_keys=False)
    )
    print(f"wrote {out_path} with {len(services)} services")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--world", default="world.json")
    ap.add_argument("--out", default="docker-compose.yml")
    ap.add_argument("--workstations", type=int, default=0,
                    help="materialize N sample workstations on the lan")
    args = ap.parse_args()
    compile_world(args.world, args.out, args.workstations)


if __name__ == "__main__":
    main()
