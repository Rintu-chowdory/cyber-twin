"""Cyber Twin world model schema.

The world model is the single source of truth for the simulated company.
The compiler materializes it into running containers; the scenario tick
mutates it. Nothing here touches Docker - it's pure data.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal, Optional

import json

Net = Literal["dmz", "lan", "mgmt"]


@dataclass
class Employee:
    id: str
    name: str
    email: str
    dept: str
    title: str
    workstation: str
    creds: list[str] = field(default_factory=list)
    risk: float = 0.3          # 0 = paranoid, 1 = clicks everything
    admin: bool = False


@dataclass
class Asset:
    id: str
    kind: str                  # workstation | server | appliance
    hostname: str
    ip: str
    net: Net
    os: str
    services: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)
    holds: list[str] = field(default_factory=list)   # cred/secret ids on disk
    data: list[str] = field(default_factory=list)    # data labels
    owner: Optional[str] = None                      # employee id
    crown_jewel: bool = False
    isolated: bool = False        # set by the defender via control API


@dataclass
class Credential:
    id: str
    username: str
    password: str              # plaintext BY DESIGN - lab only, never reuse
    kind: str = "password"     # password | ssh_key | token
    strength: float = 0.5
    owner: Optional[str] = None
    grants: list[str] = field(default_factory=list)  # asset ids this works on


@dataclass
class Secret:
    id: str
    kind: str                  # api_key | db_password | ssh_key | cloud_cred
    location: str
    unlocks: list[str] = field(default_factory=list)
    exposure: float = 0.0      # 0 = internal only, 1 = public internet


@dataclass
class Vuln:
    id: str
    kind: str
    on: str                    # asset id
    severity: str              # low | medium | high | critical
    cve: Optional[str] = None
    requires: list[str] = field(default_factory=list)  # prereqs (creds, position)
    grants: list[str] = field(default_factory=list)     # what you get


@dataclass
class World:
    org: dict
    employees: list[Employee]
    assets: list[Asset]
    credentials: list[Credential]
    secrets: list[Secret]
    vulns: list[Vuln]
    day: int = 0

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str) -> "World":
        with open(path) as f:
            d = json.load(f)
        return cls(
            org=d["org"],
            employees=[Employee(**e) for e in d["employees"]],
            assets=[Asset(**{**{'isolated': False}, **a}) for a in d["assets"]],
            credentials=[Credential(**c) for c in d["credentials"]],
            secrets=[Secret(**s) for s in d["secrets"]],
            vulns=[Vuln(**v) for v in d["vulns"]],
            day=d.get("day", 0),
        )

    def index(self) -> dict:
        """Fast lookups by id, used by the compiler and scenarios."""
        return {
            "employees": {e.id: e for e in self.employees},
            "assets": {a.id: a for a in self.assets},
            "credentials": {c.id: c for c in self.credentials},
            "secrets": {s.id: s for s in self.secrets},
            "vulns": {v.id: v for v in self.vulns},
        }
