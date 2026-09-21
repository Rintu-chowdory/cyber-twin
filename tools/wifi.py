"""Wireless recon and attack for the Cyber Twin lab.

    python -m tools.wifi [--crack] [--report]

Scan: enumerates the org's SSIDs as a war-driving pass would see them.
Crack: wordlist attack on WPA2-PSK passphrases plus a WPS pin attack
on WPS-enabled networks. Report: submit cracked psks as credential
findings (proof = the psk) - unless the defender rotated them.
"""
from __future__ import annotations

import argparse
import json
import urllib.request

from world.schema import World
from world.seed import WEAK_PASSWORDS


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--world", default="world.json")
    ap.add_argument("--api", default="http://localhost:8000")
    ap.add_argument("--crack", action="store_true")
    ap.add_argument("--report", action="store_true")
    args = ap.parse_args()

    world = World.load(args.world)
    nets = world.wifi_networks

    if not args.crack:
        print("== wifi scan ==")
        for w in nets:
            lock = "OPEN" if w.security == "open" else w.security.upper()
            extra = " [WPS]" if w.wps else ""
            print(f"  {w.ssid:<14} {lock:<10} clients: {len(w.clients)}{extra}")
        print("\n(--crack runs a wordlist + WPS pin attack)")
        return

    print(f"== wifi crack: wordlist x {len(WEAK_PASSWORDS)} + WPS pin attack ==")
    cracked = []
    for w in nets:
        if w.security == "open":
            print(f"  {w.ssid:<14} open network - just join it")
            cracked.append(w)
        elif w.psk in WEAK_PASSWORDS:
            print(f"  {w.ssid:<14} HANDSHAKE CAPTURED - psk cracked: '{w.psk}'")
            cracked.append(w)
        elif w.wps:
            print(f"  {w.ssid:<14} WPS PIN attack - pixie-dust: no luck "
                  "(patched firmware)")
        else:
            print(f"  {w.ssid:<14} handshake captured, psk resisted wordlist")

    if not args.report:
        return
    for w in cracked:
        cred = next((c for c in world.credentials
                     if c.kind == "wifi_psk" and c.username == w.ssid), None)
        if not cred:
            print(f"  {w.ssid}: open network, no psk to score")
            continue
        body = json.dumps({"kind": "credential", "id": cred.id,
                           "proof": cred.password}).encode()
        req = urllib.request.Request(f"{args.api}/report", data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                res = json.loads(r.read())
            print(f"  reported {w.ssid} psk: "
                  + (f"+{res['awarded']} pts" if res.get("ok") else str(res)))
        except urllib.error.HTTPError as e:
            print(f"  reported {w.ssid} psk: REJECTED ({e.code}) - rotated?")


if __name__ == "__main__":
    main()
