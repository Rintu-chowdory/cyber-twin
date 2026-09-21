# Cyber Twin

A virtual company you can hack. The point isn't finding CVE X — it's
reasoning about an entire organization's security posture.

**Fictional org:** *Nimbus Dynamics* (~120 employees, HR/Finance/Dev/etc.,
workstations, servers, credentials, secrets, logs) living across three
networks: `dmz`, `lan`, `mgmt`.

## Architecture

    world.json  --compiler-->  docker-compose.yml
        ^                              |
        |                              v
     tick.py  <-- scenarios/      running containers
        |
        +--> defender API (phase 4)

The **world model is the source of truth**. Containers are materialized
from it. Scenarios mutate the model daily and the environment drifts.
The AI defender reasons over state + real service logs, not fiction.

## Status

- [x] Phase 1 — World model (schema + deterministic seeder)
- [x] Phase 2 — Compiler: world -> docker-compose (3 networks, attacker on dmz, defender-api on mgmt)
- [x] Phase 3 — Scenario tick (9 weighted cards + `--random` daily draw)
- [x] Phase 4 — Defender control API (reads, actions, daily budget, collateral)
- [x] Phase 5 — Kubernetes attack paths: SA tokens, overprivileged RBAC, ingress chains (world model + attack graph + dashboard; live cluster materialization still future)

## Quickstart

```bash
pip install -r requirements.txt

# 1. generate the org (deterministic: same seed = same company)
python -m world.seed --seed 1337 --out world.json

# 2. materialize it into a REAL container stack
python -m compiler.materialize --world world.json --out runtime/generated

# 3. boot the company (needs Docker)
docker compose -f runtime/generated/docker-compose.yml up -d --build

# 4. the company is live:
#    http://localhost:18080           - Nimbus Dynamics public site (real logins)
#    http://localhost:18000/state      - defender API
#    (ports overridable: WEB_PORT=... API_PORT=... docker compose up)
```

## What actually runs now

Real containers, real software, credentials straight from the world
model (so tools/crack.py output really works):

- **web-dmz-01** - Flask + gunicorn, dual-homed dmz/corp. Employee
  logins check the provisioned passwords. Seeded flaws are real code:
  `/fetch` is a working SSRF (http AND file scheme) and the only
  network pivot from dmz into corp; `/fork-billing-api/.env` serves
  the day-0 leak, including the real db-prod-01 password.
- **gitea-01** - git over ssh (git-shell), bare repo `billing-api`
  seeded at first boot with the same leaked `.env`.
- **db-prod-01 / db-hr-01** - real Postgres 16 with generated
  customer PII and the actual 120-employee org chart. Passwords from
  the world model; NOT published to the host - you must pivot.
- **workstations + jump-01** - real sshd; each box provisions its
  owner's credentials. 12 materialized by default
  (`--workstations N` to change).
- **api** - the defender control plane, on the mgmt network.
- **attacker** (profile) - kali box on dmz: external starting position.
  **attacker-corp** (profile `onnet`) - kali box inside corp: simulates
  a cracked-wifi / insider position.

```bash
docker compose -f runtime/generated/docker-compose.yml --profile attacker run --rm attacker bash
# in the kali box: apt update && apt install -y nmap sqlmap ssh ...
```

Docker's inter-network isolation enforces the zones: the dmz can reach
nothing on corp except through web-dmz-01's SSRF, or by cracking wifi
(the onnet profile). WiFi radios and a live k8s cluster are the two
pieces still simulated rather than containerized.

## Rules of the game

**Attacker** (you): start outside, on the dmz network only. Points for
touching crown jewels (`db-prod-01`, `db-hr-01`), reading secrets, and
staying undetected.

**Defender** (AI, phase 4): reads real logs (nginx/sshd/postgres auth lines
shipped to `log-01`), detects, and acts within a daily action budget:

```
read:  logs.query, assets.list, net.flows, world.diff
write: net.block_ip, host.isolate, cred.rotate, svc.patch, backup.restore
budget: 100 pts/day   (block_ip=1, isolate=3, rotate=2, patch=5, restore=20)
```

Collateral damage (blocking an employee mid-shift) costs points — so the
defender can't just nuke everything.

## Notes

- Credentials in `world.json` are **plaintext by design** (lab only). Never
  reuse them anywhere real. Keep the repo private.
- Day-0 incident is pre-seeded: one API key is already sitting in a public
  GitHub fork. The first defender job is finding it.

## Layout

```
world/schema.py          dataclasses: Employee, Asset, Credential, Secret, Vuln
world/seed.py            deterministic org generator (--seed)
compiler/materialize.py  world.json -> docker-compose.yml
scenarios/*.yaml          daily mutation cards (weight, predicates, expected response)
tick.py                  apply a card (weighted --random or explicit), bump the day
tools/recon.py           passive recon: public attack surface, leaks, weak-cred candidates
tools/crack.py           wordlist attack on user accounts (--report scores the cracks)
tools/attack_paths.py    BFS from the internet to every crown jewel, with the exact chain
tools/wifi.py            wireless: scan SSIDs, wordlist psk crack, WPS pin attack
dashboard.py             generates the live hacking dashboard (site/index.html)
defender/agent.py         observe -> decide -> act loop skeleton (LLM hook marked)
control/api.py            defender control plane (reads, actions, budget)
```

## Scenario library

Nine weighted cards drive the daily drift (weight = relative chance
in the `--random` draw). Cards carry predicates, so a card that no
longer applies (secret already leaked, vuln already present) skips
itself instead of double-applying:

| weight | card                  | what happens                                      |
|--------|-----------------------|---------------------------------------------------|
| 3      | leaked_api_key        | API key pushed to a public GitHub fork            |
| 3      | vulnerable_deploy     | unreviewed hotfix adds SQLi to web-dmz-01         |
| 2      | phishing_upload       | high-risk employee lands a macro doc on their PC  |
| 2      | breach_dump           | a strong password appears in a breach dump        |
| 2      | firewall_misconfig    | admin console exposed to the internet             |
| 2      | leaked_ssh_key        | deploy key pasted to a public pastebin            |
| 2      | db_backup_exposed     | unencrypted prod backup on the world-readable share |
| 2      | malicious_dependency  | typo-squatted package taints CI artifacts         |
| 1      | overprivileged_access | contractor keeps local admin                     |

Each card also declares what the defender is expected to do
(`defender_expected`) - that's the raw material for the scoring system.
The attacker-vs-defender rematch writes itself: once the defender
rotates the leaked key, the card becomes eligible again on a later day.

## Scoring (phase 6)

It's a game now:

**Attacker** submits findings with proof to `POST /report`:

```json
{"kind": "credential", "id": "c00042", "proof": "<actual password>"}
{"kind": "asset_access", "id": "db-prod-01", "credential": "c00181", "proof": "<password>"}
```

Points: weak credential 10, strong credential 25, dmz asset 5, lan asset
15, **crown jewel 50**. No proof, no points - and a proof that no longer
matches (the defender rotated it) is worth nothing, so rotations bite.

**Defender** scores per incident: severity points (critical 50 / high 35 /
medium 20 / low 10) minus 15 per day of delay, floor 0. Every incident a
day of drift stays unresolved decays toward zero. Collateral (isolating a
workstation = locking out a user) costs 10 per event.

`python -m score` prints the scoreboard; `python -m score --html
site/index.html` writes the publishable page. Play a scripted demo round:

    python -m world.seed && uvicorn control.api:app & python demo_game.py

## Hacking dashboard

**Live: https://cyber-twin-scoreboard.onrender.com** (auto-deploys from main)

Interactive network map of the whole org - DMZ/LAN/MGMT zones, every
asset with live vuln/jewel/leak badges, incident feed with MTTR,
attacker findings, and the public attack surface at a glance. Click
any node for its detail (services, vulns, held secrets, data).

    python -m dashboard --html site/index.html   # regenerate after a game

## Attacker toolkit

```bash
python -m tools.recon            # what an outsider sees
python -m tools.crack            # wordlist attack on user accounts
python -m tools.crack --report   # ... and score the cracks via the API
python -m tools.attack_paths     # internet -> crown jewel, exact chain
python -m tools.wifi             # scan SSIDs
python -m tools.wifi --crack     # wordlist attack on WPA2 PSKs + WPS pin
python -m tools.wifi --report    # score cracked psks via the control API
```

`attack_paths.py` is also the defender's triage tool: cut the cheapest
link in each chain first (rotate the leaked key and the shortest path
to `db-prod-01` dies).

### Kubernetes attack paths

The world now carries a cluster slice: `ingress-01` (dmz) routes to
`billing-api-pod`, whose mounted service-account token (`s0006`)
belongs to the overprivileged `sa-001` (`secrets.list`, `pods.list`).
The chain the tool finds:

    internet -> ingress-01 --ingress route--> billing-api-pod
      --vuln v0007 (api_auth_bypass)--> billing-api-pod
      --sa token sa-001 (billing-api) - rbac: secrets.list--> db-hr-01

The `privileged_pod` scenario card drifts the cluster daily (privileged
container -> node escape).

### Wireless attack surface

`Nimbus-Corp` runs WPA2-PSK with the same weak passphrase half the org
uses as a password - a parking-lot wordlist attack lands straight on
engineering workstations. `Nimbus-Guest` is open. `Nimbus-IoT` has WPS
enabled (pin attack). Cracked wifi is an entry edge in
`attack_paths.py`, and the dashboard has a WIRELESS / WIFI panel. The dashboard has a K8S/CLUSTER zone, RBAC
badges on pods and a SERVICE ACCOUNTS / RBAC panel.

## Scoreboard page (legacy simple board)

`python -m score --html` still writes the plain scoreboard. Regenerate after a game with
`python -m score --html site/index.html`, commit, push.

## Defender control API (phase 4)

The defender's whole world goes through `http://localhost:8000`:

```
GET  /state      day, budget left, blocked IPs, collateral count
GET  /assets     every asset: ip, net, services, vulns, isolation state
GET  /secrets    secret locations + exposure (values are never returned)
GET  /logs       real service logs, ?source=&q=&limit= (compose mounts them at /mnt)
GET  /diff       what changed since yesterday's tick snapshot
POST /act        {"action", "target", "param", "note"}
```

Actions and prices (100 pts per day, reset by the tick):

| action            | pts | target        | note                                    |
|-------------------|-----|---------------|-----------------------------------------|
| block_ip          | 1   | IPv4          |                                        |
| isolate_host      | 3   | asset id      | collateral recorded if it's a workstation |
| rotate_credential | 2   | credential id | old password dead, strength 1.0          |
| rotate_secret    | 2   | secret id     | exposure back to 0, leaked copies dead   |
| patch_service     | 5   | asset id      | param = vuln id                          |
| restore_backup    | 20  | asset id      | rebuild from backup, clears vulns        |

Run it locally:

```bash
pip install -r requirements-control.txt
uvicorn control.api:app --port 8000     # swagger docs at /docs
```

Or inside the lab (logs mounted read-only at /mnt): `docker compose up defender-api`.

`defender/agent.py` is the skeleton loop: observe -> decide -> act. The
`decide()` function is the marked LLM hook where the defender brain goes -
it gets state, diff and recent log lines, and returns actions within budget.
