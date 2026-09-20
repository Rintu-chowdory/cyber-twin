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
- [x] Phase 2 — Compiler: world -> docker-compose (3 networks, attacker box on dmz)
- [x] Phase 3 — Scenario tick (1 card: leaked_api_key)
- [ ] Phase 4 — Defender control API (block_ip, isolate, rotate, patch)
- [ ] Phase 5 — Kubernetes port (RBAC / ServiceAccount attack paths)

## Quickstart

```bash
pip install -r requirements.txt

# 1. generate the org (deterministic: same seed = same company)
python -m world.seed --seed 1337 --out world.json

# 2. compile it into docker-compose.yml
python -m compiler.materialize --world world.json

# 3. run the company (needs Docker)
docker compose up -d

# 4. attack from the attacker box (dmz only - pivot to reach the lan)
docker compose exec attacker bash

# 5. advance a day: apply a scenario card and recompile
python -m tick --scenario scenarios/leaked_api_key.yaml
python -m compiler.materialize --world world.json
```

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
scenarios/*.yaml          daily mutation cards
tick.py                  apply a card, bump the day, save
```
