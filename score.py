"""Score the game: attacker findings vs defender response.

Attacker scores by submitting findings to the control API (POST /report):
a compromised credential or a reached asset, each with proof. Points
come from what was touched, not how loud you were.

Defender scores per incident: severity points, decaying by a day of
inaction, with a penalty for collateral damage (users locked out).

    python -m score                       # console scoreboard
    python -m score --html site/index.html # publishable page
"""
from __future__ import annotations

import argparse
import html
import json
from pathlib import Path

from world.schema import World

SEVERITY_POINTS = {"critical": 50, "high": 35, "medium": 20, "low": 10, "info": 5}
DAILY_DECAY = 15
COLLATERAL_PENALTY = 10
ATTACKER_POINTS = {
    "credential_weak": 10,
    "credential_strong": 25,   # strong creds = better attacker work
    "asset_dmz": 5,
    "asset_lan": 15,
    "crown_jewel": 50,
}

_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _incident_severity(incident: dict) -> str:
    sev = "low"
    for ch in incident.get("changes", []):
        t = ch.get("type")
        if t == "new_vuln":
            s = ch.get("severity", "medium")
        elif t == "entity_set" and ch.get("entity") == "secrets":
            s = "high"
        elif t in ("new_service", "new_data", "entity_set", "entity_append"):
            s = "medium"
        else:
            s = "low"
        if _SEV_ORDER.get(s, 0) > _SEV_ORDER.get(sev, 0):
            sev = s
    return sev


def compute_scores(world: World, state: dict) -> dict:
    # ---- defender ----
    incidents: list[dict] = []
    mttrs: list[int] = []
    earned = 0
    unresolved = 0

    for inc in state.get("incidents", []):
        sev = _incident_severity(inc)
        base = SEVERITY_POINTS.get(sev, 10)
        targets = set(inc.get("targets", []))

        # first defender action touching one of the incident's targets
        res_day = None
        for act in state.get("actions", []):
            if act.get("day", -1) >= inc.get("day", 0) and act.get("target") in targets:
                res_day = act["day"]
                break

        if res_day is None:
            unresolved += 1
            points, mttr = 0, None
        else:
            mttr = max(0, res_day - inc.get("day", 0))
            mttrs.append(mttr)
            points = max(0, base - DAILY_DECAY * mttr)
        earned += points
        incidents.append({
            "card": inc.get("card"), "day": inc.get("day"),
            "severity": sev, "targets": sorted(targets),
            "resolved_day": res_day, "mttr_days": mttr, "points": points,
        })

    collateral = len(state.get("collateral", []))
    defender = {
        "score": earned - COLLATERAL_PENALTY * collateral,
        "incidents": incidents,
        "unresolved": unresolved,
        "collateral_events": collateral,
        "mttr_avg_days": round(sum(mttrs) / len(mttrs), 1) if mttrs else None,
        "actions_taken": len(state.get("actions", [])),
    }

    # ---- attacker ----
    findings = []
    att = 0
    for f in state.get("findings", []):
        att += f.get("points", 0)
        findings.append({k: f.get(k) for k in ("day", "kind", "id", "label", "points")})
    attacker = {"score": att, "findings": findings}

    return {"day": world.day, "org": world.org,
            "attacker": attacker, "defender": defender}


# ---------------------------------------------------------------- console

def print_scores(sc: dict) -> None:
    print(f"=== Cyber Twin scoreboard - day {sc['day']} "
          f"({sc['org']['name']}) ===")
    print(f"\nATTACKER: {sc['attacker']['score']} pts")
    for f in sc["attacker"]["findings"]:
        print(f"  day {f['day']:>2}  {f['points']:>3} pts  {f['label']}")
    d = sc["defender"]
    print(f"\nDEFENDER: {d['score']} pts  "
          f"(avg MTTR {d['mttr_avg_days']}d, {d['unresolved']} unresolved, "
          f"{d['collateral_events']} collateral)")
    for i in d["incidents"]:
        status = (f"resolved day {i['resolved_day']} (MTTR {i['mttr_days']}d)"
                  if i["resolved_day"] is not None else "OPEN")
        print(f"  day {i['day']:>2}  {i['severity']:<8} {i['card']:<24} "
              f"{i['points']:>3} pts  {status}")


# ---------------------------------------------------------------- html

def build_html(sc: dict) -> str:
    d = sc["defender"]
    a = sc["attacker"]
    esc = html.escape

    def _row(i: dict) -> str:
        if i["resolved_day"] is None:
            css, status = "open", "OPEN"
        else:
            css = "ok"
            status = f"resolved day {i['resolved_day']} (MTTR {i['mttr_days']}d)"
        return (
            f'<tr class="{css}"><td>{i["day"]}</td>'
            f'<td>{esc(i["card"] or "")}</td>'
            f'<td><span class="sev {i["severity"]}">{i["severity"]}</span></td>'
            f'<td>{esc(", ".join(i["targets"]))}</td>'
            f"<td>{status}</td>"
            f'<td class="num">{i["points"]}</td></tr>')

    inc_rows = "".join(_row(i) for i in d["incidents"])

    find_rows = "".join(
        f"<tr><td>{f['day']}</td><td>{esc(f['kind'])}</td>"
        f"<td>{esc(f['label'] or '')}</td>"
        f"<td class=\"num\">{f['points']}</td></tr>"
        for f in a["findings"]) or "<tr><td colspan=\"4\" class=\"none\">no findings submitted yet</td></tr>"

    mttr = d["mttr_avg_days"] if d["mttr_avg_days"] is not None else "n/a"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cyber Twin - scoreboard</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; font-family: ui-monospace, "SF Mono", Menlo, monospace;
          background: #0b0e14; color: #c9d1d9; padding: 2.5rem 1rem; }}
  .wrap {{ max-width: 900px; margin: 0 auto; }}
  h1 {{ font-size: 1.4rem; letter-spacing: .2em; margin: 0 0 .2rem; }}
  .sub {{ color: #8b949e; margin: 0 0 2rem; }}
  .tiles {{ display: grid; gap: 1rem; grid-template-columns: 1fr 1fr; }}
  .tile {{ border: 1px solid #21262d; border-radius: 10px; padding: 1.2rem 1.4rem; }}
  .tile.att {{ border-color: #f8514966; }}
  .tile.def {{ border-color: #3fb95066; }}
  .tile h2 {{ margin: 0; font-size: .75rem; letter-spacing: .15em;
              text-transform: uppercase; color: #8b949e; }}
  .tile .pts {{ font-size: 2.6rem; font-weight: 700; margin-top: .3rem; }}
  .att .pts {{ color: #f85149; }} .def .pts {{ color: #3fb950; }}
  .tile .meta {{ color: #8b949e; font-size: .8rem; margin-top: .4rem; }}
  h3 {{ margin: 2.2rem 0 .6rem; font-size: .8rem; letter-spacing: .15em;
        text-transform: uppercase; color: #8b949e; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
  th, td {{ text-align: left; padding: .45rem .6rem; border-bottom: 1px solid #21262d; }}
  th {{ color: #8b949e; font-weight: 400; font-size: .75rem;
        text-transform: uppercase; letter-spacing: .1em; }}
  td.num {{ text-align: right; }}
  tr.open td {{ background: #f8514912; }}
  .none {{ color: #484f58; }}
  .sev {{ font-size: .7rem; padding: .1rem .45rem; border-radius: 99px;
          border: 1px solid #30363d; text-transform: uppercase; }}
  .sev.critical {{ color: #f85149; border-color: #f8514966; }}
  .sev.high {{ color: #d29922; border-color: #d2992266; }}
  .sev.medium {{ color: #58a6ff; border-color: #58a6ff66; }}
  .sev.low {{ color: #8b949e; }}
  footer {{ margin-top: 3rem; color: #484f58; font-size: .75rem; }}
</style></head><body><div class="wrap">
<h1>CYBER TWIN</h1>
<p class="sub">{esc(sc['org']['name'])} &middot; day {sc['day']} &middot; attacker vs defender</p>
<div class="tiles">
  <div class="tile att"><h2>Attacker</h2>
    <div class="pts">{a['score']} pts</div>
    <div class="meta">{len(a['findings'])} findings submitted</div></div>
  <div class="tile def"><h2>Defender</h2>
    <div class="pts">{d['score']} pts</div>
    <div class="meta">avg MTTR {mttr}d &middot; {d['unresolved']} unresolved &middot;
      {d['collateral_events']} collateral &middot; {d['actions_taken']} actions</div></div>
</div>
<h3>Incidents (daily drift)</h3>
<table><tr><th>Day</th><th>Card</th><th>Severity</th><th>Targets</th>
<th>Status</th><th style="text-align:right">Pts</th></tr>
{inc_rows or '<tr><td colspan="6" class="none">no incidents yet</td></tr>'}</table>
<h3>Attacker findings</h3>
<table><tr><th>Day</th><th>Kind</th><th>Claim</th>
<th style="text-align:right">Pts</th></tr>{find_rows}</table>
<footer>Regenerate with <code>python -m score --html site/index.html</code>,
then commit and push - the page auto-deploys.</footer>
</div></body></html>"""


# ---------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--world", default="world.json")
    ap.add_argument("--state", default="control/state.json")
    ap.add_argument("--html", help="write a standalone scoreboard page")
    args = ap.parse_args()

    world = World.load(args.world)
    state = json.loads(Path(args.state).read_text()) if Path(args.state).exists() else {}

    sc = compute_scores(world, state)
    print_scores(sc)

    if args.html:
        out = Path(args.html)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(build_html(sc))
        print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
