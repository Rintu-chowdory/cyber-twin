"""Generate the Cyber Twin hacking dashboard - a live, interactive
network map of the org with scores, incidents and attacker findings.

    python -m dashboard [--world world.json] [--state control/state.json]
                       [--html site/index.html]

The page is fully self-contained (vanilla JS, no CDN): the current
world + game state is embedded as JSON. Regenerate after a game,
commit, push - Render auto-deploys it.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from score import compute_scores
from world.schema import World

TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CYBER TWIN // live ops</title>
<style>
  :root { color-scheme: dark;
    --bg:#050807; --panel:#0a100d; --line:#1d2b22; --txt:#c8e6cc;
    --dim:#5d7a66; --hot:#00ff88; --red:#ff4d5e; --amber:#ffb454; --blue:#54c2ff; }
  * { box-sizing:border-box; margin:0; }
  body { background:var(--bg); color:var(--txt);
    font-family:ui-monospace,"SF Mono",Menlo,monospace; font-size:13px;
    padding:14px; overflow-x:hidden; }
  body::before { content:""; position:fixed; inset:0; pointer-events:none;
    background:repeating-linear-gradient(0deg,transparent 0 2px,rgba(0,255,136,.015) 2px 4px); }
  .bar { display:flex; flex-wrap:wrap; gap:10px; align-items:stretch;
    border:1px solid var(--line); background:var(--panel); padding:10px 14px; }
  .bar h1 { font-size:15px; letter-spacing:.25em; color:var(--hot);
    text-shadow:0 0 8px rgba(0,255,136,.4); padding-top:6px; }
  .bar .sub { color:var(--dim); font-size:11px; letter-spacing:.1em; }
  .scores { display:flex; gap:10px; margin-left:auto; }
  .tile { border:1px solid var(--line); padding:6px 14px; text-align:right; min-width:120px; }
  .tile .k { color:var(--dim); font-size:10px; letter-spacing:.2em; }
  .tile .v { font-size:22px; font-weight:700; }
  .tile.att .v { color:var(--red); } .tile.def .v { color:var(--hot); }
  .grid { display:grid; grid-template-columns:1fr 340px; gap:10px; margin-top:10px; }
  @media (max-width:900px){ .grid{grid-template-columns:1fr} }
  .panel { border:1px solid var(--line); background:var(--panel); }
  .panel h2 { font-size:10px; letter-spacing:.25em; color:var(--dim);
    padding:8px 12px; border-bottom:1px solid var(--line);
    display:flex; justify-content:space-between; }
  .panel h2 b { color:var(--txt); }
  .zones { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; padding:10px; }
  @media (max-width:1100px){ .zones{grid-template-columns:repeat(2,1fr)} }
  @media (max-width:700px){ .zones{grid-template-columns:1fr} }
  .b.rbac { color:#000; background:var(--amber); border-color:var(--amber); font-weight:700; }
  .zone { border:1px dashed var(--line); padding:8px; min-height:120px; }
  .zone h3 { font-size:10px; letter-spacing:.2em; color:var(--dim); margin-bottom:8px;
    display:flex; justify-content:space-between; }
  .zone h3 span { color:var(--hot); }
  .node { border:1px solid var(--line); background:#0c1410; padding:6px 8px;
    margin-bottom:6px; cursor:pointer; transition:all .12s; position:relative; }
  .node:hover { border-color:var(--hot); box-shadow:0 0 10px rgba(0,255,136,.15); }
  .node.sel { border-color:var(--hot); }
  .node .id { font-weight:700; } .node .ip { color:var(--dim); font-size:11px; }
  .node .svcs { color:var(--blue); font-size:10px; margin-top:2px; }
  .node .badges { position:absolute; top:6px; right:6px; display:flex; gap:3px; }
  .b { font-size:9px; padding:0 4px; border:1px solid var(--line); color:var(--dim); }
  .b.crit { color:var(--red); border-color:var(--red); }
  .b.high { color:var(--amber); border-color:var(--amber); }
  .b.jewel { color:#000; background:var(--hot); border-color:var(--hot); }
  .b.leak { color:#000; background:var(--red); border-color:var(--red); }
  .b.own { color:#000; background:var(--red); border-color:var(--red); font-weight:700; }
  .b.cred { color:var(--red); border-color:var(--red); }
  .node.own { border-color:var(--red); box-shadow:0 0 14px rgba(255,77,94,.35); }
  .node.own .id { color:var(--red); }
  .chip.own { color:var(--red); border-color:var(--red); }
  .chips { display:flex; flex-wrap:wrap; gap:4px; margin-top:8px; }
  .chip { font-size:10px; border:1px solid var(--line); color:var(--dim);
    padding:1px 5px; cursor:pointer; }
  .chip:hover { color:var(--hot); border-color:var(--hot); }
  .chip.sel { color:var(--hot); border-color:var(--hot); }
  .feed { max-height:420px; overflow-y:auto; }
  .inc { padding:8px 12px; border-bottom:1px solid var(--line); }
  .inc .card { font-weight:700; }
  .inc .meta { color:var(--dim); font-size:11px; margin-top:2px; }
  .st { font-size:10px; padding:0 5px; border:1px solid var(--line); }
  .st.open { color:var(--red); border-color:var(--red); animation:blink 1.4s infinite; }
  .st.res { color:var(--hot); border-color:var(--hot); }
  .sev { font-size:10px; padding:0 5px; border:1px solid var(--line); color:var(--dim); }
  .sev.critical { color:var(--red); border-color:var(--red); }
  .sev.high { color:var(--amber); border-color:var(--amber); }
  .sev.medium { color:var(--blue); border-color:var(--blue); }
  .fnd { padding:8px 12px; border-bottom:1px solid var(--line); color:var(--red); }
  .fnd .meta { color:var(--dim); font-size:11px; }
  .stat { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-top:10px; }
  .stat .panel { padding:10px 12px; }
  .stat .v { font-size:20px; font-weight:700; color:var(--hot); }
  .stat .v.bad { color:var(--red); }
  .stat .k { color:var(--dim); font-size:10px; letter-spacing:.15em; }
  #detail { position:fixed; right:14px; bottom:14px; width:340px;
    border:1px solid var(--hot); background:#07120c; padding:12px;
    box-shadow:0 0 24px rgba(0,255,136,.25); display:none; z-index:9; }
  #detail h4 { color:var(--hot); letter-spacing:.1em; }
  #detail .x { float:right; cursor:pointer; color:var(--dim); }
  #detail .row { margin-top:6px; font-size:11px; }
  #detail .row b { color:var(--dim); font-weight:400; }
  footer { margin-top:10px; color:#2e3b32; font-size:10px; letter-spacing:.1em; }
  @keyframes blink { 50% { opacity:.35; } }
</style></head><body>
<div class="bar">
  <div><h1>&gt;_ CYBER TWIN</h1>
    <div class="sub" id="sub"></div></div>
  <div class="scores">
    <div class="tile att"><div class="k">ATTACKER</div><div class="v" id="att">0</div></div>
    <div class="tile def"><div class="k">DEFENDER</div><div class="v" id="def">0</div></div>
  </div>
</div>
<div class="stat" id="stat"></div>
<div class="grid">
  <div class="panel"><h2>NETWORK MAP <b>click any node</b></h2><div class="zones" id="zones"></div></div>
  <div>
    <div class="panel"><h2>INCIDENT FEED <b id="incn"></b></h2><div class="feed" id="inc"></div></div>
    <div class="panel" style="margin-top:10px"><h2>ATTACKER FINDINGS <b id="fndn"></b></h2><div class="feed" id="fnd"></div></div>
    <div class="panel" style="margin-top:10px"><h2>SERVICE ACCOUNTS / RBAC <b id="san"></b></h2><div class="feed" id="sa"></div></div>
  </div>
</div>
<div id="detail"></div>
<footer>CYBER TWIN // world.json embedded, regenerate with <span>python -m dashboard</span> // auto-deploys on push</footer>
<script>
const D = __DATA__;
const $ = id => document.getElementById(id);

$('sub').textContent = D.org.name + ' · day ' + D.day + ' · ' + D.org.domain;
$('att').textContent = D.scores.attacker + ' pts';
$('def').textContent = D.scores.defender + ' pts';

// ---- surface stats
$('stat').innerHTML = [
  ['exposed secrets', D.surface.exposed_secrets, D.surface.exposed_secrets > 0],
  ['weak credentials', D.surface.weak_creds, D.surface.weak_creds > 0],
  ['known vulns', D.surface.total_vulns, D.surface.total_vulns > 0],
  ['crown jewels', D.scores.jewels, false],
].map(([k, v, bad]) =>
  `<div class="panel"><div class="v ${bad ? 'bad' : ''}">${v}</div><div class="k">${k}</div></div>`).join('');

// ---- zones + nodes
const zones = { dmz: 'DMZ / internet-facing', k8s: 'K8S / CLUSTER', lan: 'LAN / internal', mgmt: 'MGMT / control' };
const inZone = (a, z) => z === 'k8s' ? (a.kind === 'pod' || a.kind === 'node')
  : a.net === z && a.kind !== 'pod' && a.kind !== 'node';
let html = '';
for (const [net, label] of Object.entries(zones)) {
  const assets = D.assets.filter(a => inZone(a, net));
  const servers = assets.filter(a => a.kind !== 'workstation');
  const wss = assets.filter(a => a.kind === 'workstation');
  html += `<div class="zone"><h3>${label}<span>${assets.length}</span></div>`;
  for (const a of servers) html += node(a);
  if (wss.length) {
    const byDept = {};
    for (const w of wss) (byDept[w.id.split('-')[1]] ??= []).push(w);
    for (const [dept, list] of Object.entries(byDept))
      html += `<div class="chips">` + list.map(w =>
        `<span class="chip${w.cred_breach ? ' own' : ''}" onclick="show('${w.id}')">${w.id}${w.cred_breach ? ' !' : ''}</span>`).join('') +
        `</div><div class="chips" style="color:#2e3b32;font-size:9px">^ ${dept} workstations (${list.length})</div>`;
  }
  html += '</div>';
}
$('zones').innerHTML = html;

function node(a) {
  const sev = a.vulns.length ? a.vulns.map(v => v.severity) : [];
  const crit = sev.includes('critical'), high = sev.includes('high');
  let badges = '';
  if (a.owned) badges += '<span class="b own">OWNED</span>';
  if (a.crown_jewel) badges += '<span class="b jewel">JEWEL</span>';
  if (crit) badges += '<span class="b crit">CRIT</span>';
  if (high && !crit) badges += '<span class="b high">HIGH</span>';
  if (a.leaked) badges += '<span class="b leak">LEAK</span>';
  if (a.sas.length) badges += a.sas.some(x => x.overprivileged)
    ? '<span class="b rbac">RBAC!</span>' : '<span class="b">SA</span>';
  if (a.cred_breach) badges += '<span class="b cred">CRACKED</span>';
  return `<div class="node${a.owned ? ' own' : ''}" onclick="show('${a.id}')">
    <div class="badges">${badges}</div>
    <div class="id">${a.id}</div><div class="ip">${a.ip}</div>
    <div class="svcs">${a.services.join(' ') || '-'}</div></div>`;
}

function show(id) {
  const a = D.assets.find(x => x.id === id);
  const held = a.holds.length ? a.holds.join(', ') : 'none';
  const vulns = a.vulns.length ? a.vulns.map(v =>
    `${v.id} ${v.kind} (${v.severity})`).join('<br>') : 'none';
  const data = a.data.length ? a.data.join(', ') : 'none';
  const sas = a.sas.length ? a.sas.map(x => x.name + (x.overprivileged ? ' (OVERPRIVILEGED: ' + x.permissions.join(', ') + ')' : '')).join(', ') : 'none';
  const breach = a.owned ? '<div class="row" style="color:var(--red)">COMPROMISED - attacker access confirmed</div>'
    : a.cred_breach ? '<div class="row" style="color:var(--red)">OWNER CREDENTIALS CRACKED</div>' : '';
  $('detail').innerHTML = `<span class="x" onclick="detail.style.display='none'">[x]</span>
    <h4>${a.id}</h4>${breach}
    <div class="row"><b>host</b> ${a.hostname} · ${a.os}</div>
    <div class="row"><b>net</b> ${a.net} · ${a.ip} · services: ${a.services.join(', ') || '-'}</div>
    <div class="row"><b>vulns</b><br>${vulns}</div>
    <div class="row"><b>service accounts</b> ${sas}</div>
    <div class="row"><b>holds</b> ${held}</div>
    <div class="row"><b>data</b> ${data}</div>`;
  $('detail').style.display = 'block';
}

// ---- incidents + findings
$('incn').textContent = D.scores.incident_count;
$('inc').innerHTML = D.incidents.map(i => `
  <div class="inc"><span class="card">${i.card}</span>
    <span class="sev ${i.severity}">${i.severity}</span>
    <span class="st ${i.resolved_day === null ? 'open' : 'res'}">
    ${i.resolved_day === null ? 'OPEN' : 'FIXED d' + i.resolved_day + ' · MTTR ' + i.mtr_days + 'd'}</span>
    <div class="meta">day ${i.day} · targets ${i.targets.join(', ')}</div>
  </div>`).join('') || '<div class="inc"><div class="meta">no incidents yet</div></div>';

$('fndn').textContent = D.findings.length + ' live';

// ---- RBAC panel
const over = D.service_accounts.filter(s => s.overprivileged).length;
$('san').textContent = over + ' overprivileged';
$('sa').innerHTML = D.service_accounts.map(s => `
  <div class="inc"><span class="card">${s.name}</span>
    ${s.overprivileged ? '<span class="st open">OVERPRIVILEGED</span>' : '<span class="st res">ok</span>'}
    <div class="meta">ns ${s.namespace} · token mounted: ${s.mounts.join(', ') || 'none'}</div>
    <div class="meta">rbac: ${s.permissions.join(', ') || 'none'}</div>
    ${s.escalates_to.length ? `<div class="meta" style="color:var(--amber)">escalates to: ${s.escalates_to.join(', ')}</div>` : ''}
  </div>`).join('');
$('fnd').innerHTML = D.findings.map(f => `
  <div class="fnd">+${f.points} · <span style="color:var(--amber)">${f.kind}</span> · ${f.label}
    <div class="meta">day ${f.day} · ${f.id}</div></div>`).join('')
  || '<div class="fnd" style="color:#2e3b32">no findings submitted</div>';
</script></body></html>"""


def build_payload(world: World, state: dict) -> dict:
    sc = compute_scores(world, state)

    # map findings onto assets: crown-jewel hits mark the asset OWNED,
    # cracked credentials mark the owner's workstation
    sa_by_pod: dict[str, list] = {}
    for sa in world.service_accounts:
        for m in sa.mounts:
            sa_by_pod.setdefault(m, []).append(sa)
    owned_assets = set()
    cracked_ws = set()
    for f in sc["attacker"]["findings"]:
        if f["kind"] == "asset_access":
            owned_assets.add(f["id"])
        elif f["kind"] == "credential":
            cred = next((c for c in world.credentials if c.id == f["id"]), None)
            if cred and cred.owner:
                ws = next((a for a in world.assets if a.owner == cred.owner
                           and a.kind == "workstation"), None)
                if ws:
                    cracked_ws.add(ws.id)
    vuln_by_on: dict[str, list] = {}
    for v in world.vulns:
        vuln_by_on.setdefault(v.on, []).append(
            {"id": v.id, "kind": v.kind, "severity": v.severity})
    assets = [{
        "id": a.id, "kind": a.kind, "hostname": a.hostname, "ip": a.ip,
        "net": a.net, "os": a.os, "services": a.services,
        "vulns": vuln_by_on.get(a.id, []), "holds": a.holds,
        "data": a.data, "crown_jewel": a.crown_jewel,
        "leaked": any(s.id in a.holds and s.exposure > 0 for s in world.secrets),
        "sas": [{"name": sa.name, "namespace": sa.namespace,
                 "overprivileged": sa.overprivileged,
                 "permissions": sa.permissions}
                for sa in sa_by_pod.get(a.id, [])],
        "owned": a.id in owned_assets,
        "cred_breach": a.id in cracked_ws,
    } for a in world.assets]

    return {
        "org": world.org, "day": world.day,
        "scores": {
            "attacker": sc["attacker"]["score"],
            "defender": sc["defender"]["score"],
            "jewels": sum(1 for a in world.assets if a.crown_jewel),
            "incident_count": len(sc["defender"]["incidents"]),
        },
        "surface": {
            "exposed_secrets": sum(1 for s in world.secrets if s.exposure > 0),
            "weak_creds": sum(1 for c in world.credentials
                              if c.owner and c.strength <= 0.3),
            "total_vulns": len(world.vulns),
        },
        "assets": assets,
        "service_accounts": [{
            "id": sa.id, "name": sa.name, "namespace": sa.namespace,
            "permissions": sa.permissions, "mounts": sa.mounts,
            "overprivileged": sa.overprivileged,
            "escalates_to": sa.escalates_to,
        } for sa in world.service_accounts],
        "incidents": [{
            "card": i["card"], "day": i["day"], "severity": i["severity"],
            "targets": i["targets"], "resolved_day": i["resolved_day"],
            "mtr_days": i["mttr_days"], "points": i["points"],
        } for i in sc["defender"]["incidents"]],
        "findings": sc["attacker"]["findings"],
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--world", default="world.json")
    ap.add_argument("--state", default="control/state.json")
    ap.add_argument("--html", default="site/index.html")
    args = ap.parse_args()

    world = World.load(args.world)
    state = (json.loads(Path(args.state).read_text())
             if Path(args.state).exists() else {})

    page = TEMPLATE.replace("__DATA__", json.dumps(build_payload(world, state)))
    out = Path(args.html)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page)
    print(f"wrote {out} ({len(page) // 1024} kb, day {world.day})")


if __name__ == "__main__":
    main()
