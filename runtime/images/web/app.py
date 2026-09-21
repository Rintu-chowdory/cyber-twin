"""Nimbus Dynamics public site - the real (deliberately flawed) web tier.

Real logins check the provisioned credential file, so cracked
passwords from the world model actually work here. Seeded flaws:
  /fetch                    SSRF - the only route from DMZ into corp
  /fork-billing-api/.env   the day-0 leaked secret
"""
import os
import urllib.request

from flask import Flask, redirect, request, session

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "nimbus-lab-only-secret")
USERS = os.environ.get("USERS_FILE", "/provision/users.txt")
LEAK = os.environ.get("LEAK_FILE", "/provision/leaked.env")
INTRANET = os.environ.get("INTRANET_FILE", "/provision/intranet.txt")


def load_users():
    users = {}
    try:
        with open(USERS) as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 3:
                    users[parts[0]] = (parts[1], parts[2])
    except FileNotFoundError:
        pass
    return users


@app.route("/")
def index():
    return """<h1>Nimbus Dynamics</h1>
<p>Cloud billing and IoT telemetry for mid-market Europe.</p>
<ul>
<li><a href="/login">Employee login</a></li>
<li><a href="/careers">Careers</a></li>
</ul>
<p><small>(c) Nimbus Dynamics GmbH - nimbus.local</small></p>"""


@app.route("/careers")
def careers():
    return "<h1>Careers</h1><p>We are hiring! 120 employees and growing.</p>"


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u, p = request.form.get("u", ""), request.form.get("p", "")
        users = load_users()
        if u in users and users[u][0] == p:
            session["user"] = u
            return redirect("/intranet")
        return "<h3>Login failed</h3>", 401
    return """<h3>Employee login</h3>
<form method="post">user <input name=u> pass <input name=p type=password>
<input type=submit value=Login></form>"""


@app.route("/intranet")
def intranet():
    if "user" not in session:
        return redirect("/login")
    try:
        body = open(INTRANET).read()
    except FileNotFoundError:
        body = "internal directory not provisioned"
    return "<h2>Nimbus intranet</h2><pre>" + body + "</pre>"


@app.route("/fetch")
def fetch():
    """v0001 - SSRF. The pivot from DMZ into the corp network."""
    url = request.args.get("url", "")
    if not url:
        return "usage: /fetch?url=http://10.20.1.20:5432/ ...", 400
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.read()[:5000]
    except Exception as e:  # noqa: BLE001 - part of the vuln surface
        return f"error: {e}", 502


@app.route("/fork-billing-api/.env")
def leaked_env():
    """day-0 incident: a public fork still carries the real .env"""
    try:
        return open(LEAK).read()
    except FileNotFoundError:
        return "gone", 404
