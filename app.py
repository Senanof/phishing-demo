"""University phishing simulation: automatic TCP scans of approved lab IPs.

SETUP (Debian/Ubuntu/Kali; Python 3.10+):
    sudo apt install nmap python3-venv
    python3 -m venv .venv
    . .venv/bin/activate
    pip install flask gunicorn

Keep your existing templates/index.html next to this file. A plain fallback
page is supplied if it is missing. Set the exact IPs approved for your lab:
    export ALLOWED_SCAN_IPS='192.168.1.50,192.168.1.51'
    python app.py

Open http://SERVER_LAN_IP:5000/ from an approved device. For a same-computer
demo, set ALLOWED_SCAN_IPS='127.0.0.1' and visit http://127.0.0.1:5000/.
An empty allowlist means visits are logged but no scans run.

Results: data/scans/<UTC-time>_<random-id>.txt and matching .json metadata.
Visits: data/visits.jsonl (one JSON object per line).
Change DATA_DIR to a private writable directory outside any static web root.

For a deployed lab use ONE process, no preload/reloader:
    gunicorn --workers 1 --threads 4 --bind 0.0.0.0:5000 app:app
The scan slot and cooldown are process-local and reset on restart. Jobs are
not durable; use a persistent job queue for multiple processes or replicas.

PROXIES: Forwarded headers are ignored by default. Only if you control ONE
reverse proxy that appends the actual client IP as the RIGHTMOST X-Forwarded-For
entry, set TRUSTED_PROXY_IPS to its exact socket IP(s). Restrict the origin to
that proxy. For multiple proxies or a hosting platform, verify its actual
header behavior/network topology before adapting this setting. Do not simply
trust the leftmost header value or mark all addresses trusted.

HOSTING: The runtime must contain the nmap executable, permit outbound TCP,
and keep the process alive. A plain Python dependency install does not install
nmap. Hosted results need persistent storage if they must survive redeploys.
The observed public IP may be a router/VPN/CGNAT gateway, not the visitor's
device. A LAN lab with distinct device IPs gives a more reliable demonstration.
Approve the actual target/network, not merely the person clicking the link.
Email preview/security bots can also visit links; a hit is not proof of a click.

The scan checks only 22,80,443,8080 via TCP connect. No credentials are collected,
and no service/version probing or vulnerability scripts are run. Exit code zero
does not guarantee a complete scan; inspect the saved output for timeouts.
"""

import ipaddress
import json
import logging
import os
import shutil
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, render_template, request
from jinja2 import TemplateNotFound

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
DATA_DIR = Path(os.environ.get("DATA_DIR", "data"))
SCAN_DIR = DATA_DIR / "scans"
SCAN_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
NMAP = shutil.which("nmap")
PORTS = "22,80,443,8080"
COOLDOWN_SECONDS = 600


def normalize_ip(value):
    if not value or "%" in value:
        raise ValueError("Missing IP or unsupported scope identifier")
    address = ipaddress.ip_address(value.strip())
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def configured_ips(name):
    # Exact numeric addresses only: no hostnames, ranges, flags or shell input.
    return frozenset(normalize_ip(x) for x in os.getenv(name, "").split(",") if x.strip())


ALLOWED_IPS = configured_ips("ALLOWED_SCAN_IPS")
TRUSTED_PROXIES = configured_ips("TRUSTED_PROXY_IPS")
lock = threading.Lock()
scan_slot = threading.BoundedSemaphore(1)
last_scan = {}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def visitor_ip():
    direct = normalize_ip(request.remote_addr)
    if direct not in TRUSTED_PROXIES:
        return direct
    # Fail closed if the configured proxy did not supply a usable address.
    forwarded = request.headers.get("X-Forwarded-For", "")
    if not forwarded or len(forwarded) > 4096:
        raise ValueError("Missing or oversized proxy header")
    return normalize_ip(forwarded.split(",")[-1])


def run_scan(target, scan_id):
    metadata = {"id": scan_id, "target": target, "started": utc_now()}
    try:
        command = [NMAP, "--unprivileged", "-sT", "-Pn", "-n", "-p", PORTS,
                   "--max-retries", "1", "--host-timeout", "30s"]
        if ipaddress.ip_address(target).version == 6:
            command.append("-6")
        command.append(target)
        metadata["command"] = command
        # Direct output to disk: no shell, and no unbounded in-memory capture.
        with (SCAN_DIR / f"{scan_id}.txt").open("w", encoding="utf-8") as output:
            try:
                result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT,
                                        timeout=40, check=False, shell=False)
                metadata.update(status="exited", returncode=result.returncode)
            except subprocess.TimeoutExpired:
                metadata["status"] = "process_timeout"
    except Exception as exc:
        metadata.update(status="error", error=str(exc))
        app.logger.exception("Scan failed: %s", scan_id)
    finally:
        try:
            metadata["finished"] = utc_now()
            (SCAN_DIR / f"{scan_id}.json").write_text(
                json.dumps(metadata, indent=2), encoding="utf-8")
            app.logger.info("scan=%s target=%s status=%s", scan_id, target, metadata["status"])
        except OSError:
            app.logger.exception("Could not save scan metadata")
        finally:
            scan_slot.release()


def schedule_scan(target):
    if target not in ALLOWED_IPS:
        return "not_allowlisted", None
    address = ipaddress.ip_address(target)
    if address.is_multicast or address.is_unspecified or address.is_link_local:
        return "unsupported_target", None
    if NMAP is None:
        return "nmap_missing", None
    with lock:
        now = time.monotonic()
        previous = last_scan.get(target)
        if previous is not None and now - previous < COOLDOWN_SECONDS:
            return "cooldown", None
        if not scan_slot.acquire(blocking=False):
            return "scanner_busy", None
        scan_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex
        last_scan[target] = now
        try:
            threading.Thread(target=run_scan, args=(target, scan_id), daemon=True).start()
        except Exception:
            if previous is None:
                last_scan.pop(target, None)
            else:
                last_scan[target] = previous
            scan_slot.release()
            app.logger.exception("Could not start scan worker")
            return "worker_error", None
        return "started", scan_id


@app.route("/")
def home():
    try:
        target = visitor_ip()
        # HEAD requests from link checkers should not trigger scans.
        status, scan_id = schedule_scan(target) if request.method == "GET" else ("head_only", None)
    except ValueError:
        target, status, scan_id = None, "invalid_ip", None
    entry = {"timestamp": utc_now(), "visitor": target,
             "direct": request.remote_addr, "scan_status": status, "scan_id": scan_id}
    with lock:
        with (DATA_DIR / "visits.jsonl").open("a", encoding="utf-8") as log:
            log.write(json.dumps(entry) + "\n")
    app.logger.info("visit=%s", json.dumps(entry))
    try:
        return render_template("index.html")
    except TemplateNotFound as exc:
        if exc.name != "index.html":
            raise
        return "<!doctype html><title>University lab</title><h1>University simulation</h1>"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
