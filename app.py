import os
import time
import uuid
import ipaddress
import threading
import logging
from collections import deque
from flask import Flask, jsonify, request, send_from_directory

import scanner
from response_manager import (
    validate_ip,
    validate_mac,
    unblock_ip,
    unblock_mac,
    is_ip_blocked as rm_is_ip_blocked,
    is_mac_blocked as rm_is_mac_blocked,
    verify_ip_rule_present,
    verify_mac_rule_present,
    resolve_and_block_source,
    get_source_block_snapshot,
    mac_blocking_supported,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("netsentinel")

app = Flask(__name__, static_folder=None)

MAX_ALERTS = 500
MAX_SCAN_HISTORY = 100
MAX_SCAN_JOBS = 200
SCAN_JOB_RETENTION = 50

# -- incident correlation settings ------------------------------------------
# One intentional attack (e.g. a single Nmap run) can trigger several related
# detections (port scan + host sweep, or several port-scan hits as thresholds
# re-cross cooldowns). Alerts sharing the same source IP, target IP, and
# category within INCIDENT_MERGE_WINDOW seconds of each other are folded into
# a single incident instead of creating duplicate top-level entries.
# Different categories (Reconnaissance / DoS / Anomaly / MAC-ARP) are never
# merged with each other.
INCIDENT_MERGE_WINDOW = 45
MAX_INCIDENTS = 300
MAX_EVENTS_PER_INCIDENT = 50
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

RECOMMENDED_RESPONSES = {
    "Reconnaissance": "Review firewall rules for the source IP; consider rate-limiting or blocking if scanning continues.",
    "DoS / Flood": "Investigate the source IP immediately; consider temporary rate-limiting or upstream filtering.",
    "Anomaly": "Review application/service logs for the target; confirm whether retries are expected client behavior.",
    "MAC / ARP": "Verify the device physically; investigate possible ARP spoofing, DHCP churn, or a NIC replacement.",
}

state_lock = threading.RLock()
scan_lock = threading.Lock()

devices = {}
scan_jobs = {}
scan_history = deque(maxlen=MAX_SCAN_HISTORY)

# incidents: incident_id -> full incident record (rich detail preserved here)
# incident_index: (source_ip, target_ip, category) -> incident_id of the most
#   recent active incident for that combination, used to correlate new alerts.
incidents = {}
incident_index = {}

monitor_state = {
    "running": False,
    "interface": None,
    "started_at": None,
}

network_monitor = None
network_monitor_lock = threading.Lock()

ALLOWED_BLOCK_DURATIONS = {300, 600, 900, 1800}
DEFAULT_BLOCK_DURATION = 300
blocked_ips = {}
blocked_macs = {}
# Tracks repeated attack attempts from sources that are already blocked.
# Unlike the old "ignored" log, these attempts are always still surfaced in
# the dashboard/alert history - this is purely a counter for display.
source_repeat_log = {}


def get_block_status(source_ip, source_mac=None):
    """
    Returns (blocked, method, expires_at) for a source, checking MAC first
    (the primary blocking mechanism for local-network devices) and falling
    back to IP (used for remote/off-segment sources). Lazily expires local
    bookkeeping - and asks the response manager to remove the underlying
    firewall rule - once the block duration has elapsed.
    """
    now = time.time()

    if source_mac:
        expired_mac = None
        with state_lock:
            mac_info = blocked_macs.get(source_mac)
            if mac_info:
                if mac_info["expires_at"] > now:
                    return True, "mac", mac_info["expires_at"]
                blocked_macs.pop(source_mac, None)
                expired_mac = source_mac
        if expired_mac:
            logger.info("BLOCK_EXPIRED mac=%s", expired_mac)
            result = unblock_mac(expired_mac)
            if not result.get("success"):
                logger.debug("Unblock for expired mac=%s returned: %s", expired_mac, result.get("error"))

    if not source_ip:
        return False, None, None

    expired_ip = None
    with state_lock:
        block_info = blocked_ips.get(source_ip)
        if block_info:
            if block_info["expires_at"] > now:
                return True, "ip", block_info["expires_at"]
            blocked_ips.pop(source_ip, None)
            expired_ip = source_ip

    if expired_ip:
        logger.info("BLOCK_EXPIRED source_ip=%s", expired_ip)
        result = unblock_ip(expired_ip)
        if not result.get("success"):
            logger.debug(
                "Unblock for expired source_ip=%s returned: %s",
                expired_ip, result.get("error"),
            )
    return False, None, None


def get_verification_status(method, source_ip, source_mac):
    """Live, read-only re-check against the firewall (not just our bookkeeping)."""
    if method == "mac" and source_mac:
        return "traffic_stopped" if verify_mac_rule_present(source_mac) else "verification_failed"
    if method == "ip" and source_ip:
        return "traffic_stopped" if verify_ip_rule_present(source_ip) else "verification_failed"
    return None


def is_ip_blocked(source_ip):
    blocked, _method, _expires_at = get_block_status(source_ip)
    return blocked


def _severity_rank(severity):
    return SEVERITY_RANK.get(severity, 0)


def cleanup_incidents_locked():
    if len(incidents) <= MAX_INCIDENTS:
        return
    ordered = sorted(incidents.items(), key=lambda kv: kv[1]["last_seen"])
    excess = len(incidents) - MAX_INCIDENTS
    for incident_id, _record in ordered[:excess]:
        incidents.pop(incident_id, None)
        stale_keys = [k for k, v in incident_index.items() if v == incident_id]
        for k in stale_keys:
            incident_index.pop(k, None)


def add_alert(alert):
    """
    Callback passed into scanner.NetworkMonitor. Every detection rule in
    scanner.py produces a dict with `category` + `attack_type` + rich
    evidence fields; this function is where those individual detections get
    correlated into incidents (source IP + target IP + category + time
    window) so one real attack doesn't show up as many duplicate top-level
    alerts. Full detail is retained on the incident object for later use by
    the frontend; the existing dashboard alert list continues to receive a
    simple row shape via api_alerts().
    """
    if not isinstance(alert, dict):
        return

    source_ip = alert.get("source_ip")
    source_mac = alert.get("source_mac")
    attack_type = alert.get("attack_type") or alert.get("detection_type") or "Unknown"

    # IMPORTANT: a blocked source is NEVER hidden, suppressed, or dropped
    # here. We only look up its current block/verification status so the
    # dashboard can show it accurately (e.g. "Already blocked / traffic
    # stopped" vs "Attack ongoing"), then fall through to record the alert
    # exactly like any other detection.
    blocked, block_method, block_expires_at = get_block_status(source_ip, source_mac)
    verification_status = get_verification_status(block_method, source_ip, source_mac) if blocked else None

    repeat_count = None
    if blocked:
        repeat_key = (block_method, source_mac if block_method == "mac" else source_ip)
        with state_lock:
            entry = source_repeat_log.setdefault(repeat_key, {"repeat_count": 0, "last_attempt_at": None})
            entry["repeat_count"] += 1
            entry["last_attempt_at"] = time.time()
            repeat_count = entry["repeat_count"]
        logger.info(
            "BLOCKED_SOURCE_REPEAT_ATTEMPT source_ip=%s source_mac=%s method=%s attack_type=%s "
            "repeat_count=%s verification=%s",
            source_ip, source_mac, block_method, attack_type, repeat_count, verification_status,
        )

    if blocked and verification_status == "traffic_stopped":
        response_status = "mitigated" if repeat_count == 1 else "blocked_source_repeated_attempt"
    elif blocked:
        # The block is recorded but the firewall rule can no longer be
        # confirmed - do not claim success that hasn't been verified.
        response_status = "attack_ongoing"
    else:
        response_status = "unblocked"

    now = time.time()
    category = alert.get("category") or "Reconnaissance"
    target_ip = alert.get("target_ip")
    severity = alert.get("severity", "medium")
    # Backward-compatible fallback in case any caller still uses the old field name.
    destination_port = alert.get("destination_port", alert.get("target_ports"))

    raw_event = {
        "alert_id": str(uuid.uuid4()),
        "attack_type": attack_type,
        "timestamp": now,
        "source_port": alert.get("source_port"),
        "destination_port": destination_port,
        "protocol": alert.get("protocol"),
        "packet_count": alert.get("packet_count"),
        "event_count": alert.get("event_count"),
        "ports_scanned_count": alert.get("ports_scanned_count"),
        "hosts_contacted_count": alert.get("hosts_contacted_count"),
        "evidence": alert.get("evidence") or alert.get("details"),
        "severity": severity,
        "source_blocked": blocked,
        "block_method": block_method,
        "verification_status": verification_status,
        "response_status": response_status,
    }

    index_key = (source_ip, target_ip, category)

    with state_lock:
        incident_id = incident_index.get(index_key)
        incident = incidents.get(incident_id) if incident_id else None

        if incident and now - incident["last_seen"] <= INCIDENT_MERGE_WINDOW:
            # Same source + target + category within the correlation window:
            # merge into the existing incident rather than creating a new one.
            incident["last_seen"] = now
            incident["event_count"] = incident.get("event_count", 0) + 1
            if attack_type not in incident["related_techniques"]:
                incident["related_techniques"].append(attack_type)
            if alert.get("source_mac"):
                incident["source_mac"] = alert["source_mac"]
            if alert.get("target_mac"):
                incident["target_mac"] = alert["target_mac"]
            if destination_port is not None:
                new_ports = destination_port if isinstance(destination_port, list) else [destination_port]
                incident["destination_ports"] = sorted(set(incident.get("destination_ports") or []) | set(new_ports))
            if alert.get("ports_scanned_count"):
                incident["ports_scanned_count"] = max(incident.get("ports_scanned_count") or 0, alert["ports_scanned_count"])
            if alert.get("hosts_contacted_count"):
                incident["hosts_contacted_count"] = max(incident.get("hosts_contacted_count") or 0, alert["hosts_contacted_count"])
            if alert.get("packet_count"):
                incident["packet_count"] = (incident.get("packet_count") or 0) + alert["packet_count"]
            if _severity_rank(severity) > _severity_rank(incident["severity"]):
                incident["severity"] = severity
            incident["raw_events"].append(raw_event)
            if len(incident["raw_events"]) > MAX_EVENTS_PER_INCIDENT:
                incident["raw_events"] = incident["raw_events"][-MAX_EVENTS_PER_INCIDENT:]
            incident["status"] = "active"
            incident["source_blocked"] = blocked
            incident["block_method"] = block_method
            incident["block_expires_at"] = block_expires_at
            incident["verification_status"] = verification_status
            incident["response_status"] = response_status
            if repeat_count is not None:
                incident["repeat_count"] = repeat_count
        else:
            incident_id = str(uuid.uuid4())
            incident = {
                "incident_id": incident_id,
                "category": category,
                "attack_type": attack_type,
                "related_techniques": [attack_type],
                "source_ip": source_ip,
                "source_mac": alert.get("source_mac"),
                "target_ip": target_ip,
                "target_mac": alert.get("target_mac"),
                "destination_ports": (
                    sorted(set(destination_port)) if isinstance(destination_port, list)
                    else ([destination_port] if destination_port is not None else [])
                ),
                "protocol": alert.get("protocol"),
                "packet_count": alert.get("packet_count") or 0,
                "event_count": 1,
                "ports_scanned_count": alert.get("ports_scanned_count"),
                "hosts_contacted_count": alert.get("hosts_contacted_count"),
                "recommended_response": RECOMMENDED_RESPONSES.get(category),
                "raw_events": [raw_event],
                "first_seen": now,
                "last_seen": now,
                "severity": severity,
                "status": "active",
                "source_blocked": blocked,
                "block_method": block_method,
                "block_expires_at": block_expires_at,
                "verification_status": verification_status,
                "response_status": response_status,
                "repeat_count": repeat_count,
            }
            incidents[incident_id] = incident
            incident_index[index_key] = incident_id
            cleanup_incidents_locked()

    logger.info(
        "Security alert: %s from %s (incident %s) blocked=%s method=%s response_status=%s",
        attack_type, source_ip, incident_id, blocked, block_method, response_status,
    )


def merge_device(info):
    if not isinstance(info, dict) or not info.get("ip"):
        return
    key = info.get("mac") or info["ip"]
    with state_lock:
        existing = devices.get(key, {})
        for k, v in info.items():
            if v is not None:
                existing[k] = v
        existing["last_seen"] = time.time()
        if "online" in info and info["online"] is not None:
            existing["online"] = bool(info["online"])
        devices[key] = existing


def cleanup_scan_jobs_locked():
    if len(scan_jobs) <= MAX_SCAN_JOBS:
        return
    finished = [
        (job_id, job) for job_id, job in scan_jobs.items()
        if job["status"] in ("completed", "failed")
    ]
    finished.sort(key=lambda item: item[1].get("completed_at") or 0)
    excess = len(scan_jobs) - MAX_SCAN_JOBS
    to_remove = max(0, len(finished) - SCAN_JOB_RETENTION)
    to_remove = min(to_remove, excess) if excess > 0 else to_remove
    for job_id, _job in finished[:to_remove]:
        scan_jobs.pop(job_id, None)


def validate_ip_or_cidr(value):
    if value is None:
        return None
    if not isinstance(value, str):
        return False
    value = value.strip()
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        return False


def run_discovery_job(job_id):
    try:
        interface, cidr = scanner.get_local_network_info()
        results = scanner.discover_devices(cidr)
        if not isinstance(results, list):
            results = []
        with state_lock:
            for dev in results:
                merge_device(dev)
            job = scan_jobs.get(job_id)
            if job:
                job["status"] = "completed"
                job["completed_at"] = time.time()
                job["results"] = results
                job["target"] = cidr
                scan_history.appendleft({
                    "id": job_id,
                    "type": "discovery",
                    "target": cidr,
                    "started_at": job["started_at"],
                    "completed_at": job["completed_at"],
                    "device_count": len(results),
                })
            cleanup_scan_jobs_locked()
    except Exception:
        logger.exception("Discovery scan failed")
        with state_lock:
            job = scan_jobs.get(job_id)
            if job:
                job["status"] = "failed"
                job["error"] = "discovery scan failed"
                job["completed_at"] = time.time()
            cleanup_scan_jobs_locked()
    finally:
        if scan_lock.locked():
            try:
                scan_lock.release()
            except RuntimeError:
                pass


def run_target_scan_job(job_id, target):
    try:
        result = scanner.scan_target(target)
        if not isinstance(result, dict):
            result = {}
        with state_lock:
            merge_device(result)
            job = scan_jobs.get(job_id)
            if job:
                job["status"] = "completed"
                job["completed_at"] = time.time()
                job["results"] = result
                job["target"] = target
                scan_history.appendleft({
                    "id": job_id,
                    "type": "target_scan",
                    "target": target,
                    "started_at": job["started_at"],
                    "completed_at": job["completed_at"],
                    "open_ports": result.get("open_ports"),
                })
            cleanup_scan_jobs_locked()
    except Exception:
        logger.exception("Target scan failed for %s", target)
        with state_lock:
            job = scan_jobs.get(job_id)
            if job:
                job["status"] = "failed"
                job["error"] = "target scan failed"
                job["completed_at"] = time.time()
            cleanup_scan_jobs_locked()
    finally:
        if scan_lock.locked():
            try:
                scan_lock.release()
            except RuntimeError:
                pass


def launch_scan(job_type, target=None):
    job_id = str(uuid.uuid4())
    with state_lock:
        scan_jobs[job_id] = {
            "id": job_id,
            "status": "running",
            "started_at": time.time(),
            "completed_at": None,
            "type": job_type,
            "target": target,
            "results": None,
            "error": None,
        }

    if job_type == "discovery":
        thread = threading.Thread(target=run_discovery_job, args=(job_id,), daemon=True)
    else:
        thread = threading.Thread(target=run_target_scan_job, args=(job_id, target), daemon=True)
    thread.start()
    return job_id


@app.route("/")
def serve_index():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/style.css")
def serve_css():
    return send_from_directory(BASE_DIR, "style.css")


@app.route("/api/status", methods=["GET"])
def api_status():
    with state_lock:
        return jsonify({
            "monitoring_running": monitor_state["running"],
            "monitoring_interface": monitor_state["interface"],
            "monitoring_started_at": monitor_state["started_at"],
            "device_count": len(devices),
            "alert_count": len(incidents),
            "scan_history_count": len(scan_history),
            "scan_in_progress": scan_lock.locked(),
        })


@app.route("/api/devices", methods=["GET"])
def api_devices():
    with state_lock:
        result = list(devices.values())
    result.sort(key=lambda d: d.get("last_seen", 0), reverse=True)
    return jsonify({"devices": result, "count": len(result)})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    payload = request.get_json(silent=True) or {}
    target = payload.get("target")

    validated_target = None
    if target is not None:
        validated = validate_ip_or_cidr(target)
        if validated is False:
            return jsonify({"error": "invalid target IP or CIDR"}), 400
        validated_target = validated

    if not scan_lock.acquire(blocking=False):
        return jsonify({"error": "a scan is already in progress"}), 409

    try:
        if validated_target is not None:
            job_id = launch_scan("target_scan", validated_target)
        else:
            job_id = launch_scan("discovery")
    except Exception:
        scan_lock.release()
        logger.exception("Failed to launch scan")
        return jsonify({"error": "failed to start scan"}), 500

    return jsonify({
        "job_id": job_id,
        "status": "running",
        "type": "target_scan" if validated_target is not None else "discovery",
        "target": validated_target,
    }), 202


@app.route("/api/scan/<job_id>", methods=["GET"])
def api_scan_status(job_id):
    with state_lock:
        job = scan_jobs.get(job_id)
        if not job:
            return jsonify({"error": "scan job not found"}), 404
        return jsonify(job)


@app.route("/api/scan/history", methods=["GET"])
def api_scan_history():
    with state_lock:
        return jsonify({"history": list(scan_history)})


@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    """
    Existing route and response shape preserved: {"alerts": [...], "count": N}.
    Each row is now backed by a correlated incident rather than a raw
    detection, so one attack shows up once. The row keeps the original
    simple fields (id, source_ip, source_mac, target_ip, target_mac,
    timestamp, status, severity) and adds a few backward-compatible extra
    fields (category, attack_type, event_count) that older frontend code can
    safely ignore. Full evidence is available via GET /api/alerts/<id>.
    """
    limit = request.args.get("limit", default=100, type=int)
    if limit is None:
        limit = 100
    limit = max(1, min(limit, MAX_ALERTS))

    now = time.time()
    with state_lock:
        for incident in incidents.values():
            if incident["status"] == "active" and now - incident["last_seen"] > INCIDENT_MERGE_WINDOW * 3:
                incident["status"] = "resolved"

        ordered = sorted(incidents.values(), key=lambda inc: inc["last_seen"], reverse=True)
        rows = []
        for inc in ordered[:limit]:
            rows.append({
                "id": inc["incident_id"],
                "source_ip": inc["source_ip"],
                "source_mac": inc["source_mac"],
                "target_ip": inc["target_ip"],
                "target_mac": inc["target_mac"],
                "timestamp": inc["last_seen"],
                "status": inc["status"],
                "severity": inc["severity"],
                "category": inc["category"],
                "attack_type": inc["attack_type"],
                "event_count": inc["event_count"],
            })
        total = len(incidents)

    return jsonify({"alerts": rows, "count": total})


@app.route("/api/alerts/<incident_id>", methods=["GET"])
def api_alert_detail(incident_id):
    """
    New route (additive, does not affect existing endpoints). Returns the
    complete incident record - full evidence, related techniques, raw
    events, recommended response - for the frontend to show when a user
    clicks an alert.
    """
    with state_lock:
        incident = incidents.get(incident_id)
        if not incident:
            return jsonify({"error": "incident not found"}), 404
        return jsonify(dict(incident))


@app.route("/api/suspicious-sources", methods=["GET"])
def api_suspicious_sources():
    with state_lock:
        ordered = sorted(incidents.values(), key=lambda inc: inc["last_seen"], reverse=True)
        aggregated = {}
        for inc in ordered:
            source_ip = inc.get("source_ip")
            if not source_ip:
                continue
            row = aggregated.get(source_ip)
            if row is None:
                aggregated[source_ip] = {
                    "incident_id": inc["incident_id"],
                    "source_ip": source_ip,
                    "source_mac": inc.get("source_mac"),
                    "attack_type": inc["attack_type"],
                    "category": inc["category"],
                    "severity": inc["severity"],
                    "first_seen": inc["first_seen"],
                    "last_seen": inc["last_seen"],
                    "event_count": inc["event_count"],
                    "status": inc["status"],
                }
                continue
            row["event_count"] += inc["event_count"]
            row["first_seen"] = min(row["first_seen"], inc["first_seen"])
            if inc["last_seen"] > row["last_seen"]:
                row["last_seen"] = inc["last_seen"]
            if _severity_rank(inc["severity"]) > _severity_rank(row["severity"]):
                row["severity"] = inc["severity"]
            if inc["status"] == "active":
                row["status"] = "active"
        source_ips = list(aggregated.keys())

    rows = []
    for source_ip in source_ips:
        row = aggregated[source_ip]
        blocked, method, expires_at = get_block_status(source_ip, row.get("source_mac"))
        row["blocked"] = blocked
        row["block_method"] = method
        row["block_expires_at"] = expires_at
        row["verification_status"] = get_verification_status(method, source_ip, row.get("source_mac")) if blocked else None
        rows.append(row)

    rows.sort(key=lambda r: r["last_seen"], reverse=True)
    return jsonify({"suspicious_sources": rows, "count": len(rows)})


@app.route("/api/response/block", methods=["POST"])
def api_response_block():
    payload = request.get_json(silent=True) or {}
    ips = payload.get("ips")
    duration = payload.get("duration", DEFAULT_BLOCK_DURATION)

    if not isinstance(ips, list) or len(ips) == 0:
        return jsonify({"success": False, "message": "ips must be a non-empty list", "blocked_ips": [], "failed_ips": []}), 400

    try:
        duration = int(duration)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "duration must be an integer number of seconds", "blocked_ips": [], "failed_ips": []}), 400

    if duration not in ALLOWED_BLOCK_DURATIONS:
        allowed = ", ".join(str(d) for d in sorted(ALLOWED_BLOCK_DURATIONS))
        return jsonify({"success": False, "message": "duration must be one of: " + allowed, "blocked_ips": [], "failed_ips": []}), 400

    seen = set()
    unique_ips = []
    failed_ips = []
    for raw_ip in ips:
        if not isinstance(raw_ip, str):
            failed_ips.append({"ip": raw_ip, "error": "invalid IPv4 address"})
            continue
        candidate = raw_ip.strip()
        if candidate in seen:
            continue
        if not validate_ip(candidate):
            failed_ips.append({"ip": candidate, "error": "invalid IPv4 address"})
            continue
        seen.add(candidate)
        unique_ips.append(candidate)

    if not unique_ips:
        return jsonify({"success": False, "message": "no valid IPv4 addresses provided", "blocked_ips": [], "failed_ips": failed_ips, "already_blocked_ips": []}), 400

    with state_lock:
        interface = monitor_state.get("interface")
        # Best-effort MAC hint from the most recent incident for this
        # source, so we don't have to re-resolve if we already saw it on
        # the wire; resolve_and_block_source() will still independently
        # verify/re-resolve rather than trusting this blindly.
        mac_hints = {}
        for inc in incidents.values():
            ip = inc.get("source_ip")
            if ip in unique_ips and inc.get("source_mac") and ip not in mac_hints:
                mac_hints[ip] = inc["source_mac"]

    already_blocked_ips = []
    successfully_blocked = []
    now = time.time()

    for ip in unique_ips:
        try:
            outcome = resolve_and_block_source(
                ip, source_mac_hint=mac_hints.get(ip), interface=interface, duration=duration
            )
        except Exception:
            logger.exception("Unexpected error while blocking source %s", ip)
            failed_ips.append({"ip": ip, "error": "failed to process block request"})
            continue

        method = outcome.get("method")
        mac = outcome.get("source_mac")
        action = outcome.get("action")
        verification = outcome.get("verification")
        status = outcome.get("status")

        if action == "block_failed":
            error = outcome.get("error") or "failed to apply block"
            failed_ips.append({"ip": ip, "mac": mac, "method": method, "error": error})
            logger.info(
                "BLOCK_FAILED source_ip=%s mac=%s method=%s error=%s", ip, mac, method, error
            )
            continue

        # Record local bookkeeping (expiry timestamps for the dashboard) to
        # mirror what the response manager just did in the firewall.
        expires_at = now + duration
        if method == "mac" and mac:
            with state_lock:
                existing = blocked_macs.get(mac)
                if not existing:
                    blocked_macs[mac] = {"blocked_at": now, "duration": duration, "expires_at": expires_at, "source_ip": ip}
                    existing = blocked_macs[mac]
            expires_at = existing["expires_at"]
        elif method == "ip":
            with state_lock:
                existing = blocked_ips.get(ip)
                if not existing:
                    blocked_ips[ip] = {"blocked_at": now, "duration": duration, "expires_at": expires_at}
                    existing = blocked_ips[ip]
            expires_at = existing["expires_at"]

        entry = {
            "ip": ip,
            "mac": mac,
            "method": method,
            "status": status,
            "verification": verification,
            "duration": duration,
            "expires_at": expires_at,
        }

        if action == "already_blocked":
            entry["status"] = "already_blocked"
            already_blocked_ips.append(entry)
            logger.info(
                "BLOCK_APPLIED source_ip=%s mac=%s method=%s status=already_blocked verification=%s",
                ip, mac, method, verification,
            )
        else:
            successfully_blocked.append(entry)
            logger.info(
                "BLOCK_APPLIED source_ip=%s mac=%s method=%s duration=%s verification=%s",
                ip, mac, method, duration, verification,
            )

    has_new = bool(successfully_blocked)
    has_already = bool(already_blocked_ips)
    has_failed = bool(failed_ips)

    if has_new and not has_failed:
        success = True
        message = "selected IPs blocked successfully" if not has_already else "selected IPs blocked successfully (some were already blocked)"
    elif not has_new and has_already and not has_failed:
        success = True
        message = "selected IPs are already blocked"
    elif (has_new or has_already) and has_failed:
        success = False
        message = "some IPs were blocked, others failed"
    else:
        success = False
        message = "failed to block selected IPs"

    status_code = 200 if success else 207
    return jsonify({
        "success": success,
        "message": message,
        "blocked_ips": successfully_blocked,
        "failed_ips": failed_ips,
        "already_blocked_ips": already_blocked_ips,
    }), status_code


@app.route("/api/monitoring/start", methods=["POST"])
def api_monitoring_start():
    global network_monitor
    with network_monitor_lock:
        with state_lock:
            already_running = monitor_state["running"]
        if already_running:
            return jsonify({"error": "monitoring already running"}), 409

        try:
            interface, _ = scanner.get_local_network_info()
            monitor = scanner.NetworkMonitor(interface, add_alert)
            monitor.start()
        except Exception:
            logger.exception("Failed to start monitoring")
            with state_lock:
                monitor_state["running"] = False
                monitor_state["interface"] = None
                monitor_state["started_at"] = None
            return jsonify({"error": "failed to start monitoring"}), 500

        network_monitor = monitor
        with state_lock:
            monitor_state["running"] = True
            monitor_state["interface"] = interface
            monitor_state["started_at"] = time.time()

        return jsonify({"status": "started", "interface": interface})


@app.route("/api/monitoring/stop", methods=["POST"])
def api_monitoring_stop():
    global network_monitor
    with network_monitor_lock:
        with state_lock:
            running = monitor_state["running"]
        if not running or network_monitor is None:
            return jsonify({"error": "monitoring is not running"}), 409

        monitor = network_monitor
        stop_error = None
        try:
            monitor.stop()
        except Exception:
            logger.exception("Failed to stop monitoring cleanly")
            stop_error = "monitoring stopped with errors"

        network_monitor = None
        with state_lock:
            monitor_state["running"] = False
            monitor_state["interface"] = None
            monitor_state["started_at"] = None

        if stop_error:
            return jsonify({"status": "stopped", "warning": stop_error})
        return jsonify({"status": "stopped"})


@app.errorhandler(400)
def bad_request(_err):
    return jsonify({"error": "bad request"}), 400


@app.errorhandler(404)
def not_found(_err):
    return jsonify({"error": "not found"}), 404


@app.errorhandler(405)
def method_not_allowed(_err):
    return jsonify({"error": "method not allowed"}), 405


@app.errorhandler(500)
def server_error(_err):
    return jsonify({"error": "internal server error"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
