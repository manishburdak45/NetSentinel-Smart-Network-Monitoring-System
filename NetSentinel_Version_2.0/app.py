import os
import time
import uuid
import ipaddress
import threading
import logging
from collections import deque, OrderedDict
from flask import Flask, jsonify, request, send_from_directory

import scanner

try:
    import detector
    DETECTOR_AVAILABLE = True
except Exception:
    detector = None
    DETECTOR_AVAILABLE = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("netsentinel")

app = Flask(__name__, static_folder=None)

MAX_ALERTS = 500
MAX_SCAN_HISTORY = 100
MAX_SCAN_JOBS = 200
SCAN_JOB_RETENTION = 50
MAX_INCIDENTS_CACHE = 600
MAX_EVENT_DEDUP = 5000
EVENT_POLL_INTERVAL_SECONDS = 2
MAX_CONSOLIDATED_ALERTS = 100
CONSOLIDATED_ALERT_ACTIVE_WINDOW_SECONDS = 300
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

state_lock = threading.RLock()
scan_lock = threading.Lock()

devices = {}
scan_jobs = {}
scan_history = deque(maxlen=MAX_SCAN_HISTORY)
alerts = deque(maxlen=MAX_ALERTS)
incidents_cache = OrderedDict()

monitor_state = {
    "running": False,
    "interface": None,
    "started_at": None,
}

network_monitor = None
network_monitor_lock = threading.Lock()
event_poll_thread = None
event_poll_stop_event = None

event_dedup_lock = threading.Lock()
event_dedup_set = set()
event_dedup_order = deque()


def safe_ingest_alert(alert):
    if not DETECTOR_AVAILABLE:
        return []
    try:
        result = detector.default_engine.ingest_alert(alert)
        return result if isinstance(result, list) else []
    except Exception:
        logger.exception("detector ingest_alert failed")
        return []


def safe_ingest_event(event):
    if not DETECTOR_AVAILABLE:
        return []
    try:
        result = detector.default_engine.ingest_event(event)
        return result if isinstance(result, list) else []
    except Exception:
        logger.exception("detector ingest_event failed")
        return []


def safe_run_maintenance():
    if not DETECTOR_AVAILABLE:
        return
    try:
        detector.default_engine.run_maintenance()
    except Exception:
        logger.exception("detector maintenance failed")


def safe_get_incidents(limit=None, status=None):
    if DETECTOR_AVAILABLE:
        try:
            return detector.default_engine.get_incidents(limit=limit, status=status)
        except Exception:
            logger.exception("detector get_incidents failed")
    with state_lock:
        pool = list(incidents_cache.values())
    if status:
        pool = [incident for incident in pool if incident.get("status") == status]
    pool.sort(key=lambda incident: incident.get("last_seen", 0), reverse=True)
    if limit:
        pool = pool[:limit]
    return pool


def safe_get_incident(incident_id):
    if DETECTOR_AVAILABLE:
        try:
            incident = detector.default_engine.get_incident(incident_id)
            if incident is not None:
                return incident
        except Exception:
            logger.exception("detector get_incident failed")
    with state_lock:
        return incidents_cache.get(incident_id)


def update_incidents_cache(produced):
    if not produced:
        return
    with state_lock:
        for incident in produced:
            if not isinstance(incident, dict):
                continue
            incident_id = incident.get("id")
            if not incident_id:
                continue
            incidents_cache[incident_id] = incident
            incidents_cache.move_to_end(incident_id)
        while len(incidents_cache) > MAX_INCIDENTS_CACHE:
            incidents_cache.popitem(last=False)


def event_fingerprint(event):
    return (
        event.get("timestamp"),
        event.get("source_ip"),
        event.get("source_mac"),
        event.get("source_port"),
        event.get("target_ip"),
        event.get("target_port"),
        event.get("protocol"),
        event.get("event_type"),
    )


def mark_event_seen(fingerprint):
    with event_dedup_lock:
        if fingerprint in event_dedup_set:
            return False
        event_dedup_set.add(fingerprint)
        event_dedup_order.append(fingerprint)
        while len(event_dedup_order) > MAX_EVENT_DEDUP:
            oldest = event_dedup_order.popleft()
            event_dedup_set.discard(oldest)
        return True


def reset_event_dedup():
    with event_dedup_lock:
        event_dedup_set.clear()
        event_dedup_order.clear()


def event_poll_loop(monitor, stop_event):
    while not stop_event.is_set():
        try:
            safe_run_maintenance()
            events = monitor.get_recent_events()
            for event in events:
                if not isinstance(event, dict):
                    continue
                fingerprint = event_fingerprint(event)
                if not mark_event_seen(fingerprint):
                    continue
                produced = safe_ingest_event(event)
                update_incidents_cache(produced)
        except Exception:
            logger.exception("event correlation polling failed")
        stop_event.wait(EVENT_POLL_INTERVAL_SECONDS)


def add_alert(alert):
    if not isinstance(alert, dict):
        return
    attack_type = alert.get("attack_type") or alert.get("detection_type")
    severity = scanner.resolve_alert_severity(alert.get("severity"))
    alert_record = {
        "id": str(uuid.uuid4()),
        "timestamp": time.time(),
        "attack_type": attack_type,
        "category": alert.get("category"),
        "source_ip": alert.get("source_ip"),
        "source_mac": alert.get("source_mac"),
        "target_ip": alert.get("target_ip"),
        "target_port": alert.get("target_port"),
        "target_ports": alert.get("target_ports"),
        "protocol": alert.get("protocol"),
        "detection_type": attack_type,
        "severity": severity,
        "details": alert.get("details"),
        "evidence": alert.get("evidence"),
    }
    if not scanner.is_eligible_severity(severity):
        return
    with state_lock:
        alerts.appendleft(alert_record)
    logger.info("Security alert: %s from %s", alert_record["detection_type"], alert_record["source_ip"])
    produced = safe_ingest_alert(alert_record)
    update_incidents_cache(produced)


def build_consolidated_alerts():
    """Group raw detection alerts by (attack type, source, target) so that a
    single attack pattern -- e.g. one Nmap scan touching hundreds of ports --
    is represented as one row instead of one row per underlying detection.

    This performs real backend aggregation over the alerts already produced
    by scanner.py / detector.py: it unions the port sets, tracks first/last
    seen, escalates severity, and counts related raw detections. No alert
    fields are invented; every value here is derived from existing alert
    records. Returned newest-activity-first.
    """
    with state_lock:
        raw_alerts = list(alerts)

    groups = OrderedDict()
    for raw in raw_alerts:
        if not isinstance(raw, dict):
            continue
        attack_type = raw.get("attack_type") or raw.get("detection_type") or "Unknown Activity"
        key = (attack_type, raw.get("source_ip"), raw.get("target_ip"))

        ports = set()
        target_ports = raw.get("target_ports")
        if target_ports:
            try:
                ports.update(p for p in target_ports if p is not None)
            except TypeError:
                pass
        elif raw.get("target_port") is not None:
            ports.add(raw.get("target_port"))

        timestamp = raw.get("timestamp")
        group = groups.get(key)
        if group is None:
            groups[key] = {
                "id": raw.get("id"),
                "attack_type": attack_type,
                "category": raw.get("category"),
                "source_ip": raw.get("source_ip"),
                "source_mac": raw.get("source_mac"),
                "target_ip": raw.get("target_ip"),
                "protocol": raw.get("protocol"),
                "severity": raw.get("severity") or "medium",
                "ports": ports,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "event_count": 1,
                "related_alert_ids": [raw.get("id")],
                "latest_details": raw.get("details"),
                "evidence": raw.get("evidence") or {},
            }
        else:
            group["ports"] |= ports
            if timestamp is not None:
                if group["first_seen"] is None or timestamp < group["first_seen"]:
                    group["first_seen"] = timestamp
                if group["last_seen"] is None or timestamp > group["last_seen"]:
                    group["last_seen"] = timestamp
                    group["latest_details"] = raw.get("details") or group["latest_details"]
            group["event_count"] += 1
            group["related_alert_ids"].append(raw.get("id"))
            if SEVERITY_RANK.get((raw.get("severity") or "").lower(), 0) > SEVERITY_RANK.get((group["severity"] or "").lower(), 0):
                group["severity"] = raw.get("severity")
            if not group.get("source_mac") and raw.get("source_mac"):
                group["source_mac"] = raw.get("source_mac")
            if not group.get("protocol") and raw.get("protocol"):
                group["protocol"] = raw.get("protocol")

    now = time.time()
    consolidated = []
    for group in groups.values():
        ports_sorted = sorted(group["ports"])
        port_count = len(ports_sorted)
        last_seen = group["last_seen"] or 0
        status = "active" if (now - last_seen) <= CONSOLIDATED_ALERT_ACTIVE_WINDOW_SECONDS else "resolved"
        consolidated.append({
            "id": group["id"],
            "attack_type": group["attack_type"],
            "category": group["category"],
            "source_ip": group["source_ip"],
            "source_mac": group["source_mac"],
            "target_ip": group["target_ip"],
            "protocol": group["protocol"],
            "severity": group["severity"],
            "ports": ports_sorted,
            "port_count": port_count,
            "first_port": ports_sorted[0] if ports_sorted else None,
            "last_port": ports_sorted[-1] if ports_sorted else None,
            "first_seen": group["first_seen"],
            "last_seen": group["last_seen"],
            "related_event_count": group["event_count"],
            "activity_summary": scanner.build_activity_summary(
                group["attack_type"], group["category"], port_count, group["event_count"],
            ),
            "details": group["latest_details"],
            "evidence": group["evidence"],
            "status": status,
        })

    consolidated.sort(key=lambda item: item["last_seen"] or 0, reverse=True)
    return consolidated


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


def _current_network_monitor():
    with network_monitor_lock:
        return network_monitor


def begin_internal_scan_context(job_id, targets):
    monitor = _current_network_monitor()
    if monitor is None:
        return
    try:
        monitor.begin_internal_scan(job_id, targets)
    except Exception:
        logger.exception("failed to start internal scan context for job %s", job_id)


def end_internal_scan_context(job_id):
    monitor = _current_network_monitor()
    if monitor is None:
        return
    try:
        monitor.end_internal_scan(job_id)
    except Exception:
        logger.exception("failed to end internal scan context for job %s", job_id)


def run_discovery_job(job_id):
    try:
        interface, cidr = scanner.get_local_network_info()
        begin_internal_scan_context(job_id, [cidr])
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
        end_internal_scan_context(job_id)
        if scan_lock.locked():
            try:
                scan_lock.release()
            except RuntimeError:
                pass


def run_target_scan_job(job_id, target):
    try:
        begin_internal_scan_context(job_id, [target])
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
        end_internal_scan_context(job_id)
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
    active_incidents = len(safe_get_incidents(status="active"))
    total_incidents = len(safe_get_incidents())
    with state_lock:
        return jsonify({
            "monitoring_running": monitor_state["running"],
            "monitoring_interface": monitor_state["interface"],
            "monitoring_started_at": monitor_state["started_at"],
            "device_count": len(devices),
            "alert_count": len(alerts),
            "scan_history_count": len(scan_history),
            "scan_in_progress": scan_lock.locked(),
            "active_incidents": active_incidents,
            "total_incidents": total_incidents,
            "detector_available": DETECTOR_AVAILABLE,
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
    limit = request.args.get("limit", default=100, type=int)
    if limit is None:
        limit = 100
    limit = max(1, min(limit, MAX_ALERTS))
    with state_lock:
        return jsonify({"alerts": list(alerts)[:limit], "count": len(alerts)})


@app.route("/api/alerts/consolidated", methods=["GET"])
def api_alerts_consolidated():
    limit = request.args.get("limit", default=30, type=int)
    if limit is None:
        limit = 30
    limit = max(1, min(limit, MAX_CONSOLIDATED_ALERTS))
    try:
        consolidated = build_consolidated_alerts()
    except Exception:
        logger.exception("Failed to build consolidated alerts")
        return jsonify({"error": "failed to build consolidated alerts"}), 500
    return jsonify({"alerts": consolidated[:limit], "count": len(consolidated)})


@app.route("/api/incidents", methods=["GET"])
def api_incidents():
    status = request.args.get("status")
    if status not in (None, "active", "closed"):
        return jsonify({"error": "invalid status filter"}), 400
    limit = request.args.get("limit", default=100, type=int)
    if limit is None:
        limit = 100
    limit = max(1, min(limit, MAX_INCIDENTS_CACHE))
    try:
        incidents_list = safe_get_incidents(limit=limit, status=status)
    except Exception:
        logger.exception("Failed to fetch incidents")
        return jsonify({"error": "failed to fetch incidents"}), 500
    return jsonify({"incidents": incidents_list, "count": len(incidents_list)})


@app.route("/api/incidents/<incident_id>", methods=["GET"])
def api_incident_detail(incident_id):
    try:
        incident = safe_get_incident(incident_id)
    except Exception:
        logger.exception("Failed to fetch incident %s", incident_id)
        return jsonify({"error": "failed to fetch incident"}), 500
    if incident is None:
        return jsonify({"error": "incident not found"}), 404
    return jsonify(incident)


@app.route("/api/monitoring/start", methods=["POST"])
def api_monitoring_start():
    global network_monitor, event_poll_thread, event_poll_stop_event
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

        reset_event_dedup()
        stop_event = threading.Event()
        poll_thread = threading.Thread(target=event_poll_loop, args=(monitor, stop_event), daemon=True)
        poll_thread.start()
        event_poll_thread = poll_thread
        event_poll_stop_event = stop_event

        return jsonify({"status": "started", "interface": interface})


@app.route("/api/monitoring/stop", methods=["POST"])
def api_monitoring_stop():
    global network_monitor, event_poll_thread, event_poll_stop_event
    with network_monitor_lock:
        with state_lock:
            running = monitor_state["running"]
        if not running or network_monitor is None:
            return jsonify({"error": "monitoring is not running"}), 409

        monitor = network_monitor
        stop_error = None

        if event_poll_stop_event is not None:
            event_poll_stop_event.set()
        if event_poll_thread is not None:
            event_poll_thread.join(timeout=5)
        event_poll_thread = None
        event_poll_stop_event = None
        reset_event_dedup()

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
