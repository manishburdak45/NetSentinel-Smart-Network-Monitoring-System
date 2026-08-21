import os
import time
import uuid
import ipaddress
import threading
import logging
from collections import deque
from flask import Flask, jsonify, request, send_from_directory

import scanner

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("netsentinel")

app = Flask(__name__, static_folder=None)

MAX_ALERTS = 500
MAX_SCAN_HISTORY = 100
MAX_SCAN_JOBS = 200
SCAN_JOB_RETENTION = 50

state_lock = threading.RLock()
scan_lock = threading.Lock()

devices = {}
scan_jobs = {}
scan_history = deque(maxlen=MAX_SCAN_HISTORY)
alerts = deque(maxlen=MAX_ALERTS)

monitor_state = {
    "running": False,
    "interface": None,
    "started_at": None,
}

network_monitor = None
network_monitor_lock = threading.Lock()


def add_alert(alert):
    if not isinstance(alert, dict):
        return
    alert_record = {
        "id": str(uuid.uuid4()),
        "timestamp": time.time(),
        "source_ip": alert.get("source_ip"),
        "source_mac": alert.get("source_mac"),
        "target_ip": alert.get("target_ip"),
        "target_ports": alert.get("target_ports"),
        "detection_type": alert.get("detection_type"),
        "severity": alert.get("severity", "medium"),
        "details": alert.get("details"),
    }
    with state_lock:
        alerts.appendleft(alert_record)
    logger.info("Security alert: %s from %s", alert_record["detection_type"], alert_record["source_ip"])


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
            "alert_count": len(alerts),
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
    limit = request.args.get("limit", default=100, type=int)
    if limit is None:
        limit = 100
    limit = max(1, min(limit, MAX_ALERTS))
    with state_lock:
        return jsonify({"alerts": list(alerts)[:limit], "count": len(alerts)})


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
