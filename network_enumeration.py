"""
network_enumeration.py

Adds SMB and LDAP network-reconnaissance detection to NetSentinel.

Architecture
------------
scanner.NetworkMonitor already turns every observed TCP SYN packet (a
connection attempt) into a call to NetworkMonitor.record_event(src_ip,
src_mac, "syn", dest_ip, dest_port, now) - for *every* destination port,
not just the ports scanner.py's own checks (Port Scan, Host Sweep, etc.)
care about. That means the SMB (139/445) and LDAP (389/636) connection
attempts this module needs are already flowing through the existing Scapy
capture, so this module does not start a second sniffer and does not need
any change to scanner.py.

SMB detection covers two distinct patterns, because real SMB reconnaissance
shows up either way depending on the tool used:

  A. Host enumeration - one source contacts SMB_ENUMERATION_HOST_THRESHOLD
     or more *distinct* SMB hosts within SMB_ENUMERATION_WINDOW_SECONDS
     (e.g. a network-wide SMB sweep).
  B. Repeated probing of one target - one source makes
     SMB_ENUMERATION_REQUEST_THRESHOLD or more SMB connection attempts to
     the *same* host within SMB_ENUMERATION_WINDOW_SECONDS (e.g.
     smbclient/enum4linux-style share/session enumeration run repeatedly
     against a single server). A single, isolated SMB connection never
     satisfies either condition and does not alert.

LDAP detection uses the equivalent of pattern B only: repeated connection
attempts from one source to the same host within
LDAP_ENUMERATION_WINDOW_SECONDS.

attach_network_enumeration_detection(monitor) wraps record_event on one
running NetworkMonitor *instance* only (an instance attribute, not a change
to the scanner module or class). The original method still runs completely
unchanged; every SYN destined for an SMB or LDAP port is additionally handed
to process_network_enumeration_packet(). Any alert this module produces is
handed back to the monitor's own existing self.queue_alert(), so it flows
through the same alert queue / alert_callback pipeline (handle_new_alert in
app.py) as scanner.py's built-in Port Scan / Host Sweep / etc. detections.

LDAP limitation
---------------
The existing capture filter is "tcp or arp or icmp" and scanner.py never
parses LDAP's BER-encoded application data - it only sees TCP handshake
packets. This module therefore cannot see individual LDAP bind/search
operations carried inside one TCP stream. It uses the safest network-level
proxy available instead: the rate of new TCP connection attempts (SYNs) to
ports 389/636 from one source to one destination host. This is
conservative, but it means enumeration performed over a single, already
established, long-lived LDAP connection will not be caught.
"""

import threading
from collections import deque

SMB_PORTS = {139, 445}
LDAP_PORTS = {389, 636}

SMB_ENUMERATION_WINDOW_SECONDS = 10
SMB_ENUMERATION_HOST_THRESHOLD = 2
SMB_ENUMERATION_REQUEST_THRESHOLD = 3

LDAP_ENUMERATION_WINDOW_SECONDS = 10
LDAP_ENUMERATION_REQUEST_THRESHOLD = 5

NETWORK_ENUMERATION_ALERT_COOLDOWN = 60
MAX_TRACKED_ENUMERATION_SOURCES = 500
MAX_EVENTS_PER_ENUMERATION_SOURCE = 500
STALE_ENUMERATION_SOURCE_TTL = max(SMB_ENUMERATION_WINDOW_SECONDS, LDAP_ENUMERATION_WINDOW_SECONDS) * 6

_state_lock = threading.Lock()
_smb_activity = {}
_ldap_activity = {}
_last_enumeration_alert = {}


def attach_network_enumeration_detection(monitor):
    """
    Hook SMB/LDAP enumeration detection into an already-constructed
    scanner.NetworkMonitor instance, before monitor.start() is called.

    This does not modify scanner.py or NetworkMonitor's class behavior: it
    wraps record_event on this one instance so every SYN it already
    observes is also handed to process_network_enumeration_packet(), and it
    resets this module's own tracking state so a fresh "start monitoring"
    cycle doesn't inherit stale data from a previous run.
    """
    original_record_event = monitor.record_event

    with _state_lock:
        _smb_activity.clear()
        _ldap_activity.clear()
        _last_enumeration_alert.clear()

    def record_event_with_network_enumeration(src_ip, src_mac, kind, target_ip, target_port, now):
        original_record_event(src_ip, src_mac, kind, target_ip, target_port, now)

        if kind != "syn" or target_port is None:
            return
        if target_port not in SMB_PORTS and target_port not in LDAP_PORTS:
            return

        alert = process_network_enumeration_packet(src_ip, src_mac, target_ip, target_port, now)
        if alert:
            monitor.queue_alert(alert)

    monitor.record_event = record_event_with_network_enumeration
    return monitor


def process_network_enumeration_packet(source_ip, source_mac, target_ip, destination_port, now):
    """
    Route one SMB/LDAP connection-attempt observation to the right
    tracker/detector pair and return an alert dict if one fires.
    """
    alert = None
    with _state_lock:
        if destination_port in SMB_PORTS:
            entry = track_smb_activity(source_ip, source_mac, target_ip, destination_port, now)
            alert = detect_smb_enumeration(source_ip, entry, now)
        elif destination_port in LDAP_PORTS:
            entry = track_ldap_activity(source_ip, source_mac, target_ip, destination_port, now)
            alert = detect_ldap_enumeration(source_ip, entry, now)

        evict_stale_enumeration_sources(now)

    return alert


def track_smb_activity(source_ip, source_mac, target_ip, destination_port, now):
    entry = _smb_activity.setdefault(source_ip, {"mac": source_mac, "attempts": deque()})
    if source_mac:
        entry["mac"] = source_mac
    entry["attempts"].append((now, target_ip, destination_port))
    trim_expired_events(entry["attempts"], now, SMB_ENUMERATION_WINDOW_SECONDS)
    return entry


def track_ldap_activity(source_ip, source_mac, target_ip, destination_port, now):
    entry = _ldap_activity.setdefault(source_ip, {"mac": source_mac, "attempts": deque()})
    if source_mac:
        entry["mac"] = source_mac
    entry["attempts"].append((now, target_ip, destination_port))
    trim_expired_events(entry["attempts"], now, LDAP_ENUMERATION_WINDOW_SECONDS)
    return entry


def trim_expired_events(event_queue, now, window_seconds):
    while event_queue and now - event_queue[0][0] > window_seconds:
        event_queue.popleft()
    while len(event_queue) > MAX_EVENTS_PER_ENUMERATION_SOURCE:
        event_queue.popleft()


def enumeration_alert_cooldown_ok(key, now, cooldown=NETWORK_ENUMERATION_ALERT_COOLDOWN):
    last_alert_time = _last_enumeration_alert.get(key, 0)
    if now - last_alert_time < cooldown:
        return False
    _last_enumeration_alert[key] = now
    return True


def detect_smb_enumeration(source_ip, entry, now):
    recent = [e for e in entry["attempts"] if now - e[0] <= SMB_ENUMERATION_WINDOW_SECONDS]
    if not recent:
        return None

    hosts_contacted = {dest_ip for _, dest_ip, _ in recent}

    # Pattern A: same source, multiple unique SMB hosts, short window.
    if len(hosts_contacted) >= SMB_ENUMERATION_HOST_THRESHOLD:
        alert_key = (source_ip, "smb_host_enumeration")
        if enumeration_alert_cooldown_ok(alert_key, now):
            ports_used = sorted({port for _, _, port in recent})
            return create_smb_enumeration_alert(
                source_ip, entry.get("mac"), None, hosts_contacted, ports_used, recent, now
            )

    # Pattern B: same source, same SMB target, repeated connection attempts,
    # short window (e.g. smbclient/enum4linux-style enumeration run
    # repeatedly against one server).
    requests_by_host = {}
    for event_time, dest_ip, dest_port in recent:
        host_activity = requests_by_host.setdefault(dest_ip, {"times": [], "ports": set()})
        host_activity["times"].append(event_time)
        host_activity["ports"].add(dest_port)

    for dest_ip, host_activity in requests_by_host.items():
        if len(host_activity["times"]) < SMB_ENUMERATION_REQUEST_THRESHOLD:
            continue

        alert_key = (source_ip, dest_ip, "smb_repeated_probe")
        if not enumeration_alert_cooldown_ok(alert_key, now):
            continue

        ports_used = sorted(host_activity["ports"])
        host_events = [e for e in recent if e[1] == dest_ip]
        return create_smb_enumeration_alert(
            source_ip, entry.get("mac"), dest_ip, {dest_ip}, ports_used, host_events, now
        )

    return None


def detect_ldap_enumeration(source_ip, entry, now):
    recent = [e for e in entry["attempts"] if now - e[0] <= LDAP_ENUMERATION_WINDOW_SECONDS]

    requests_by_host = {}
    for event_time, dest_ip, dest_port in recent:
        host_activity = requests_by_host.setdefault(dest_ip, {"times": [], "ports": set()})
        host_activity["times"].append(event_time)
        host_activity["ports"].add(dest_port)

    for dest_ip, host_activity in requests_by_host.items():
        if len(host_activity["times"]) < LDAP_ENUMERATION_REQUEST_THRESHOLD:
            continue

        alert_key = (source_ip, dest_ip, "ldap_enumeration")
        if not enumeration_alert_cooldown_ok(alert_key, now):
            continue

        return create_ldap_enumeration_alert(
            source_ip, entry.get("mac"), dest_ip, host_activity["ports"], host_activity["times"], now
        )

    return None


def create_smb_enumeration_alert(source_ip, source_mac, target_ip, hosts_contacted, ports_used, recent_events, now):
    first_seen = min(event_time for event_time, _, _ in recent_events) if recent_events else now
    hosts_contacted_count = len(hosts_contacted)

    if target_ip is not None:
        evidence = (
            f"{len(recent_events)} SMB connection attempts from {source_ip} to "
            f"{target_ip} on port(s) {ports_used} within {SMB_ENUMERATION_WINDOW_SECONDS}s, "
            "indicating possible repeated SMB session/share enumeration against a single host"
        )
    else:
        evidence = (
            f"{source_ip} initiated SMB connections (ports {ports_used}) to "
            f"{hosts_contacted_count} distinct hosts within {SMB_ENUMERATION_WINDOW_SECONDS}s, "
            "consistent with SMB host/share reconnaissance"
        )

    return {
        "category": "Reconnaissance",
        "attack_type": "SMB Enumeration",
        "source_ip": source_ip,
        "source_mac": source_mac,
        "target_ip": target_ip,
        "target_mac": None,
        "source_port": None,
        "destination_port": ports_used,
        "protocol": "tcp",
        "packet_count": len(recent_events),
        "event_count": len(recent_events) if target_ip is not None else hosts_contacted_count,
        "ports_scanned_count": None,
        "hosts_contacted_count": hosts_contacted_count,
        "evidence": evidence,
        "first_seen": first_seen,
        "last_seen": now,
        "severity": "medium",
        "related_techniques": ["SMB Enumeration"],
    }


def create_ldap_enumeration_alert(source_ip, source_mac, target_ip, ports_used, request_times, now):
    first_seen = min(request_times) if request_times else now
    ports_sorted = sorted(ports_used)
    return {
        "category": "Reconnaissance",
        "attack_type": "LDAP Enumeration",
        "source_ip": source_ip,
        "source_mac": source_mac,
        "target_ip": target_ip,
        "target_mac": None,
        "source_port": None,
        "destination_port": ports_sorted,
        "protocol": "tcp",
        "packet_count": len(request_times),
        "event_count": len(request_times),
        "ports_scanned_count": None,
        "hosts_contacted_count": 1,
        "evidence": (
            f"{len(request_times)} LDAP connection attempts from {source_ip} to "
            f"{target_ip} on port(s) {ports_sorted} within {LDAP_ENUMERATION_WINDOW_SECONDS}s, "
            "indicating possible LDAP directory reconnaissance"
        ),
        "first_seen": first_seen,
        "last_seen": now,
        "severity": "medium",
        "related_techniques": ["LDAP Enumeration"],
    }


def evict_stale_enumeration_sources(now):
    for activity_map in (_smb_activity, _ldap_activity):
        stale_sources = [
            src_ip for src_ip, entry in activity_map.items()
            if not entry["attempts"] or now - entry["attempts"][-1][0] > STALE_ENUMERATION_SOURCE_TTL
        ]
        for src_ip in stale_sources:
            activity_map.pop(src_ip, None)

        if len(activity_map) > MAX_TRACKED_ENUMERATION_SOURCES:
            ordered = sorted(
                activity_map.items(),
                key=lambda item: item[1]["attempts"][-1][0] if item[1]["attempts"] else 0,
            )
            excess = len(activity_map) - MAX_TRACKED_ENUMERATION_SOURCES
            for src_ip, _ in ordered[:excess]:
                activity_map.pop(src_ip, None)

    if len(_last_enumeration_alert) > MAX_TRACKED_ENUMERATION_SOURCES * 2:
        stale_keys = [
            key for key, alert_time in _last_enumeration_alert.items()
            if now - alert_time > NETWORK_ENUMERATION_ALERT_COOLDOWN * 5
        ]
        for key in stale_keys:
            _last_enumeration_alert.pop(key, None)
