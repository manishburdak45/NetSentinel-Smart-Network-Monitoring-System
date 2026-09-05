import threading
import time
import uuid
from collections import deque

import scanner

CATEGORY_RECON = "Reconnaissance"
CATEGORY_FLOOD = "DoS / Flood"
CATEGORY_ANOMALY = "Anomaly"
CATEGORY_ARP = "MAC / ARP"
VALID_CATEGORIES = frozenset({CATEGORY_RECON, CATEGORY_FLOOD, CATEGORY_ANOMALY, CATEGORY_ARP})

STATUS_ACTIVE = "active"
STATUS_CLOSED = "closed"

SEVERITY_ORDER = ["low", "medium", "high", "critical"]
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}

CATEGORY_PRIORITY = {CATEGORY_FLOOD: 3, CATEGORY_ARP: 2, CATEGORY_RECON: 1, CATEGORY_ANOMALY: 0}

INCIDENT_TYPE_SEVERITY_FLOOR = {
    "Distributed Reconnaissance": "high",
    "Slow Distributed Reconnaissance": "high",
    "Cross-Target Reconnaissance Sweep": "medium",
    "Multi-Technique Reconnaissance": "medium",
    "Attack Campaign": "high",
    "Multi-Vector Flood Campaign": "critical",
    "Coordinated MAC/ARP Activity": "high",
}

EVENT_CORRELATION_WINDOW_SECONDS = 900
INCIDENT_IDLE_TIMEOUT_SECONDS = 1200
MAINTENANCE_INTERVAL_SECONDS = 30

MAX_ACTIVE_INCIDENTS = 400
MAX_CLOSED_INCIDENTS = 200
MAX_TIMELINE_ENTRIES = 40
MAX_INCIDENT_SOURCES = 200
MAX_INCIDENT_SOURCE_MACS = 200
MAX_INCIDENT_TARGETS = 200
MAX_INCIDENT_PORTS = 200
MAX_INCIDENT_PROTOCOLS = 10
MAX_RELATED_TYPES = 20

MAX_TRACKED_TARGET_GRAPHS = 500
MAX_TRACKED_SOURCE_GRAPHS = 500
MAX_EVENT_ENTRIES_PER_GRAPH = 3000

INCIDENT_MIN_SIGNALS_FOR_SURFACE = 2
INCIDENT_MIN_TYPES_FOR_CAMPAIGN = 2
ALERT_DISTRIBUTED_RECON_MIN_SOURCES = 4
CROSS_TARGET_MIN_TARGETS = 4

DISTRIBUTED_RECON_EVENT_MIN_SOURCES = 6
DISTRIBUTED_RECON_EVENT_MAX_AVG_PORTS = 2.5
DISTRIBUTED_RECON_EVENT_MIN_TOTAL_PORTS = 5
SLOW_DISTRIBUTED_RECON_MIN_SPAN_SECONDS = 120

DETECTION_LIMITATIONS = (
    "Detection only covers traffic visible to the monitored network interface.",
    "Encrypted payloads are not inspected; only metadata patterns are used for correlation.",
    "Traffic outside the monitored segment or crossing asymmetric routes may not be observed.",
    "Extremely low-volume or very long-duration activity may fall outside tracked correlation windows.",
    "Source IP and MAC address are treated as changeable attributes rather than guaranteed identity.",
    "This engine correlates the alert and event types produced by scanner.py; it is not a complete attack coverage guarantee.",
)


def get_detection_limitations():
    return list(DETECTION_LIMITATIONS)


def _trim_window(entries, now, window_seconds):
    while entries and now - entries[0][0] > window_seconds:
        entries.popleft()


def _trim_size(entries, max_size):
    while len(entries) > max_size:
        entries.popleft()


def _bounded_add(container, item, cap):
    if item is None:
        return
    if item in container:
        return
    if len(container) >= cap:
        return
    container.add(item)


def _escalate_severity(current, candidate):
    if SEVERITY_RANK.get(candidate, 0) > SEVERITY_RANK.get(current, 0):
        return candidate
    return current


def _dominant_attack_type(related_attack_types):
    if not related_attack_types:
        return "Unknown Activity"
    return max(related_attack_types.items(), key=lambda kv: kv[1])[0]


def _dominant_category(categories_seen):
    if not categories_seen:
        return CATEGORY_ANOMALY
    return max(categories_seen.items(), key=lambda kv: (kv[1], CATEGORY_PRIORITY.get(kv[0], 0)))[0]


def _format_duration(seconds):
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, remainder_seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {remainder_seconds}s" if remainder_seconds else f"{minutes}m"
    hours, remainder_minutes = divmod(minutes, 60)
    return f"{hours}h {remainder_minutes}m" if remainder_minutes else f"{hours}h"


class CorrelationEngine:
    def __init__(self):
        self._lock = threading.RLock()
        self._incidents = {}
        self._incident_index = {}
        self._closed_incidents = deque(maxlen=MAX_CLOSED_INCIDENTS)
        self._target_event_graph = {}
        self._source_event_graph = {}
        self._last_maintenance = 0.0

    def ingest_alert(self, alert):
        if not isinstance(alert, dict):
            return []
        with self._lock:
            now = time.time()
            self._run_maintenance(now)

            category = alert.get("category")
            if category not in VALID_CATEGORIES:
                category = CATEGORY_ANOMALY
            attack_type = alert.get("attack_type") or alert.get("detection_type") or "Unknown Activity"
            severity = scanner.resolve_alert_severity(alert.get("severity"))
            if not scanner.is_eligible_severity(severity):
                return []

            source_ip = alert.get("source_ip")
            source_mac = alert.get("source_mac")
            target_ip = alert.get("target_ip")
            target_port = alert.get("target_port")
            target_ports = alert.get("target_ports")
            if target_ports:
                ports = set(target_ports)
            elif target_port is not None:
                ports = {target_port}
            else:
                ports = set()
            protocol = alert.get("protocol")

            produced = []
            for key_type, key_value in self._resolve_alert_keys(category, source_ip, target_ip, source_mac):
                key = (key_type, key_value)
                incident = self._get_or_create_incident(key, category, now)
                self._ingest_into_incident(
                    incident, "alert", category, attack_type, severity,
                    source_ip, source_mac, target_ip, ports, protocol, now,
                )
                self._mark_detection_basis(incident, "alert_correlation")
                self._refresh_incident_narrative(incident, now, key_type)
                if self._incident_is_surfaceable(incident):
                    produced.append(self._public_incident(incident))
            return produced

    def ingest_event(self, event):
        if not isinstance(event, dict):
            return []
        protocol = event.get("protocol")
        if protocol == "ARP":
            return []
        source_ip = event.get("source_ip")
        source_mac = event.get("source_mac")
        target_ip = event.get("target_ip")
        target_port = event.get("target_port")
        if not source_ip or not target_ip:
            return []

        with self._lock:
            now = event.get("timestamp") or time.time()
            self._run_maintenance(now)

            target_graph = self._get_target_graph(target_ip)
            target_graph.append((now, source_ip, source_mac, target_port, protocol))
            _trim_window(target_graph, now, EVENT_CORRELATION_WINDOW_SECONDS)
            _trim_size(target_graph, MAX_EVENT_ENTRIES_PER_GRAPH)

            source_graph = self._get_source_graph(source_ip)
            source_graph.append((now, target_ip, target_port, protocol))
            _trim_window(source_graph, now, EVENT_CORRELATION_WINDOW_SECONDS)
            _trim_size(source_graph, MAX_EVENT_ENTRIES_PER_GRAPH)

            produced = []
            distributed_incident = self._check_event_distributed_recon(target_ip, target_graph, now)
            if distributed_incident is not None:
                produced.append(distributed_incident)
            cross_target_incident = self._check_event_cross_target(source_ip, source_graph, now)
            if cross_target_incident is not None:
                produced.append(cross_target_incident)
            return produced

    def bulk_ingest_alerts(self, alerts):
        produced = []
        for alert in alerts:
            produced.extend(self.ingest_alert(alert))
        return produced

    def bulk_ingest_events(self, events):
        produced = []
        for event in events:
            produced.extend(self.ingest_event(event))
        return produced

    def get_incidents(self, limit=None, status=None):
        with self._lock:
            if status == STATUS_CLOSED:
                pool = list(self._closed_incidents)
            elif status == STATUS_ACTIVE:
                pool = list(self._incidents.values())
            else:
                pool = list(self._incidents.values()) + list(self._closed_incidents)
            pool = self._dedupe_incidents(pool)
            pool.sort(key=lambda incident: incident["last_seen"], reverse=True)
            if limit:
                pool = pool[:limit]
            return [self._public_incident(incident) for incident in pool]

    def _dedupe_incidents(self, pool):
        """Alerts are correlated under both a per-target key and a per-source
        key (see _resolve_alert_keys) so that genuinely different patterns --
        one source sweeping many targets, or many sources hitting one target
        -- are each captured. When a source has only touched one target,
        those two keys describe the exact same activity and would otherwise
        surface as two identical-looking incident rows. Collapse those cases
        to a single row, keeping whichever accumulated more signal, without
        changing how correlation itself works."""
        best_by_signature = {}
        order = []
        for incident in pool:
            signature = (
                incident["incident_type"],
                incident["category"],
                frozenset(incident["sources"]),
                frozenset(incident["targets"]),
            )
            existing = best_by_signature.get(signature)
            if existing is None:
                best_by_signature[signature] = incident
                order.append(signature)
                continue
            existing_signal = existing["alert_count"] + existing["event_count"]
            candidate_signal = incident["alert_count"] + incident["event_count"]
            if candidate_signal > existing_signal or (
                candidate_signal == existing_signal and incident["last_seen"] > existing["last_seen"]
            ):
                best_by_signature[signature] = incident
        return [best_by_signature[sig] for sig in order]

    def get_incident(self, incident_id):
        with self._lock:
            incident = self._incidents.get(incident_id)
            if incident is None:
                for closed_incident in self._closed_incidents:
                    if closed_incident["id"] == incident_id:
                        incident = closed_incident
                        break
            return self._public_incident(incident) if incident else None

    def run_maintenance(self, now=None):
        with self._lock:
            self._run_maintenance(now or time.time())

    def _resolve_alert_keys(self, category, source_ip, target_ip, source_mac):
        keys = []
        if category == CATEGORY_ARP:
            if target_ip:
                keys.append(("arp_ip", target_ip))
            elif source_mac:
                keys.append(("arp_mac", source_mac))
            return keys
        if target_ip:
            keys.append(("target", target_ip))
        if source_ip:
            keys.append(("source", source_ip))
        return keys

    def _get_target_graph(self, target_ip):
        graph = self._target_event_graph.get(target_ip)
        if graph is None:
            if len(self._target_event_graph) >= MAX_TRACKED_TARGET_GRAPHS:
                oldest = min(
                    self._target_event_graph.items(),
                    key=lambda kv: kv[1][0][0] if kv[1] else 0,
                    default=(None, None),
                )[0]
                if oldest is not None:
                    self._target_event_graph.pop(oldest, None)
            graph = deque()
            self._target_event_graph[target_ip] = graph
        return graph

    def _get_source_graph(self, source_ip):
        graph = self._source_event_graph.get(source_ip)
        if graph is None:
            if len(self._source_event_graph) >= MAX_TRACKED_SOURCE_GRAPHS:
                oldest = min(
                    self._source_event_graph.items(),
                    key=lambda kv: kv[1][0][0] if kv[1] else 0,
                    default=(None, None),
                )[0]
                if oldest is not None:
                    self._source_event_graph.pop(oldest, None)
            graph = deque()
            self._source_event_graph[source_ip] = graph
        return graph

    def _new_incident_shell(self, incident_id, key, category, now):
        return {
            "id": incident_id,
            "_key": key,
            "first_seen": now,
            "last_seen": now,
            "category": category,
            "incident_type": "Unknown Activity",
            "severity": "low",
            "sources": set(),
            "source_macs": set(),
            "targets": set(),
            "ports": set(),
            "protocols": set(),
            "related_attack_types": {},
            "alert_count": 0,
            "event_count": 0,
            "evidence": {},
            "details": "",
            "status": STATUS_ACTIVE,
            "_timeline": deque(maxlen=MAX_TIMELINE_ENTRIES),
            "_categories_seen": {},
            "_last_narrated_type": None,
            "_detection_basis": set(),
        }

    def _get_or_create_incident(self, key, category, now):
        incident_id = self._incident_index.get(key)
        incident = self._incidents.get(incident_id) if incident_id else None
        if incident is not None and now - incident["last_seen"] > INCIDENT_IDLE_TIMEOUT_SECONDS:
            self._close_incident(incident_id, now)
            incident = None
        if incident is None:
            if len(self._incidents) >= MAX_ACTIVE_INCIDENTS:
                self._evict_oldest_incident(now)
            incident_id = uuid.uuid4().hex
            incident = self._new_incident_shell(incident_id, key, category, now)
            self._incidents[incident_id] = incident
            self._incident_index[key] = incident_id
        return incident

    def _close_incident(self, incident_id, now):
        incident = self._incidents.pop(incident_id, None)
        if incident is None:
            return
        incident["status"] = STATUS_CLOSED
        incident["last_seen"] = max(incident["last_seen"], now)
        key = incident.get("_key")
        if key is not None and self._incident_index.get(key) == incident_id:
            self._incident_index.pop(key, None)
        self._closed_incidents.append(incident)

    def _evict_oldest_incident(self, now):
        if not self._incidents:
            return
        oldest_id = min(self._incidents.items(), key=lambda kv: kv[1]["last_seen"])[0]
        self._close_incident(oldest_id, now)

    def _mark_detection_basis(self, incident, basis):
        incident["_detection_basis"].add(basis)

    def _ingest_into_incident(self, incident, source_kind, category, attack_type, severity,
                               source_ip, source_mac, target_ip, ports, protocol, now):
        incident["last_seen"] = now
        if source_kind == "alert":
            incident["alert_count"] += 1
        else:
            incident["event_count"] += 1

        categories_seen = incident["_categories_seen"]
        categories_seen[category] = categories_seen.get(category, 0) + 1

        related_attack_types = incident["related_attack_types"]
        if attack_type in related_attack_types or len(related_attack_types) < MAX_RELATED_TYPES:
            related_attack_types[attack_type] = related_attack_types.get(attack_type, 0) + 1

        incident["severity"] = _escalate_severity(incident["severity"], severity)

        _bounded_add(incident["sources"], source_ip, MAX_INCIDENT_SOURCES)
        _bounded_add(incident["source_macs"], source_mac, MAX_INCIDENT_SOURCE_MACS)
        _bounded_add(incident["targets"], target_ip, MAX_INCIDENT_TARGETS)
        if protocol:
            _bounded_add(incident["protocols"], protocol, MAX_INCIDENT_PROTOCOLS)
        for port in ports:
            _bounded_add(incident["ports"], port, MAX_INCIDENT_PORTS)

        port_for_timeline = next(iter(ports)) if ports else None
        self._append_timeline(incident, now, source_ip, target_ip, port_for_timeline, protocol, attack_type)

    def _append_timeline(self, incident, now, source_ip, target_ip, port, protocol, note):
        incident["_timeline"].append({
            "timestamp": now,
            "source_ip": source_ip,
            "target_ip": target_ip,
            "port": port,
            "protocol": protocol,
            "note": note,
        })

    def _check_event_distributed_recon(self, target_ip, graph, now):
        source_ports = {}
        macs = set()
        protocols = set()
        for _, source_ip, source_mac, port, protocol in graph:
            if protocol:
                protocols.add(protocol)
            if source_mac:
                macs.add(source_mac)
            if port is None:
                continue
            source_ports.setdefault(source_ip, set()).add(port)

        source_count = len(source_ports)
        if source_count < DISTRIBUTED_RECON_EVENT_MIN_SOURCES:
            return None
        total_ports = sum(len(port_set) for port_set in source_ports.values())
        if total_ports < DISTRIBUTED_RECON_EVENT_MIN_TOTAL_PORTS:
            return None
        average_ports = total_ports / source_count
        if average_ports > DISTRIBUTED_RECON_EVENT_MAX_AVG_PORTS:
            return None

        span = graph[-1][0] - graph[0][0]
        attack_type = "Slow Distributed Reconnaissance" if span >= SLOW_DISTRIBUTED_RECON_MIN_SPAN_SECONDS else "Distributed Reconnaissance"

        key = ("target", target_ip)
        incident = self._get_or_create_incident(key, CATEGORY_RECON, now)
        incident["last_seen"] = now
        seen_source_ports = incident.setdefault("_seen_source_ports", {})
        for source_ip, port_set in source_ports.items():
            previous_ports = seen_source_ports.get(source_ip)
            if previous_ports is None:
                self._ingest_into_incident(
                    incident, "event", CATEGORY_RECON, attack_type, "high",
                    source_ip, None, target_ip, port_set, None, now,
                )
                seen_source_ports[source_ip] = set(port_set)
            else:
                new_ports = port_set - previous_ports
                if new_ports:
                    self._ingest_into_incident(
                        incident, "event", CATEGORY_RECON, attack_type, "high",
                        source_ip, None, target_ip, new_ports, None, now,
                    )
                    previous_ports.update(new_ports)

        for mac in macs:
            _bounded_add(incident["source_macs"], mac, MAX_INCIDENT_SOURCE_MACS)
        for protocol in protocols:
            _bounded_add(incident["protocols"], protocol, MAX_INCIDENT_PROTOCOLS)

        incident["evidence"]["average_ports_per_source"] = round(average_ports, 2)
        incident["evidence"]["window_seconds"] = EVENT_CORRELATION_WINDOW_SECONDS
        self._mark_detection_basis(incident, "raw_event_correlation")
        self._refresh_incident_narrative(incident, now, "target")
        return self._public_incident(incident) if self._incident_is_surfaceable(incident) else None

    def _check_event_cross_target(self, source_ip, graph, now):
        targets = {}
        protocols = set()
        for _, target_ip, port, protocol in graph:
            if protocol:
                protocols.add(protocol)
            port_set = targets.setdefault(target_ip, set())
            if port is not None:
                port_set.add(port)

        target_count = len(targets)
        if target_count < CROSS_TARGET_MIN_TARGETS:
            return None

        key = ("source", source_ip)
        incident = self._get_or_create_incident(key, CATEGORY_RECON, now)
        incident["last_seen"] = now
        seen_targets = incident.setdefault("_seen_targets", {})
        for target_ip, port_set in targets.items():
            previous_ports = seen_targets.get(target_ip)
            if previous_ports is None:
                self._ingest_into_incident(
                    incident, "event", CATEGORY_RECON, "Cross-Target Reconnaissance Sweep", "medium",
                    source_ip, None, target_ip, port_set, None, now,
                )
                seen_targets[target_ip] = set(port_set)
            else:
                new_ports = port_set - previous_ports
                if new_ports:
                    self._ingest_into_incident(
                        incident, "event", CATEGORY_RECON, "Cross-Target Reconnaissance Sweep", "medium",
                        source_ip, None, target_ip, new_ports, None, now,
                    )
                    previous_ports.update(new_ports)

        for protocol in protocols:
            _bounded_add(incident["protocols"], protocol, MAX_INCIDENT_PROTOCOLS)

        incident["evidence"]["window_seconds"] = EVENT_CORRELATION_WINDOW_SECONDS
        self._mark_detection_basis(incident, "raw_event_correlation")
        self._refresh_incident_narrative(incident, now, "source")
        return self._public_incident(incident) if self._incident_is_surfaceable(incident) else None

    def _refresh_incident_narrative(self, incident, now, key_type):
        incident["category"] = _dominant_category(incident["_categories_seen"])
        related_attack_types = incident["related_attack_types"]
        distinct_type_count = len(related_attack_types)
        source_count = len(incident["sources"])
        target_count = len(incident["targets"])

        if key_type == "target":
            if incident["category"] == CATEGORY_RECON:
                if source_count >= ALERT_DISTRIBUTED_RECON_MIN_SOURCES:
                    span = now - incident["first_seen"]
                    incident["incident_type"] = (
                        "Slow Distributed Reconnaissance"
                        if span >= SLOW_DISTRIBUTED_RECON_MIN_SPAN_SECONDS
                        else "Distributed Reconnaissance"
                    )
                elif distinct_type_count >= INCIDENT_MIN_TYPES_FOR_CAMPAIGN:
                    incident["incident_type"] = "Multi-Technique Reconnaissance"
                else:
                    incident["incident_type"] = _dominant_attack_type(related_attack_types)
            elif incident["category"] == CATEGORY_FLOOD:
                incident["incident_type"] = (
                    "Multi-Vector Flood Campaign"
                    if distinct_type_count >= INCIDENT_MIN_TYPES_FOR_CAMPAIGN
                    else _dominant_attack_type(related_attack_types)
                )
            elif distinct_type_count >= INCIDENT_MIN_TYPES_FOR_CAMPAIGN:
                incident["incident_type"] = "Attack Campaign"
            else:
                incident["incident_type"] = _dominant_attack_type(related_attack_types)
        elif key_type == "source":
            if target_count >= CROSS_TARGET_MIN_TARGETS and incident["category"] == CATEGORY_RECON:
                incident["incident_type"] = "Cross-Target Reconnaissance Sweep"
            elif distinct_type_count >= INCIDENT_MIN_TYPES_FOR_CAMPAIGN:
                incident["incident_type"] = "Attack Campaign"
            else:
                incident["incident_type"] = _dominant_attack_type(related_attack_types)
        else:
            if distinct_type_count >= INCIDENT_MIN_TYPES_FOR_CAMPAIGN or incident["alert_count"] >= 3:
                incident["incident_type"] = "Coordinated MAC/ARP Activity"
            else:
                incident["incident_type"] = _dominant_attack_type(related_attack_types)

        severity_floor = INCIDENT_TYPE_SEVERITY_FLOOR.get(incident["incident_type"])
        if severity_floor:
            incident["severity"] = _escalate_severity(incident["severity"], severity_floor)

        incident["evidence"]["source_count"] = source_count
        incident["evidence"]["target_count"] = target_count
        incident["evidence"]["port_count"] = len(incident["ports"])
        incident["evidence"]["distinct_attack_types"] = sorted(related_attack_types.keys())
        incident["evidence"]["duration_seconds"] = int(now - incident["first_seen"])

        incident["details"] = self._build_attack_story(incident, now)

        if incident["incident_type"] != incident.get("_last_narrated_type"):
            self._append_timeline(incident, now, None, None, None, None, f"{incident['incident_type']} pattern identified")
            incident["_last_narrated_type"] = incident["incident_type"]

    def _build_attack_story(self, incident, now):
        span = now - incident["first_seen"]
        duration_text = _format_duration(span)
        source_count = len(incident["sources"])
        target_count = len(incident["targets"])
        port_count = len(incident["ports"])
        incident_type = incident["incident_type"]

        if incident_type in ("Distributed Reconnaissance", "Slow Distributed Reconnaissance"):
            target = next(iter(incident["targets"]), "the target")
            return (
                f"{source_count} different sources contacted {target} across {port_count} ports within "
                f"{duration_text}. Each source generated only a small number of probes, but the combined "
                f"behavior indicates possible coordinated or evasive reconnaissance."
            )
        if incident_type == "Cross-Target Reconnaissance Sweep":
            source = next(iter(incident["sources"]), "A source")
            return (
                f"{source} probed {target_count} different targets across {port_count} ports within "
                f"{duration_text}, suggesting a broad sweep rather than focused interest in a single host."
            )
        if incident_type == "Multi-Technique Reconnaissance":
            return (
                f"{source_count} source(s) combined {len(incident['related_attack_types'])} different "
                f"reconnaissance techniques against the same target within {duration_text}."
            )
        if incident_type == "Attack Campaign":
            types_list = ", ".join(sorted(incident["related_attack_types"].keys()))
            return (
                f"Related activity ({types_list}) was observed across overlapping sources and targets within "
                f"{duration_text}, indicating one coordinated campaign rather than {incident['alert_count'] + incident['event_count']} unrelated events."
            )
        if incident_type == "Multi-Vector Flood Campaign":
            protocols_text = ", ".join(sorted(incident["protocols"])) or "multiple protocols"
            return (
                f"Flood-style traffic using {protocols_text} was observed against the same target across "
                f"{incident['alert_count']} alerts within {duration_text}, consistent with a sustained "
                f"denial-of-service attempt."
            )
        if incident_type == "Coordinated MAC/ARP Activity":
            return (
                f"{incident['alert_count']} related MAC/ARP anomalies were observed within {duration_text}. "
                f"MAC addresses can be changed by an attacker, so this pattern should be treated as supporting "
                f"evidence rather than proof of a specific device's identity."
            )

        return (
            f"{incident['alert_count'] + incident['event_count']} related signal(s) of type '{incident_type}' "
            f"were correlated across {source_count} source(s) and {target_count} target(s) within {duration_text}."
        )

    def _incident_is_surfaceable(self, incident):
        if incident["status"] != STATUS_ACTIVE:
            return False
        return (incident["alert_count"] + incident["event_count"]) >= INCIDENT_MIN_SIGNALS_FOR_SURFACE

    def _public_incident(self, incident):
        evidence = dict(incident["evidence"])
        evidence["detection_basis"] = sorted(incident.get("_detection_basis", set()))
        ports_sorted = sorted(incident["ports"])
        related_event_count = incident["alert_count"] + incident["event_count"]
        return {
            "id": incident["id"],
            "first_seen": incident["first_seen"],
            "last_seen": incident["last_seen"],
            "category": incident["category"],
            "incident_type": incident["incident_type"],
            "severity": incident["severity"],
            "sources": sorted(incident["sources"]),
            "source_macs": sorted(incident["source_macs"]),
            "targets": sorted(incident["targets"]),
            "ports": ports_sorted,
            "port_count": len(ports_sorted),
            "first_port": ports_sorted[0] if ports_sorted else None,
            "last_port": ports_sorted[-1] if ports_sorted else None,
            "protocols": sorted(incident["protocols"]),
            "related_attack_types": dict(incident["related_attack_types"]),
            "alert_count": incident["alert_count"],
            "event_count": incident["event_count"],
            "related_event_count": related_event_count,
            "activity_summary": scanner.build_activity_summary(
                incident["incident_type"], incident["category"], len(ports_sorted), related_event_count,
            ),
            "evidence": evidence,
            "details": incident["details"],
            "status": incident["status"],
            "timeline": list(incident["_timeline"]),
        }

    def _run_maintenance(self, now):
        if now - self._last_maintenance < MAINTENANCE_INTERVAL_SECONDS:
            return
        self._last_maintenance = now

        stale_incident_ids = [
            incident_id for incident_id, incident in self._incidents.items()
            if now - incident["last_seen"] > INCIDENT_IDLE_TIMEOUT_SECONDS
        ]
        for incident_id in stale_incident_ids:
            self._close_incident(incident_id, now)

        stale_targets = [
            target_ip for target_ip, graph in self._target_event_graph.items()
            if not graph or now - graph[-1][0] > EVENT_CORRELATION_WINDOW_SECONDS
        ]
        for target_ip in stale_targets:
            self._target_event_graph.pop(target_ip, None)

        stale_sources = [
            source_ip for source_ip, graph in self._source_event_graph.items()
            if not graph or now - graph[-1][0] > EVENT_CORRELATION_WINDOW_SECONDS
        ]
        for source_ip in stale_sources:
            self._source_event_graph.pop(source_ip, None)


default_engine = CorrelationEngine()
