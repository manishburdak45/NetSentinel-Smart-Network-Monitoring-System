import os
import re
import socket
import shutil
import subprocess
import threading
import time
import uuid
import ipaddress
import xml.etree.ElementTree as ET
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from scapy.all import AsyncSniffer, ARP, Ether, IP, TCP, UDP, ICMP, srp
    _SCAPY_AVAILABLE = True
except Exception:
    _SCAPY_AVAILABLE = False

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 631, 993, 995, 1433, 1723, 2049, 27017, 3306, 3389, 5432,
    5900, 6379, 8000, 8080, 8443, 8888, 9000, 9200,
]

DISCOVERY_FALLBACK_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995,
    3306, 3389, 5432, 5900, 8080, 8443,
]

MAX_FALLBACK_WORKERS = 20
NMAP_MULTI_HOST_TIMEOUT = "20s"

CATEGORY_RECON = "Reconnaissance"
CATEGORY_FLOOD = "DoS / Flood"
CATEGORY_ANOMALY = "Anomaly"
CATEGORY_ARP = "MAC / ARP"

SEVERITY_LEVELS = ("low", "medium", "high", "critical")
ALERT_ELIGIBLE_SEVERITIES = frozenset({"medium", "high", "critical"})


def normalize_severity(value):
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if normalized in SEVERITY_LEVELS:
        return normalized
    return None


def resolve_alert_severity(value):
    normalized = normalize_severity(value)
    return normalized if normalized is not None else "medium"


def is_eligible_severity(value):
    return normalize_severity(value) in ALERT_ELIGIBLE_SEVERITIES


def build_activity_summary(attack_type, category, port_count, event_count):
    """Build a short, human-readable summary of a consolidated attack pattern
    from real, already-computed counts. Used by both the correlation engine
    (incidents) and the alert consolidation layer (app.py) so the dashboard
    and incident modal describe the same activity the same way."""
    attack_type_text = (attack_type or "").lower()
    event_count = event_count or 0
    port_count = port_count or 0

    if port_count > 1:
        return f"{port_count} ports scanned"
    if category == CATEGORY_ARP or "arp" in attack_type_text or "mac" in attack_type_text:
        return f"{event_count} ARP/MAC change(s) detected"
    if category == CATEGORY_FLOOD or "flood" in attack_type_text or "burst" in attack_type_text or "spike" in attack_type_text:
        return f"{event_count} abnormal traffic burst(s)"
    if "repeated" in attack_type_text or "failed connection" in attack_type_text:
        return f"{event_count} repeated connection attempt(s)"
    if "sweep" in attack_type_text:
        return f"{event_count} sweep event(s) detected"
    if port_count == 1:
        return f"{event_count} probe(s) on 1 port"
    return f"{event_count} related event(s)"


INTERNAL_SCAN_GRACE_SECONDS = 5

WINDOW_SECONDS = 8
SLOW_WINDOW_SECONDS = 300
FLOOD_WINDOW_SECONDS = 5
BURST_BUCKET_SECONDS = 2
BURST_HISTORY_BUCKETS = 30

PORT_SCAN_THRESHOLD = 12
UDP_SCAN_PORT_THRESHOLD = 10
MULTI_PORT_PROBE_THRESHOLD = 6
SLOW_SCAN_PORT_THRESHOLD = 6
SLOW_SCAN_MIN_SPAN_SECONDS = 45
REPEATED_SINGLE_PORT_THRESHOLD = 15
HOST_SWEEP_THRESHOLD = 10
ICMP_SWEEP_HOST_THRESHOLD = 8

SYN_FLOOD_PACKET_THRESHOLD = 150
UDP_FLOOD_PACKET_THRESHOLD = 200
ICMP_FLOOD_PACKET_THRESHOLD = 120
TCP_CONN_FLOOD_THRESHOLD = 150
TRAFFIC_BURST_RATIO = 4.0
TRAFFIC_BURST_MIN_CURRENT = 40

UNUSUAL_PORT_PROFILE_WINDOW = 3600
UNUSUAL_PORT_MIN_PROFILE_EVENTS = 20
UNUSUAL_PORT_MAX_PROFILE_ENTRIES = 64
FAILED_CONNECTION_THRESHOLD = 8
FAILED_CONNECTION_WINDOW = 30

SOURCE_SPIKE_RATIO = 6.0
SOURCE_SPIKE_MIN_CURRENT = 60
SOURCE_SPIKE_WARMUP_SECONDS = 60
SOURCE_SPIKE_PERSIST_BUCKETS = 2

NEW_PAIR_BURST_THRESHOLD = 40
NEW_PAIR_BURST_WINDOW = 10
NEW_PAIR_SUBWINDOW_SECONDS = 5
NEW_PAIR_SUBWINDOW_MIN_EVENTS = 15
KNOWN_PAIR_HISTORY_SECONDS = 1800

ANOMALY_ALERT_COOLDOWN = 300
DNS_PORT = 53

DISTRIBUTED_RECON_WINDOW = 300
DISTRIBUTED_RECON_MIN_SOURCES = 8
DISTRIBUTED_RECON_MAX_AVG_PORTS = 2.0
DISTRIBUTED_RECON_MIN_TOTAL_PORTS = 6

ARP_MAC_HISTORY_WINDOW = 600
ARP_IP_MAC_CHANGE_THRESHOLD = 2
ARP_MAC_IP_CHANGE_THRESHOLD = 3
ARP_STABLE_OBSERVATIONS = 3

ALERT_COOLDOWN = 60
MAX_ALERT_KEYS = 2000

MAX_TRACKED_SOURCES = 800
MAX_TRACKED_TARGETS = 800
MAX_EVENTS_PER_SOURCE = 4000
MAX_EVENTS_PER_TARGET = 4000
MAX_PENDING_HANDSHAKES = 4000
MAX_KNOWN_PAIRS = 6000
MAX_IP_MAC_ENTRIES = 2000
MAX_TARGET_RECON_PROBES = 4000
RECENT_EVENTS_BUFFER = 5000

STATE_CLEANUP_INTERVAL = 30
STALE_ENTRY_TTL = max(SLOW_WINDOW_SECONDS, ARP_MAC_HISTORY_WINDOW, UNUSUAL_PORT_PROFILE_WINDOW) + 120


def _run_command(args, timeout=5):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except Exception:
        return None


def _get_default_interface():
    proc = _run_command(["ip", "route", "show", "default"])
    if not proc or not proc.stdout:
        return None
    match = re.search(r"\bdev\s+(\S+)", proc.stdout)
    return match.group(1) if match else None


def _get_default_gateway():
    proc = _run_command(["ip", "route", "show", "default"])
    if not proc or not proc.stdout:
        return None
    match = re.search(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)", proc.stdout)
    return match.group(1) if match else None


def _is_infrastructure_address(ip):
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_multicast or addr.is_link_local or addr.is_reserved or addr.is_unspecified


def _get_interface_ipv4(interface):
    proc = _run_command(["ip", "-o", "-4", "addr", "show", "dev", interface])
    if not proc or not proc.stdout:
        return None, None
    match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", proc.stdout)
    if not match:
        return None, None
    return match.group(1), int(match.group(2))


def get_local_network_info():
    interface = _get_default_interface()
    if not interface:
        raise RuntimeError("no active default network interface found")
    ip_addr, prefix = _get_interface_ipv4(interface)
    if not ip_addr or prefix is None:
        raise RuntimeError(f"no IPv4 address found on interface {interface}")
    network = ipaddress.ip_network(f"{ip_addr}/{prefix}", strict=False)
    return interface, str(network)


def _resolve_hostname(ip):
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(1.5)
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def _ping_host(ip, timeout=1):
    proc = _run_command(["ping", "-c", "1", "-W", str(timeout), ip], timeout=timeout + 2)
    return bool(proc and proc.returncode == 0)


def _get_mac_for_ip(ip):
    proc = _run_command(["ip", "neigh", "show", ip])
    if not proc or not proc.stdout:
        return None
    match = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", proc.stdout)
    return match.group(1).lower() if match else None


def _check_port(ip, port, timeout=0.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False


def _quick_port_scan(ip, ports):
    open_ports = []
    services = []
    for port in ports:
        if _check_port(ip, port):
            open_ports.append(port)
            try:
                name = socket.getservbyport(port)
            except OSError:
                name = None
            services.append({"port": port, "protocol": "tcp", "name": name, "product": None})
    return open_ports, services


def discover_devices(cidr):
    network = ipaddress.ip_network(cidr, strict=False)
    if network.num_addresses > 65536:
        raise ValueError("network range too large for discovery")
    if not _SCAPY_AVAILABLE:
        raise RuntimeError("scapy is required for device discovery")

    try:
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        answered, _unanswered = srp(request, timeout=3, retry=1, verbose=False)
    except PermissionError as exc:
        raise PermissionError("elevated privileges required for ARP discovery") from exc
    except OSError as exc:
        raise RuntimeError(f"ARP discovery failed: {exc}") from exc

    devices = {}
    for _sent, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        devices[ip] = {
            "ip": ip,
            "mac": mac,
            "hostname": _resolve_hostname(ip),
            "online": True,
            "open_ports": None,
            "services": None,
            "os": None,
        }

    if not devices:
        return []

    ips = list(devices.keys())

    scan_results = {}
    if shutil.which("nmap"):
        scan_results = _run_nmap_multi_host(ips)

    fallback_ips = []
    for ip in ips:
        scanned = scan_results.get(ip)
        if _nmap_result_is_usable(scanned):
            devices[ip]["open_ports"] = scanned.get("open_ports") or []
            devices[ip]["services"] = scanned.get("services") or []
            if scanned.get("os"):
                devices[ip]["os"] = scanned["os"]
            if scanned.get("mac") and not devices[ip].get("mac"):
                devices[ip]["mac"] = scanned["mac"]
            if scanned.get("hostname") and not devices[ip].get("hostname"):
                devices[ip]["hostname"] = scanned["hostname"]
        else:
            fallback_ips.append(ip)

    if fallback_ips:
        _fill_fallback_port_data(devices, fallback_ips)

    return list(devices.values())


def _nmap_result_is_usable(result):
    if not result:
        return False
    if result.get("open_ports"):
        return True
    if result.get("os"):
        return True
    if result.get("online"):
        return True
    return False


def _fill_fallback_port_data(devices, ips):
    max_workers = max(1, min(MAX_FALLBACK_WORKERS, len(ips)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(_quick_port_scan, ip, DISCOVERY_FALLBACK_PORTS): ip
            for ip in ips
        }
        for future in as_completed(future_map):
            ip = future_map[future]
            try:
                open_ports, services = future.result()
            except Exception:
                open_ports, services = [], []
            devices[ip]["open_ports"] = open_ports
            devices[ip]["services"] = services


def _run_nmap_multi_host(ips, timeout=None):
    if timeout is None:
        timeout = max(60, min(300, 20 * len(ips)))
    args = [
        "nmap", "-Pn", "-sV", "-O", "-T4",
        "--host-timeout", NMAP_MULTI_HOST_TIMEOUT,
        "--max-retries", "1",
        "-oX", "-",
    ] + ips
    proc = _run_command(args, timeout=timeout)
    if not proc or not proc.stdout:
        return {}
    return _parse_nmap_output_multi(proc.stdout)


def _parse_nmap_host_element(host):
    status = host.find("status")
    online = bool(status is not None and status.get("state") == "up")

    ip = None
    mac = None
    for addr in host.findall("address"):
        addrtype = addr.get("addrtype")
        if addrtype == "ipv4":
            ip = addr.get("addr")
        elif addrtype == "mac":
            mac = addr.get("addr")

    if not ip:
        return None

    hostname = None
    hostname_el = host.find("hostnames/hostname")
    if hostname_el is not None:
        hostname = hostname_el.get("name")

    open_ports = []
    services = []
    ports_el = host.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            try:
                port_id = int(port_el.get("portid"))
            except (TypeError, ValueError):
                continue
            protocol = port_el.get("protocol")
            service_el = port_el.find("service")
            service_name = service_el.get("name") if service_el is not None else None
            product = service_el.get("product") if service_el is not None else None
            open_ports.append(port_id)
            services.append({"port": port_id, "protocol": protocol, "name": service_name, "product": product})

    os_name = None
    os_el = host.find("os")
    if os_el is not None:
        match_el = os_el.find("osmatch")
        if match_el is not None:
            accuracy = match_el.get("accuracy")
            try:
                if accuracy is not None and int(accuracy) >= 85:
                    os_name = match_el.get("name")
            except ValueError:
                os_name = None

    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "online": online,
        "open_ports": open_ports,
        "services": services,
        "os": os_name,
    }


def _parse_nmap_output_multi(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}

    results = {}
    for host in root.findall("host"):
        parsed = _parse_nmap_host_element(host)
        if parsed and parsed.get("ip"):
            results[parsed["ip"]] = parsed
    return results


def _parse_nmap_output(xml_text, ip):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    host = root.find("host")
    if host is None:
        return None

    parsed = _parse_nmap_host_element(host)
    if parsed is None:
        return None
    parsed["ip"] = ip
    return parsed


def _fallback_scan(ip):
    online = _ping_host(ip)
    open_ports, services = _quick_port_scan(ip, COMMON_PORTS)
    if open_ports:
        online = True
    return {
        "ip": ip,
        "mac": _get_mac_for_ip(ip),
        "hostname": _resolve_hostname(ip),
        "online": online,
        "open_ports": open_ports,
        "services": services,
        "os": None,
    }


def _run_nmap(ip):
    if not shutil.which("nmap"):
        return None
    args = ["nmap", "-Pn", "-sV", "-O", "-T4", "--host-timeout", "30s", "-oX", "-", ip]
    proc = _run_command(args, timeout=60)
    if not proc or not proc.stdout:
        return None
    return proc.stdout


def scan_target(target):
    network = ipaddress.ip_network(target, strict=False)
    if network.num_addresses != 1:
        raise ValueError("scan_target requires a single IP address")
    ip = str(network.network_address)

    xml_output = _run_nmap(ip)
    if xml_output:
        parsed = _parse_nmap_output(xml_output, ip)
        if _nmap_result_is_usable(parsed):
            if not parsed.get("mac"):
                parsed["mac"] = _get_mac_for_ip(ip)
            if not parsed.get("hostname"):
                parsed["hostname"] = _resolve_hostname(ip)
            return parsed

    return _fallback_scan(ip)


def _trim_window(events, now, window):
    while events and now - events[0][0] > window:
        events.popleft()


def _trim_size(events, max_size):
    while len(events) > max_size:
        events.popleft()


def _bucket_index(now, epoch, bucket_seconds):
    return int((now - epoch) // bucket_seconds)


class _RateBurstTracker:
    def __init__(self, epoch):
        self.epoch = epoch
        self.buckets = deque()
        self.created_at = None

    def record(self, now):
        if self.created_at is None:
            self.created_at = now
        index = _bucket_index(now, self.epoch, BURST_BUCKET_SECONDS)
        if self.buckets and self.buckets[-1][0] == index:
            self.buckets[-1][1] += 1
        else:
            self.buckets.append([index, 1])
        while len(self.buckets) > BURST_HISTORY_BUCKETS:
            self.buckets.popleft()

    def burst_ratio(self):
        if len(self.buckets) < 3:
            return 0.0, 0
        current = self.buckets[-1][1]
        history = [count for _, count in list(self.buckets)[:-1]]
        if not history:
            return 0.0, current
        baseline = sum(history) / len(history)
        if baseline <= 0:
            return float(current), current
        return current / baseline, current

    def warmed_up(self, now, seconds):
        return self.created_at is not None and (now - self.created_at) >= seconds

    def persistent_burst_ratio(self, persist_buckets, ratio_threshold, min_current):
        if len(self.buckets) < persist_buckets + 3:
            return False, 0.0, 0
        ordered = list(self.buckets)
        recent = ordered[-persist_buckets:]
        history = ordered[:-persist_buckets]
        counts = [count for _, count in history]
        baseline = sum(counts) / len(counts) if counts else 0.0
        if baseline <= 0:
            baseline = 1.0
        persistent = all(
            count >= min_current and (count / baseline) >= ratio_threshold
            for _, count in recent
        )
        last_count = recent[-1][1]
        return persistent, last_count / baseline, last_count


class NetworkMonitor:
    def __init__(self, interface, alert_callback):
        if not _SCAPY_AVAILABLE:
            raise RuntimeError("scapy is required for network monitoring")
        if not interface:
            raise ValueError("a valid network interface is required")
        if not callable(alert_callback):
            raise ValueError("alert_callback must be callable")

        self.interface = interface
        self.alert_callback = alert_callback
        self._lock = threading.RLock()
        self._sniffer = None
        self._running = False
        self._epoch = time.time()
        self._gateway_ip = _get_default_gateway()
        local_ip, _local_prefix = _get_interface_ipv4(interface)
        self._local_ip = local_ip
        self._active_scan = None

        self._source_state = {}
        self._target_state = {}
        self._target_bursts = {}
        self._source_bursts = {}
        self._target_recon_probes = {}
        self._pending_handshakes = {}
        self._known_pairs = {}
        self._port_profiles = {}
        self._ip_mac_history = {}
        self._mac_ip_history = {}
        self._ip_mac_current = {}
        self._recent_events = deque(maxlen=RECENT_EVENTS_BUFFER)
        self._last_alert = {}
        self._last_cleanup = 0.0

    def start(self):
        with self._lock:
            if self._running:
                return
            try:
                sniffer = AsyncSniffer(
                    iface=self.interface,
                    filter="tcp or udp or icmp or arp",
                    prn=self._handle_packet,
                    store=False,
                )
                sniffer.start()
            except PermissionError as exc:
                raise PermissionError("elevated privileges required for packet capture") from exc
            except Exception as exc:
                raise RuntimeError(f"failed to start packet capture: {exc}") from exc

            self._sniffer = sniffer
            self._running = True

    def stop(self):
        with self._lock:
            if not self._running:
                return
            sniffer = self._sniffer
            self._sniffer = None
            self._running = False
            self._source_state.clear()
            self._target_state.clear()
            self._target_bursts.clear()
            self._source_bursts.clear()
            self._target_recon_probes.clear()
            self._pending_handshakes.clear()
            self._known_pairs.clear()
            self._port_profiles.clear()
            self._ip_mac_history.clear()
            self._mac_ip_history.clear()
            self._ip_mac_current.clear()
            self._recent_events.clear()
            self._last_alert.clear()
            self._active_scan = None

        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass

    def get_recent_events(self, limit=None):
        with self._lock:
            events = list(self._recent_events)
        if limit:
            return events[-limit:]
        return events

    def begin_internal_scan(self, job_id, targets, source_ip=None):
        networks = []
        for target in targets or []:
            try:
                networks.append(ipaddress.ip_network(target, strict=False))
            except ValueError:
                continue
        with self._lock:
            self._active_scan = {
                "job_id": job_id,
                "source_ip": source_ip or self._local_ip,
                "networks": networks,
                "started_at": time.time(),
                "ended_at": None,
            }

    def end_internal_scan(self, job_id):
        with self._lock:
            if self._active_scan and self._active_scan.get("job_id") == job_id:
                self._active_scan["ended_at"] = time.time()

    def _internal_scan_in_scope(self, ip, networks):
        if not ip:
            return False
        if not networks:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in network for network in networks)

    def _is_internal_scan_traffic(self, src_ip, dst_ip, now):
        scan = self._active_scan
        if not scan:
            return False
        ended_at = scan.get("ended_at")
        if ended_at is not None and now - ended_at > INTERNAL_SCAN_GRACE_SECONDS:
            return False
        local_ip = scan.get("source_ip")
        if not local_ip:
            return False
        networks = scan.get("networks") or []
        if src_ip == local_ip and self._internal_scan_in_scope(dst_ip, networks):
            return True
        if dst_ip == local_ip and self._internal_scan_in_scope(src_ip, networks):
            return True
        return False

    def _handle_packet(self, packet):
        try:
            now = time.time()
            if packet.haslayer(ARP):
                self._process_arp_packet(packet, now)
                return
            if not packet.haslayer(IP):
                return

            ip_layer = packet[IP]
            src_mac = packet[Ether].src if packet.haslayer(Ether) else None

            if packet.haslayer(TCP):
                self._process_tcp_packet(packet, ip_layer, src_mac, now)
            elif packet.haslayer(UDP):
                self._process_udp_packet(packet, ip_layer, src_mac, now)
            elif packet.haslayer(ICMP):
                self._process_icmp_packet(packet, ip_layer, src_mac, now)
        except Exception:
            return

    def _record_event(self, event):
        self._recent_events.append(event)

    def _flag_string(self, flags):
        names = []
        if flags & 0x01:
            names.append("FIN")
        if flags & 0x02:
            names.append("SYN")
        if flags & 0x04:
            names.append("RST")
        if flags & 0x08:
            names.append("PSH")
        if flags & 0x10:
            names.append("ACK")
        if flags & 0x20:
            names.append("URG")
        return "".join(names) if names else "NONE"

    def _process_tcp_packet(self, packet, ip_layer, src_mac, now):
        tcp_layer = packet[TCP]
        flags = int(tcp_layer.flags)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
        packet_size = len(packet)
        flag_str = self._flag_string(flags)

        event = {
            "timestamp": now,
            "protocol": "TCP",
            "source_ip": src_ip,
            "source_mac": src_mac,
            "source_port": src_port,
            "target_ip": dst_ip,
            "target_port": dst_port,
            "tcp_flags": flag_str,
            "packet_size": packet_size,
            "event_type": flag_str.lower(),
        }

        alerts_to_send = []
        with self._lock:
            if not self._running:
                return
            if self._is_internal_scan_traffic(src_ip, dst_ip, now):
                self._maybe_run_cleanup(now)
                return
            self._record_event(event)
            if src_mac:
                self._register_ip_mac(src_ip, src_mac, now, alerts_to_send)

            self._record_source_target_event(src_ip, src_mac, dst_ip, dst_port, "TCP", flags, now)
            self._record_target_event(dst_ip, src_ip, dst_port, "TCP", flags, now)
            self._track_handshake_state(src_ip, dst_ip, dst_port, flags, now)

            is_syn_only = bool(flags & 0x02) and not bool(flags & 0x10)
            is_rst = bool(flags & 0x04)

            if is_syn_only:
                self._detect_reconnaissance(src_ip, dst_ip, dst_port, "TCP", now, alerts_to_send)
                self._detect_syn_flood(dst_ip, now, alerts_to_send)
                self._detect_tcp_connection_flood(dst_ip, src_ip, src_port, now, alerts_to_send)

            if is_rst:
                self._detect_failed_connection(dst_ip, src_ip, src_port, now, alerts_to_send)

            self._detect_unusual_port_activity(src_ip, dst_port, "TCP", now, alerts_to_send)
            self._detect_abnormal_pair_pattern(src_ip, dst_ip, dst_port, "TCP", now, alerts_to_send)
            self._detect_traffic_burst(dst_ip, now, alerts_to_send)
            self._detect_source_traffic_spike(src_ip, dst_ip, dst_port, "TCP", now, alerts_to_send)
            self._maybe_run_cleanup(now)

        self._dispatch_alerts(alerts_to_send)

    def _process_udp_packet(self, packet, ip_layer, src_mac, now):
        udp_layer = packet[UDP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = int(udp_layer.sport)
        dst_port = int(udp_layer.dport)
        packet_size = len(packet)

        event = {
            "timestamp": now,
            "protocol": "UDP",
            "source_ip": src_ip,
            "source_mac": src_mac,
            "source_port": src_port,
            "target_ip": dst_ip,
            "target_port": dst_port,
            "tcp_flags": None,
            "packet_size": packet_size,
            "event_type": "udp",
        }

        alerts_to_send = []
        with self._lock:
            if not self._running:
                return
            if self._is_internal_scan_traffic(src_ip, dst_ip, now):
                self._maybe_run_cleanup(now)
                return
            self._record_event(event)
            if src_mac:
                self._register_ip_mac(src_ip, src_mac, now, alerts_to_send)

            self._record_source_target_event(src_ip, src_mac, dst_ip, dst_port, "UDP", 0, now)
            self._record_target_event(dst_ip, src_ip, dst_port, "UDP", 0, now)

            self._detect_reconnaissance(src_ip, dst_ip, dst_port, "UDP", now, alerts_to_send)
            self._detect_udp_flood(dst_ip, now, alerts_to_send)
            self._detect_unusual_port_activity(src_ip, dst_port, "UDP", now, alerts_to_send)
            self._detect_abnormal_pair_pattern(src_ip, dst_ip, dst_port, "UDP", now, alerts_to_send)
            self._detect_traffic_burst(dst_ip, now, alerts_to_send)
            self._detect_source_traffic_spike(src_ip, dst_ip, dst_port, "UDP", now, alerts_to_send)
            self._maybe_run_cleanup(now)

        self._dispatch_alerts(alerts_to_send)

    def _process_icmp_packet(self, packet, ip_layer, src_mac, now):
        icmp_layer = packet[ICMP]
        icmp_type = int(getattr(icmp_layer, "type", -1))
        if icmp_type != 8:
            return

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        packet_size = len(packet)

        event = {
            "timestamp": now,
            "protocol": "ICMP",
            "source_ip": src_ip,
            "source_mac": src_mac,
            "source_port": None,
            "target_ip": dst_ip,
            "target_port": None,
            "tcp_flags": None,
            "packet_size": packet_size,
            "event_type": "icmp_echo",
        }

        alerts_to_send = []
        with self._lock:
            if not self._running:
                return
            if self._is_internal_scan_traffic(src_ip, dst_ip, now):
                self._maybe_run_cleanup(now)
                return
            self._record_event(event)
            if src_mac:
                self._register_ip_mac(src_ip, src_mac, now, alerts_to_send)

            self._record_source_target_event(src_ip, src_mac, dst_ip, None, "ICMP", 0, now)
            self._record_target_event(dst_ip, src_ip, None, "ICMP", 0, now)

            self._detect_icmp_sweep(src_ip, now, alerts_to_send)
            self._detect_icmp_flood(dst_ip, now, alerts_to_send)
            self._detect_traffic_burst(dst_ip, now, alerts_to_send)
            self._maybe_run_cleanup(now)

        self._dispatch_alerts(alerts_to_send)

    def _process_arp_packet(self, packet, now):
        arp_layer = packet[ARP]
        op = int(arp_layer.op)
        sender_ip = arp_layer.psrc
        sender_mac = arp_layer.hwsrc
        event_type = "arp_request" if op == 1 else "arp_reply" if op == 2 else "arp_other"

        event = {
            "timestamp": now,
            "protocol": "ARP",
            "source_ip": sender_ip,
            "source_mac": sender_mac,
            "source_port": None,
            "target_ip": arp_layer.pdst,
            "target_port": None,
            "tcp_flags": None,
            "packet_size": len(packet),
            "event_type": event_type,
        }

        alerts_to_send = []
        with self._lock:
            if not self._running:
                return
            if self._is_internal_scan_traffic(sender_ip, arp_layer.pdst, now):
                self._maybe_run_cleanup(now)
                return
            self._record_event(event)
            if sender_ip and sender_mac and sender_ip != "0.0.0.0":
                self._register_ip_mac(sender_ip, sender_mac, now, alerts_to_send)
            self._maybe_run_cleanup(now)

        self._dispatch_alerts(alerts_to_send)

    def _dispatch_alerts(self, alerts):
        for alert in alerts:
            try:
                self.alert_callback(alert)
            except Exception:
                pass

    def _build_alert(self, category, attack_type, severity, source_ip, source_mac,
                      target_ip, target_port, target_ports, protocol, details, evidence):
        return {
            "id": uuid.uuid4().hex,
            "timestamp": time.time(),
            "category": category,
            "attack_type": attack_type,
            "detection_type": attack_type,
            "severity": severity,
            "source_ip": source_ip,
            "source_mac": source_mac,
            "target_ip": target_ip,
            "target_port": target_port,
            "target_ports": target_ports,
            "protocol": protocol,
            "details": details,
            "evidence": evidence or {},
        }

    def _emit(self, alerts_out, dedup_key, now, category, attack_type, severity,
               source_ip, source_mac, target_ip, target_port, target_ports,
               protocol, details, evidence, cooldown=None):
        effective_cooldown = cooldown if cooldown is not None else ALERT_COOLDOWN
        last = self._last_alert.get(dedup_key, 0)
        if now - last < effective_cooldown:
            return
        self._last_alert[dedup_key] = now
        alerts_out.append(self._build_alert(
            category, attack_type, severity, source_ip, source_mac,
            target_ip, target_port, target_ports, protocol, details, evidence,
        ))

    def _is_routine_target(self, ip, port, protocol):
        if not ip:
            return False
        if ip == self._gateway_ip:
            return True
        if ip in ("255.255.255.255", "0.0.0.0"):
            return True
        if _is_infrastructure_address(ip):
            return True
        if port == DNS_PORT:
            return True
        return False

    def _get_source_entry(self, src_ip, src_mac, now):
        if src_ip not in self._source_state and len(self._source_state) >= MAX_TRACKED_SOURCES:
            self._evict_oldest(self._source_state)
        entry = self._source_state.setdefault(src_ip, {
            "mac": src_mac,
            "events": deque(),
            "single_port_hits": {},
        })
        if src_mac:
            entry["mac"] = src_mac
        return entry

    def _get_target_entry(self, dst_ip, now):
        if dst_ip not in self._target_state and len(self._target_state) >= MAX_TRACKED_TARGETS:
            self._evict_oldest(self._target_state)
        return self._target_state.setdefault(dst_ip, {"events": deque()})

    def _evict_oldest(self, state_dict):
        if not state_dict:
            return
        oldest_key = None
        oldest_time = None
        for key, entry in state_dict.items():
            events = entry.get("events")
            last_seen = events[-1][0] if events else 0
            if oldest_time is None or last_seen < oldest_time:
                oldest_time = last_seen
                oldest_key = key
        if oldest_key is not None:
            state_dict.pop(oldest_key, None)

    def _record_source_target_event(self, src_ip, src_mac, dst_ip, dst_port, protocol, flags, now):
        entry = self._get_source_entry(src_ip, src_mac, now)
        entry["events"].append((now, protocol, dst_ip, dst_port, flags))
        _trim_window(entry["events"], now, SLOW_WINDOW_SECONDS)
        _trim_size(entry["events"], MAX_EVENTS_PER_SOURCE)

    def _record_target_event(self, dst_ip, src_ip, dst_port, protocol, flags, now):
        entry = self._get_target_entry(dst_ip, now)
        entry["events"].append((now, protocol, src_ip, dst_port, flags))
        _trim_window(entry["events"], now, SLOW_WINDOW_SECONDS)
        _trim_size(entry["events"], MAX_EVENTS_PER_TARGET)

        if len(self._target_recon_probes) >= MAX_TARGET_RECON_PROBES and dst_ip not in self._target_recon_probes:
            oldest = min(self._target_recon_probes.items(), key=lambda kv: kv[1][0][0] if kv[1] else 0, default=(None, None))[0]
            if oldest is not None:
                self._target_recon_probes.pop(oldest, None)
        probes = self._target_recon_probes.setdefault(dst_ip, deque())
        probes.append((now, src_ip, dst_port))
        while probes and now - probes[0][0] > DISTRIBUTED_RECON_WINDOW:
            probes.popleft()
        _trim_size(probes, MAX_TARGET_RECON_PROBES)

    def _detect_reconnaissance(self, src_ip, dst_ip, dst_port, protocol, now, alerts_out):
        entry = self._source_state.get(src_ip)
        if entry is None:
            return
        events = entry["events"]

        fast_window_events = [ev for ev in events if now - ev[0] <= WINDOW_SECONDS]
        fast_ports_by_target = {}
        fast_hosts = set()
        fast_udp_ports_by_target = {}
        mixed_ports_by_target = {}
        for ev_time, ev_proto, ev_dst_ip, ev_dst_port, ev_flags in fast_window_events:
            fast_hosts.add(ev_dst_ip)
            if ev_dst_port is not None:
                mixed_ports_by_target.setdefault(ev_dst_ip, set()).add((ev_proto, ev_dst_port))
            if ev_proto == "TCP" and ev_dst_port is not None:
                if not (ev_flags & 0x10):
                    fast_ports_by_target.setdefault(ev_dst_ip, set()).add(ev_dst_port)
            elif ev_proto == "UDP" and ev_dst_port is not None:
                fast_udp_ports_by_target.setdefault(ev_dst_ip, set()).add(ev_dst_port)

        target_syn_ports = fast_ports_by_target.get(dst_ip, set())
        if protocol == "TCP" and len(target_syn_ports) >= PORT_SCAN_THRESHOLD:
            self._emit(
                alerts_out, ("tcp_syn_scan", src_ip, dst_ip), now,
                CATEGORY_RECON, "TCP SYN Scan", "high",
                src_ip, entry.get("mac"), dst_ip, None, sorted(target_syn_ports), "TCP",
                f"Source {src_ip} sent SYN probes to {len(target_syn_ports)} distinct TCP ports on {dst_ip} within {WINDOW_SECONDS}s",
                {"window_seconds": WINDOW_SECONDS, "port_count": len(target_syn_ports)},
            )
            return

        target_udp_ports = fast_udp_ports_by_target.get(dst_ip, set())
        if protocol == "UDP" and len(target_udp_ports) >= UDP_SCAN_PORT_THRESHOLD:
            self._emit(
                alerts_out, ("udp_port_scan", src_ip, dst_ip), now,
                CATEGORY_RECON, "UDP Port Scan", "high",
                src_ip, entry.get("mac"), dst_ip, None, sorted(target_udp_ports), "UDP",
                f"Source {src_ip} probed {len(target_udp_ports)} distinct UDP ports on {dst_ip} within {WINDOW_SECONDS}s",
                {"window_seconds": WINDOW_SECONDS, "port_count": len(target_udp_ports)},
            )
            return

        mixed_ports = mixed_ports_by_target.get(dst_ip, set())
        if len(mixed_ports) >= MULTI_PORT_PROBE_THRESHOLD:
            protocols_seen = {p for p, _ in mixed_ports}
            self._emit(
                alerts_out, ("multi_port_probe", src_ip, dst_ip), now,
                CATEGORY_RECON, "Multi-Port Probing", "medium",
                src_ip, entry.get("mac"), dst_ip, None, sorted({port for _, port in mixed_ports}),
                "/".join(sorted(protocols_seen)),
                f"Source {src_ip} touched {len(mixed_ports)} distinct target ports across {len(protocols_seen)} protocol(s) on {dst_ip} within {WINDOW_SECONDS}s",
                {"window_seconds": WINDOW_SECONDS, "protocols": sorted(protocols_seen)},
            )

        if len(fast_hosts) >= HOST_SWEEP_THRESHOLD:
            self._emit(
                alerts_out, ("host_sweep", src_ip, None), now,
                CATEGORY_RECON, "Host Sweep", "medium",
                src_ip, entry.get("mac"), None, None, None, protocol,
                f"Source {src_ip} contacted {len(fast_hosts)} distinct hosts within {WINDOW_SECONDS}s",
                {"window_seconds": WINDOW_SECONDS, "host_count": len(fast_hosts)},
            )

        single_port_key = (dst_ip, dst_port)
        hits = entry["single_port_hits"].setdefault(single_port_key, deque())
        hits.append(now)
        while hits and now - hits[0] > WINDOW_SECONDS:
            hits.popleft()
        if len(entry["single_port_hits"]) > 256:
            stale = [k for k, v in entry["single_port_hits"].items() if not v or now - v[-1] > SLOW_WINDOW_SECONDS]
            for k in stale:
                entry["single_port_hits"].pop(k, None)
        if len(hits) >= REPEATED_SINGLE_PORT_THRESHOLD and len(target_syn_ports) <= 1:
            self._emit(
                alerts_out, ("repeated_single_port", src_ip, dst_ip, dst_port), now,
                CATEGORY_RECON, "Repeated Single-Port Probing", "medium",
                src_ip, entry.get("mac"), dst_ip, dst_port, None, protocol,
                f"Source {src_ip} probed port {dst_port} on {dst_ip} {len(hits)} times within {WINDOW_SECONDS}s without diversifying ports",
                {"window_seconds": WINDOW_SECONDS, "hit_count": len(hits)},
            )

        self._detect_slow_reconnaissance(src_ip, dst_ip, entry, now, alerts_out)
        self._detect_distributed_reconnaissance(dst_ip, now, alerts_out)

    def _detect_slow_reconnaissance(self, src_ip, dst_ip, entry, now, alerts_out):
        events = entry["events"]
        target_events = [ev for ev in events if ev[2] == dst_ip and ev[3] is not None]
        if len(target_events) < SLOW_SCAN_PORT_THRESHOLD:
            return
        ports = {ev[3] for ev in target_events}
        if len(ports) < SLOW_SCAN_PORT_THRESHOLD:
            return
        span = target_events[-1][0] - target_events[0][0]
        if span < SLOW_SCAN_MIN_SPAN_SECONDS:
            return
        self._emit(
            alerts_out, ("slow_recon", src_ip, dst_ip), now,
            CATEGORY_RECON, "Slow Reconnaissance", "medium",
            src_ip, entry.get("mac"), dst_ip, None, sorted(ports), None,
            f"Source {src_ip} probed {len(ports)} distinct ports on {dst_ip} spread over {int(span)}s, consistent with slow scanning",
            {"span_seconds": int(span), "port_count": len(ports)},
        )

    def _detect_distributed_reconnaissance(self, dst_ip, now, alerts_out):
        probes = self._target_recon_probes.get(dst_ip)
        if not probes:
            return
        source_ports = {}
        for _, src_ip, port in probes:
            if port is None:
                continue
            source_ports.setdefault(src_ip, set()).add(port)
        source_count = len(source_ports)
        if source_count < DISTRIBUTED_RECON_MIN_SOURCES:
            return
        total_ports = sum(len(p) for p in source_ports.values())
        if total_ports < DISTRIBUTED_RECON_MIN_TOTAL_PORTS:
            return
        avg_ports = total_ports / source_count
        if avg_ports > DISTRIBUTED_RECON_MAX_AVG_PORTS:
            return
        self._emit(
            alerts_out, ("distributed_recon", None, dst_ip), now,
            CATEGORY_RECON, "Distributed Reconnaissance", "high",
            None, None, dst_ip, None, None, None,
            f"{source_count} distinct sources probed {dst_ip} with low per-source port diversity (avg {avg_ports:.1f} ports/source) within {DISTRIBUTED_RECON_WINDOW}s, suggesting coordinated or evasive scanning",
            {
                "window_seconds": DISTRIBUTED_RECON_WINDOW,
                "source_count": source_count,
                "average_ports_per_source": round(avg_ports, 2),
                "note": "confirm correlation with correlation.py before treating as a confirmed incident",
            },
        )

    def _detect_icmp_sweep(self, src_ip, now, alerts_out):
        entry = self._source_state.get(src_ip)
        if entry is None:
            return
        recent = [ev for ev in entry["events"] if ev[1] == "ICMP" and now - ev[0] <= WINDOW_SECONDS]
        hosts = {ev[2] for ev in recent}
        if len(hosts) >= ICMP_SWEEP_HOST_THRESHOLD:
            self._emit(
                alerts_out, ("icmp_sweep", src_ip, None), now,
                CATEGORY_RECON, "ICMP Sweep", "medium",
                src_ip, entry.get("mac"), None, None, None, "ICMP",
                f"Source {src_ip} sent ICMP echo requests to {len(hosts)} distinct hosts within {WINDOW_SECONDS}s",
                {"window_seconds": WINDOW_SECONDS, "host_count": len(hosts)},
            )

    def _detect_syn_flood(self, dst_ip, now, alerts_out):
        entry = self._target_state.get(dst_ip)
        if entry is None:
            return
        recent = [ev for ev in entry["events"] if ev[1] == "TCP" and not (ev[4] & 0x10) and now - ev[0] <= FLOOD_WINDOW_SECONDS]
        if len(recent) >= SYN_FLOOD_PACKET_THRESHOLD:
            sources = {ev[2] for ev in recent}
            self._emit(
                alerts_out, ("syn_flood", None, dst_ip), now,
                CATEGORY_FLOOD, "SYN Flood-like Activity", "critical",
                None, None, dst_ip, None, None, "TCP",
                f"{len(recent)} TCP SYN packets from {len(sources)} source(s) hit {dst_ip} within {FLOOD_WINDOW_SECONDS}s",
                {"window_seconds": FLOOD_WINDOW_SECONDS, "packet_count": len(recent), "source_count": len(sources)},
            )

    def _detect_udp_flood(self, dst_ip, now, alerts_out):
        entry = self._target_state.get(dst_ip)
        if entry is None:
            return
        recent = [ev for ev in entry["events"] if ev[1] == "UDP" and now - ev[0] <= FLOOD_WINDOW_SECONDS]
        if len(recent) >= UDP_FLOOD_PACKET_THRESHOLD:
            sources = {ev[2] for ev in recent}
            self._emit(
                alerts_out, ("udp_flood", None, dst_ip), now,
                CATEGORY_FLOOD, "UDP Flood-like Activity", "critical",
                None, None, dst_ip, None, None, "UDP",
                f"{len(recent)} UDP packets from {len(sources)} source(s) hit {dst_ip} within {FLOOD_WINDOW_SECONDS}s",
                {"window_seconds": FLOOD_WINDOW_SECONDS, "packet_count": len(recent), "source_count": len(sources)},
            )

    def _detect_icmp_flood(self, dst_ip, now, alerts_out):
        entry = self._target_state.get(dst_ip)
        if entry is None:
            return
        recent = [ev for ev in entry["events"] if ev[1] == "ICMP" and now - ev[0] <= FLOOD_WINDOW_SECONDS]
        if len(recent) >= ICMP_FLOOD_PACKET_THRESHOLD:
            sources = {ev[2] for ev in recent}
            self._emit(
                alerts_out, ("icmp_flood", None, dst_ip), now,
                CATEGORY_FLOOD, "ICMP Flood-like Activity", "critical",
                None, None, dst_ip, None, None, "ICMP",
                f"{len(recent)} ICMP echo requests from {len(sources)} source(s) hit {dst_ip} within {FLOOD_WINDOW_SECONDS}s",
                {"window_seconds": FLOOD_WINDOW_SECONDS, "packet_count": len(recent), "source_count": len(sources)},
            )

    def _detect_tcp_connection_flood(self, dst_ip, src_ip, src_port, now, alerts_out):
        entry = self._target_state.get(dst_ip)
        if entry is None:
            return
        recent = [ev for ev in entry["events"] if ev[1] == "TCP" and not (ev[4] & 0x10) and now - ev[0] <= FLOOD_WINDOW_SECONDS]
        distinct_connections = {(ev[2], ev[3]) for ev in recent}
        if len(distinct_connections) >= TCP_CONN_FLOOD_THRESHOLD:
            sources = {ev[2] for ev in recent}
            self._emit(
                alerts_out, ("tcp_conn_flood", None, dst_ip), now,
                CATEGORY_FLOOD, "TCP Connection Flood-like Activity", "critical",
                None, None, dst_ip, None, None, "TCP",
                f"{len(distinct_connections)} distinct TCP connection attempts from {len(sources)} source(s) hit {dst_ip} within {FLOOD_WINDOW_SECONDS}s",
                {"window_seconds": FLOOD_WINDOW_SECONDS, "connection_count": len(distinct_connections), "source_count": len(sources)},
            )

    def _detect_traffic_burst(self, dst_ip, now, alerts_out):
        tracker = self._target_bursts.get(dst_ip)
        if tracker is None:
            if len(self._target_bursts) >= MAX_TRACKED_TARGETS:
                self._target_bursts.pop(next(iter(self._target_bursts)), None)
            tracker = _RateBurstTracker(self._epoch)
            self._target_bursts[dst_ip] = tracker
        tracker.record(now)
        ratio, current = tracker.burst_ratio()
        if ratio >= TRAFFIC_BURST_RATIO and current >= TRAFFIC_BURST_MIN_CURRENT:
            self._emit(
                alerts_out, ("traffic_burst", None, dst_ip), now,
                CATEGORY_FLOOD, "Abnormal Packet/Traffic Burst", "high",
                None, None, dst_ip, None, None, None,
                f"Traffic toward {dst_ip} spiked to {current} packets in {BURST_BUCKET_SECONDS}s, {ratio:.1f}x the recent baseline",
                {"bucket_seconds": BURST_BUCKET_SECONDS, "current_count": current, "burst_ratio": round(ratio, 2)},
            )

    def _detect_source_traffic_spike(self, src_ip, dst_ip, dst_port, protocol, now, alerts_out):
        if self._is_routine_target(src_ip, None, None):
            return
        if self._is_routine_target(dst_ip, dst_port, protocol):
            return
        tracker = self._source_bursts.get(src_ip)
        if tracker is None:
            if len(self._source_bursts) >= MAX_TRACKED_SOURCES:
                self._source_bursts.pop(next(iter(self._source_bursts)), None)
            tracker = _RateBurstTracker(self._epoch)
            self._source_bursts[src_ip] = tracker
        tracker.record(now)
        if not tracker.warmed_up(now, SOURCE_SPIKE_WARMUP_SECONDS):
            return
        persistent, ratio, current = tracker.persistent_burst_ratio(
            SOURCE_SPIKE_PERSIST_BUCKETS, SOURCE_SPIKE_RATIO, SOURCE_SPIKE_MIN_CURRENT,
        )
        if persistent:
            entry = self._source_state.get(src_ip)
            mac = entry.get("mac") if entry else None
            self._emit(
                alerts_out, ("source_spike", src_ip, None), now,
                CATEGORY_ANOMALY, "Sudden Traffic Spike", "medium",
                src_ip, mac, None, None, None, None,
                f"Source {src_ip} sustained {current} packets per {BURST_BUCKET_SECONDS}s across {SOURCE_SPIKE_PERSIST_BUCKETS} consecutive windows, {ratio:.1f}x its baseline",
                {
                    "bucket_seconds": BURST_BUCKET_SECONDS,
                    "current_count": current,
                    "burst_ratio": round(ratio, 2),
                    "persisted_windows": SOURCE_SPIKE_PERSIST_BUCKETS,
                    "warmup_seconds": SOURCE_SPIKE_WARMUP_SECONDS,
                },
                cooldown=ANOMALY_ALERT_COOLDOWN,
            )

    def _detect_unusual_port_activity(self, src_ip, dst_port, protocol, now, alerts_out):
        if dst_port is None:
            return
        profile = self._port_profiles.get(src_ip)
        if profile is None:
            if len(self._port_profiles) >= MAX_TRACKED_SOURCES:
                self._port_profiles.pop(next(iter(self._port_profiles)), None)
            profile = {"ports": {}, "total_events": 0}
            self._port_profiles[src_ip] = profile

        ports = profile["ports"]
        already_known = dst_port in ports
        profile["total_events"] += 1
        ports[dst_port] = now
        if len(ports) > UNUSUAL_PORT_MAX_PROFILE_ENTRIES:
            oldest_port = min(ports.items(), key=lambda kv: kv[1])[0]
            ports.pop(oldest_port, None)

        stale_ports = [p for p, t in ports.items() if now - t > UNUSUAL_PORT_PROFILE_WINDOW]
        for p in stale_ports:
            ports.pop(p, None)

        if already_known:
            return
        if profile["total_events"] < UNUSUAL_PORT_MIN_PROFILE_EVENTS:
            return
        if dst_port in COMMON_PORTS:
            return
        if len(ports) <= 1:
            return

        entry = self._source_state.get(src_ip)
        mac = entry.get("mac") if entry else None
        self._emit(
            alerts_out, ("unusual_port", src_ip, dst_port), now,
            CATEGORY_ANOMALY, "Unusual Port Activity", "low",
            src_ip, mac, None, dst_port, None, protocol,
            f"Source {src_ip} contacted port {dst_port}/{protocol}, which is outside its established baseline of {len(ports) - 1} ports",
            {"profile_size": len(ports), "profile_window_seconds": UNUSUAL_PORT_PROFILE_WINDOW},
        )

    def _track_handshake_state(self, src_ip, dst_ip, dst_port, flags, now):
        key = (src_ip, dst_ip, dst_port)
        is_syn_only = bool(flags & 0x02) and not bool(flags & 0x10)
        if is_syn_only:
            if key not in self._pending_handshakes and len(self._pending_handshakes) >= MAX_PENDING_HANDSHAKES:
                oldest = min(self._pending_handshakes.items(), key=lambda kv: kv[1][-1] if kv[1] else 0, default=(None, None))[0]
                if oldest is not None:
                    self._pending_handshakes.pop(oldest, None)
            attempts = self._pending_handshakes.setdefault(key, deque())
            attempts.append(now)
            while attempts and now - attempts[0] > FAILED_CONNECTION_WINDOW:
                attempts.popleft()

    def _detect_failed_connection(self, client_ip, server_ip, server_port, now, alerts_out):
        key = (client_ip, server_ip, server_port)
        attempts = self._pending_handshakes.get(key)
        if not attempts:
            return
        while attempts and now - attempts[0] > FAILED_CONNECTION_WINDOW:
            attempts.popleft()
        if len(attempts) >= FAILED_CONNECTION_THRESHOLD:
            entry = self._source_state.get(client_ip)
            mac = entry.get("mac") if entry else None
            self._emit(
                alerts_out, ("failed_connections", client_ip, server_ip, server_port), now,
                CATEGORY_ANOMALY, "Repeated Failed Connections", "medium",
                client_ip, mac, server_ip, server_port, None, "TCP",
                f"{len(attempts)} connection attempts from {client_ip} to {server_ip}:{server_port} were reset within {FAILED_CONNECTION_WINDOW}s",
                {"window_seconds": FAILED_CONNECTION_WINDOW, "attempt_count": len(attempts)},
            )
            attempts.clear()

    def _detect_abnormal_pair_pattern(self, src_ip, dst_ip, dst_port, protocol, now, alerts_out):
        if self._is_routine_target(dst_ip, dst_port, protocol):
            return
        if self._is_routine_target(src_ip, None, None):
            return

        pair_key = (src_ip, dst_ip)
        first_seen = self._known_pairs.get(pair_key)
        if first_seen is None:
            if len(self._known_pairs) >= MAX_KNOWN_PAIRS:
                oldest = min(self._known_pairs.items(), key=lambda kv: kv[1], default=(None, None))[0]
                if oldest is not None:
                    self._known_pairs.pop(oldest, None)
            self._known_pairs[pair_key] = now
            first_seen = now
        elif now - first_seen > KNOWN_PAIR_HISTORY_SECONDS:
            self._known_pairs[pair_key] = now
            first_seen = now

        if now - first_seen > NEW_PAIR_BURST_WINDOW:
            return

        entry = self._source_state.get(src_ip)
        if entry is None:
            return
        recent = [ev for ev in entry["events"] if ev[2] == dst_ip and now - ev[0] <= NEW_PAIR_BURST_WINDOW]
        if len(recent) < NEW_PAIR_BURST_THRESHOLD:
            return

        older_half = [ev for ev in recent if now - ev[0] > NEW_PAIR_SUBWINDOW_SECONDS]
        newer_half = [ev for ev in recent if now - ev[0] <= NEW_PAIR_SUBWINDOW_SECONDS]
        if len(older_half) < NEW_PAIR_SUBWINDOW_MIN_EVENTS or len(newer_half) < NEW_PAIR_SUBWINDOW_MIN_EVENTS:
            return

        self._emit(
            alerts_out, ("abnormal_pair", src_ip, dst_ip), now,
            CATEGORY_ANOMALY, "Abnormal Source-to-Target Communication Pattern", "medium",
            src_ip, entry.get("mac"), dst_ip, None, None, None,
            f"Source {src_ip} sustained {len(recent)} events toward previously-unseen destination {dst_ip} across both halves of a {NEW_PAIR_BURST_WINDOW}s window",
            {
                "window_seconds": NEW_PAIR_BURST_WINDOW,
                "event_count": len(recent),
                "subwindow_seconds": NEW_PAIR_SUBWINDOW_SECONDS,
                "subwindow_min_events": NEW_PAIR_SUBWINDOW_MIN_EVENTS,
            },
            cooldown=ANOMALY_ALERT_COOLDOWN,
        )

    def _register_ip_mac(self, ip, mac, now, alerts_out):
        mac = mac.lower()

        current = self._ip_mac_current.get(ip)
        previous_mac = None
        previous_observations = 0
        if current is None:
            self._ip_mac_current[ip] = {"mac": mac, "observations": 1, "last_seen": now}
        elif current["mac"] == mac:
            current["observations"] += 1
            current["last_seen"] = now
        else:
            previous_mac = current["mac"]
            previous_observations = current["observations"]
            self._ip_mac_current[ip] = {"mac": mac, "observations": 1, "last_seen": now}
        if len(self._ip_mac_current) > MAX_IP_MAC_ENTRIES:
            oldest = min(self._ip_mac_current.items(), key=lambda kv: kv[1]["last_seen"], default=(None, None))[0]
            if oldest is not None:
                self._ip_mac_current.pop(oldest, None)

        if len(self._ip_mac_history) >= MAX_IP_MAC_ENTRIES and ip not in self._ip_mac_history:
            oldest = min(self._ip_mac_history.items(), key=lambda kv: kv[1][-1][0] if kv[1] else 0, default=(None, None))[0]
            if oldest is not None:
                self._ip_mac_history.pop(oldest, None)
        ip_history = self._ip_mac_history.setdefault(ip, deque())
        if not ip_history or ip_history[-1][1] != mac:
            ip_history.append((now, mac))
        while ip_history and now - ip_history[0][0] > ARP_MAC_HISTORY_WINDOW:
            ip_history.popleft()
        _trim_size(ip_history, 32)

        if len(self._mac_ip_history) >= MAX_IP_MAC_ENTRIES and mac not in self._mac_ip_history:
            oldest = min(self._mac_ip_history.items(), key=lambda kv: kv[1][-1][0] if kv[1] else 0, default=(None, None))[0]
            if oldest is not None:
                self._mac_ip_history.pop(oldest, None)
        mac_history = self._mac_ip_history.setdefault(mac, deque())
        if not mac_history or mac_history[-1][1] != ip:
            mac_history.append((now, ip))
        while mac_history and now - mac_history[0][0] > ARP_MAC_HISTORY_WINDOW:
            mac_history.popleft()
        _trim_size(mac_history, 32)

        distinct_macs_for_ip = {m for _, m in ip_history}
        distinct_ips_for_mac = {i for _, i in mac_history}

        if previous_mac and previous_mac != mac:
            if previous_observations >= ARP_STABLE_OBSERVATIONS:
                self._emit(
                    alerts_out, ("ip_mac_mismatch", ip), now,
                    CATEGORY_ARP, "IP-MAC Mismatch / Possible ARP Spoofing", "high",
                    ip, mac, ip, None, None, "ARP",
                    f"IP {ip} was previously associated with MAC {previous_mac} but is now observed using {mac}",
                    {"previous_mac": previous_mac, "new_mac": mac},
                )

        if len(distinct_macs_for_ip) >= ARP_IP_MAC_CHANGE_THRESHOLD:
            self._emit(
                alerts_out, ("ip_multi_mac", ip), now,
                CATEGORY_ARP, "Same IP Associated With Changing MAC Addresses", "high",
                ip, mac, ip, None, None, "ARP",
                f"IP {ip} has been observed with {len(distinct_macs_for_ip)} distinct MAC addresses within {ARP_MAC_HISTORY_WINDOW}s",
                {"window_seconds": ARP_MAC_HISTORY_WINDOW, "mac_addresses": sorted(distinct_macs_for_ip)},
            )

        if len(distinct_ips_for_mac) >= ARP_MAC_IP_CHANGE_THRESHOLD:
            self._emit(
                alerts_out, ("mac_multi_ip", mac), now,
                CATEGORY_ARP, "Same MAC Appearing With Multiple IP Addresses", "medium",
                None, mac, None, None, None, "ARP",
                f"MAC {mac} has been observed with {len(distinct_ips_for_mac)} distinct IP addresses within {ARP_MAC_HISTORY_WINDOW}s",
                {"window_seconds": ARP_MAC_HISTORY_WINDOW, "ip_addresses": sorted(distinct_ips_for_mac)},
            )

    def _maybe_run_cleanup(self, now):
        if now - self._last_cleanup < STATE_CLEANUP_INTERVAL:
            return
        self._last_cleanup = now

        if self._active_scan is not None:
            ended_at = self._active_scan.get("ended_at")
            if ended_at is not None and now - ended_at > INTERNAL_SCAN_GRACE_SECONDS:
                self._active_scan = None

        for state_dict in (self._source_state, self._target_state):
            stale = [k for k, e in state_dict.items() if not e["events"] or now - e["events"][-1][0] > STALE_ENTRY_TTL]
            for k in stale:
                state_dict.pop(k, None)

        stale_probes = [k for k, v in self._target_recon_probes.items() if not v or now - v[-1][0] > DISTRIBUTED_RECON_WINDOW]
        for k in stale_probes:
            self._target_recon_probes.pop(k, None)

        stale_handshakes = [k for k, v in self._pending_handshakes.items() if not v or now - v[-1] > FAILED_CONNECTION_WINDOW]
        for k in stale_handshakes:
            self._pending_handshakes.pop(k, None)

        stale_pairs = [k for k, t in self._known_pairs.items() if now - t > KNOWN_PAIR_HISTORY_SECONDS]
        for k in stale_pairs:
            self._known_pairs.pop(k, None)

        stale_profiles = [k for k, p in self._port_profiles.items() if not p["ports"] or now - max(p["ports"].values()) > UNUSUAL_PORT_PROFILE_WINDOW]
        for k in stale_profiles:
            self._port_profiles.pop(k, None)

        stale_ip_mac = [k for k, v in self._ip_mac_history.items() if not v or now - v[-1][0] > ARP_MAC_HISTORY_WINDOW]
        for k in stale_ip_mac:
            self._ip_mac_history.pop(k, None)

        stale_mac_ip = [k for k, v in self._mac_ip_history.items() if not v or now - v[-1][0] > ARP_MAC_HISTORY_WINDOW]
        for k in stale_mac_ip:
            self._mac_ip_history.pop(k, None)

        if len(self._last_alert) > MAX_ALERT_KEYS:
            stale_alert_keys = [k for k, t in self._last_alert.items() if now - t > ALERT_COOLDOWN * 5]
            for k in stale_alert_keys:
                self._last_alert.pop(k, None)
