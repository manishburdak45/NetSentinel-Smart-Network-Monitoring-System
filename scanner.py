import os
import re
import socket
import shutil
import subprocess
import threading
import time
import queue
import ipaddress
import xml.etree.ElementTree as ET
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from scapy.all import AsyncSniffer, ARP, Ether, IP, TCP, ICMP, srp
    _SCAPY_AVAILABLE = True
except Exception:
    _SCAPY_AVAILABLE = False

# ---------------------------------------------------------------------------
# Detection thresholds (all configurable here, no external config file).
# ---------------------------------------------------------------------------

# Short window used for port-scan and flood-rate style checks.
WINDOW_SECONDS = 8
# Existing port-scan rule: distinct destination ports on one target within WINDOW_SECONDS.
PORT_SCAN_THRESHOLD = 12
# Host-sweep rule: distinct hosts probed via ICMP/ARP discovery within WINDOW_SECONDS.
HOST_SWEEP_THRESHOLD = 10

# Host-discovery-probe rule: Nmap's default "ping scan" sends an ICMP echo
# request plus a TCP SYN/ACK probe to a target before deciding whether to run
# a full port scan. If the target never responds, Nmap reports it as down and
# never sends the full port scan - so the Port Scan rule's PORT_SCAN_THRESHOLD
# is never reached even though a real scan happened. This window is short
# because the discovery probes for a single target are sent back-to-back.
HOST_DISCOVERY_WINDOW_SECONDS = 6

# SYN / connection flood: a *very* short, high-rate window focused on a single
# target and a small number of ports. This is intentionally much shorter and
# stricter than the port-scan window so a normal multi-port Nmap scan (many
# ports, moderate per-port rate) is never misclassified as a flood.
FLOOD_WINDOW_SECONDS = 3
SYN_FLOOD_RATE_THRESHOLD = 40
FLOOD_MAX_DISTINCT_PORTS = 2
FLOOD_MIN_COMPLETION_RATIO = 0.05

# Repeated failed connections: longer window, low volume, but conservative -
# requires actual observed rejections (RSTs), not just repeated attempts, to
# avoid flagging normal application retry behavior.
FAILED_CONN_WINDOW_SECONDS = 30
FAILED_CONN_ATTEMPTS_THRESHOLD = 6
FAILED_CONN_MIN_RST = 4

# IP-MAC mapping change: only alert once a mapping has been stable for a
# while, and only once per IP per cooldown period, to avoid flagging normal
# ARP refreshes, DHCP lease churn, or a device's first appearance.
MAC_MAPPING_STABLE_SECONDS = 30
MAC_CHANGE_COOLDOWN = 300
MAX_IP_MAC_ENTRIES = 2000
IP_MAC_MAP_TTL = 3600

# General bookkeeping.
ALERT_COOLDOWN = 60
MAX_TRACKED_SOURCES = 500
MAX_EVENTS_PER_SOURCE = 2000
MAX_ALERT_KEYS = 1000
# Deques are trimmed to the longest window any rule needs.
RETENTION_SECONDS = max(WINDOW_SECONDS, FAILED_CONN_WINDOW_SECONDS)
STALE_SOURCE_TTL = RETENTION_SECONDS * 3

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


class NetworkMonitor:
    """
    RAM-only packet monitor. Every produced alert dict carries a `category`
    and `attack_type` (plus rich evidence fields) so app.py can correlate
    related alerts from the same attack into a single incident, and so the
    frontend can eventually show full detail on click.

    Detection rules implemented here:
      1. Port Scan            (existing rule, kept)
      2. Host Sweep           (existing rule, now driven by ICMP/ARP discovery
                                evidence instead of TCP-only host counting)
      3. SYN / Connection Flood   (new - high rate, single/near-single port)
      4. Repeated Failed Connections (new - conservative, requires observed RSTs)
      5. IP-MAC Mapping Change     (new - ARP-derived, debounced)
    """

    def __init__(self, interface, alert_callback):
        if not _SCAPY_AVAILABLE:
            raise RuntimeError("scapy is required for network monitoring")
        if not interface:
            raise ValueError("a valid network interface is required")
        if not callable(alert_callback):
            raise ValueError("alert_callback must be callable")

        self.interface = interface
        self.alert_callback = alert_callback
        self._lock = threading.Lock()
        self._sniffer = None
        self._running = False
        self._state = {}          # src_ip -> per-source tracking entry
        self._last_alert = {}     # cooldown key -> last-fired timestamp
        self._ip_mac_map = {}     # ip -> {"mac": ..., "first_seen": ..., "last_seen": ...}

        # Alerts are handed off to a dedicated worker thread instead of being
        # invoked directly from the packet-capture callback. alert_callback
        # (app.add_alert) checks/verifies firewall block state, which runs
        # real subprocess calls (iptables); running that synchronously inside
        # _handle_packet blocked the sniffer from processing the next packet
        # until it returned, which is what made normal traffic look "slow"
        # once the blocking feature started producing alerts. The queue is
        # bounded so a stuck callback can't grow memory unbounded either.
        self._alert_queue = queue.Queue(maxsize=2000)
        self._alert_worker = None

    def start(self):
        with self._lock:
            if self._running:
                return
            try:
                # Widened from "tcp" to also capture ARP (host discovery /
                # IP-MAC mapping) and ICMP (host discovery) traffic needed by
                # the new rules. Port-scan/flood/failed-connection logic still
                # only looks at TCP.
                sniffer = AsyncSniffer(
                    iface=self.interface,
                    filter="tcp or arp or icmp",
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

            worker = threading.Thread(target=self._alert_worker_loop, daemon=True)
            worker.start()
            self._alert_worker = worker

    def stop(self):
        with self._lock:
            if not self._running:
                return
            sniffer = self._sniffer
            worker = self._alert_worker
            self._sniffer = None
            self._alert_worker = None
            self._running = False
            self._state.clear()
            self._last_alert.clear()
            self._ip_mac_map.clear()

        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass

        # Packet capture is already stopped above, so no new alerts can be
        # enqueued from here on. Do NOT discard what's already queued -
        # append the sentinel *after* it so the worker keeps pulling and
        # processing every pending alert (via alert_callback) and only
        # exits once it reaches the sentinel. This can briefly block this
        # (non-capture) thread if the queue is momentarily full, but never
        # blocks the packet-capture thread, which has already stopped.
        if worker is not None:
            try:
                self._alert_queue.put(None, timeout=5)
            except queue.Full:
                # Worker is presumably wedged in an unusually slow
                # callback; don't hang shutdown forever waiting for room.
                pass
            worker.join(timeout=10)

    # -- packet dispatch -----------------------------------------------

    def _handle_packet(self, packet):
        try:
            now = time.time()
            if packet.haslayer(ARP):
                self._process_arp(packet, now)
            elif packet.haslayer(IP) and packet.haslayer(TCP):
                self._process_tcp(packet, now)
            elif packet.haslayer(IP) and packet.haslayer(ICMP):
                self._process_icmp(packet, now)
        except Exception:
            return

    def _process_tcp(self, packet, now):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        flags = int(tcp_layer.flags)
        syn = bool(flags & 0x02)
        ack = bool(flags & 0x10)
        rst = bool(flags & 0x04)
        src_mac = packet[Ether].src if packet.haslayer(Ether) else None

        if syn and not ack and not rst:
            # Pure SYN: a connection attempt. The attacker is the one opening
            # the connection.
            self._ingest(ip_layer.src, src_mac, "syn", ip_layer.dst, int(tcp_layer.dport), now)
        elif syn and ack:
            # SYN-ACK response: sent by the target back to the original
            # attacker/client. Used as a "completed handshake" signal to tell
            # reconnaissance (many ports, some open) apart from a flood
            # (many SYNs, almost nothing completes).
            self._ingest(ip_layer.dst, None, "synack", ip_layer.src, int(tcp_layer.sport), now)
        elif rst:
            # RST: heuristically treated as the target rejecting/aborting a
            # connection back toward the original attacker. This is a
            # simplification (a client can also RST its own connection), but
            # combined with a minimum-count threshold it is conservative
            # enough to avoid flagging normal traffic.
            self._ingest(ip_layer.dst, None, "rst", ip_layer.src, int(tcp_layer.sport), now)

    def _process_icmp(self, packet, now):
        icmp_layer = packet[ICMP]
        try:
            icmp_type = int(icmp_layer.type)
        except Exception:
            return
        if icmp_type != 8:  # echo-request only (host discovery ping)
            return
        ip_layer = packet[IP]
        src_mac = packet[Ether].src if packet.haslayer(Ether) else None
        self._ingest(ip_layer.src, src_mac, "icmp", ip_layer.dst, None, now)

    def _process_arp(self, packet, now):
        arp_layer = packet[ARP]
        psrc, pdst = arp_layer.psrc, arp_layer.pdst
        hwsrc = arp_layer.hwsrc
        src_mac = packet[Ether].src if packet.haslayer(Ether) else hwsrc
        try:
            op = int(arp_layer.op)
        except Exception:
            op = None

        # Every ARP packet (request or reply) advertises the sender's own
        # IP-MAC pairing. Use this to maintain a mapping table and catch
        # drift, regardless of request/reply type.
        mac_alert = None
        with self._lock:
            if not self._running:
                return
            mac_alert = self._check_mac_mapping_locked(psrc, hwsrc, now)
        if mac_alert:
            self._safe_emit(mac_alert)

        # A "who-has" request (op == 1) for a real target (not gratuitous,
        # i.e. pdst != psrc) is a host-discovery probe.
        if op == 1 and pdst and pdst != psrc:
            self._ingest(psrc, src_mac, "arp_probe", pdst, None, now)

    # -- shared ingestion / evaluation -----------------------------------

    def _ingest(self, src_ip, src_mac, kind, target_ip, target_port, now):
        alerts_to_emit = []
        with self._lock:
            if not self._running:
                return
            entry = self._get_entry_locked(src_ip, src_mac, now)

            if kind == "syn":
                entry["syn_events"].append((now, target_ip, target_port))
            elif kind == "synack":
                entry["synack_received"].append((now, target_ip, target_port))
            elif kind == "rst":
                entry["rst_received"].append((now, target_ip, target_port))
            elif kind == "icmp":
                entry["icmp_targets"].append((now, target_ip))
            elif kind == "arp_probe":
                entry["arp_targets"].append((now, target_ip))

            self._trim_entry_locked(entry, now)
            alerts_to_emit = self._evaluate_source_locked(src_ip, entry, now)
            self._housekeeping_locked(now)

        for alert in alerts_to_emit:
            self._safe_emit(alert)

    def _get_entry_locked(self, src_ip, src_mac, now):
        if src_ip not in self._state and len(self._state) >= MAX_TRACKED_SOURCES:
            self._evict_stale_sources(now, force_one=True)
        entry = self._state.setdefault(src_ip, {
            "mac": src_mac,
            "syn_events": deque(),        # (ts, dst_ip, dst_port) - connection attempts
            "synack_received": deque(),   # (ts, dst_ip, dst_port) - completed handshakes
            "rst_received": deque(),      # (ts, dst_ip, dst_port) - rejections/resets
            "icmp_targets": deque(),      # (ts, dst_ip) - ICMP echo-request targets
            "arp_targets": deque(),       # (ts, dst_ip) - ARP who-has targets
        })
        if src_mac:
            entry["mac"] = src_mac
        return entry

    def _trim_entry_locked(self, entry, now):
        for key in ("syn_events", "synack_received", "rst_received"):
            dq = entry[key]
            while dq and now - dq[0][0] > RETENTION_SECONDS:
                dq.popleft()
            while len(dq) > MAX_EVENTS_PER_SOURCE:
                dq.popleft()
        for key in ("icmp_targets", "arp_targets"):
            dq = entry[key]
            while dq and now - dq[0][0] > RETENTION_SECONDS:
                dq.popleft()
            while len(dq) > MAX_EVENTS_PER_SOURCE:
                dq.popleft()

    def _evaluate_source_locked(self, src_ip, entry, now):
        results = []
        for check in (
            self._check_port_scan,
            self._check_host_sweep,
            self._check_host_discovery_probe,
            self._check_syn_flood,
            self._check_failed_connections,
        ):
            result = check(src_ip, entry, now)
            if result:
                results.append(result)
        return results

    def _cooldown_ok(self, key, now, cooldown=None):
        if cooldown is None:
            cooldown = ALERT_COOLDOWN
        last = self._last_alert.get(key, 0)
        if now - last < cooldown:
            return False
        self._last_alert[key] = now
        return True

    def _safe_emit(self, alert):
        # Hand off to the background worker instead of calling
        # alert_callback() here - this method runs on the packet-capture
        # thread and must return immediately (see __init__ comment).
        try:
            self._alert_queue.put_nowait(alert)
        except queue.Full:
            # Consumer is falling behind (e.g. a slow firewall check) -
            # drop the oldest queued alert rather than blocking capture or
            # growing the queue without bound.
            try:
                self._alert_queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self._alert_queue.put_nowait(alert)
            except queue.Full:
                pass

    def _alert_worker_loop(self):
        while True:
            alert = self._alert_queue.get()
            try:
                if alert is None:
                    return
                try:
                    self.alert_callback(alert)
                except Exception:
                    pass
            finally:
                self._alert_queue.task_done()

    # -- rule 1: port scan (existing rule, preserved) --------------------

    def _check_port_scan(self, src_ip, entry, now):
        recent = [e for e in entry["syn_events"] if now - e[0] <= WINDOW_SECONDS]
        port_map = {}
        for t, d_ip, d_port in recent:
            port_map.setdefault(d_ip, set()).add(d_port)

        for d_ip, ports in port_map.items():
            if len(ports) < PORT_SCAN_THRESHOLD:
                continue
            key = (src_ip, d_ip, "port_scan")
            if not self._cooldown_ok(key, now):
                continue
            target_mac = self._ip_mac_map.get(d_ip, {}).get("mac")
            pair_events = [t for t, dip, _ in recent if dip == d_ip]
            return {
                "category": "Reconnaissance",
                "attack_type": "Port Scan",
                "source_ip": src_ip,
                "source_mac": entry.get("mac"),
                "target_ip": d_ip,
                "target_mac": target_mac,
                "source_port": None,
                "destination_port": sorted(ports),
                "protocol": "tcp",
                "packet_count": len(pair_events),
                "event_count": len(ports),
                "ports_scanned_count": len(ports),
                "hosts_contacted_count": None,
                "evidence": (
                    f"{len(ports)} distinct destination ports probed on {d_ip} from {src_ip} "
                    f"within {WINDOW_SECONDS}s using TCP SYN packets"
                ),
                "first_seen": min(pair_events) if pair_events else now,
                "last_seen": now,
                "severity": "high",
                "related_techniques": ["TCP SYN Port Scan"],
            }
        return None

    # -- rule 2: host sweep (now ICMP/ARP driven) -------------------------

    def _check_host_sweep(self, src_ip, entry, now):
        icmp_recent = [e for e in entry["icmp_targets"] if now - e[0] <= WINDOW_SECONDS]
        arp_recent = [e for e in entry["arp_targets"] if now - e[0] <= WINDOW_SECONDS]
        hosts = {d for _, d in icmp_recent} | {d for _, d in arp_recent}

        if len(hosts) < HOST_SWEEP_THRESHOLD:
            return None
        key = (src_ip, "host_sweep")
        if not self._cooldown_ok(key, now):
            return None

        if icmp_recent and arp_recent:
            protocol = "icmp+arp"
        elif icmp_recent:
            protocol = "icmp"
        else:
            protocol = "arp"

        all_times = [t for t, _ in icmp_recent] + [t for t, _ in arp_recent]
        return {
            "category": "Reconnaissance",
            "attack_type": "Host Sweep",
            "source_ip": src_ip,
            "source_mac": entry.get("mac"),
            "target_ip": None,
            "target_mac": None,
            "source_port": None,
            "destination_port": None,
            "protocol": protocol,
            "packet_count": len(icmp_recent) + len(arp_recent),
            "event_count": len(hosts),
            "ports_scanned_count": None,
            "hosts_contacted_count": len(hosts),
            "evidence": (
                f"{len(hosts)} distinct hosts probed from {src_ip} within {WINDOW_SECONDS}s "
                f"({len(icmp_recent)} ICMP echo requests, {len(arp_recent)} ARP discovery probes)"
            ),
            "first_seen": min(all_times) if all_times else now,
            "last_seen": now,
            "severity": "medium",
            "related_techniques": ["ICMP Host Discovery", "ARP Host Discovery"],
        }

    # -- rule 2b: host discovery probe (new) ------------------------------
    #
    # Nmap's default behaviour (e.g. plain `nmap <ip>`) is to first send a
    # small, fixed set of host-discovery probes - typically an ICMP echo
    # request plus a TCP SYN/ACK probe to one or two "likely open" ports
    # (80/443) - before deciding whether the host is up. Only if the host
    # responds does Nmap proceed to the full port scan that the existing
    # Port Scan rule (rule 1) detects. Against a host that never responds,
    # Nmap reports it as down and stops after those few probes, so rule 1's
    # PORT_SCAN_THRESHOLD (many distinct ports) is never reached even though
    # a real scan occurred. This rule catches that case by looking for the
    # ICMP+TCP combination itself, rather than counting ports, so it does
    # not depend on the full scan completing and is not tied to any
    # specific source or destination IP.
    def _check_host_discovery_probe(self, src_ip, entry, now):
        icmp_recent = [e for e in entry["icmp_targets"] if now - e[0] <= HOST_DISCOVERY_WINDOW_SECONDS]
        if not icmp_recent:
            return None
        syn_recent = [e for e in entry["syn_events"] if now - e[0] <= HOST_DISCOVERY_WINDOW_SECONDS]
        if not syn_recent:
            return None

        icmp_by_host = {}
        for t, d_ip in icmp_recent:
            icmp_by_host.setdefault(d_ip, []).append(t)

        for d_ip, icmp_times in icmp_by_host.items():
            syn_to_host = [e for e in syn_recent if e[1] == d_ip]
            if not syn_to_host:
                continue
            ports = {p for _, _, p in syn_to_host}

            # A full port scan against this host is already reported by
            # rule 1 - don't also raise this lighter-weight alert for it.
            if len(ports) >= PORT_SCAN_THRESHOLD:
                continue

            key = (src_ip, d_ip, "host_discovery_probe")
            if not self._cooldown_ok(key, now):
                continue

            target_mac = self._ip_mac_map.get(d_ip, {}).get("mac")
            syn_times = [t for t, _, _ in syn_to_host]
            all_times = icmp_times + syn_times
            return {
                "category": "Reconnaissance",
                "attack_type": "Host Discovery Probe",
                "source_ip": src_ip,
                "source_mac": entry.get("mac"),
                "target_ip": d_ip,
                "target_mac": target_mac,
                "source_port": None,
                "destination_port": sorted(ports),
                "protocol": "icmp+tcp",
                "packet_count": len(icmp_times) + len(syn_times),
                "event_count": len(icmp_times) + len(syn_times),
                "ports_scanned_count": len(ports),
                "hosts_contacted_count": None,
                "evidence": (
                    f"ICMP echo request combined with TCP SYN probe(s) to port(s) "
                    f"{sorted(ports)} on {d_ip} from {src_ip} within "
                    f"{HOST_DISCOVERY_WINDOW_SECONDS}s - matches the default Nmap "
                    f"host-discovery ('ping scan') probe pattern"
                ),
                "first_seen": min(all_times),
                "last_seen": now,
                "severity": "medium",
                "related_techniques": ["Nmap Host Discovery / Ping Scan"],
            }
        return None

    # -- rule 3: SYN / connection flood (new) -----------------------------

    def _check_syn_flood(self, src_ip, entry, now):
        flood_recent = [e for e in entry["syn_events"] if now - e[0] <= FLOOD_WINDOW_SECONDS]
        by_host = {}
        for t, d_ip, d_port in flood_recent:
            info = by_host.setdefault(d_ip, {"count": 0, "ports": set(), "times": []})
            info["count"] += 1
            info["ports"].add(d_port)
            info["times"].append(t)

        for d_ip, info in by_host.items():
            # Distinguish from reconnaissance: a flood hits very few ports
            # extremely fast; a scan spreads across many ports.
            if info["count"] < SYN_FLOOD_RATE_THRESHOLD or len(info["ports"]) > FLOOD_MAX_DISTINCT_PORTS:
                continue

            established = [
                e for e in entry["synack_received"]
                if e[1] == d_ip and now - e[0] <= FLOOD_WINDOW_SECONDS
            ]
            completion_ratio = (len(established) / info["count"]) if info["count"] else 0
            if completion_ratio > FLOOD_MIN_COMPLETION_RATIO:
                # Plenty of completed handshakes - looks like real traffic,
                # not a flood. Skip.
                continue

            key = (src_ip, d_ip, "syn_flood")
            if not self._cooldown_ok(key, now):
                continue
            target_mac = self._ip_mac_map.get(d_ip, {}).get("mac")
            return {
                "category": "DoS / Flood",
                "attack_type": "SYN / Connection Flood",
                "source_ip": src_ip,
                "source_mac": entry.get("mac"),
                "target_ip": d_ip,
                "target_mac": target_mac,
                "source_port": None,
                "destination_port": sorted(info["ports"]),
                "protocol": "tcp",
                "packet_count": info["count"],
                "event_count": info["count"],
                "ports_scanned_count": len(info["ports"]),
                "hosts_contacted_count": None,
                "evidence": (
                    f"{info['count']} SYN packets from {src_ip} to {d_ip} on port(s) "
                    f"{sorted(info['ports'])} within {FLOOD_WINDOW_SECONDS}s; only "
                    f"{len(established)} completed handshake(s) observed"
                ),
                "first_seen": min(info["times"]),
                "last_seen": now,
                "severity": "critical",
                "related_techniques": ["High-rate SYN flood"],
            }
        return None

    # -- rule 4: repeated failed connections (new, conservative) ----------

    def _check_failed_connections(self, src_ip, entry, now):
        long_window = [e for e in entry["syn_events"] if now - e[0] <= FAILED_CONN_WINDOW_SECONDS]
        by_pair = {}
        for t, d_ip, d_port in long_window:
            by_pair.setdefault((d_ip, d_port), []).append(t)

        for (d_ip, d_port), times in by_pair.items():
            attempt_count = len(times)
            if attempt_count < FAILED_CONN_ATTEMPTS_THRESHOLD:
                continue
            # Very high-rate cases are better explained (and already reported)
            # as a SYN flood - don't double-classify them here.
            if attempt_count >= SYN_FLOOD_RATE_THRESHOLD:
                continue

            rst_count = len([
                1 for t2, dip, dport in entry["rst_received"]
                if dip == d_ip and dport == d_port and now - t2 <= FAILED_CONN_WINDOW_SECONDS
            ])
            synack_count = len([
                1 for t2, dip, dport in entry["synack_received"]
                if dip == d_ip and dport == d_port and now - t2 <= FAILED_CONN_WINDOW_SECONDS
            ])

            # Conservative: require actual observed rejections, not just
            # repeated attempts, so normal application retry logic (which
            # usually eventually succeeds, or is talking to a live service)
            # does not get flagged.
            mostly_failed = rst_count >= FAILED_CONN_MIN_RST or (synack_count == 0 and rst_count >= 1)
            if not mostly_failed:
                continue

            key = (src_ip, d_ip, d_port, "failed_conn")
            if not self._cooldown_ok(key, now):
                continue
            target_mac = self._ip_mac_map.get(d_ip, {}).get("mac")
            return {
                "category": "Anomaly",
                "attack_type": "Repeated Failed Connections",
                "source_ip": src_ip,
                "source_mac": entry.get("mac"),
                "target_ip": d_ip,
                "target_mac": target_mac,
                "source_port": None,
                "destination_port": d_port,
                "protocol": "tcp",
                "packet_count": attempt_count,
                "event_count": attempt_count,
                "ports_scanned_count": 1,
                "hosts_contacted_count": None,
                "evidence": (
                    f"{attempt_count} connection attempts from {src_ip} to {d_ip}:{d_port} "
                    f"within {FAILED_CONN_WINDOW_SECONDS}s, {rst_count} rejected and "
                    f"{synack_count} completed"
                ),
                "first_seen": min(times),
                "last_seen": now,
                "severity": "low",
                "related_techniques": ["Repeated Failed Connections"],
            }
        return None

    # -- rule 5: IP-MAC mapping change (new) ------------------------------

    def _check_mac_mapping_locked(self, ip, mac, now):
        if not ip or not mac:
            return None
        mac = mac.lower()
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return None

        prev = self._ip_mac_map.get(ip)
        if prev is None:
            self._ip_mac_map[ip] = {"mac": mac, "first_seen": now, "last_seen": now}
            return None

        if prev["mac"] == mac:
            prev["last_seen"] = now
            return None

        # Mapping changed. Only alert if the previous mapping had been
        # stable for a while - otherwise this is likely just the normal
        # settling period when a device first joins the network.
        age = now - prev["first_seen"]
        old_mac = prev["mac"]
        self._ip_mac_map[ip] = {"mac": mac, "first_seen": now, "last_seen": now}
        if age < MAC_MAPPING_STABLE_SECONDS:
            return None

        key = ("mac_change", ip)
        if not self._cooldown_ok(key, now, cooldown=MAC_CHANGE_COOLDOWN):
            return None

        return {
            "category": "MAC / ARP",
            "attack_type": "IP-MAC Mapping Change",
            "source_ip": ip,
            "source_mac": mac,
            "target_ip": None,
            "target_mac": None,
            "source_port": None,
            "destination_port": None,
            "protocol": "arp",
            "packet_count": 1,
            "event_count": 1,
            "ports_scanned_count": None,
            "hosts_contacted_count": None,
            "evidence": (
                f"IP {ip} was mapped to MAC {old_mac} for {age:.0f}s, now observed "
                f"with MAC {mac}"
            ),
            "first_seen": now,
            "last_seen": now,
            "severity": "medium",
            "related_techniques": ["IP-MAC Mapping Change"],
        }

    # -- housekeeping ------------------------------------------------------

    def _housekeeping_locked(self, now):
        self._evict_stale_sources(now, force_one=False)
        if len(self._last_alert) > MAX_ALERT_KEYS:
            stale_keys = [k for k, t in self._last_alert.items() if now - t > ALERT_COOLDOWN * 5]
            for k in stale_keys:
                self._last_alert.pop(k, None)
        if len(self._ip_mac_map) > MAX_IP_MAC_ENTRIES:
            stale_ips = [
                ip for ip, info in self._ip_mac_map.items()
                if now - info["last_seen"] > IP_MAC_MAP_TTL
            ]
            for ip in stale_ips:
                self._ip_mac_map.pop(ip, None)

    def _evict_stale_sources(self, now, force_one):
        def last_activity(entry):
            candidates = [dq[-1][0] for dq in (
                entry["syn_events"], entry["synack_received"], entry["rst_received"],
                entry["icmp_targets"], entry["arp_targets"],
            ) if dq]
            return max(candidates) if candidates else 0

        stale = [src for src, entry in self._state.items() if now - last_activity(entry) > STALE_SOURCE_TTL]
        for src in stale:
            self._state.pop(src, None)

        if force_one and len(self._state) >= MAX_TRACKED_SOURCES and self._state:
            oldest_src = min(self._state.items(), key=lambda kv: last_activity(kv[1]))[0]
            self._state.pop(oldest_src, None)
