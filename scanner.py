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
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

WINDOW_SECONDS = 8
PORT_SCAN_THRESHOLD = 12
HOST_SWEEP_THRESHOLD = 10

HOST_DISCOVERY_WINDOW_SECONDS = 6

FLOOD_WINDOW_SECONDS = 3
SYN_FLOOD_RATE_THRESHOLD = 40
FLOOD_MAX_DISTINCT_PORTS = 2
FLOOD_MIN_COMPLETION_RATIO = 0.05

FAILED_CONN_WINDOW_SECONDS = 30
FAILED_CONN_ATTEMPTS_THRESHOLD = 6
FAILED_CONN_MIN_RST = 4

MAC_MAPPING_STABLE_SECONDS = 30
MAC_CHANGE_COOLDOWN = 300
MAX_IP_MAC_ENTRIES = 2000
IP_MAC_MAP_TTL = 3600

ALERT_COOLDOWN = 60
MAX_TRACKED_SOURCES = 500
MAX_EVENTS_PER_SOURCE = 2000
MAX_ALERT_KEYS = 1000
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


def run_command(args, timeout=5):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except Exception:
        return None


def get_default_interface():
    proc = run_command(["ip", "route", "show", "default"])
    if not proc or not proc.stdout:
        return None
    match = re.search(r"\bdev\s+(\S+)", proc.stdout)
    return match.group(1) if match else None


def get_interface_ipv4(interface):
    proc = run_command(["ip", "-o", "-4", "addr", "show", "dev", interface])
    if not proc or not proc.stdout:
        return None, None
    match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", proc.stdout)
    if not match:
        return None, None
    return match.group(1), int(match.group(2))


def get_local_network_info():
    interface = get_default_interface()
    if not interface:
        raise RuntimeError("no active default network interface found")
    ip_addr, prefix = get_interface_ipv4(interface)
    if not ip_addr or prefix is None:
        raise RuntimeError(f"no IPv4 address found on interface {interface}")
    network = ipaddress.ip_network(f"{ip_addr}/{prefix}", strict=False)
    return interface, str(network)


def resolve_hostname(ip):
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(1.5)
        name, aliases, addresses = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def ping_host(ip, timeout=1):
    proc = run_command(["ping", "-c", "1", "-W", str(timeout), ip], timeout=timeout + 2)
    return bool(proc and proc.returncode == 0)


def get_mac_for_ip(ip):
    proc = run_command(["ip", "neigh", "show", ip])
    if not proc or not proc.stdout:
        return None
    match = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", proc.stdout)
    return match.group(1).lower() if match else None


def check_port(ip, port, timeout=0.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False


def quick_port_scan(ip, ports):
    open_ports = []
    services = []
    for port in ports:
        if check_port(ip, port):
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
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy is required for device discovery")

    try:
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        answered, unanswered = srp(arp_request, timeout=3, retry=1, verbose=False)
    except PermissionError as exc:
        raise PermissionError("elevated privileges required for ARP discovery") from exc
    except OSError as exc:
        raise RuntimeError(f"ARP discovery failed: {exc}") from exc

    devices = {}
    for sent, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        devices[ip] = {
            "ip": ip,
            "mac": mac,
            "hostname": resolve_hostname(ip),
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
        scan_results = run_nmap_multi_host(ips)

    fallback_ips = []
    for ip in ips:
        scanned = scan_results.get(ip)
        if nmap_result_is_usable(scanned):
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
        fill_fallback_port_data(devices, fallback_ips)

    return list(devices.values())


def nmap_result_is_usable(result):
    if not result:
        return False
    if result.get("open_ports"):
        return True
    if result.get("os"):
        return True
    if result.get("online"):
        return True
    return False


def fill_fallback_port_data(devices, ips):
    max_workers = max(1, min(MAX_FALLBACK_WORKERS, len(ips)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(quick_port_scan, ip, DISCOVERY_FALLBACK_PORTS): ip
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


def run_nmap_multi_host(ips, timeout=None):
    if timeout is None:
        timeout = max(60, min(300, 20 * len(ips)))
    args = [
        "nmap", "-Pn", "-sV", "-O", "-T4",
        "--host-timeout", NMAP_MULTI_HOST_TIMEOUT,
        "--max-retries", "1",
        "-oX", "-",
    ] + ips
    proc = run_command(args, timeout=timeout)
    if not proc or not proc.stdout:
        return {}
    return parse_nmap_output_multi(proc.stdout)


def parse_nmap_host_element(host):
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


def parse_nmap_output_multi(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}

    results = {}
    for host in root.findall("host"):
        parsed = parse_nmap_host_element(host)
        if parsed and parsed.get("ip"):
            results[parsed["ip"]] = parsed
    return results


def parse_nmap_output(xml_text, ip):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    host = root.find("host")
    if host is None:
        return None

    parsed = parse_nmap_host_element(host)
    if parsed is None:
        return None
    parsed["ip"] = ip
    return parsed


def fallback_scan(ip):
    online = ping_host(ip)
    open_ports, services = quick_port_scan(ip, COMMON_PORTS)
    if open_ports:
        online = True
    return {
        "ip": ip,
        "mac": get_mac_for_ip(ip),
        "hostname": resolve_hostname(ip),
        "online": online,
        "open_ports": open_ports,
        "services": services,
        "os": None,
    }


def run_nmap(ip):
    if not shutil.which("nmap"):
        return None
    args = ["nmap", "-Pn", "-sV", "-O", "-T4", "--host-timeout", "30s", "-oX", "-", ip]
    proc = run_command(args, timeout=60)
    if not proc or not proc.stdout:
        return None
    return proc.stdout


def scan_target(target):
    network = ipaddress.ip_network(target, strict=False)
    if network.num_addresses != 1:
        raise ValueError("scan_target requires a single IP address")
    ip = str(network.network_address)

    xml_output = run_nmap(ip)
    if xml_output:
        parsed = parse_nmap_output(xml_output, ip)
        if nmap_result_is_usable(parsed):
            if not parsed.get("mac"):
                parsed["mac"] = get_mac_for_ip(ip)
            if not parsed.get("hostname"):
                parsed["hostname"] = resolve_hostname(ip)
            return parsed

    return fallback_scan(ip)


class NetworkMonitor:

    def __init__(self, interface, alert_callback):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy is required for network monitoring")
        if not interface:
            raise ValueError("a valid network interface is required")
        if not callable(alert_callback):
            raise ValueError("alert_callback must be callable")

        self.interface = interface
        self.alert_callback = alert_callback
        self.lock = threading.Lock()
        self.sniffer = None
        self.running = False
        self.state = {}
        self.last_alert = {}
        self.ip_mac_map = {}

        self.alert_queue = queue.Queue(maxsize=2000)
        self.alert_worker = None

    def start(self):
        with self.lock:
            if self.running:
                return
            try:
                sniffer = AsyncSniffer(
                    iface=self.interface,
                    filter="tcp or arp or icmp",
                    prn=self.handle_packet,
                    store=False,
                )
                sniffer.start()
            except PermissionError as exc:
                raise PermissionError("elevated privileges required for packet capture") from exc
            except Exception as exc:
                raise RuntimeError(f"failed to start packet capture: {exc}") from exc

            self.sniffer = sniffer
            self.running = True

            worker = threading.Thread(target=self.alert_worker_loop, daemon=True)
            worker.start()
            self.alert_worker = worker

    def stop(self):
        with self.lock:
            if not self.running:
                return
            sniffer = self.sniffer
            worker = self.alert_worker
            self.sniffer = None
            self.alert_worker = None
            self.running = False
            self.state.clear()
            self.last_alert.clear()
            self.ip_mac_map.clear()

        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass

        if worker is not None:
            try:
                self.alert_queue.put(None, timeout=5)
            except queue.Full:
                pass
            worker.join(timeout=10)

    def handle_packet(self, packet):
        try:
            now = time.time()
            if packet.haslayer(ARP):
                self.process_arp(packet, now)
            elif packet.haslayer(IP) and packet.haslayer(TCP):
                self.process_tcp(packet, now)
            elif packet.haslayer(IP) and packet.haslayer(ICMP):
                self.process_icmp(packet, now)
        except Exception:
            return

    def process_tcp(self, packet, now):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        flags = int(tcp_layer.flags)
        syn = bool(flags & 0x02)
        ack = bool(flags & 0x10)
        rst = bool(flags & 0x04)
        src_mac = packet[Ether].src if packet.haslayer(Ether) else None

        if syn and not ack and not rst:
            self.record_event(ip_layer.src, src_mac, "syn", ip_layer.dst, int(tcp_layer.dport), now)
        elif syn and ack:
            self.record_event(ip_layer.dst, None, "synack", ip_layer.src, int(tcp_layer.sport), now)
        elif rst:
            self.record_event(ip_layer.dst, None, "rst", ip_layer.src, int(tcp_layer.sport), now)

    def process_icmp(self, packet, now):
        icmp_layer = packet[ICMP]
        try:
            icmp_type = int(icmp_layer.type)
        except Exception:
            return
        if icmp_type != 8:
            return
        ip_layer = packet[IP]
        src_mac = packet[Ether].src if packet.haslayer(Ether) else None
        self.record_event(ip_layer.src, src_mac, "icmp", ip_layer.dst, None, now)

    def process_arp(self, packet, now):
        arp_layer = packet[ARP]
        psrc, pdst = arp_layer.psrc, arp_layer.pdst
        hwsrc = arp_layer.hwsrc
        src_mac = packet[Ether].src if packet.haslayer(Ether) else hwsrc
        try:
            op = int(arp_layer.op)
        except Exception:
            op = None

        mac_alert = None
        with self.lock:
            if not self.running:
                return
            mac_alert = self.check_mac_mapping_locked(psrc, hwsrc, now)
        if mac_alert:
            self.queue_alert(mac_alert)

        if op == 1 and pdst and pdst != psrc:
            self.record_event(psrc, src_mac, "arp_probe", pdst, None, now)

    def record_event(self, src_ip, src_mac, kind, target_ip, target_port, now):
        alerts_to_emit = []
        with self.lock:
            if not self.running:
                return
            entry = self.get_source_entry_locked(src_ip, src_mac, now)

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

            self.trim_entry_locked(entry, now)
            alerts_to_emit = self.evaluate_source_locked(src_ip, entry, now)
            self.housekeeping_locked(now)

        for alert in alerts_to_emit:
            self.queue_alert(alert)

    def get_source_entry_locked(self, src_ip, src_mac, now):
        if src_ip not in self.state and len(self.state) >= MAX_TRACKED_SOURCES:
            self.evict_stale_sources(now, force_one=True)
        entry = self.state.setdefault(src_ip, {
            "mac": src_mac,
            "syn_events": deque(),
            "synack_received": deque(),
            "rst_received": deque(),
            "icmp_targets": deque(),
            "arp_targets": deque(),
        })
        if src_mac:
            entry["mac"] = src_mac
        return entry

    def trim_entry_locked(self, entry, now):
        for field_name in ("syn_events", "synack_received", "rst_received"):
            event_queue = entry[field_name]
            while event_queue and now - event_queue[0][0] > RETENTION_SECONDS:
                event_queue.popleft()
            while len(event_queue) > MAX_EVENTS_PER_SOURCE:
                event_queue.popleft()
        for field_name in ("icmp_targets", "arp_targets"):
            event_queue = entry[field_name]
            while event_queue and now - event_queue[0][0] > RETENTION_SECONDS:
                event_queue.popleft()
            while len(event_queue) > MAX_EVENTS_PER_SOURCE:
                event_queue.popleft()

    def evaluate_source_locked(self, src_ip, entry, now):
        results = []
        for check in (
            self.check_port_scan,
            self.check_host_sweep,
            self.check_host_discovery_probe,
            self.check_syn_flood,
            self.check_failed_connections,
        ):
            result = check(src_ip, entry, now)
            if result:
                results.append(result)
        return results

    def cooldown_ok(self, key, now, cooldown=None):
        if cooldown is None:
            cooldown = ALERT_COOLDOWN
        last = self.last_alert.get(key, 0)
        if now - last < cooldown:
            return False
        self.last_alert[key] = now
        return True

    def queue_alert(self, alert):
        try:
            self.alert_queue.put_nowait(alert)
        except queue.Full:
            try:
                self.alert_queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self.alert_queue.put_nowait(alert)
            except queue.Full:
                pass

    def alert_worker_loop(self):
        while True:
            alert = self.alert_queue.get()
            try:
                if alert is None:
                    return
                try:
                    self.alert_callback(alert)
                except Exception:
                    pass
            finally:
                self.alert_queue.task_done()

    def check_port_scan(self, src_ip, entry, now):
        recent = [e for e in entry["syn_events"] if now - e[0] <= WINDOW_SECONDS]
        port_map = {}
        for event_time, dest_ip, dest_port in recent:
            port_map.setdefault(dest_ip, set()).add(dest_port)

        for dest_ip, ports in port_map.items():
            if len(ports) < PORT_SCAN_THRESHOLD:
                continue
            key = (src_ip, dest_ip, "port_scan")
            if not self.cooldown_ok(key, now):
                continue
            target_mac = self.ip_mac_map.get(dest_ip, {}).get("mac")
            pair_events = [event_time for event_time, dip, port in recent if dip == dest_ip]
            return {
                "category": "Reconnaissance",
                "attack_type": "Port Scan",
                "source_ip": src_ip,
                "source_mac": entry.get("mac"),
                "target_ip": dest_ip,
                "target_mac": target_mac,
                "source_port": None,
                "destination_port": sorted(ports),
                "protocol": "tcp",
                "packet_count": len(pair_events),
                "event_count": len(ports),
                "ports_scanned_count": len(ports),
                "hosts_contacted_count": None,
                "evidence": (
                    f"{len(ports)} distinct destination ports probed on {dest_ip} from {src_ip} "
                    f"within {WINDOW_SECONDS}s using TCP SYN packets"
                ),
                "first_seen": min(pair_events) if pair_events else now,
                "last_seen": now,
                "severity": "high",
                "related_techniques": ["TCP SYN Port Scan"],
            }
        return None

    def check_host_sweep(self, src_ip, entry, now):
        icmp_recent = [e for e in entry["icmp_targets"] if now - e[0] <= WINDOW_SECONDS]
        arp_recent = [e for e in entry["arp_targets"] if now - e[0] <= WINDOW_SECONDS]
        hosts = {d for t, d in icmp_recent} | {d for t, d in arp_recent}

        if len(hosts) < HOST_SWEEP_THRESHOLD:
            return None
        key = (src_ip, "host_sweep")
        if not self.cooldown_ok(key, now):
            return None

        if icmp_recent and arp_recent:
            protocol = "icmp+arp"
        elif icmp_recent:
            protocol = "icmp"
        else:
            protocol = "arp"

        all_times = [t for t, d in icmp_recent] + [t for t, d in arp_recent]
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

    def check_host_discovery_probe(self, src_ip, entry, now):
        icmp_recent = [e for e in entry["icmp_targets"] if now - e[0] <= HOST_DISCOVERY_WINDOW_SECONDS]
        if not icmp_recent:
            return None
        syn_recent = [e for e in entry["syn_events"] if now - e[0] <= HOST_DISCOVERY_WINDOW_SECONDS]
        if not syn_recent:
            return None

        icmp_by_host = {}
        for event_time, dest_ip in icmp_recent:
            icmp_by_host.setdefault(dest_ip, []).append(event_time)

        for dest_ip, icmp_times in icmp_by_host.items():
            syn_to_host = [e for e in syn_recent if e[1] == dest_ip]
            if not syn_to_host:
                continue
            ports = {p for t, dip, p in syn_to_host}

            if len(ports) >= PORT_SCAN_THRESHOLD:
                continue

            key = (src_ip, dest_ip, "host_discovery_probe")
            if not self.cooldown_ok(key, now):
                continue

            target_mac = self.ip_mac_map.get(dest_ip, {}).get("mac")
            syn_times = [t for t, dip, p in syn_to_host]
            all_times = icmp_times + syn_times
            return {
                "category": "Reconnaissance",
                "attack_type": "Host Discovery Probe",
                "source_ip": src_ip,
                "source_mac": entry.get("mac"),
                "target_ip": dest_ip,
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
                    f"{sorted(ports)} on {dest_ip} from {src_ip} within "
                    f"{HOST_DISCOVERY_WINDOW_SECONDS}s - matches the default Nmap "
                    f"host-discovery ('ping scan') probe pattern"
                ),
                "first_seen": min(all_times),
                "last_seen": now,
                "severity": "medium",
                "related_techniques": ["Nmap Host Discovery / Ping Scan"],
            }
        return None

    def check_syn_flood(self, src_ip, entry, now):
        flood_recent = [e for e in entry["syn_events"] if now - e[0] <= FLOOD_WINDOW_SECONDS]
        by_host = {}
        for event_time, dest_ip, dest_port in flood_recent:
            host_info = by_host.setdefault(dest_ip, {"count": 0, "ports": set(), "times": []})
            host_info["count"] += 1
            host_info["ports"].add(dest_port)
            host_info["times"].append(event_time)

        for dest_ip, host_info in by_host.items():
            if host_info["count"] < SYN_FLOOD_RATE_THRESHOLD or len(host_info["ports"]) > FLOOD_MAX_DISTINCT_PORTS:
                continue

            established = [
                e for e in entry["synack_received"]
                if e[1] == dest_ip and now - e[0] <= FLOOD_WINDOW_SECONDS
            ]
            completion_ratio = (len(established) / host_info["count"]) if host_info["count"] else 0
            if completion_ratio > FLOOD_MIN_COMPLETION_RATIO:
                continue

            key = (src_ip, dest_ip, "syn_flood")
            if not self.cooldown_ok(key, now):
                continue
            target_mac = self.ip_mac_map.get(dest_ip, {}).get("mac")
            return {
                "category": "DoS / Flood",
                "attack_type": "SYN / Connection Flood",
                "source_ip": src_ip,
                "source_mac": entry.get("mac"),
                "target_ip": dest_ip,
                "target_mac": target_mac,
                "source_port": None,
                "destination_port": sorted(host_info["ports"]),
                "protocol": "tcp",
                "packet_count": host_info["count"],
                "event_count": host_info["count"],
                "ports_scanned_count": len(host_info["ports"]),
                "hosts_contacted_count": None,
                "evidence": (
                    f"{host_info['count']} SYN packets from {src_ip} to {dest_ip} on port(s) "
                    f"{sorted(host_info['ports'])} within {FLOOD_WINDOW_SECONDS}s; only "
                    f"{len(established)} completed handshake(s) observed"
                ),
                "first_seen": min(host_info["times"]),
                "last_seen": now,
                "severity": "critical",
                "related_techniques": ["High-rate SYN flood"],
            }
        return None

    def check_failed_connections(self, src_ip, entry, now):
        long_window = [e for e in entry["syn_events"] if now - e[0] <= FAILED_CONN_WINDOW_SECONDS]
        by_pair = {}
        for event_time, dest_ip, dest_port in long_window:
            by_pair.setdefault((dest_ip, dest_port), []).append(event_time)

        for (dest_ip, dest_port), times in by_pair.items():
            attempt_count = len(times)
            if attempt_count < FAILED_CONN_ATTEMPTS_THRESHOLD:
                continue
            if attempt_count >= SYN_FLOOD_RATE_THRESHOLD:
                continue

            rst_count = len([
                1 for event_time, dip, port in entry["rst_received"]
                if dip == dest_ip and port == dest_port and now - event_time <= FAILED_CONN_WINDOW_SECONDS
            ])
            synack_count = len([
                1 for event_time, dip, port in entry["synack_received"]
                if dip == dest_ip and port == dest_port and now - event_time <= FAILED_CONN_WINDOW_SECONDS
            ])

            mostly_failed = rst_count >= FAILED_CONN_MIN_RST or (synack_count == 0 and rst_count >= 1)
            if not mostly_failed:
                continue

            key = (src_ip, dest_ip, dest_port, "failed_conn")
            if not self.cooldown_ok(key, now):
                continue
            target_mac = self.ip_mac_map.get(dest_ip, {}).get("mac")
            return {
                "category": "Anomaly",
                "attack_type": "Repeated Failed Connections",
                "source_ip": src_ip,
                "source_mac": entry.get("mac"),
                "target_ip": dest_ip,
                "target_mac": target_mac,
                "source_port": None,
                "destination_port": dest_port,
                "protocol": "tcp",
                "packet_count": attempt_count,
                "event_count": attempt_count,
                "ports_scanned_count": 1,
                "hosts_contacted_count": None,
                "evidence": (
                    f"{attempt_count} connection attempts from {src_ip} to {dest_ip}:{dest_port} "
                    f"within {FAILED_CONN_WINDOW_SECONDS}s, {rst_count} rejected and "
                    f"{synack_count} completed"
                ),
                "first_seen": min(times),
                "last_seen": now,
                "severity": "low",
                "related_techniques": ["Repeated Failed Connections"],
            }
        return None

    def check_mac_mapping_locked(self, ip, mac, now):
        if not ip or not mac:
            return None
        mac = mac.lower()
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return None

        prev = self.ip_mac_map.get(ip)
        if prev is None:
            self.ip_mac_map[ip] = {"mac": mac, "first_seen": now, "last_seen": now}
            return None

        if prev["mac"] == mac:
            prev["last_seen"] = now
            return None

        age = now - prev["first_seen"]
        old_mac = prev["mac"]
        self.ip_mac_map[ip] = {"mac": mac, "first_seen": now, "last_seen": now}
        if age < MAC_MAPPING_STABLE_SECONDS:
            return None

        key = ("mac_change", ip)
        if not self.cooldown_ok(key, now, cooldown=MAC_CHANGE_COOLDOWN):
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

    def housekeeping_locked(self, now):
        self.evict_stale_sources(now, force_one=False)
        if len(self.last_alert) > MAX_ALERT_KEYS:
            stale_keys = [key for key, alert_time in self.last_alert.items() if now - alert_time > ALERT_COOLDOWN * 5]
            for stale_key in stale_keys:
                self.last_alert.pop(stale_key, None)
        if len(self.ip_mac_map) > MAX_IP_MAC_ENTRIES:
            stale_ips = [
                ip for ip, info in self.ip_mac_map.items()
                if now - info["last_seen"] > IP_MAC_MAP_TTL
            ]
            for ip in stale_ips:
                self.ip_mac_map.pop(ip, None)

    def evict_stale_sources(self, now, force_one):
        def last_activity(entry):
            candidates = [event_queue[-1][0] for event_queue in (
                entry["syn_events"], entry["synack_received"], entry["rst_received"],
                entry["icmp_targets"], entry["arp_targets"],
            ) if event_queue]
            return max(candidates) if candidates else 0

        stale = [src for src, entry in self.state.items() if now - last_activity(entry) > STALE_SOURCE_TTL]
        for src in stale:
            self.state.pop(src, None)

        if force_one and len(self.state) >= MAX_TRACKED_SOURCES and self.state:
            oldest_src = min(self.state.items(), key=lambda item: last_activity(item[1]))[0]
            self.state.pop(oldest_src, None)
