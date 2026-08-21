import os
import re
import socket
import shutil
import subprocess
import threading
import time
import ipaddress
import xml.etree.ElementTree as ET
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from scapy.all import AsyncSniffer, ARP, Ether, IP, TCP, srp
    _SCAPY_AVAILABLE = True
except Exception:
    _SCAPY_AVAILABLE = False

WINDOW_SECONDS = 8
PORT_SCAN_THRESHOLD = 12
HOST_SWEEP_THRESHOLD = 10
ALERT_COOLDOWN = 60
MAX_TRACKED_SOURCES = 500
MAX_EVENTS_PER_SOURCE = 2000
MAX_ALERT_KEYS = 1000
STALE_SOURCE_TTL = WINDOW_SECONDS * 5

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
        self._state = {}
        self._last_alert = {}

    def start(self):
        with self._lock:
            if self._running:
                return
            try:
                sniffer = AsyncSniffer(
                    iface=self.interface,
                    filter="tcp",
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
            self._state.clear()
            self._last_alert.clear()

        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass

    def _handle_packet(self, packet):
        try:
            if not packet.haslayer(IP) or not packet.haslayer(TCP):
                return
            tcp_layer = packet[TCP]
            flags = int(tcp_layer.flags)
            if not (flags & 0x02) or (flags & 0x10):
                return

            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            dst_port = int(tcp_layer.dport)
            src_mac = None
            if packet.haslayer(Ether):
                src_mac = packet[Ether].src

            self._record_and_check(src_ip, src_mac, dst_ip, dst_port, time.time())
        except Exception:
            return

    def _record_and_check(self, src_ip, src_mac, dst_ip, dst_port, now):
        alert_payload = None

        with self._lock:
            if not self._running:
                return

            if src_ip not in self._state and len(self._state) >= MAX_TRACKED_SOURCES:
                self._evict_stale_sources(now, force_one=True)

            entry = self._state.setdefault(src_ip, {"events": deque(), "mac": src_mac})
            if src_mac:
                entry["mac"] = src_mac
            entry["events"].append((now, dst_ip, dst_port))

            while entry["events"] and now - entry["events"][0][0] > WINDOW_SECONDS:
                entry["events"].popleft()
            while len(entry["events"]) > MAX_EVENTS_PER_SOURCE:
                entry["events"].popleft()

            port_map = {}
            host_set = set()
            for _, d_ip, d_port in entry["events"]:
                host_set.add(d_ip)
                port_map.setdefault(d_ip, set()).add(d_port)

            for d_ip, ports in port_map.items():
                if len(ports) >= PORT_SCAN_THRESHOLD:
                    key = (src_ip, d_ip, "port_scan")
                    last = self._last_alert.get(key, 0)
                    if now - last >= ALERT_COOLDOWN:
                        self._last_alert[key] = now
                        alert_payload = {
                            "source_ip": src_ip,
                            "source_mac": entry.get("mac"),
                            "target_ip": d_ip,
                            "target_ports": sorted(ports),
                            "detection_type": "TCP SYN Port Scan",
                            "severity": "high",
                            "details": f"{len(ports)} distinct destination ports probed on {d_ip} from {src_ip} within {WINDOW_SECONDS}s",
                        }
                    break

            if alert_payload is None and len(host_set) >= HOST_SWEEP_THRESHOLD:
                key = (src_ip, "sweep")
                last = self._last_alert.get(key, 0)
                if now - last >= ALERT_COOLDOWN:
                    self._last_alert[key] = now
                    alert_payload = {
                        "source_ip": src_ip,
                        "source_mac": entry.get("mac"),
                        "target_ip": None,
                        "target_ports": None,
                        "detection_type": "Network Reconnaissance Sweep",
                        "severity": "medium",
                        "details": f"{len(host_set)} distinct hosts probed from {src_ip} within {WINDOW_SECONDS}s",
                    }

            self._evict_stale_sources(now, force_one=False)
            if len(self._last_alert) > MAX_ALERT_KEYS:
                stale_keys = [k for k, t in self._last_alert.items() if now - t > ALERT_COOLDOWN * 5]
                for k in stale_keys:
                    self._last_alert.pop(k, None)

        if alert_payload:
            try:
                self.alert_callback(alert_payload)
            except Exception:
                pass

    def _evict_stale_sources(self, now, force_one):
        stale = [
            src for src, entry in self._state.items()
            if not entry["events"] or now - entry["events"][-1][0] > STALE_SOURCE_TTL
        ]
        for src in stale:
            self._state.pop(src, None)

        if force_one and len(self._state) >= MAX_TRACKED_SOURCES and self._state:
            oldest_src = min(
                self._state.items(),
                key=lambda kv: kv[1]["events"][0][0] if kv[1]["events"] else 0,
            )[0]
            self._state.pop(oldest_src, None)
