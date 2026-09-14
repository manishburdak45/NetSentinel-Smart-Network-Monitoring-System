import ipaddress
import re
import subprocess
import threading
import time

DEFAULT_DURATION = 300
IPTABLES_BIN = "iptables"
CHAIN = "INPUT"

lock = threading.Lock()
blocked_ips = {}
blocked_macs = {}

MAC_PATTERN = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
NEIGH_MAC_PATTERN = re.compile(r"lladdr\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")
LINK_ETHER_PATTERN = re.compile(r"link/ether\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")
DEFAULT_ROUTE_DEV_PATTERN = re.compile(r"\bdev\s+(\S+)")
DEFAULT_ROUTE_VIA_PATTERN = re.compile(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)")
MAC_COUNTER_PATTERN = re.compile(
    r"^\s*(\d+)\s+(\d+)\s+DROP\s+.*\bMAC\b\s+([0-9A-Fa-f:]{17})", re.MULTILINE
)

mac_module_unsupported = False


def run_command(args, timeout=5):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except Exception:
        return None


def run_iptables_command(args, timeout=5):
    try:
        result = subprocess.run(
            [IPTABLES_BIN] + args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return False, "iptables not found"
    except subprocess.TimeoutExpired:
        return False, "iptables command timed out"
    except Exception as exc:
        return False, str(exc)

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        if "Permission denied" in stderr or "Operation not permitted" in stderr:
            return False, "insufficient privileges to modify firewall rules"
        return False, stderr or "iptables command failed"
    return True, None


def validate_ip(ip):
    if not isinstance(ip, str):
        return False
    try:
        parsed = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    if not isinstance(parsed, ipaddress.IPv4Address):
        return False
    if parsed.is_multicast or parsed.is_unspecified or parsed.is_reserved:
        return False
    return str(parsed)


def validate_mac(mac):
    if not isinstance(mac, str):
        return False
    candidate = mac.strip()
    if not MAC_PATTERN.match(candidate):
        return False
    normalized = candidate.lower()
    if normalized in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return False
    first_octet = int(normalized.split(":")[0], 16)
    if first_octet & 0x01:
        return False
    return normalized


def get_default_interface():
    proc = run_command(["ip", "route", "show", "default"])
    if not proc or not proc.stdout:
        return None
    match = DEFAULT_ROUTE_DEV_PATTERN.search(proc.stdout)
    return match.group(1) if match else None


def get_default_gateway_ip():
    proc = run_command(["ip", "route", "show", "default"])
    if not proc or not proc.stdout:
        return None
    match = DEFAULT_ROUTE_VIA_PATTERN.search(proc.stdout)
    return match.group(1) if match else None


def get_own_mac(interface=None):
    iface = interface or get_default_interface()
    if not iface:
        return None
    proc = run_command(["ip", "link", "show", iface])
    if not proc or not proc.stdout:
        return None
    match = LINK_ETHER_PATTERN.search(proc.stdout)
    return match.group(1).lower() if match else None


def resolve_mac_for_ip(ip, interface=None, ping_if_missing=True):
    valid_ip = validate_ip(ip)
    if not valid_ip:
        return None

    def lookup_mac():
        args = ["ip", "neigh", "show", valid_ip]
        if interface:
            args += ["dev", interface]
        proc = run_command(args)
        if not proc or not proc.stdout:
            return None
        match = NEIGH_MAC_PATTERN.search(proc.stdout)
        return match.group(1).lower() if match else None

    mac = lookup_mac()
    if mac:
        return validate_mac(mac) or None

    if ping_if_missing:
        run_command(["ping", "-c", "1", "-W", "1", valid_ip], timeout=3)
        time.sleep(0.2)
        mac = lookup_mac()

    return validate_mac(mac) or None if mac else None


def get_gateway_mac(interface=None):
    gw_ip = get_default_gateway_ip()
    if not gw_ip:
        return None
    return resolve_mac_for_ip(gw_ip, interface=interface, ping_if_missing=True)


def is_protected_mac(mac, interface=None):
    own_mac = get_own_mac(interface)
    if own_mac and own_mac == mac:
        return "refusing to block the monitoring host's own MAC address"
    gw_mac = get_gateway_mac(interface)
    if gw_mac and gw_mac == mac:
        return "refusing to block the gateway's MAC address"
    return None


def is_ip_blocked(ip):
    valid_ip = validate_ip(ip)
    if not valid_ip:
        return False
    with lock:
        return valid_ip in blocked_ips


def block_ip(ip, duration=DEFAULT_DURATION):
    valid_ip = validate_ip(ip)
    if not valid_ip:
        return {"success": False, "ip": ip, "method": "ip", "error": "invalid IPv4 address"}

    try:
        duration = int(duration)
    except (TypeError, ValueError):
        duration = DEFAULT_DURATION
    if duration <= 0:
        duration = DEFAULT_DURATION

    with lock:
        if valid_ip in blocked_ips:
            return {"success": True, "ip": valid_ip, "method": "ip", "status": "already blocked"}

        ok, error = run_iptables_command(["-I", CHAIN, "-s", valid_ip, "-j", "DROP"])
        if not ok:
            return {"success": False, "ip": valid_ip, "method": "ip", "error": error}

        timer = threading.Timer(duration, unblock_ip, args=(valid_ip,))
        timer.daemon = True
        blocked_ips[valid_ip] = timer
        timer.start()

    return {"success": True, "ip": valid_ip, "method": "ip", "status": "blocked", "duration": duration}


def unblock_ip(ip):
    valid_ip = validate_ip(ip)
    if not valid_ip:
        return {"success": False, "ip": ip, "error": "invalid IPv4 address"}

    with lock:
        timer = blocked_ips.pop(valid_ip, None)
        if timer is not None:
            timer.cancel()

    ok, error = run_iptables_command(["-D", CHAIN, "-s", valid_ip, "-j", "DROP"])
    if not ok:
        return {"success": False, "ip": valid_ip, "error": error}

    return {"success": True, "ip": valid_ip, "status": "unblocked"}


def verify_ip_rule_present(ip):
    valid_ip = validate_ip(ip)
    if not valid_ip:
        return False
    try:
        result = subprocess.run(
            [IPTABLES_BIN, "-C", CHAIN, "-s", valid_ip, "-j", "DROP"],
            shell=False, capture_output=True, text=True, timeout=5, check=False,
        )
    except Exception:
        return False
    return result.returncode == 0


def block_selected_ips(ip_list, duration=DEFAULT_DURATION):
    if not isinstance(ip_list, (list, tuple, set)):
        return {"success": False, "error": "ip_list must be a list of IP addresses"}

    results = []
    for ip in ip_list:
        results.append(block_ip(ip, duration=duration))

    overall_success = all(r.get("success") for r in results) if results else False
    return {"success": overall_success, "results": results}


def is_mac_blocked(mac):
    valid_mac = validate_mac(mac)
    if not valid_mac:
        return False
    with lock:
        return valid_mac in blocked_macs


def block_mac(mac, source_ip=None, interface=None, duration=DEFAULT_DURATION):
    global mac_module_unsupported

    valid_mac = validate_mac(mac)
    if not valid_mac:
        return {"success": False, "mac": mac, "method": "mac", "error": "invalid MAC address"}

    try:
        duration = int(duration)
    except (TypeError, ValueError):
        duration = DEFAULT_DURATION
    if duration <= 0:
        duration = DEFAULT_DURATION

    protection_error = is_protected_mac(valid_mac, interface=interface)
    if protection_error:
        return {"success": False, "mac": valid_mac, "method": "mac", "error": protection_error}

    with lock:
        if valid_mac in blocked_macs:
            return {"success": True, "mac": valid_mac, "method": "mac", "status": "already blocked"}

        ok, error = run_iptables_command(["-I", CHAIN, "-m", "mac", "--mac-source", valid_mac, "-j", "DROP"])
        if not ok:
            lowered = (error or "").lower()
            if "no chain/target/match" in lowered or "unknown option" in lowered or "unknown arg" in lowered:
                mac_module_unsupported = True
                return {
                    "success": False,
                    "mac": valid_mac,
                    "method": "mac",
                    "error": "MAC-based blocking is not supported on this system (xt_mac / iptables mac module unavailable)",
                }
            return {"success": False, "mac": valid_mac, "method": "mac", "error": error}

        timer = threading.Timer(duration, unblock_mac, args=(valid_mac,))
        timer.daemon = True
        blocked_macs[valid_mac] = {"timer": timer, "source_ip": source_ip, "blocked_at": time.time()}
        timer.start()

    return {"success": True, "mac": valid_mac, "method": "mac", "status": "blocked", "duration": duration}


def unblock_mac(mac):
    valid_mac = validate_mac(mac)
    if not valid_mac:
        return {"success": False, "mac": mac, "error": "invalid MAC address"}

    with lock:
        entry = blocked_macs.pop(valid_mac, None)
        if entry and entry.get("timer") is not None:
            entry["timer"].cancel()

    ok, error = run_iptables_command(["-D", CHAIN, "-m", "mac", "--mac-source", valid_mac, "-j", "DROP"])
    if not ok:
        return {"success": False, "mac": valid_mac, "error": error}

    return {"success": True, "mac": valid_mac, "status": "unblocked"}


def verify_mac_rule_present(mac):
    valid_mac = validate_mac(mac)
    if not valid_mac:
        return False
    try:
        result = subprocess.run(
            [IPTABLES_BIN, "-C", CHAIN, "-m", "mac", "--mac-source", valid_mac, "-j", "DROP"],
            shell=False, capture_output=True, text=True, timeout=5, check=False,
        )
    except Exception:
        return False
    return result.returncode == 0


def get_mac_rule_hits(mac):
    valid_mac = validate_mac(mac)
    if not valid_mac:
        return None
    try:
        result = subprocess.run(
            [IPTABLES_BIN, "-L", CHAIN, "-v", "-n", "-x"],
            shell=False, capture_output=True, text=True, timeout=5, check=False,
        )
    except Exception:
        return None
    if result.returncode != 0:
        return None
    for match in MAC_COUNTER_PATTERN.finditer(result.stdout or ""):
        packet_count, byte_count, rule_mac = match.groups()
        if rule_mac.lower() == valid_mac:
            return int(packet_count)
    return None


def mac_blocking_supported():
    return not mac_module_unsupported


def resolve_and_block_source(source_ip, source_mac_hint=None, interface=None, duration=DEFAULT_DURATION):
    result = {
        "source_ip": source_ip,
        "source_mac": None,
        "method": None,
        "action": "block_requested",
        "status": "attack_ongoing",
        "verification": None,
        "duration": duration,
        "error": None,
    }

    valid_ip = validate_ip(source_ip)
    if not valid_ip:
        result["action"] = "block_failed"
        result["error"] = "invalid IPv4 address"
        return result

    mac = None
    if source_mac_hint:
        mac = validate_mac(source_mac_hint) or None
    if not mac:
        mac = resolve_mac_for_ip(valid_ip, interface=interface)

    if mac:
        result["source_mac"] = mac
        result["method"] = "mac"

        if is_mac_blocked(mac):
            result["action"] = "already_blocked"
            if verify_mac_rule_present(mac):
                result["verification"] = "traffic_stopped"
                result["status"] = "blocked_source_repeated_attempt"
            else:
                result["verification"] = "verification_failed"
                result["status"] = "attack_ongoing"
            return result

        block_result = block_mac(mac, source_ip=valid_ip, interface=interface, duration=duration)
        if not block_result.get("success"):
            result["action"] = "block_failed"
            result["status"] = "attack_ongoing"
            result["error"] = block_result.get("error")
            return result

        result["action"] = "already_blocked" if block_result.get("status") == "already blocked" else "block_applied"
        if verify_mac_rule_present(mac):
            result["verification"] = "traffic_stopped"
            result["status"] = "mitigated"
        else:
            result["verification"] = "verification_failed"
            result["status"] = "attack_ongoing"
        return result

    result["method"] = "ip"

    if is_ip_blocked(valid_ip):
        result["action"] = "already_blocked"
        if verify_ip_rule_present(valid_ip):
            result["verification"] = "traffic_stopped"
            result["status"] = "blocked_source_repeated_attempt"
        else:
            result["verification"] = "verification_failed"
            result["status"] = "attack_ongoing"
        return result

    ip_result = block_ip(valid_ip, duration=duration)
    if not ip_result.get("success"):
        result["action"] = "block_failed"
        result["status"] = "attack_ongoing"
        result["error"] = ip_result.get("error")
        return result

    result["action"] = "already_blocked" if ip_result.get("status") == "already blocked" else "block_applied"
    if verify_ip_rule_present(valid_ip):
        result["verification"] = "traffic_stopped"
        result["status"] = "mitigated"
    else:
        result["verification"] = "verification_failed"
        result["status"] = "attack_ongoing"
    return result


def get_source_block_snapshot(source_ip, source_mac=None):
    snapshot = {"blocked": False, "method": None, "verification": None}

    if source_mac:
        valid_mac = validate_mac(source_mac)
        if valid_mac and is_mac_blocked(valid_mac):
            snapshot["blocked"] = True
            snapshot["method"] = "mac"
            snapshot["verification"] = "traffic_stopped" if verify_mac_rule_present(valid_mac) else "verification_failed"
            return snapshot

    valid_ip = validate_ip(source_ip)
    if valid_ip and is_ip_blocked(valid_ip):
        snapshot["blocked"] = True
        snapshot["method"] = "ip"
        snapshot["verification"] = "traffic_stopped" if verify_ip_rule_present(valid_ip) else "verification_failed"
        return snapshot

    return snapshot
