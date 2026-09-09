import ipaddress
import re
import subprocess
import threading
import time

DEFAULT_DURATION = 300
IPTABLES_BIN = "iptables"
CHAIN = "INPUT"

# Single lock guarding both the IP-block and MAC-block bookkeeping dicts.
# NOTE: functions that acquire this lock must never call another
# lock-acquiring function while already holding it (the lock is not
# reentrant) - internal helpers below are written to respect that.
_lock = threading.Lock()
_blocked = {}       # ip  -> threading.Timer
_mac_blocked = {}   # mac -> {"timer": threading.Timer, "source_ip": str|None, "blocked_at": float}

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
_NEIGH_MAC_RE = re.compile(r"lladdr\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")
_LINK_ETHER_RE = re.compile(r"link/ether\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")
_DEFAULT_ROUTE_DEV_RE = re.compile(r"\bdev\s+(\S+)")
_DEFAULT_ROUTE_VIA_RE = re.compile(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)")
_MAC_COUNTER_RE = re.compile(
    r"^\s*(\d+)\s+(\d+)\s+DROP\s+.*\bMAC\b\s+([0-9A-Fa-f:]{17})", re.MULTILINE
)

# Cached once we learn the mac module is unavailable, to avoid repeatedly
# trying (and logging) a doomed iptables call for every alert.
_mac_module_unsupported = False


# ---------------------------------------------------------------------------
# Small process helpers
# ---------------------------------------------------------------------------

def _run(args, timeout=5):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except Exception:
        return None


def _run_iptables(args, timeout=5):
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


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

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
    if not _MAC_RE.match(candidate):
        return False
    normalized = candidate.lower()
    if normalized in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return False
    # Reject multicast/broadcast MACs (least significant bit of first octet).
    first_octet = int(normalized.split(":")[0], 16)
    if first_octet & 0x01:
        return False
    return normalized


# ---------------------------------------------------------------------------
# Local-network topology helpers (used to resolve MACs and to avoid ever
# blocking the monitoring host itself or the gateway).
# ---------------------------------------------------------------------------

def _get_default_interface():
    proc = _run(["ip", "route", "show", "default"])
    if not proc or not proc.stdout:
        return None
    match = _DEFAULT_ROUTE_DEV_RE.search(proc.stdout)
    return match.group(1) if match else None


def _get_default_gateway_ip():
    proc = _run(["ip", "route", "show", "default"])
    if not proc or not proc.stdout:
        return None
    match = _DEFAULT_ROUTE_VIA_RE.search(proc.stdout)
    return match.group(1) if match else None


def get_own_mac(interface=None):
    iface = interface or _get_default_interface()
    if not iface:
        return None
    proc = _run(["ip", "link", "show", iface])
    if not proc or not proc.stdout:
        return None
    match = _LINK_ETHER_RE.search(proc.stdout)
    return match.group(1).lower() if match else None


def resolve_mac_for_ip(ip, interface=None, ping_if_missing=True):
    """
    Resolve an IPv4 address to a MAC address using the kernel's neighbor
    (ARP) table - the appropriate Linux mechanism for local-segment MAC
    resolution. Returns None (never a guess) if the address cannot be
    resolved, which is the expected/normal outcome for a remote source that
    is not on the same local network segment.
    """
    valid_ip = validate_ip(ip)
    if not valid_ip:
        return None

    def _lookup():
        args = ["ip", "neigh", "show", valid_ip]
        if interface:
            args += ["dev", interface]
        proc = _run(args)
        if not proc or not proc.stdout:
            return None
        match = _NEIGH_MAC_RE.search(proc.stdout)
        return match.group(1).lower() if match else None

    mac = _lookup()
    if mac:
        return validate_mac(mac) or None

    if ping_if_missing:
        # A single, low-cost ARP-triggering probe. If the host is remote
        # (different subnet) this will simply fail to populate an ARP
        # entry, which is the correct, honest outcome.
        _run(["ping", "-c", "1", "-W", "1", valid_ip], timeout=3)
        time.sleep(0.2)
        mac = _lookup()

    return validate_mac(mac) or None if mac else None


def get_gateway_mac(interface=None):
    gw_ip = _get_default_gateway_ip()
    if not gw_ip:
        return None
    return resolve_mac_for_ip(gw_ip, interface=interface, ping_if_missing=True)


def _is_protected_mac(mac, interface=None):
    """Refuse to ever block the monitoring host's own MAC or the gateway's MAC."""
    own_mac = get_own_mac(interface)
    if own_mac and own_mac == mac:
        return "refusing to block the monitoring host's own MAC address"
    gw_mac = get_gateway_mac(interface)
    if gw_mac and gw_mac == mac:
        return "refusing to block the gateway's MAC address"
    return None


# ---------------------------------------------------------------------------
# IP blocking (kept for identification / fallback when no local MAC is
# available, e.g. the attacker is off-segment / remote).
# ---------------------------------------------------------------------------

def is_ip_blocked(ip):
    valid_ip = validate_ip(ip)
    if not valid_ip:
        return False
    with _lock:
        return valid_ip in _blocked


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

    with _lock:
        if valid_ip in _blocked:
            return {"success": True, "ip": valid_ip, "method": "ip", "status": "already blocked"}

        ok, error = _run_iptables(["-I", CHAIN, "-s", valid_ip, "-j", "DROP"])
        if not ok:
            return {"success": False, "ip": valid_ip, "method": "ip", "error": error}

        timer = threading.Timer(duration, unblock_ip, args=(valid_ip,))
        timer.daemon = True
        _blocked[valid_ip] = timer
        timer.start()

    return {"success": True, "ip": valid_ip, "method": "ip", "status": "blocked", "duration": duration}


def unblock_ip(ip):
    valid_ip = validate_ip(ip)
    if not valid_ip:
        return {"success": False, "ip": ip, "error": "invalid IPv4 address"}

    with _lock:
        timer = _blocked.pop(valid_ip, None)
        if timer is not None:
            timer.cancel()

    ok, error = _run_iptables(["-D", CHAIN, "-s", valid_ip, "-j", "DROP"])
    if not ok:
        return {"success": False, "ip": valid_ip, "error": error}

    return {"success": True, "ip": valid_ip, "status": "unblocked"}


def verify_ip_rule_present(ip):
    """Read-only check that the DROP rule for this IP is actually installed."""
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


# ---------------------------------------------------------------------------
# MAC blocking - the primary blocking workflow for local-network sources.
# Uses the existing iptables architecture (xt_mac match) rather than
# introducing a separate/parallel firewall system.
# ---------------------------------------------------------------------------

def is_mac_blocked(mac):
    valid_mac = validate_mac(mac)
    if not valid_mac:
        return False
    with _lock:
        return valid_mac in _mac_blocked


def block_mac(mac, source_ip=None, interface=None, duration=DEFAULT_DURATION):
    global _mac_module_unsupported

    valid_mac = validate_mac(mac)
    if not valid_mac:
        return {"success": False, "mac": mac, "method": "mac", "error": "invalid MAC address"}

    try:
        duration = int(duration)
    except (TypeError, ValueError):
        duration = DEFAULT_DURATION
    if duration <= 0:
        duration = DEFAULT_DURATION

    protection_error = _is_protected_mac(valid_mac, interface=interface)
    if protection_error:
        return {"success": False, "mac": valid_mac, "method": "mac", "error": protection_error}

    with _lock:
        if valid_mac in _mac_blocked:
            return {"success": True, "mac": valid_mac, "method": "mac", "status": "already blocked"}

        ok, error = _run_iptables(["-I", CHAIN, "-m", "mac", "--mac-source", valid_mac, "-j", "DROP"])
        if not ok:
            lowered = (error or "").lower()
            if "no chain/target/match" in lowered or "unknown option" in lowered or "unknown arg" in lowered:
                _mac_module_unsupported = True
                return {
                    "success": False,
                    "mac": valid_mac,
                    "method": "mac",
                    "error": "MAC-based blocking is not supported on this system (xt_mac / iptables mac module unavailable)",
                }
            return {"success": False, "mac": valid_mac, "method": "mac", "error": error}

        timer = threading.Timer(duration, unblock_mac, args=(valid_mac,))
        timer.daemon = True
        _mac_blocked[valid_mac] = {"timer": timer, "source_ip": source_ip, "blocked_at": time.time()}
        timer.start()

    return {"success": True, "mac": valid_mac, "method": "mac", "status": "blocked", "duration": duration}


def unblock_mac(mac):
    valid_mac = validate_mac(mac)
    if not valid_mac:
        return {"success": False, "mac": mac, "error": "invalid MAC address"}

    with _lock:
        entry = _mac_blocked.pop(valid_mac, None)
        if entry and entry.get("timer") is not None:
            entry["timer"].cancel()

    ok, error = _run_iptables(["-D", CHAIN, "-m", "mac", "--mac-source", valid_mac, "-j", "DROP"])
    if not ok:
        return {"success": False, "mac": valid_mac, "error": error}

    return {"success": True, "mac": valid_mac, "status": "unblocked"}


def verify_mac_rule_present(mac):
    """Read-only check (iptables -C) that the DROP rule for this MAC exists."""
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
    """
    Returns the packet counter for the MAC DROP rule, or None if the rule
    can't be found/read. A rising counter confirms the firewall is actively
    intercepting matching traffic before it reaches the protected service
    (the strongest verification signal available without instrumenting the
    protected service itself).
    """
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
    for match in _MAC_COUNTER_RE.finditer(result.stdout or ""):
        pkts, _bytes, rule_mac = match.groups()
        if rule_mac.lower() == valid_mac:
            return int(pkts)
    return None


def mac_blocking_supported():
    return not _mac_module_unsupported


# ---------------------------------------------------------------------------
# Orchestration: resolve -> block -> verify, used by the response API route.
# ---------------------------------------------------------------------------

def resolve_and_block_source(source_ip, source_mac_hint=None, interface=None, duration=DEFAULT_DURATION):
    """
    High-level workflow:
      1. Validate the source IP.
      2. Resolve it to a MAC address (local segment only) unless a
         pre-validated MAC was already supplied.
      3. If a MAC is available: check whether it's already blocked; if not,
         apply the MAC block; verify the rule is actually present.
      4. If no MAC is available (remote source): fall back to IP blocking,
         which is the only mechanism that can apply to an off-segment host.

    Returns a structured dict using the response states:
      action:       block_requested | block_applied | block_failed | already_blocked
      status:       mitigated | attack_ongoing | blocked_source_repeated_attempt
      verification: traffic_stopped | verification_failed | None
    """
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

    # No local MAC available: the source is off-segment/remote (or the
    # segment doesn't expose ARP-resolvable MACs). Do not invent one - fall
    # back to IP-based blocking, the only mechanism that can reach it.
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
    """
    Read-only status lookup used to annotate every incoming alert without
    ever hiding it and without performing any new blocking action or ARP
    probing. Reports on sources that have already been blocked via
    resolve_and_block_source / block_mac / block_ip.
    """
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
