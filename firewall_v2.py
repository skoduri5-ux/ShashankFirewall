
#!/usr/bin/env python3
import sys
print("PYTHON:", sys.executable)
"""
ShashFirewall v2.0 — Dual-Engine Firewall
Author: shash / SHAshank61

Engine 1: Packet Filtering Firewall
  - Stateless, checks headers only (src/dst IP, port, protocol, flags)
  - ACL rule engine: ALLOW / DENY / LOG rules evaluated top-down
  - ICMP flood guard, port/protocol whitelisting

Engine 2: Stateful Inspection Firewall
  - Tracks full TCP connection lifecycle: SYN → ESTABLISHED → FIN/RST → CLOSED
  - Rejects packets that don't match a known connection state
  - Detects: SYN flood, half-open connection exhaustion, out-of-state packets
  - Connection table with TTL-based cleanup

Active Countermeasures (same as v1):
  - iptables block on confirmed attacker
  - RST flood back at attacker
  - Tarpit

Dashboard: Flask on :5000
"""

import os, sys, time, json, socket, logging, threading, subprocess
from datetime import datetime
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Set, List, Tuple, Optional

# ─── Enums & Constants ────────────────────────────────────────────────────────

class Action(Enum):
    ALLOW = "ALLOW"
    DENY  = "DENY"
    LOG   = "LOG"

class Proto(Enum):
    TCP  = "TCP"
    UDP  = "UDP"
    ICMP = "ICMP"
    ANY  = "ANY"

class TCPState(Enum):
    SYN_SENT    = "SYN_SENT"      # We saw SYN from client
    SYN_RCVD    = "SYN_RCVD"      # We saw SYN+ACK from server
    ESTABLISHED = "ESTABLISHED"   # Full handshake complete
    FIN_WAIT    = "FIN_WAIT"      # FIN seen, closing
    CLOSED      = "CLOSED"        # RST or complete close

# Connection TTLs in seconds
STATE_TTL = {
    TCPState.SYN_SENT:    10,
    TCPState.SYN_RCVD:    10,
    TCPState.ESTABLISHED: 3600,
    TCPState.FIN_WAIT:    30,
    TCPState.CLOSED:      5,
}

# Attack thresholds
PORT_SCAN_THRESHOLD    = 10
SYN_FLOOD_THRESHOLD    = 100   # SYNs/sec
BRUTE_FORCE_THRESHOLD  = 5     # hits/min on auth ports
HALF_OPEN_THRESHOLD    = 50    # max half-open connections from one IP
ICMP_FLOOD_THRESHOLD   = 30    # ICMP packets/sec
DETECTION_WINDOW       = 60
RST_VOLLEY             = 20

AUTH_PORTS  = {22, 21, 3389, 5900, 23, 25, 110, 143, 8080}
LOG_FILE    = "firewall_v2.log"

# ─── Trusted IPs — NEVER blocked, never counted toward attack thresholds ──────
# Add your admin IPs, loopback, WSL bridge, LAN gateway here.
TRUSTED_IPS: Set[str] = {
    "127.0.0.1",          # loopback
    "::1",                # IPv6 loopback
    "192.168.141.1",      # WSL host (Windows side) — update to match your setup
    "192.168.141.105",    # your WSL IP
    "10.0.0.1",           # common LAN gateway
}

def is_trusted(ip: str) -> bool:
    return ip in TRUSTED_IPS

# ─── ACL Rules (Packet Filtering Engine) ──────────────────────────────────────

@dataclass
class ACLRule:
    """
    A single stateless packet-filtering rule.
    None means wildcard (match anything).
    Rules are evaluated top-down; first match wins.
    """
    action:   Action
    proto:    Proto           = Proto.ANY
    src_ip:   Optional[str]  = None   # exact IP or None=any
    src_port: Optional[int]  = None
    dst_ip:   Optional[str]  = None
    dst_port: Optional[int]  = None
    flags:    Optional[int]  = None   # TCP flag mask (e.g. 0x02 = SYN)
    comment:  str            = ""

    def matches(self, src_ip: str, dst_ip: str, src_port: int,
                dst_port: int, proto: str, flags: int) -> bool:
        if self.proto != Proto.ANY and self.proto.value != proto:
            return False
        if self.src_ip   and self.src_ip   != src_ip:   return False
        if self.dst_ip   and self.dst_ip   != dst_ip:   return False
        if self.src_port and self.src_port != src_port: return False
        if self.dst_port and self.dst_port != dst_port: return False
        if self.flags    is not None and not (flags & self.flags): return False
        return True

# Default ACL ruleset — edit freely
DEFAULT_RULES: List[ACLRule] = [
    ACLRule(Action.DENY,  comment="Block RFC1918 spoofed src on external iface (example)",
            src_ip="10.0.0.0"),

    ACLRule(Action.ALLOW, Proto.TCP,  dst_port=22,   comment="Allow SSH inbound"),
    ACLRule(Action.ALLOW, Proto.TCP,  dst_port=80,   comment="Allow HTTP"),
    ACLRule(Action.ALLOW, Proto.TCP,  dst_port=443,  comment="Allow HTTPS"),
    ACLRule(Action.ALLOW, Proto.UDP,  dst_port=53,   comment="Allow DNS"),
    ACLRule(Action.ALLOW, Proto.UDP,  dst_port=123,  comment="Allow NTP"),   # ← add here
    ACLRule(Action.ALLOW, Proto.ICMP, comment="Allow ICMP (rate-limited separately)"),

    ACLRule(Action.LOG,   comment="Log unmatched traffic"),
    ACLRule(Action.DENY,  comment="Default deny"),
]

# ─── Connection Tracking (Stateful Engine) ─────────────────────────────────────

ConnKey = Tuple[str, int, str, int, str]   # (src_ip, sport, dst_ip, dport, proto)

@dataclass
class ConnEntry:
    key:       ConnKey
    state:     TCPState
    created:   float = field(default_factory=time.time)
    updated:   float = field(default_factory=time.time)
    pkts_in:   int = 0
    pkts_out:  int = 0

    @property
    def age(self) -> float:
        return time.time() - self.created

    @property
    def expired(self) -> bool:
        ttl = STATE_TTL.get(self.state, 60)
        return (time.time() - self.updated) > ttl

class ConnectionTable:
    """Thread-safe TCP connection state tracker."""
    def __init__(self):
        self._table: Dict[ConnKey, ConnEntry] = {}
        self._lock  = threading.Lock()

    def _normalize(self, src_ip, sport, dst_ip, dport, proto) -> Tuple[ConnKey, bool]:
        """Return canonical key and whether packet is from client side."""
        fwd = (src_ip, sport, dst_ip, dport, proto)
        rev = (dst_ip, dport, src_ip, sport, proto)
        with self._lock:
            if fwd in self._table: return fwd, True
            if rev in self._table: return rev, False
        return fwd, True

    def process(self, src_ip: str, sport: int, dst_ip: str, dport: int,
                proto: str, flags: int) -> Tuple[bool, str]:
        """
        Returns (allow: bool, reason: str).
        Updates or creates connection entries for TCP.
        For UDP: allows if no explicit block.
        """
        if proto != "TCP":
            return True, "UDP/ICMP pass-through"

        key, is_client = self._normalize(src_ip, sport, dst_ip, dport, proto)

        SYN = bool(flags & 0x02)
        ACK = bool(flags & 0x10)
        FIN = bool(flags & 0x01)
        RST = bool(flags & 0x04)

        with self._lock:
            entry = self._table.get(key)

            # ── New connection attempt ────────────────────────────────────────
            if entry is None:
                if SYN and not ACK:
                    e = ConnEntry(key=key, state=TCPState.SYN_SENT)
                    self._table[key] = e
                    return True, "NEW SYN accepted"
                else:
                    return False, f"OUT-OF-STATE: no conn for non-SYN packet (flags={flags:#x})"

            # ── RST: tear down ────────────────────────────────────────────────
            if RST:
                entry.state   = TCPState.CLOSED
                entry.updated = time.time()
                return True, "RST → CLOSED"

            # ── State machine ─────────────────────────────────────────────────
            st = entry.state

            if st == TCPState.SYN_SENT:
                if SYN and ACK and not is_client:
                    entry.state   = TCPState.SYN_RCVD
                    entry.updated = time.time()
                    return True, "SYN-ACK → SYN_RCVD"
                elif ACK and is_client:
                    # Simultaneous open or re-ACK
                    entry.state   = TCPState.ESTABLISHED
                    entry.updated = time.time()
                    return True, "ACK → ESTABLISHED"
                return False, f"Invalid in SYN_SENT (flags={flags:#x})"

            elif st == TCPState.SYN_RCVD:
                if ACK and is_client:
                    entry.state   = TCPState.ESTABLISHED
                    entry.updated = time.time()
                    return True, "ACK → ESTABLISHED (handshake done)"
                return False, f"Invalid in SYN_RCVD (flags={flags:#x})"

            elif st == TCPState.ESTABLISHED:
                if FIN:
                    entry.state   = TCPState.FIN_WAIT
                    entry.updated = time.time()
                    return True, "FIN → FIN_WAIT"
                entry.updated = time.time()
                if is_client: entry.pkts_out += 1
                else:         entry.pkts_in  += 1
                return True, "ESTABLISHED flow"

            elif st == TCPState.FIN_WAIT:
                if FIN or ACK:
                    entry.state   = TCPState.CLOSED
                    entry.updated = time.time()
                    return True, "FIN/ACK → CLOSED"
                return True, "FIN_WAIT data"

            elif st == TCPState.CLOSED:
                return False, "Connection CLOSED, rejecting packet"

        return True, "default allow"

    def half_open_count(self, src_ip: str) -> int:
        with self._lock:
            return sum(
                1 for e in self._table.values()
                if e.key[0] == src_ip and e.state == TCPState.SYN_SENT
            )

    def cleanup(self):
        """Remove expired entries."""
        with self._lock:
            expired = [k for k, e in self._table.items() if e.expired]
            for k in expired:
                del self._table[k]

    def snapshot(self) -> List[dict]:
        with self._lock:
            return [
                {"src": f"{e.key[0]}:{e.key[1]}", "dst": f"{e.key[2]}:{e.key[3]}",
                 "proto": e.key[4], "state": e.state.value,
                 "age": round(e.age, 1), "pkts_in": e.pkts_in, "pkts_out": e.pkts_out}
                for e in list(self._table.values())[:50]
            ]

# ─── Shared State ─────────────────────────────────────────────────────────────

class FirewallState:
    def __init__(self):
        self.lock         = threading.Lock()
        self.conn_table   = ConnectionTable()
        self.acl_rules    = list(DEFAULT_RULES)

        self.syn_tracker:   Dict[str, deque] = defaultdict(deque)
        self.port_tracker:  Dict[str, set]   = defaultdict(set)
        self.brute_tracker: Dict[str, deque] = defaultdict(deque)
        self.icmp_tracker:  Dict[str, deque] = defaultdict(deque)

        self.blocked_ips:   Set[str] = set()
        self.attacker_ips:  Set[str] = set()

        self.packets_seen          = 0
        self.acl_denied            = 0
        self.stateful_denied       = 0
        self.attacks_detected      = 0
        self.connections_tracked   = 0
        self.events: List[dict]    = []

    def add_event(self, level: str, src: str, msg: str):
        evt = {"time": datetime.now().strftime("%H:%M:%S"),
               "level": level, "src": src, "msg": msg}
        with self.lock:
            self.events.append(evt)
            if len(self.events) > 300:
                self.events.pop(0)

state = FirewallState()

# ─── Logger ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("ShashFirewall")

# ─── iptables Helpers ─────────────────────────────────────────────────────────

def iptables(args):
    try:
        r = subprocess.run(["sudo","iptables"] + args, capture_output=True, text=True)
        return r.returncode == 0
    except FileNotFoundError:
        return False

def block_ip(ip: str, reason: str = "attack"):
    if is_trusted(ip):
        log.warning(f"[WHITELIST] Block attempt on trusted IP {ip} ignored ({reason})")
        return
    with state.lock:
        if ip in state.blocked_ips: return
        state.blocked_ips.add(ip)
    ok = iptables(["-I","INPUT","-s",ip,"-j","DROP"])
    iptables(["-I","OUTPUT","-d",ip,"-j","DROP"])
    mode = "iptables" if ok else "simulated"
    log.warning(f"[BLOCK/{mode}] {ip} — {reason}")
    state.add_event("BLOCK", ip, f"{mode}: {reason}")

def unblock_ip(ip: str):
    with state.lock:
        state.blocked_ips.discard(ip)
    iptables(["-D","INPUT","-s",ip,"-j","DROP"])
    iptables(["-D","OUTPUT","-d",ip,"-j","DROP"])
    log.info(f"[UNBLOCK] {ip}")
    state.add_event("INFO", ip, "Unblocked")

def block_domain(domain: str):
    try:
        ip = socket.gethostbyname(domain)
        block_ip(ip, reason=f"blocked domain: {domain}")
    except socket.gaierror:
        log.warning(f"[DOMAIN] Cannot resolve {domain}")

# ─── Countermeasures ──────────────────────────────────────────────────────────

def rst_flood(attacker_ip, attacker_port, victim_port):
    try:
        from scapy.all import IP, TCP, send
        pkt = IP(dst=attacker_ip)/TCP(sport=victim_port, dport=attacker_port, flags="R", seq=1000)
        send(pkt, count=RST_VOLLEY, verbose=False)
        log.warning(f"[COUNTER] RST x{RST_VOLLEY} → {attacker_ip}:{attacker_port}")
        state.add_event("COUNTER", attacker_ip, f"RST x{RST_VOLLEY} → port {attacker_port}")
    except Exception as e:
        state.add_event("COUNTER", attacker_ip, f"RST simulated: {e}")

def tarpit(attacker_ip):
    def _hold():
        state.add_event("COUNTER", attacker_ip, "Tarpit: wasting 30s of attacker time")
        time.sleep(30)
    threading.Thread(target=_hold, daemon=True).start()

def deploy_countermeasures(attacker_ip, attack_type, attacker_port=0, victim_port=0):
    with state.lock:
        if attacker_ip in state.attacker_ips: return
        state.attacker_ips.add(attacker_ip)
        state.attacks_detected += 1
    log.critical(f"[ATTACK] {attack_type} from {attacker_ip}")
    state.add_event("ATTACK", attacker_ip, f"{attack_type}")
    block_ip(attacker_ip, reason=attack_type)
    if attacker_port and victim_port:
        threading.Thread(target=rst_flood, args=(attacker_ip, attacker_port, victim_port), daemon=True).start()
    tarpit(attacker_ip)

# ─── ENGINE 1: Packet Filtering ───────────────────────────────────────────────

def run_acl(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
            proto: str, flags: int) -> Tuple[Action, str]:
    """
    Evaluate packet against ACL ruleset top-down.
    Returns (Action, comment) of first matching rule.
    """
    for rule in state.acl_rules:
        if rule.matches(src_ip, dst_ip, src_port, dst_port, proto, flags):
            return rule.action, rule.comment
    return Action.DENY, "Default deny (no rule matched)"

# ─── ENGINE 2: Stateful Inspection + Attack Detection ─────────────────────────

def run_stateful(src_ip: str, sport: int, dst_ip: str, dport: int,
                 proto: str, flags: int, now: float) -> Tuple[bool, str]:
    """
    1. Check connection table → accept/reject based on state
    2. Run attack detectors (port scan, SYN flood, brute force, ICMP flood)
    """
    # Half-open connection exhaustion check
    if proto == "TCP" and (flags & 0x02) and not (flags & 0x10):
        half_open = state.conn_table.half_open_count(src_ip)
        if half_open >= HALF_OPEN_THRESHOLD:
            deploy_countermeasures(src_ip, f"Half-Open Exhaustion ({half_open})", sport, dport)
            return False, f"Half-open limit exceeded ({half_open})"

    # Connection table lookup
    allow, reason = state.conn_table.process(src_ip, sport, dst_ip, dport, proto, flags)
    if not allow:
        return False, f"Stateful DENY: {reason}"

    # ── Port Scan ─────────────────────────────────────────────────────────────
    if proto == "TCP" and (flags & 0x02):
        with state.lock:
            state.port_tracker[src_ip].add(dport)
            pt = state.port_tracker[src_ip]
        if len(pt) >= PORT_SCAN_THRESHOLD:
            deploy_countermeasures(src_ip, "Port Scan", sport, dport)
            with state.lock: state.port_tracker[src_ip] = set()

    # ── SYN Flood ─────────────────────────────────────────────────────────────
    if proto == "TCP" and (flags & 0x02):
        with state.lock:
            q = state.syn_tracker[src_ip]
            q.append(now)
            while q and now - q[0] > 1.0: q.popleft()
            rate = len(q)
        if rate >= SYN_FLOOD_THRESHOLD:
            deploy_countermeasures(src_ip, f"SYN Flood ({rate}/s)", sport, dport)

    # ── Brute Force ───────────────────────────────────────────────────────────
    if proto == "TCP" and dport in AUTH_PORTS and (flags & 0x02):
        with state.lock:
            q = state.brute_tracker[src_ip]
            q.append(now)
            while q and now - q[0] > DETECTION_WINDOW: q.popleft()
            rate = len(q)
        if rate >= BRUTE_FORCE_THRESHOLD:
            deploy_countermeasures(src_ip, f"Brute Force port {dport}", sport, dport)

    # ── ICMP Flood ────────────────────────────────────────────────────────────
    if proto == "ICMP":
        # In WSL, we see replies coming IN — dst_ip is us, src_ip is the remote.
        # High rate = WE are flood pinging src_ip. Log it, don't block the remote.
        with state.lock:
            q = state.icmp_tracker[src_ip]
            q.append(now)
            while q and now - q[0] > 1.0: q.popleft()
            rate = len(q)
        if rate >= ICMP_FLOOD_THRESHOLD:
            log.warning(f"[ICMP FLOOD] Outbound flood detected → {src_ip} ({rate}/s)")
            state.add_event("ICMP-FLOOD", src_ip, f"Outbound flood detected ({rate}/s) — not blocking remote")

# ─── Unified Packet Processor ─────────────────────────────────────────────────

def process_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                   proto: str, flags: int):
    """
    Two-stage pipeline:
      Stage 1: Packet Filtering (ACL)  — fast, stateless header check
      Stage 2: Stateful Inspection     — connection tracking + attack detection
    """
    now = time.time()
    state.packets_seen += 1

    # Trusted IPs bypass all detection and blocking — admin whitelist
    if is_trusted(src_ip):
        return

    with state.lock:
        if src_ip in state.blocked_ips: return

    # ── Stage 1: ACL / Packet Filtering ──────────────────────────────────────
    action, acl_comment = run_acl(src_ip, dst_ip, src_port, dst_port, proto, flags)

    if action == Action.DENY:
        state.acl_denied += 1
        log.info(f"[ACL DENY] {src_ip}:{src_port} → {dst_ip}:{dst_port} ({proto}) — {acl_comment}")
        state.add_event("ACL-DENY", src_ip, f"→{dst_ip}:{dst_port} {proto} | {acl_comment}")
        return  # Drop packet, don't proceed to stateful

    if action == Action.LOG:
        state.add_event("ACL-LOG", src_ip, f"→{dst_ip}:{dst_port} {proto} | {acl_comment}")

    # ── Stage 2: Stateful Inspection ──────────────────────────────────────────
    allowed, sf_reason = run_stateful(src_ip, src_port, dst_ip, dst_port, proto, flags, now)

    if not allowed:
        state.stateful_denied += 1
        log.info(f"[SF DENY] {src_ip}:{src_port} → {dst_ip}:{dst_port} | {sf_reason}")
        state.add_event("SF-DENY", src_ip, f"→{dst_ip}:{dst_port} | {sf_reason}")

# ─── Scapy Sniffer ────────────────────────────────────────────────────────────

def analyze_packet(pkt):
    try:
        from scapy.all import IP, TCP, UDP, ICMP
        if IP not in pkt: return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        if TCP in pkt:
            process_packet(src_ip, dst_ip, pkt[TCP].sport, pkt[TCP].dport,
                           "TCP", int(pkt[TCP].flags))
        elif UDP in pkt:
            process_packet(src_ip, dst_ip, pkt[UDP].sport, pkt[UDP].dport, "UDP", 0)
        elif ICMP in pkt:
            process_packet(src_ip, dst_ip, 0, 0, "ICMP", 0)

    except Exception as e:
        log.debug(f"[SNIFFER] {e}")

def start_sniffer(iface=None):
    try:
        from scapy.all import sniff, conf
        iface = iface or conf.iface
        log.info(f"[SNIFFER] Listening on {iface}")
        sniff(prn=analyze_packet, store=False, iface=iface)
    except PermissionError:
        log.error("[SNIFFER] Need root: sudo python3 firewall_v2.py")
        sys.exit(1)
    except Exception as e:
        log.error(f"[SNIFFER] {e}"); sys.exit(1)

# ─── Background Workers ───────────────────────────────────────────────────────

def conn_cleanup_worker():
    while True:
        time.sleep(30)
        state.conn_table.cleanup()
        log.debug("[CLEANUP] Expired connections pruned")

def stats_writer():
    while True:
        time.sleep(10)
        data = {
            "packets_seen": state.packets_seen,
            "acl_denied": state.acl_denied,
            "stateful_denied": state.stateful_denied,
            "attacks_detected": state.attacks_detected,
            "blocked_ips": list(state.blocked_ips),
            "events": state.events[-50:],
            "connections": state.conn_table.snapshot()
        }
        with open("firewall_v2_stats.json","w") as f: json.dump(data, f, indent=2)

# ─── Flask Dashboard ──────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta http-equiv="refresh" content="5"><title>ShashFirewall v2</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--green:#3fb950;--red:#f85149;
      --yellow:#d29922;--blue:#58a6ff;--purple:#bc8cff;--text:#c9d1d9;--dim:#8b949e}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font:13px/1.5 'Courier New',monospace}
header{background:var(--panel);border-bottom:1px solid var(--border);
       padding:12px 20px;display:flex;align-items:center;gap:12px}
header h1{color:var(--green);font-size:18px;letter-spacing:2px}
.badge{border:1px solid var(--green);color:var(--green);padding:2px 8px;border-radius:4px;font-size:11px}
.badge2{border:1px solid var(--blue);color:var(--blue);padding:2px 8px;border-radius:4px;font-size:11px}
.engines{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:16px}
.engine{background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:14px}
.engine h3{font-size:12px;letter-spacing:1px;margin-bottom:10px;text-transform:uppercase}
.engine h3.pf{color:var(--blue)}.engine h3.sf{color:var(--purple)}
.engine p{color:var(--dim);font-size:11px;margin-bottom:8px}
.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;padding:0 16px 16px}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:12px;text-align:center}
.stat .val{font-size:22px;font-weight:bold}.stat .lbl{color:var(--dim);font-size:10px;margin-top:4px}
.green{color:var(--green)}.red{color:var(--red)}.yellow{color:var(--yellow)}
.blue{color:var(--blue)}.purple{color:var(--purple)}
section{padding:0 16px 16px}
h2{color:var(--dim);font-size:11px;letter-spacing:1px;text-transform:uppercase;
   margin-bottom:8px;border-bottom:1px solid var(--border);padding-bottom:6px}
table{width:100%;border-collapse:collapse}
th{color:var(--dim);font-size:11px;text-align:left;padding:5px 8px;border-bottom:1px solid var(--border)}
td{padding:5px 8px;border-bottom:1px solid #1c2128;font-size:11px}
tr:hover td{background:#1c2128}
.tag{display:inline-block;padding:1px 5px;border-radius:3px;font-size:10px;font-weight:bold}
.tag-ATTACK{background:#3d1c1c;color:var(--red)}
.tag-BLOCK{background:#2d1c00;color:var(--yellow)}
.tag-COUNTER{background:#1c2d1c;color:var(--green)}
.tag-ACL-DENY{background:#1c1c3d;color:var(--blue)}
.tag-SF-DENY{background:#2d1c2d;color:var(--purple)}
.tag-ACL-LOG{background:#1c2128;color:var(--dim)}
.tag-INFO{background:#1c1c2d;color:var(--blue)}
.st-ESTABLISHED{color:var(--green)}.st-SYN_SENT{color:var(--yellow)}
.st-SYN_RCVD{color:var(--blue)}.st-FIN_WAIT{color:var(--dim)}.st-CLOSED{color:var(--red)}
footer{text-align:center;padding:10px;color:var(--dim);font-size:11px}
</style></head><body>
<header>
  <h1>⚡ SHASHFIREWALL v2</h1>
  <span class="badge">PF ENGINE</span>
  <span class="badge2">STATEFUL ENGINE</span>
  <span style="margin-left:auto;color:var(--dim);font-size:11px">Auto-refresh 5s | {{ now }}</span>
</header>

<div class="engines">
  <div class="engine">
    <h3 class="pf">🔵 Engine 1 — Packet Filtering (Stateless)</h3>
    <p>Checks each packet independently against the ACL ruleset. Fast O(n) rule scan on headers: src/dst IP, port, protocol, TCP flags. First-match-wins. No memory of past packets.</p>
    <p>ACL Denied: <span class="blue">{{ s.acl_denied }}</span> packets</p>
  </div>
  <div class="engine">
    <h3 class="sf">🟣 Engine 2 — Stateful Inspection</h3>
    <p>Tracks TCP 3-way handshake through full lifecycle: SYN→SYN_RCVD→ESTABLISHED→FIN_WAIT→CLOSED. Rejects out-of-state packets. Detects SYN floods, half-open exhaustion, port scans, brute force.</p>
    <p>Stateful Denied: <span class="purple">{{ s.stateful_denied }}</span> | Connections: <span class="green">{{ connections|length }}</span></p>
  </div>
</div>

<div class="grid">
  <div class="stat"><div class="val green">{{ s.packets_seen }}</div><div class="lbl">TOTAL PACKETS</div></div>
  <div class="stat"><div class="val blue">{{ s.acl_denied }}</div><div class="lbl">ACL DENIED</div></div>
  <div class="stat"><div class="val purple">{{ s.stateful_denied }}</div><div class="lbl">SF DENIED</div></div>
  <div class="stat"><div class="val yellow">{{ s.attacks_detected }}</div><div class="lbl">ATTACKS</div></div>
  <div class="stat"><div class="val red">{{ s.blocked_ips|length }}</div><div class="lbl">BLOCKED IPs</div></div>
</div>

<section><h2>Connection Table (Stateful Engine)</h2>
<table><tr><th>SOURCE</th><th>DESTINATION</th><th>PROTO</th><th>STATE</th><th>AGE(s)</th><th>IN</th><th>OUT</th></tr>
{% for c in connections %}
<tr><td>{{c.src}}</td><td>{{c.dst}}</td><td>{{c.proto}}</td>
<td><span class="st-{{c.state}}">{{c.state}}</span></td>
<td>{{c.age}}</td><td>{{c.pkts_in}}</td><td>{{c.pkts_out}}</td></tr>
{% endfor %}
{% if not connections %}<tr><td colspan="7" style="color:var(--dim);text-align:center">No active connections</td></tr>{% endif %}
</table></section>

<section><h2>Live Event Feed</h2>
<table><tr><th>TIME</th><th>ENGINE/TYPE</th><th>SRC IP</th><th>DETAIL</th></tr>
{% for e in events|reverse %}
<tr><td>{{e.time}}</td><td><span class="tag tag-{{e.level}}">{{e.level}}</span></td>
<td>{{e.src}}</td><td>{{e.msg}}</td></tr>
{% endfor %}</table></section>

<section><h2>Blocked IPs</h2>
<table><tr><th>IP</th><th>STATUS</th></tr>
{% for ip in s.blocked_ips %}<tr><td>{{ip}}</td>
<td><span class="tag tag-BLOCK">BLOCKED</span></td></tr>{% endfor %}
{% if not s.blocked_ips %}<tr><td colspan="2" style="color:var(--dim)">None</td></tr>{% endif %}
</table></section>
<footer>ShashFirewall v2 | Packet Filtering + Stateful Inspection | shash / SHAshank61</footer>
</body></html>"""

def start_dashboard(port=5000):
    from flask import Flask, jsonify, render_template_string, request
    import logging as _l
    app = Flask(__name__)
    _l.getLogger("werkzeug").setLevel(_l.ERROR)

    @app.route("/")
    def dashboard():
        s = {"packets_seen": state.packets_seen, "acl_denied": state.acl_denied,
             "stateful_denied": state.stateful_denied, "attacks_detected": state.attacks_detected,
             "blocked_ips": list(state.blocked_ips)}
        return render_template_string(HTML, s=s, events=state.events,
                                      connections=state.conn_table.snapshot(),
                                      now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    @app.route("/api/stats")
    def api_stats():
        return jsonify({"packets_seen": state.packets_seen, "acl_denied": state.acl_denied,
                        "stateful_denied": state.stateful_denied,
                        "attacks_detected": state.attacks_detected,
                        "blocked_ips": list(state.blocked_ips),
                        "connections": state.conn_table.snapshot(),
                        "events": state.events[-20:]})

    @app.route("/api/block", methods=["POST"])
    def api_block():
        ip = request.json.get("ip")
        if ip: block_ip(ip,"manual"); return jsonify({"status":"blocked","ip":ip})
        return jsonify({"error":"no ip"}),400

    @app.route("/api/unblock", methods=["POST"])
    def api_unblock():
        ip = request.json.get("ip")
        if ip: unblock_ip(ip); return jsonify({"status":"unblocked","ip":ip})
        return jsonify({"error":"no ip"}),400

    @app.route("/api/acl", methods=["GET"])
    def api_acl():
        return jsonify([{"action": r.action.value, "proto": r.proto.value,
                         "src_ip": r.src_ip, "dst_port": r.dst_port,
                         "comment": r.comment} for r in state.acl_rules])

    log.info(f"[DASHBOARD] http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    p = argparse.ArgumentParser(description="ShashFirewall v2")
    p.add_argument("--iface",      default=None)
    p.add_argument("--port",       type=int, default=5000)
    p.add_argument("--no-sniffer", action="store_true")
    args = p.parse_args()

    print("""
╔══════════════════════════════════════════════════════╗
║           BRO v2.0                         ║
║  [PF] Packet Filtering + [SF] Stateful Inspection    ║
║  Detect · Block · Strike Back                        ║
╚══════════════════════════════════════════════════════╝
""")
    threading.Thread(target=conn_cleanup_worker, daemon=True).start()
    threading.Thread(target=stats_writer,        daemon=True).start()
    threading.Thread(target=start_dashboard, args=(args.port,), daemon=True).start()

    if not args.no_sniffer:
        start_sniffer(args.iface)
    else:
        log.info("[MAIN] Dashboard mode → http://localhost:5000")
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            log.info("[MAIN] Shutdown.")

if __name__ == "__main__":
    main()
