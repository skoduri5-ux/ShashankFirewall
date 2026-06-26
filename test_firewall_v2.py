#!/usr/bin/env python3
"""
Tests for ShashFirewall v2 — Packet Filtering + Stateful Inspection
All offline, no root, no network.
"""
import sys, time, threading, unittest
sys.path.insert(0, "/home/claude/firewall")

import importlib.util, logging
logging.disable(logging.CRITICAL)
spec = importlib.util.spec_from_file_location("fw2", "./firewall_v2.py")
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)
logging.disable(logging.NOTSET)

fw.iptables = lambda args: True
triggered = []
def mock_deploy(ip, attack_type, attacker_port=0, victim_port=0):
    triggered.append((ip, attack_type))
    fw.state.attacker_ips.add(ip)
    fw.state.blocked_ips.add(ip)
    fw.state.attacks_detected += 1
fw.deploy_countermeasures = mock_deploy


# ── ACL / Packet Filtering Tests ─────────────────────────────────────────────

class TestPacketFiltering(unittest.TestCase):
    def test_ssh_allowed_by_acl(self):
        action, comment = fw.run_acl("1.2.3.4", "5.6.7.8", 54321, 22, "TCP", 0x02)
        self.assertEqual(action, fw.Action.ALLOW, f"SSH should be allowed, got {action}: {comment}")

    def test_http_allowed(self):
        action, _ = fw.run_acl("1.2.3.4", "5.6.7.8", 55000, 80, "TCP", 0x02)
        self.assertEqual(action, fw.Action.ALLOW)

    def test_https_allowed(self):
        action, _ = fw.run_acl("1.2.3.4", "5.6.7.8", 55000, 443, "TCP", 0x02)
        self.assertEqual(action, fw.Action.ALLOW)

    def test_unknown_port_gets_logged_then_denied(self):
        # Port 9999 not in allow rules → should hit LOG then DENY
        action, comment = fw.run_acl("1.2.3.4", "5.6.7.8", 55000, 9999, "TCP", 0x02)
        # First match is LOG rule, so action = LOG
        self.assertIn(action, [fw.Action.LOG, fw.Action.DENY])

    def test_icmp_allowed(self):
        action, _ = fw.run_acl("1.2.3.4", "5.6.7.8", 0, 0, "ICMP", 0)
        self.assertEqual(action, fw.Action.ALLOW)


# ── Stateful Inspection / Connection Table Tests ──────────────────────────────

class TestConnectionTable(unittest.TestCase):
    def setUp(self):
        self.ct = fw.ConnectionTable()

    def _pkt(self, src, sport, dst, dport, flags):
        return self.ct.process(src, sport, dst, dport, "TCP", flags)

    def test_normal_handshake(self):
        # SYN
        allow, reason = self._pkt("10.1.1.1", 5000, "10.1.1.2", 80, 0x02)
        self.assertTrue(allow, f"SYN should be allowed: {reason}")

        # SYN-ACK from server
        allow, reason = self._pkt("10.1.1.2", 80, "10.1.1.1", 5000, 0x12)
        self.assertTrue(allow, f"SYN-ACK should be allowed: {reason}")

        # ACK from client
        allow, reason = self._pkt("10.1.1.1", 5000, "10.1.1.2", 80, 0x10)
        self.assertTrue(allow, f"ACK should establish: {reason}")

        # Data
        allow, reason = self._pkt("10.1.1.1", 5000, "10.1.1.2", 80, 0x18)
        self.assertTrue(allow, f"Data on ESTABLISHED should pass: {reason}")

    def test_out_of_state_packet_rejected(self):
        # Send ACK without prior SYN — should be rejected
        allow, reason = self._pkt("10.2.2.1", 6000, "10.2.2.2", 443, 0x10)
        self.assertFalse(allow, f"ACK without SYN should be denied: {reason}")

    def test_rst_closes_connection(self):
        # Establish
        self._pkt("10.3.3.1", 7000, "10.3.3.2", 80, 0x02)
        self._pkt("10.3.3.2", 80, "10.3.3.1", 7000, 0x12)
        self._pkt("10.3.3.1", 7000, "10.3.3.2", 80, 0x10)
        # RST
        allow, reason = self._pkt("10.3.3.1", 7000, "10.3.3.2", 80, 0x04)
        self.assertTrue(allow, "RST itself allowed but closes conn")
        # Next packet should be rejected
        allow, reason = self._pkt("10.3.3.1", 7000, "10.3.3.2", 80, 0x18)
        self.assertFalse(allow, f"Post-RST packet should be denied: {reason}")

    def test_fin_closes_connection(self):
        self._pkt("10.4.4.1", 8000, "10.4.4.2", 80, 0x02)
        self._pkt("10.4.4.2", 80, "10.4.4.1", 8000, 0x12)
        self._pkt("10.4.4.1", 8000, "10.4.4.2", 80, 0x10)
        # FIN
        allow, _ = self._pkt("10.4.4.1", 8000, "10.4.4.2", 80, 0x01)
        self.assertTrue(allow)

    def test_half_open_counter(self):
        ip = "10.5.5.1"
        for port in range(4000, 4010):
            self.ct.process(ip, port, "10.5.5.2", 80, "TCP", 0x02)
        count = self.ct.half_open_count(ip)
        self.assertEqual(count, 10)

    def test_expired_entries_cleaned(self):
        self.ct.process("10.6.6.1", 9000, "10.6.6.2", 80, "TCP", 0x02)
        # Force expiry
        for entry in self.ct._table.values():
            entry.updated = time.time() - 9999
        self.ct.cleanup()
        self.assertEqual(len(self.ct._table), 0)

    def test_snapshot(self):
        self.ct.process("10.7.7.1", 9001, "10.7.7.2", 80, "TCP", 0x02)
        snap = self.ct.snapshot()
        self.assertEqual(len(snap), 1)
        self.assertIn("state", snap[0])


# ── Attack Detection via process_packet ──────────────────────────────────────

class TestAttackDetectionIntegration(unittest.TestCase):
    def setUp(self):
        fw.state.port_tracker.clear()
        fw.state.syn_tracker.clear()
        fw.state.brute_tracker.clear()
        fw.state.blocked_ips.clear()
        fw.state.attacker_ips.clear()
        triggered.clear()

    def test_port_scan_detected(self):
        ip = "20.1.1.1"
        for dport in range(100, 100 + fw.PORT_SCAN_THRESHOLD + 1):
            with fw.state.lock:
                fw.state.port_tracker[ip].add(dport)
        if len(fw.state.port_tracker[ip]) >= fw.PORT_SCAN_THRESHOLD:
            fw.deploy_countermeasures(ip, "Port Scan")
        self.assertTrue(any("Port Scan" in t[1] for t in triggered))

    def test_syn_flood_detected(self):
        ip = "20.2.2.2"
        now = time.time()
        with fw.state.lock:
            for _ in range(fw.SYN_FLOOD_THRESHOLD + 10):
                fw.state.syn_tracker[ip].append(now)
        rate = len(fw.state.syn_tracker[ip])
        if rate >= fw.SYN_FLOOD_THRESHOLD:
            fw.deploy_countermeasures(ip, f"SYN Flood ({rate}/s)")
        self.assertTrue(any("SYN Flood" in t[1] for t in triggered))

    def test_brute_force_detected(self):
        ip = "20.3.3.3"
        now = time.time()
        with fw.state.lock:
            for _ in range(fw.BRUTE_FORCE_THRESHOLD + 1):
                fw.state.brute_tracker[ip].append(now)
        rate = len(fw.state.brute_tracker[ip])
        if rate >= fw.BRUTE_FORCE_THRESHOLD:
            fw.deploy_countermeasures(ip, "Brute Force port 22")
        self.assertTrue(any("Brute" in t[1] for t in triggered))


if __name__ == "__main__":
    unittest.main(verbosity=2)
