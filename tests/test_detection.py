"""
tests/test_detection.py - Automated tests for threat detection, scoring, correlation, and timeline.
Uses in-memory / synthetic fixtures so tests can execute without requiring large PCAP files or external tshark.
"""

import unittest
import uuid
from datetime import datetime, timezone
import os

from app import create_app
app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})
from database.database import db
from database.models import Analysis, Packet, ThreatEvent, TimelineEvent, Investigation
from analysis.threat_detector import (
    detect_port_scans,
    detect_ssh_brute_force,
    detect_dns_anomalies,
    detect_suspicious_outbound,
    detect_icmp_anomalies,
    detect_http_anomalies,
    run_all_detectors,
)
from analysis.threat_scorer import compute_risk_score, severity_label, rescore_events
from analysis.correlator import correlate_events, get_attack_narrative
from analysis.timeline_builder import build_timeline
from ai.investigator import generate_investigation
from reports.pdf_report import generate_pdf_report
import config


class TestThreatDetection(unittest.TestCase):
    def setUp(self):
        # Configure app for test mode with an in-memory SQLite database
        app.config["TESTING"] = True
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()

        self.analysis_id = str(uuid.uuid4())
        analysis = Analysis(
            id=self.analysis_id,
            filename="synthetic_test.pcap",
            original_filename="synthetic_test.pcap",
            file_size=1024,
            status="processing",
            duration=60.0,
            packet_count=100,
        )
        db.session.add(analysis)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_port_scan_detection(self):
        """Test vertical port scan detection (same src, same dst, many ports, SYN flags)."""
        base_epoch = 1700000000.0
        packets = []
        for i in range(15):  # default threshold is 10
            packets.append(Packet(
                analysis_id=self.analysis_id,
                packet_number=i + 1,
                timestamp_epoch=base_epoch + i,
                src_ip="192.168.1.100",
                dst_ip="192.168.1.1",
                src_port=50000 + i,
                dst_port=1000 + i,
                protocol="TCP",
                tcp_flags="0x002",  # SYN
                packet_length=64,
            ))
        db.session.bulk_save_objects(packets)
        db.session.commit()

        events = detect_port_scans(self.analysis_id)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "PORT_SCAN")
        self.assertEqual(events[0]["source_ip"], "192.168.1.100")
        self.assertEqual(events[0]["destination_ip"], "192.168.1.1")
        self.assertGreaterEqual(events[0]["risk_score"], 60.0)

    def test_ssh_brute_force_detection(self):
        """Test SSH repeated connection detection against port 22."""
        base_epoch = 1700000000.0
        packets = []
        for i in range(15):  # default threshold is 10
            packets.append(Packet(
                analysis_id=self.analysis_id,
                packet_number=i + 1,
                timestamp_epoch=base_epoch + i * 2,
                src_ip="192.168.1.200",
                dst_ip="192.168.1.10",
                src_port=40000 + i,
                dst_port=22,  # SSH
                protocol="TCP",
                tcp_flags="0x002",
                packet_length=120,
            ))
        db.session.bulk_save_objects(packets)
        db.session.commit()

        events = detect_ssh_brute_force(self.analysis_id)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "SSH_BRUTE_FORCE")
        self.assertEqual(events[0]["source_ip"], "192.168.1.200")
        self.assertEqual(events[0]["destination_ip"], "192.168.1.10")

    def test_dns_anomaly_detection(self):
        """Test high entropy and long domain label DNS detection."""
        base_epoch = 1700000000.0
        packets = []
        # Long random label
        suspicious_q = "x89f2kd84mz019xla019348fjz019842k.attacker-c2.net"
        for i in range(5):
            packets.append(Packet(
                analysis_id=self.analysis_id,
                packet_number=i + 1,
                timestamp_epoch=base_epoch + i,
                src_ip="192.168.1.55",
                dst_ip="8.8.8.8",
                src_port=53000 + i,
                dst_port=53,
                protocol="DNS",
                dns_query=suspicious_q,
                packet_length=150,
            ))
        db.session.bulk_save_objects(packets)
        db.session.commit()

        events = detect_dns_anomalies(self.analysis_id)
        self.assertGreaterEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "DNS_ANOMALY")
        self.assertEqual(events[0]["source_ip"], "192.168.1.55")

    def test_suspicious_outbound_detection(self):
        """Test connection to known backdoor / RAT port 4444."""
        base_epoch = 1700000000.0
        packet = Packet(
            analysis_id=self.analysis_id,
            packet_number=1,
            timestamp_epoch=base_epoch,
            src_ip="192.168.1.80",
            dst_ip="203.0.113.5",
            src_port=55123,
            dst_port=4444,  # Suspicious port
            protocol="TCP",
            packet_length=200,
        )
        db.session.add(packet)
        db.session.commit()

        events = detect_suspicious_outbound(self.analysis_id)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "SUSPICIOUS_OUTBOUND")
        self.assertEqual(events[0]["source_ip"], "192.168.1.80")

    def test_risk_scoring(self):
        """Test risk score calculation logic."""
        event = {
            "event_type": "PORT_SCAN",
            "confidence": 0.9,
            "risk_score": 60,
            "evidence": {
                "unique_ports_count": 55,
                "reasons": ["High SYN ratio", "Rapid duration"]
            }
        }
        score = compute_risk_score(event)
        self.assertGreater(score, 60)
        self.assertLessEqual(score, 100)
        self.assertEqual(severity_label(score), "HIGH" if score < 80 else "CRITICAL")

    def test_event_correlation_and_timeline(self):
        """Test multi-event correlation into attack phases and timeline construction."""
        base_epoch = 1700000000.0
        events = [
            {
                "analysis_id": self.analysis_id,
                "timestamp_epoch": base_epoch,
                "event_type": "PORT_SCAN",
                "source_ip": "192.168.1.99",
                "destination_ip": "192.168.1.5",
                "severity": "HIGH",
                "risk_score": 70,
                "confidence": 0.85,
                "description": "Port scan observed",
            },
            {
                "analysis_id": self.analysis_id,
                "timestamp_epoch": base_epoch + 15,
                "event_type": "SSH_BRUTE_FORCE",
                "source_ip": "192.168.1.99",
                "destination_ip": "192.168.1.5",
                "severity": "CRITICAL",
                "risk_score": 85,
                "confidence": 0.9,
                "description": "SSH Brute force observed",
            }
        ]

        correlated = correlate_events(events)
        self.assertEqual(correlated[0]["phase"], "RECONNAISSANCE")
        self.assertEqual(correlated[1]["phase"], "CREDENTIAL_ATTACK")

        # Save to DB as ThreatEvent
        te_objs = []
        for e in correlated:
            te = ThreatEvent(**{k: v for k, v in e.items() if k not in ("phase", "correlation_group", "correlated_with")})
            db.session.add(te)
            te_objs.append(te)
        db.session.commit()

        # Build timeline
        timeline_items = build_timeline(self.analysis_id, te_objs)
        # Should include observed events + inferred SERVICE_IDENTIFIED event
        self.assertGreaterEqual(len(timeline_items), 2)
        inferred = [t for t in timeline_items if t.is_inferred]
        self.assertGreaterEqual(len(inferred), 1)
        self.assertEqual(inferred[0].event_type, "SERVICE_IDENTIFIED")

    def test_ai_fallback_investigation(self):
        """Test deterministic investigation generation when no OpenAI API key is present."""
        analysis = db.session.get(Analysis, self.analysis_id)
        threat_events = [
            ThreatEvent(
                analysis_id=self.analysis_id,
                timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
                event_type="PORT_SCAN",
                source_ip="192.168.1.100",
                destination_ip="192.168.1.1",
                severity="HIGH",
                risk_score=75.0,
                confidence=0.88,
                description="Port scan detected",
            )
        ]
        timeline_events = [
            TimelineEvent(
                analysis_id=self.analysis_id,
                sequence_order=1,
                event_type="PORT_SCAN",
                phase="RECONNAISSANCE",
                title="Port Scan",
                description="Probing ports",
                severity="HIGH",
                source_ip="192.168.1.100",
                destination_ip="192.168.1.1",
            )
        ]
        traffic_stats = {"unique_src_ips": 1, "unique_dst_ips": 1, "total_bytes": 1024}

        inv_data = generate_investigation(analysis, threat_events, timeline_events, traffic_stats)
        self.assertIn("executive_summary", inv_data)
        self.assertIn("attack_hypothesis", inv_data)
        self.assertIn("evidence_observed", inv_data)
        self.assertIn("evidence_inferred", inv_data)
        self.assertFalse(inv_data["ai_generated"])  # Confirmed fallback

    def test_pdf_report_generation(self):
        """Test PDF compilation using ReportLab."""
        analysis = db.session.get(Analysis, self.analysis_id)
        threat_events = []
        timeline_events = []
        traffic_stats = {"unique_src_ips": 1, "unique_dst_ips": 1, "total_bytes": 1024}
        inv = Investigation(
            analysis_id=self.analysis_id,
            executive_summary="Executive summary test",
            attack_hypothesis="Attack hypothesis test",
            findings="[]",
            affected_hosts="[]",
            risk_assessment="Low risk",
            recommendations="[]",
            evidence_observed="[]",
            evidence_inferred="[]",
        )

        test_pdf_path = os.path.join(config.REPORTS_FOLDER, f"test_{self.analysis_id[:8]}.pdf")
        try:
            generated_path = generate_pdf_report(
                analysis, threat_events, timeline_events, inv, traffic_stats, test_pdf_path
            )
            self.assertTrue(os.path.exists(generated_path))
            self.assertGreater(os.path.getsize(generated_path), 1000)
        finally:
            if os.path.exists(test_pdf_path):
                os.remove(test_pdf_path)


if __name__ == "__main__":
    unittest.main()
