"""
database/models.py - SQLAlchemy ORM models define tabke and structure 
"""

from datetime import datetime
from database.database import db


class Analysis(db.Model):
    __tablename__ = "analyses"

    id = db.Column(db.String(36), primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)
    duration = db.Column(db.Float, default=0.0)          # seconds
    packet_count = db.Column(db.Integer, default=0)
    status = db.Column(db.String(50), default="pending")  # pending|processing|complete|error
    error_message = db.Column(db.Text, nullable=True)

    # Relationships
    packets = db.relationship("Packet", backref="analysis", lazy="dynamic",
                              cascade="all, delete-orphan")
    threat_events = db.relationship("ThreatEvent", backref="analysis", lazy="dynamic",
                                    cascade="all, delete-orphan")
    timeline_events = db.relationship("TimelineEvent", backref="analysis", lazy="dynamic",
                                      cascade="all, delete-orphan")
    investigation = db.relationship("Investigation", backref="analysis", uselist=False,
                                    cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "filename": self.original_filename,
            "file_size": self.file_size,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": self.duration,
            "packet_count": self.packet_count,
            "status": self.status,
            "error_message": self.error_message,
        }


class Packet(db.Model):
    __tablename__ = "packets"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    analysis_id = db.Column(db.String(36), db.ForeignKey("analyses.id"), nullable=False)
    packet_number = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=True)
    timestamp_epoch = db.Column(db.Float, nullable=True)

    # Layer 2
    src_mac = db.Column(db.String(20), nullable=True)
    dst_mac = db.Column(db.String(20), nullable=True)

    # Layer 3
    src_ip = db.Column(db.String(45), nullable=True)
    dst_ip = db.Column(db.String(45), nullable=True)

    # Layer 4
    src_port = db.Column(db.Integer, nullable=True)
    dst_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(20), nullable=True)
    packet_length = db.Column(db.Integer, nullable=True)
    tcp_flags = db.Column(db.String(20), nullable=True)

    # Application layer
    dns_query = db.Column(db.String(512), nullable=True)
    dns_response = db.Column(db.String(512), nullable=True)
    http_host = db.Column(db.String(255), nullable=True)
    http_method = db.Column(db.String(20), nullable=True)
    http_uri = db.Column(db.String(512), nullable=True)
    tls_sni = db.Column(db.String(255), nullable=True)
    transport_protocol = db.Column(db.String(20), nullable=True)
    tls_version = db.Column(db.String(30), nullable=True)
    tls_cipher = db.Column(db.String(100), nullable=True)
    tls_handshake = db.Column(db.String(100), nullable=True)
    dns_is_response = db.Column(db.Boolean, nullable=True)
    icmp_type = db.Column(db.Integer, nullable=True)
    icmp_code = db.Column(db.Integer, nullable=True)

    __table_args__ = (
        db.Index("ix_packets_analysis_id", "analysis_id"),
        db.Index("ix_packets_src_ip", "src_ip"),
        db.Index("ix_packets_dst_ip", "dst_ip"),
        db.Index("ix_packets_protocol", "protocol"),
        db.Index("ix_packets_timestamp", "timestamp_epoch"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "analysis_id": self.analysis_id,
            "packet_number": self.packet_number,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_length": self.packet_length,
            "tcp_flags": self.tcp_flags,
            "dns_query": self.dns_query,
            "dns_response": self.dns_response,
            "http_host": self.http_host,
            "http_method": self.http_method,
            "http_uri": self.http_uri,
            "tls_sni": self.tls_sni,
            "icmp_type": self.icmp_type,
            "icmp_code": self.icmp_code,
        }


class ThreatEvent(db.Model):
    __tablename__ = "threat_events"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    analysis_id = db.Column(db.String(36), db.ForeignKey("analyses.id"), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=True)
    timestamp_epoch = db.Column(db.Float, nullable=True)
    event_type = db.Column(db.String(50), nullable=False)
    source_ip = db.Column(db.String(45), nullable=True)
    destination_ip = db.Column(db.String(45), nullable=True)
    protocol = db.Column(db.String(20), nullable=True)
    severity = db.Column(db.String(20), default="MEDIUM")   # LOW|MEDIUM|HIGH|CRITICAL
    confidence = db.Column(db.Float, default=0.5)           # 0.0-1.0
    risk_score = db.Column(db.Float, default=50.0)          # 0-100
    description = db.Column(db.Text, nullable=True)
    evidence = db.Column(db.Text, nullable=True)            # JSON string
    packet_numbers = db.Column(db.Text, nullable=True)      # JSON list
    status = db.Column(db.String(20), default="open")       # open|investigating|resolved

    __table_args__ = (
        db.Index("ix_threat_events_analysis_id", "analysis_id"),
        db.Index("ix_threat_events_event_type", "event_type"),
        db.Index("ix_threat_events_severity", "severity"),
        db.Index("ix_threat_events_source_ip", "source_ip"),
    )

    def to_dict(self):
        import json
        return {
            "id": self.id,
            "analysis_id": self.analysis_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "timestamp_epoch": self.timestamp_epoch,
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "severity": self.severity,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "description": self.description,
            "evidence": json.loads(self.evidence) if self.evidence else {},
            "packet_numbers": json.loads(self.packet_numbers) if self.packet_numbers else [],
            "status": self.status,
        }


class TimelineEvent(db.Model):
    __tablename__ = "timeline_events"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    analysis_id = db.Column(db.String(36), db.ForeignKey("analyses.id"), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=True)
    timestamp_epoch = db.Column(db.Float, nullable=True)
    sequence_order = db.Column(db.Integer, default=0)
    event_type = db.Column(db.String(50), nullable=False)
    phase = db.Column(db.String(50), nullable=True)          # RECONNAISSANCE|EXPLOITATION|etc.
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), default="MEDIUM")
    source_ip = db.Column(db.String(45), nullable=True)
    destination_ip = db.Column(db.String(45), nullable=True)
    threat_event_id = db.Column(db.Integer, db.ForeignKey("threat_events.id"), nullable=True)
    is_inferred = db.Column(db.Boolean, default=False)       # True = analyst inference

    __table_args__ = (
        db.Index("ix_timeline_events_analysis_id", "analysis_id"),
        db.Index("ix_timeline_events_timestamp", "timestamp_epoch"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "analysis_id": self.analysis_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "timestamp_epoch": self.timestamp_epoch,
            "sequence_order": self.sequence_order,
            "event_type": self.event_type,
            "phase": self.phase,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "threat_event_id": self.threat_event_id,
            "is_inferred": self.is_inferred,
        }


class Investigation(db.Model):
    __tablename__ = "investigations"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    analysis_id = db.Column(db.String(36), db.ForeignKey("analyses.id"), nullable=False, unique=True)
    executive_summary = db.Column(db.Text, nullable=True)
    attack_hypothesis = db.Column(db.Text, nullable=True)
    findings = db.Column(db.Text, nullable=True)             # JSON string
    affected_hosts = db.Column(db.Text, nullable=True)       # JSON string
    risk_assessment = db.Column(db.Text, nullable=True)
    recommendations = db.Column(db.Text, nullable=True)      # JSON string
    evidence_observed = db.Column(db.Text, nullable=True)    # JSON string
    evidence_inferred = db.Column(db.Text, nullable=True)    # JSON string
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    ai_generated = db.Column(db.Boolean, default=False)
    ai_model = db.Column(db.String(100), nullable=True)

    def to_dict(self):
        import json
        def safe_json(val):
            if not val:
                return []
            try:
                return json.loads(val)
            except Exception:
                return val

        return {
            "id": self.id,
            "analysis_id": self.analysis_id,
            "executive_summary": self.executive_summary,
            "attack_hypothesis": self.attack_hypothesis,
            "findings": safe_json(self.findings),
            "affected_hosts": safe_json(self.affected_hosts),
            "risk_assessment": self.risk_assessment,
            "recommendations": safe_json(self.recommendations),
            "evidence_observed": safe_json(self.evidence_observed),
            "evidence_inferred": safe_json(self.evidence_inferred),
            "generated_at": self.generated_at.isoformat() if self.generated_at else None,
            "ai_generated": self.ai_generated,
            "ai_model": self.ai_model,
        }
