"""Additive SchoolNet tables; original packet and report records remain intact."""
import uuid
from datetime import datetime
from database.database import db

def uid():
    return str(uuid.uuid4())

class AnalysisContext(db.Model):
    __tablename__ = 'analysis_context'
    analysis_id = db.Column(db.String(36), db.ForeignKey('analyses.id'), primary_key=True)
    pcap_sha256 = db.Column(db.String(64))
    provenance = db.Column(db.String(30), default='uploaded')
    stage = db.Column(db.String(100), default='Queued')
    progress = db.Column(db.Integer, default=0)
    window_seconds = db.Column(db.Integer, default=60)
    ml_status = db.Column(db.String(200), default='Model not trained')
    warnings = db.Column(db.JSON, default=list)

class Device(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(30), nullable=False)
    notes = db.Column(db.String(500), default='')

class CommunicationPolicy(db.Model):
    __tablename__ = 'communication_policies'
    id = db.Column(db.Integer, primary_key=True)
    source_role = db.Column(db.String(30), nullable=False)
    destination_ip = db.Column(db.String(45), nullable=False)
    destination_port = db.Column(db.Integer, nullable=True)
    description = db.Column(db.String(200), default='Approved communication')

class Flow(db.Model):
    __tablename__ = 'flows'
    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.String(36), db.ForeignKey('analyses.id'), index=True, nullable=False)
    src_ip = db.Column(db.String(45))
    dst_ip = db.Column(db.String(45))
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))
    first_seen = db.Column(db.Float)
    last_seen = db.Column(db.Float)
    features = db.Column(db.JSON, default=dict)
    packet_numbers = db.Column(db.JSON, default=list)
    source_role = db.Column(db.String(30), default='Unknown')
    destination_role = db.Column(db.String(30), default='Unknown')
    policy_finding = db.Column(db.String(500))

class DeviceWindow(db.Model):
    __tablename__ = 'device_windows'
    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.String(36), db.ForeignKey('analyses.id'), index=True)
    ip = db.Column(db.String(45))
    start = db.Column(db.Float)
    features = db.Column(db.JSON)

class ModelRecord(db.Model):
    __tablename__ = 'ml_models'
    id = db.Column(db.String(36), primary_key=True, default=uid)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    metadata_json = db.Column(db.JSON)
    active = db.Column(db.Boolean, default=True)

class Anomaly(db.Model):
    __tablename__ = 'anomalies'
    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.String(36), db.ForeignKey('analyses.id'), index=True)
    flow_id = db.Column(db.Integer, db.ForeignKey('flows.id'))
    model_id = db.Column(db.String(36), db.ForeignKey('ml_models.id'))
    score = db.Column(db.Float)
    decision = db.Column(db.Float)
    unusual = db.Column(db.Boolean)
    explanation = db.Column(db.JSON)

class Incident(db.Model):
    __tablename__ = 'incidents'
    id = db.Column(db.String(36), primary_key=True, default=uid)
    analysis_id = db.Column(db.String(36), db.ForeignKey('analyses.id'), index=True)
    source_ip = db.Column(db.String(45))
    destination_ip = db.Column(db.String(200))
    device_role = db.Column(db.String(30))
    first_seen = db.Column(db.Float)
    last_seen = db.Column(db.Float)
    risk = db.Column(db.String(10))
    reasons = db.Column(db.JSON)
    evidence = db.Column(db.JSON)
    status = db.Column(db.String(30), default='open')
    confirmation = db.Column(db.String(30), default='unconfirmed')
    ai_result = db.Column(db.JSON)

class ChatMessage(db.Model):
    __tablename__ = 'chat_messages'
    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.String(36), db.ForeignKey('analyses.id'), index=True)
    role = db.Column(db.String(20))
    content = db.Column(db.Text)
    references = db.Column(db.JSON, default=list)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SecureReport(db.Model):
    __tablename__ = 'secure_reports'
    id = db.Column(db.String(36), primary_key=True, default=uid)
    analysis_id = db.Column(db.String(36), db.ForeignKey('analyses.id'), index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sha256 = db.Column(db.String(64))
    encrypted = db.Column(db.Boolean, default=False)
    signature = db.Column(db.Text)
    public_key = db.Column(db.Text)
    filename = db.Column(db.String(100))
