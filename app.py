"""
app.py - Main Flask application for the Intelligent PCAP Investigator.

Routes:
    GET  /                          - Home/landing page
    GET  /upload                    - Upload page
    POST /upload                    - Handle file upload and start analysis
    GET  /dashboard/<analysis_id>   - Analysis dashboard
    GET  /packets/<analysis_id>     - Packet explorer
    GET  /events/<analysis_id>      - Threat events list
    GET  /timeline/<analysis_id>    - Attack timeline
    GET  /investigation/<analysis_id> - AI investigation report
    POST /investigation/<analysis_id>/generate - Generate/regenerate investigation
    GET  /report/<analysis_id>      - View PDF report metadata
    GET  /report/<analysis_id>/download - Download PDF report
    GET  /api/analysis/<id>         - JSON: analysis metadata
    GET  /api/events/<id>           - JSON: threat events
    GET  /api/timeline/<id>         - JSON: timeline events
    GET  /api/stats/<id>            - JSON: traffic statistics
    GET  /about                     - About page
    GET  /demo                      - Load demo analysis
"""

import json
import logging
import os
import threading
import uuid
from datetime import datetime

from flask import (
    Flask, abort, flash, jsonify, redirect, render_template,
    request, send_file, url_for,
)
from werkzeug.exceptions import RequestEntityTooLarge

import config
from database.database import db, init_app as init_db
from database.models import Analysis, Investigation, Packet, ThreatEvent, TimelineEvent
from utils.validators import allowed_file, secure_filename_safe, validate_pcap_file
from utils.helpers import format_bytes, format_duration, severity_badge_class, get_wireshark_filter

# ─── App Factory ─────────────────────────────────────────────────────────────

def _setup_logging():
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(config.LOG_FILE, encoding="utf-8"),
        ],
    )


def create_app(test_config=None):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = config.SECRET_KEY
    app.config["SQLALCHEMY_DATABASE_URI"] = config.DATABASE_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH
    app.config["UPLOAD_FOLDER"] = config.UPLOAD_FOLDER
    app.config["TEMPLATES_AUTO_RELOAD"] = True

    # Register template filters
    app.jinja_env.filters["format_bytes"] = format_bytes
    app.jinja_env.filters["format_duration"] = format_duration
    app.jinja_env.filters["severity_badge"] = severity_badge_class
    app.jinja_env.filters["number_format"] = lambda val: f"{int(val):,}" if val is not None else "0"
    app.jinja_env.filters["format_number"] = lambda val: f"{int(val):,}" if val is not None else "0"
    def _ws_filter(e):
        if hasattr(e, "event_type"):
            return get_wireshark_filter(e.event_type or "", e.source_ip or "", e.destination_ip or "")
        elif isinstance(e, dict):
            return get_wireshark_filter(e.get("event_type", ""), e.get("source_ip", ""), e.get("destination_ip", ""))
        return ""
    app.jinja_env.filters["wireshark_filter"] = _ws_filter

    if test_config:
        app.config.update(test_config)
    init_db(app)
    _setup_logging()

    return app


app = create_app()
logger = logging.getLogger(__name__)


# ─── Analysis Pipeline ───────────────────────────────────────────────────────

def run_analysis_pipeline(analysis_id: str, filepath: str):
    """
    Background thread that executes the full PCAP analysis pipeline:
    Parse → Detect → Score → Correlate → Timeline → Store
    """
    with app.app_context():
        import asyncio
        asyncio.set_event_loop(asyncio.new_event_loop())
        analysis = db.session.get(Analysis, analysis_id)
        if not analysis:
            logger.error("Analysis %s not found in DB", analysis_id)
            return

        try:
            analysis.status = "processing"
            db.session.commit()

            # 1. Parse PCAP
            logger.info("[%s] Step 1: Parsing PCAP", analysis_id)
            from analysis.pcap_parser import parse_pcap
            summary = parse_pcap(filepath, analysis_id, app)

            analysis.packet_count = summary["packet_count"]
            analysis.start_time = summary["start_time"]
            analysis.end_time = summary["end_time"]
            analysis.duration = summary["duration"]
            db.session.commit()

            if summary["packet_count"] == 0:
                analysis.status = "complete"
                analysis.error_message = "No packets could be extracted from this file."
                db.session.commit()
                return

            from schoolnet.pipeline import enrich_analysis
            enrich_analysis(analysis_id, filepath)

            # 2. Detect threats
            logger.info("[%s] Step 2: Running threat detectors", analysis_id)
            from analysis.threat_detector import run_all_detectors
            raw_events = run_all_detectors(analysis_id)

            # 3. Score events
            logger.info("[%s] Step 3: Scoring events", analysis_id)
            from analysis.threat_scorer import rescore_events
            scored_events = rescore_events(raw_events)

            # 4. Correlate events
            logger.info("[%s] Step 4: Correlating events", analysis_id)
            from analysis.correlator import correlate_events
            correlated = correlate_events(scored_events)

            # 5. Persist threat events
            logger.info("[%s] Step 5: Storing %d threat events", analysis_id, len(correlated))
            for ev in correlated:
                te = ThreatEvent(**{k: v for k, v in ev.items()
                                   if k not in ("phase", "correlation_group", "correlated_with")})
                db.session.add(te)
            db.session.commit()

            # 6. Build timeline
            logger.info("[%s] Step 6: Building timeline", analysis_id)
            from analysis.timeline_builder import build_timeline
            stored_events = db.session.query(ThreatEvent).filter_by(analysis_id=analysis_id).all()
            timeline_events = build_timeline(analysis_id, stored_events)
            for tle in timeline_events:
                db.session.add(tle)
            db.session.commit()

            from schoolnet.incidents import correlate_incidents
            correlate_incidents(analysis_id)

            # 7. Generate deterministic investigation (auto)
            logger.info("[%s] Step 7: Generating investigation", analysis_id)
            _generate_investigation(analysis_id)

            analysis.status = "complete"
            from database.school_models import AnalysisContext
            context = db.session.get(AnalysisContext, analysis_id)
            if context:
                context.stage, context.progress = "Complete", 100
            db.session.commit()
            logger.info("[%s] Analysis complete", analysis_id)

        except Exception as e:
            logger.error("[%s] Analysis failed: %s", analysis_id, e, exc_info=True)
            db.session.rollback()
            with app.app_context():
                a = db.session.get(Analysis, analysis_id)
                if a:
                    a.status = "error"
                    a.error_message = str(e)[:500]
                    db.session.commit()


def _generate_investigation(analysis_id: str):
    """Generate and store investigation report for an analysis."""
    analysis = db.session.get(Analysis, analysis_id)
    threat_events = db.session.query(ThreatEvent).filter_by(analysis_id=analysis_id).all()
    timeline_events = db.session.query(TimelineEvent).filter_by(analysis_id=analysis_id).all()

    from analysis.traffic_analyzer import get_traffic_stats
    traffic_stats = get_traffic_stats(analysis_id)

    from ai.investigator import generate_investigation
    result = generate_investigation(analysis, threat_events, timeline_events, traffic_stats)

    # Remove or replace existing
    existing = db.session.query(Investigation).filter_by(analysis_id=analysis_id).first()
    if existing:
        db.session.delete(existing)
        db.session.commit()

    inv = Investigation(
        analysis_id=analysis_id,
        executive_summary=result.get("executive_summary"),
        attack_hypothesis=result.get("attack_hypothesis"),
        findings=json.dumps(result.get("findings", []), default=str),
        affected_hosts=json.dumps(result.get("affected_hosts", []), default=str),
        risk_assessment=result.get("risk_assessment"),
        recommendations=json.dumps(result.get("recommendations", []), default=str),
        evidence_observed=json.dumps(result.get("evidence_observed", []), default=str),
        evidence_inferred=json.dumps(result.get("evidence_inferred", []), default=str),
        generated_at=datetime.utcnow(),
        ai_generated=result.get("ai_generated", False),
        ai_model=result.get("ai_model", "rule-based"),
    )
    db.session.add(inv)
    db.session.commit()


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("schoolnet.overview"))


def legacy_index():
    recent = (
        db.session.query(Analysis)
        .order_by(Analysis.created_at.desc())
        .limit(5)
        .all()
    )
    return render_template("index.html", recent_analyses=recent)


@app.route("/upload", methods=["GET"])
def upload_page():
    return render_template("upload.html")


@app.route("/upload", methods=["POST"])
def upload_file():
    if "pcap_file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for("upload_page"))

    file = request.files["pcap_file"]
    if file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("upload_page"))

    if not allowed_file(file.filename):
        flash("Invalid file type. Only .pcap and .pcapng files are accepted.", "error")
        return redirect(url_for("upload_page"))

    # Generate unique safe filename
    safe_name = secure_filename_safe(file.filename)
    filepath = os.path.join(config.UPLOAD_FOLDER, safe_name)

    try:
        file.save(filepath)
    except Exception as e:
        logger.error("Failed to save upload: %s", e)
        flash("Failed to save uploaded file.", "error")
        return redirect(url_for("upload_page"))

    # Validate magic bytes
    is_valid, err_msg = validate_pcap_file(filepath, config.MAX_UPLOAD_MB)
    if not is_valid:
        os.remove(filepath)
        flash(f"File validation failed: {err_msg}", "error")
        return redirect(url_for("upload_page"))

    file_size = os.path.getsize(filepath)

    # Create analysis record
    analysis_id = str(uuid.uuid4())
    analysis = Analysis(
        id=analysis_id,
        filename=safe_name,
        original_filename=file.filename,
        file_size=file_size,
        status="pending",
        created_at=datetime.utcnow(),
    )
    db.session.add(analysis)
    db.session.commit()

    from schoolnet.pipeline import initialize_context
    initialize_context(analysis_id, filepath, request.form.get("provenance", "uploaded"))

    # Start background analysis
    t = threading.Thread(
        target=run_analysis_pipeline,
        args=(analysis_id, filepath),
        daemon=True,
    )
    t.start()

    if request.headers.get("Accept") == "application/json":
        return jsonify({"id": analysis_id, "url": url_for("schoolnet.analysis_page", analysis_id=analysis_id)}), 202
    flash(f"File '{file.filename}' uploaded successfully. Analysis started.", "success")
    return redirect(url_for("schoolnet.analysis_page", analysis_id=analysis_id))


@app.route("/dashboard/<analysis_id>")
def dashboard(analysis_id):
    analysis = _get_analysis_or_404(analysis_id)
    threat_events = (
        db.session.query(ThreatEvent)
        .filter_by(analysis_id=analysis_id)
        .order_by(ThreatEvent.risk_score.desc())
        .all()
    )

    from analysis.traffic_analyzer import get_traffic_stats
    stats = get_traffic_stats(analysis_id) if analysis.status == "complete" else {}

    severity_counts = _count_by_severity(threat_events)
    event_type_counts = _count_by_type(threat_events)

    return render_template(
        "dashboard.html",
        analysis=analysis,
        threat_events=threat_events[:20],
        stats=stats,
        severity_counts=severity_counts,
        event_type_counts=event_type_counts,
        ai_provider=config.AI_PROVIDER,
    )


@app.route("/packets/<analysis_id>")
def packets(analysis_id):
    analysis = _get_analysis_or_404(analysis_id)
    page = request.args.get("page", 1, type=int)
    per_page = config.PACKETS_PER_PAGE

    query = db.session.query(Packet).filter_by(analysis_id=analysis_id)

    # Filters
    src_ip = request.args.get("src_ip", "").strip()
    dst_ip = request.args.get("dst_ip", "").strip()
    protocol = request.args.get("protocol", "").strip()
    dst_port = request.args.get("dst_port", "").strip()

    if src_ip:
        query = query.filter(Packet.src_ip == src_ip)
    if dst_ip:
        query = query.filter(Packet.dst_ip == dst_ip)
    if protocol:
        query = query.filter(Packet.protocol == protocol)
    if dst_port and dst_port.isdigit():
        query = query.filter(Packet.dst_port == int(dst_port))

    total = query.count()
    packets_page = (
        query.order_by(Packet.packet_number)
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    # Get distinct protocols for filter dropdown
    protocols = [
        r[0] for r in
        db.session.query(Packet.protocol).filter_by(analysis_id=analysis_id).distinct().all()
        if r[0]
    ]

    total_pages = (total + per_page - 1) // per_page

    return render_template(
        "packets.html",
        analysis=analysis,
        packets=packets_page,
        page=page,
        total_pages=total_pages,
        total=total,
        protocols=sorted(protocols),
        filters={"src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol, "dst_port": dst_port},
    )


@app.route("/events/<analysis_id>")
def events(analysis_id):
    analysis = _get_analysis_or_404(analysis_id)

    query = db.session.query(ThreatEvent).filter_by(analysis_id=analysis_id)

    severity_filter = request.args.get("severity", "").strip().upper()
    event_type_filter = request.args.get("event_type", "").strip()
    src_ip_filter = request.args.get("src_ip", "").strip()

    if severity_filter:
        query = query.filter(ThreatEvent.severity == severity_filter)
    if event_type_filter:
        query = query.filter(ThreatEvent.event_type == event_type_filter)
    if src_ip_filter:
        query = query.filter(ThreatEvent.source_ip == src_ip_filter)

    threat_events = query.order_by(ThreatEvent.risk_score.desc()).all()

    event_types = [
        r[0] for r in
        db.session.query(ThreatEvent.event_type).filter_by(analysis_id=analysis_id).distinct().all()
        if r[0]
    ]

    return render_template(
        "events.html",
        analysis=analysis,
        threat_events=threat_events,
        event_types=sorted(event_types),
        filters={
            "severity": severity_filter,
            "event_type": event_type_filter,
            "src_ip": src_ip_filter,
        },
    )


@app.route("/timeline/<analysis_id>")
def timeline(analysis_id):
    analysis = _get_analysis_or_404(analysis_id)
    timeline_events = (
        db.session.query(TimelineEvent)
        .filter_by(analysis_id=analysis_id)
        .order_by(TimelineEvent.sequence_order)
        .all()
    )

    severity_filter = request.args.get("severity", "").strip().upper()
    if severity_filter:
        timeline_events = [e for e in timeline_events if e.severity == severity_filter]

    return render_template(
        "timeline.html",
        analysis=analysis,
        timeline_events=timeline_events,
        filters={"severity": severity_filter},
    )


@app.route("/investigation/<analysis_id>")
def investigation(analysis_id):
    analysis = _get_analysis_or_404(analysis_id)
    inv = db.session.query(Investigation).filter_by(analysis_id=analysis_id).first()
    threat_events = (
        db.session.query(ThreatEvent)
        .filter_by(analysis_id=analysis_id)
        .order_by(ThreatEvent.risk_score.desc())
        .all()
    )

    return render_template(
        "investigation.html",
        analysis=analysis,
        investigation=inv,
        threat_events=threat_events,
        ai_provider=config.AI_PROVIDER,
    )


@app.route("/investigation/<analysis_id>/generate", methods=["POST"])
def generate_investigation_route(analysis_id):
    analysis = _get_analysis_or_404(analysis_id)
    if analysis.status != "complete":
        flash("Analysis must be complete before generating investigation.", "warning")
        return redirect(url_for("investigation", analysis_id=analysis_id))

    try:
        with app.app_context():
            _generate_investigation(analysis_id)
        flash("Investigation report generated successfully.", "success")
    except Exception as e:
        logger.error("Investigation generation failed: %s", e)
        flash(f"Investigation generation failed: {str(e)[:200]}", "error")

    return redirect(url_for("investigation", analysis_id=analysis_id))


@app.route("/report/<analysis_id>")
def report_view(analysis_id):
    analysis = _get_analysis_or_404(analysis_id)
    inv = db.session.query(Investigation).filter_by(analysis_id=analysis_id).first()
    return render_template("report.html", analysis=analysis, investigation=inv)


@app.route("/report/<analysis_id>/download")
def report_download(analysis_id):
    analysis = _get_analysis_or_404(analysis_id)
    if analysis.status != "complete":
        flash("Analysis must be complete to generate a PDF report.", "warning")
        return redirect(url_for("dashboard", analysis_id=analysis_id))

    pdf_filename = f"pcap_report_{analysis_id[:8]}.pdf"
    pdf_path = os.path.join(config.REPORTS_FOLDER, pdf_filename)

    try:
        threat_events = (
            db.session.query(ThreatEvent).filter_by(analysis_id=analysis_id).all()
        )
        timeline_events = (
            db.session.query(TimelineEvent).filter_by(analysis_id=analysis_id)
            .order_by(TimelineEvent.sequence_order).all()
        )
        inv = db.session.query(Investigation).filter_by(analysis_id=analysis_id).first()

        from analysis.traffic_analyzer import get_traffic_stats
        stats = get_traffic_stats(analysis_id)

        from reports.pdf_report import generate_pdf_report
        generate_pdf_report(analysis, threat_events, timeline_events, inv, stats, pdf_path)

    except Exception as e:
        logger.error("PDF generation failed: %s", e, exc_info=True)
        flash(f"PDF generation failed: {str(e)[:200]}", "error")
        return redirect(url_for("report_view", analysis_id=analysis_id))

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f"PCAP_Investigation_{analysis_id[:8]}.pdf",
        mimetype="application/pdf",
    )


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/analyses")
def analyses_list():
    all_analyses = (
        db.session.query(Analysis)
        .order_by(Analysis.created_at.desc())
        .all()
    )
    return render_template("analyses.html", analyses=all_analyses)


# ─── JSON API Endpoints ───────────────────────────────────────────────────────

@app.route("/api/analysis/<analysis_id>")
def api_analysis(analysis_id):
    analysis = _get_analysis_or_404(analysis_id)
    return jsonify(analysis.to_dict())


@app.route("/api/analysis/<analysis_id>/status")
def api_analysis_status(analysis_id):
    analysis = _get_analysis_or_404(analysis_id)
    return jsonify({
        "status": analysis.status,
        "packet_count": analysis.packet_count,
        "error_message": analysis.error_message,
    })


@app.route("/api/events/<analysis_id>")
def api_events(analysis_id):
    _get_analysis_or_404(analysis_id)
    events = (
        db.session.query(ThreatEvent)
        .filter_by(analysis_id=analysis_id)
        .order_by(ThreatEvent.risk_score.desc())
        .all()
    )
    return jsonify([e.to_dict() for e in events])


@app.route("/api/timeline/<analysis_id>")
def api_timeline(analysis_id):
    _get_analysis_or_404(analysis_id)
    events = (
        db.session.query(TimelineEvent)
        .filter_by(analysis_id=analysis_id)
        .order_by(TimelineEvent.sequence_order)
        .all()
    )
    return jsonify([e.to_dict() for e in events])


@app.route("/api/stats/<analysis_id>")
def api_stats(analysis_id):
    _get_analysis_or_404(analysis_id)
    from analysis.traffic_analyzer import get_traffic_stats
    return jsonify(get_traffic_stats(analysis_id))


@app.route("/api/packets/<analysis_id>")
def api_packets(analysis_id):
    _get_analysis_or_404(analysis_id)
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 200)
    pkts = (
        db.session.query(Packet)
        .filter_by(analysis_id=analysis_id)
        .order_by(Packet.packet_number)
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return jsonify([p.to_dict() for p in pkts])


# ─── Demo / Sample Data ───────────────────────────────────────────────────────

@app.route("/demo")
def load_demo():
    """Load a synthetic demonstration analysis."""
    from sample_data.generate_demo import create_demo_analysis
    try:
        analysis_id = create_demo_analysis(app, db)
        flash("Demo analysis loaded successfully. This is synthetic sample data.", "info")
        return redirect(url_for("dashboard", analysis_id=analysis_id))
    except Exception as e:
        logger.error("Demo load failed: %s", e, exc_info=True)
        flash(f"Failed to load demo: {str(e)[:200]}", "error")
        return redirect(url_for("index"))


@app.route("/download-sample-pcap")
def download_sample_pcap():
    """Download the generated cyber attack sample PCAP file."""
    pcap_path = os.path.join(config.BASE_DIR, "sample_data", "cyber_attack_incident.pcap")
    if not os.path.isfile(pcap_path):
        from sample_data.create_sample_pcap import generate_incident_pcap
        generate_incident_pcap(pcap_path)
    return send_file(
        pcap_path,
        as_attachment=True,
        download_name="cyber_attack_incident.pcap",
        mimetype="application/vnd.tcpdump.pcap"
    )


# ─── Error Handlers ───────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", error_code=404,
                           message="Page not found."), 404


@app.errorhandler(413)
@app.errorhandler(RequestEntityTooLarge)
def too_large(e):
    flash(f"Upload too large. Maximum file size is {config.MAX_UPLOAD_MB} MB.", "error")
    return redirect(url_for("upload_page"))


@app.errorhandler(500)
def server_error(e):
    logger.error("Internal server error: %s", e)
    return render_template("error.html", error_code=500,
                           message="Internal server error. Check logs for details."), 500


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _get_analysis_or_404(analysis_id: str) -> Analysis:
    analysis = db.session.get(Analysis, analysis_id)
    if not analysis:
        abort(404)
    return analysis


def _count_by_severity(events) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for e in events:
        sev = (e.severity or "LOW").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _count_by_type(events) -> dict:
    counts = {}
    for e in events:
        et = e.event_type or "UNKNOWN"
        counts[et] = counts.get(et, 0) + 1
    return counts


from schoolnet.routes import bp as schoolnet_bp
app.register_blueprint(schoolnet_bp)
from schoolnet.auth import install_security
install_security(app)

if __name__ == "__main__":
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
