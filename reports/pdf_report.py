"""
reports/pdf_report.py - Professional PDF investigation report using ReportLab.
"""

import json
import logging
import os
from datetime import datetime
from typing import Optional

from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate, Flowable, Frame, Image, NextPageTemplate,
    PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle,
    KeepTogether,
)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.colors import HexColor

logger = logging.getLogger(__name__)

# ─── Color Palette ──────────────────────────────────────────────────────────
DARK_BG = HexColor('#0f1117')
ACCENT = HexColor('#00b4d8')
CRITICAL_COLOR = HexColor('#ef4444')
HIGH_COLOR = HexColor('#f97316')
MEDIUM_COLOR = HexColor('#eab308')
LOW_COLOR = HexColor('#22c55e')
GRAY = HexColor('#6b7280')
LIGHT_GRAY = HexColor('#f3f4f6')
DARK_TEXT = HexColor('#111827')
WHITE = HexColor('#ffffff')
HEADER_BG = HexColor('#1e2436')


def _severity_color(severity: str):
    mapping = {
        'CRITICAL': CRITICAL_COLOR,
        'HIGH': HIGH_COLOR,
        'MEDIUM': MEDIUM_COLOR,
        'LOW': LOW_COLOR,
    }
    return mapping.get(str(severity).upper(), GRAY)


def _build_styles():
    styles = getSampleStyleSheet()
    custom = {
        'Title': ParagraphStyle(
            'Title', fontName='Helvetica-Bold', fontSize=28,
            textColor=WHITE, spaceAfter=6, alignment=TA_CENTER
        ),
        'SubTitle': ParagraphStyle(
            'SubTitle', fontName='Helvetica', fontSize=14,
            textColor=ACCENT, spaceAfter=4, alignment=TA_CENTER
        ),
        'H1': ParagraphStyle(
            'H1', fontName='Helvetica-Bold', fontSize=16,
            textColor=ACCENT, spaceAfter=6, spaceBefore=12,
            borderPad=4,
        ),
        'H2': ParagraphStyle(
            'H2', fontName='Helvetica-Bold', fontSize=13,
            textColor=DARK_TEXT, spaceAfter=4, spaceBefore=8
        ),
        'Body': ParagraphStyle(
            'Body', fontName='Helvetica', fontSize=10,
            textColor=DARK_TEXT, spaceAfter=4, leading=14
        ),
        'BodyBold': ParagraphStyle(
            'BodyBold', fontName='Helvetica-Bold', fontSize=10,
            textColor=DARK_TEXT, spaceAfter=2
        ),
        'Small': ParagraphStyle(
            'Small', fontName='Helvetica', fontSize=8,
            textColor=GRAY, spaceAfter=2
        ),
        'Code': ParagraphStyle(
            'Code', fontName='Courier', fontSize=8,
            textColor=HexColor('#1e3a5f'), spaceAfter=2,
            backColor=HexColor('#e8f4f8'), borderPad=4,
        ),
        'Warning': ParagraphStyle(
            'Warning', fontName='Helvetica-Oblique', fontSize=9,
            textColor=HexColor('#7c3aed'), spaceAfter=4
        ),
        'CoverMeta': ParagraphStyle(
            'CoverMeta', fontName='Helvetica', fontSize=11,
            textColor=HexColor('#94a3b8'), spaceAfter=6, alignment=TA_CENTER
        ),
        'SectionLabel': ParagraphStyle(
            'SectionLabel', fontName='Helvetica-Bold', fontSize=9,
            textColor=ACCENT, spaceAfter=2, spaceBefore=4
        ),
    }
    return custom


class HorizontalLine(Flowable):
    """A horizontal rule."""
    def __init__(self, width, color=ACCENT, thickness=1):
        super().__init__()
        self.width = width
        self.color = color
        self.thickness = thickness

    def draw(self):
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(self.thickness)
        self.canv.line(0, 0, self.width, 0)

    def wrap(self, *args):
        return self.width, self.thickness + 4


class ColorBlock(Flowable):
    """Colored background block for severity indicators."""
    def __init__(self, text, color, width=60, height=18):
        super().__init__()
        self.text = text
        self.color = color
        self.block_width = width
        self.block_height = height

    def draw(self):
        self.canv.setFillColor(self.color)
        self.canv.roundRect(0, 0, self.block_width, self.block_height, 4, fill=1, stroke=0)
        self.canv.setFillColor(WHITE)
        self.canv.setFont('Helvetica-Bold', 8)
        self.canv.drawCentredString(self.block_width / 2, 5, self.text)

    def wrap(self, *args):
        return self.block_width, self.block_height + 2


def generate_pdf_report(
    analysis,
    threat_events,
    timeline_events,
    investigation,
    traffic_stats: dict,
    output_path: str,
) -> str:
    """
    Generate a comprehensive PDF investigation report.
    Returns the path to the generated PDF.
    """
    try:
        doc = BaseDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2.5 * cm,
            bottomMargin=2 * cm,
            title="PCAP Investigation Report",
            author="Intelligent PCAP Investigator",
        )

        page_w, page_h = A4
        content_w = page_w - 4 * cm

        # Page templates
        cover_frame = Frame(0, 0, page_w, page_h, leftPadding=0, rightPadding=0,
                            topPadding=0, bottomPadding=0)
        body_frame = Frame(2 * cm, 2 * cm, content_w, page_h - 4.5 * cm)

        def cover_bg(canvas, doc):
            canvas.saveState()
            canvas.setFillColor(HEADER_BG)
            canvas.rect(0, 0, page_w, page_h, fill=1, stroke=0)
            canvas.setFillColor(ACCENT)
            canvas.rect(0, page_h * 0.4, page_w, 3, fill=1, stroke=0)
            canvas.restoreState()

        def normal_page(canvas, doc):
            canvas.saveState()
            # Header bar
            canvas.setFillColor(HEADER_BG)
            canvas.rect(0, page_h - 1.5 * cm, page_w, 1.5 * cm, fill=1, stroke=0)
            canvas.setFillColor(ACCENT)
            canvas.setFont('Helvetica-Bold', 9)
            canvas.drawString(2 * cm, page_h - 1 * cm, 'PCAP INVESTIGATION REPORT')
            canvas.setFillColor(WHITE)
            canvas.setFont('Helvetica', 8)
            canvas.drawRightString(page_w - 2 * cm, page_h - 1 * cm,
                                   f'Analysis: {analysis.id[:8]}...')
            # Footer
            canvas.setFillColor(LIGHT_GRAY)
            canvas.rect(0, 0, page_w, 1.2 * cm, fill=1, stroke=0)
            canvas.setFillColor(GRAY)
            canvas.setFont('Helvetica', 7)
            canvas.drawString(2 * cm, 0.5 * cm,
                               f'Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")} | '
                               f'CONFIDENTIAL — FOR INVESTIGATION USE ONLY')
            canvas.drawRightString(page_w - 2 * cm, 0.5 * cm, f'Page {doc.page}')
            canvas.restoreState()

        cover_template = PageTemplate(id='Cover', frames=[cover_frame], onPage=cover_bg)
        body_template = PageTemplate(id='Body', frames=[body_frame], onPage=normal_page)
        doc.addPageTemplates([cover_template, body_template])

        S = _build_styles()
        story = []

        # ─── COVER PAGE ────────────────────────────────────────────────────
        story.append(Spacer(1, page_h * 0.15))
        story.append(Paragraph('SCHOOLNET AI', S['Title']))
        story.append(Paragraph('Network Investigation Report', S['SubTitle']))
        story.append(Spacer(1, 1 * cm))
        story.append(HorizontalLine(content_w, color=ACCENT, thickness=2))
        story.append(Spacer(1, 0.5 * cm))

        meta_data = [
            ('PCAP File', analysis.original_filename),
            ('Analysis ID', analysis.id),
            ('Report Date', datetime.utcnow().strftime('%B %d, %Y %H:%M UTC')),
            ('Packet Count', f"{analysis.packet_count:,}"),
            ('Capture Duration', _fmt_duration(analysis.duration)),
            ('Status', analysis.status.upper()),
        ]
        for label, value in meta_data:
            story.append(Paragraph(f'<b>{label}:</b> {value}', S['CoverMeta']))

        story.append(Spacer(1, 1 * cm))

        # Severity summary on cover
        critical_ct = sum(1 for e in threat_events if e.severity == 'CRITICAL')
        high_ct = sum(1 for e in threat_events if e.severity == 'HIGH')
        medium_ct = sum(1 for e in threat_events if e.severity == 'MEDIUM')
        low_ct = sum(1 for e in threat_events if e.severity == 'LOW')

        sev_table = Table(
            [[
                _severity_cell('CRITICAL', critical_ct, CRITICAL_COLOR),
                _severity_cell('HIGH', high_ct, HIGH_COLOR),
                _severity_cell('MEDIUM', medium_ct, MEDIUM_COLOR),
                _severity_cell('LOW', low_ct, LOW_COLOR),
            ]],
            colWidths=[content_w / 4] * 4,
        )
        sev_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(sev_table)
        story.append(Spacer(1, 0.5 * cm))
        S['Small'].alignment = 1

        story.append(Paragraph(
            'CONFIDENTIAL — FOR AUTHORIZED INVESTIGATION USE ONLY',
            S['Small']
        ))

        # Switch to body template
        story.append(NextPageTemplate('Body'))
        story.append(PageBreak())

        # ─── SECTION 1: EXECUTIVE SUMMARY ─────────────────────────────────
        story.append(Paragraph('1. Executive Summary', S['H1']))
        story.append(HorizontalLine(content_w))
        story.append(Spacer(1, 0.3 * cm))
        if investigation and investigation.executive_summary:
            story.append(Paragraph(escape(investigation.executive_summary), S['Body']))
        else:
            story.append(Paragraph('Investigation report not yet generated.', S['Body']))

        if investigation and not investigation.ai_generated:
            story.append(Spacer(1, 0.3 * cm))
            story.append(Paragraph(
                'This investigation was generated using rule-based analysis '
                '(AI provider not configured).',
                S['Warning']
            ))

        story.append(Spacer(1, 0.5 * cm))

        # ─── SECTION 2: PCAP OVERVIEW ─────────────────────────────────────
        story.append(Paragraph('2. PCAP Capture Overview', S['H1']))
        story.append(HorizontalLine(content_w))
        story.append(Spacer(1, 0.3 * cm))

        overview_data = [
            ['Parameter', 'Value'],
            ['File Name', analysis.original_filename],
            ['File Size', _fmt_bytes(analysis.file_size)],
            ['Total Packets', f"{analysis.packet_count:,}"],
            ['Capture Start', _fmt_dt(analysis.start_time)],
            ['Capture End', _fmt_dt(analysis.end_time)],
            ['Duration', _fmt_duration(analysis.duration)],
            ['Unique Source IPs', str(traffic_stats.get('unique_src_ips', 'N/A'))],
            ['Unique Destination IPs', str(traffic_stats.get('unique_dst_ips', 'N/A'))],
            ['Total Traffic', _fmt_bytes(traffic_stats.get('total_bytes', 0))],
        ]
        story.append(_build_table(overview_data, content_w, header_bg=HEADER_BG))
        story.append(Spacer(1, 0.3 * cm))

        # Protocol distribution
        proto_dist = traffic_stats.get('protocol_distribution', {})
        if proto_dist:
            story.append(Paragraph('Protocol Distribution:', S['H2']))
            proto_data = [['Protocol', 'Packet Count', 'Percentage']]
            total_pkts = sum(proto_dist.values()) or 1
            for proto, count in sorted(proto_dist.items(), key=lambda x: -x[1]):
                pct = (count / total_pkts) * 100
                proto_data.append([proto, f"{count:,}", f"{pct:.1f}%"])
            story.append(_build_table(proto_data, content_w))

        story.append(PageBreak())

        # ─── SECTION 3: THREAT SUMMARY ────────────────────────────────────
        story.append(Paragraph('3. Threat Event Summary', S['H1']))
        story.append(HorizontalLine(content_w))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            f'Total detected threat indicators: <b>{len(threat_events)}</b>',
            S['Body']
        ))
        story.append(Spacer(1, 0.2 * cm))

        if threat_events:
            threat_data = [['Event Type', 'Severity', 'Source IP', 'Destination', 'Risk Score', 'Confidence']]
            for te in sorted(threat_events, key=lambda e: -(e.risk_score or 0)):
                threat_data.append([
                    te.event_type.replace('_', ' '),
                    te.severity,
                    te.source_ip or 'N/A',
                    str(te.destination_ip or 'N/A')[:20],
                    f"{te.risk_score:.0f}/100",
                    f"{(te.confidence or 0) * 100:.0f}%",
                ])
            story.append(_build_severity_table(threat_data, content_w))
        else:
            story.append(Paragraph('No threat events detected in this capture.', S['Body']))

        story.append(PageBreak())

        # ─── SECTION 4: ATTACK TIMELINE ───────────────────────────────────
        story.append(Paragraph('4. Attack Timeline (Chronological)', S['H1']))
        story.append(HorizontalLine(content_w))
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph(
            'Events marked [INFERRED] are analyst hypotheses based on observed patterns, '
            'not directly observed in the PCAP.',
            S['Warning']
        ))
        story.append(Spacer(1, 0.3 * cm))

        if timeline_events:
            for tle in sorted(timeline_events, key=lambda e: e.sequence_order):
                inferred_tag = ' [INFERRED]' if tle.is_inferred else ''
                ts_str = _fmt_dt(tle.timestamp) if tle.timestamp else 'N/A'
                sev_color = _severity_color(tle.severity)

                row_content = [
                    KeepTogether([
                        Paragraph(f'<b>● {ts_str}</b>{inferred_tag}', S['SectionLabel']),
                        Paragraph(f'<b>{tle.title}</b> — {tle.phase or ""} | '
                                  f'Severity: {tle.severity}', S['BodyBold']),
                        Paragraph(tle.description[:300] if tle.description else '', S['Body']),
                        Spacer(1, 0.2 * cm),
                        HorizontalLine(content_w - 1 * cm, color=LIGHT_GRAY),
                        Spacer(1, 0.1 * cm),
                    ])
                ]
                story.extend(row_content)
        else:
            story.append(Paragraph('No timeline events to display.', S['Body']))

        story.append(PageBreak())

        # ─── SECTION 5: DETAILED FINDINGS ─────────────────────────────────
        story.append(Paragraph('5. Detailed Findings', S['H1']))
        story.append(HorizontalLine(content_w))
        story.append(Spacer(1, 0.2 * cm))

        for i, te in enumerate(sorted(threat_events, key=lambda e: -(e.risk_score or 0)), 1):
            evidence = {}
            if te.evidence:
                try:
                    evidence = json.loads(te.evidence)
                except Exception:
                    pass
            pkt_numbers = []
            if te.packet_numbers:
                try:
                    pkt_numbers = json.loads(te.packet_numbers)
                except Exception:
                    pass

            finding_block = [
                Spacer(1, 0.2 * cm),
                Paragraph(f'5.{i} {te.event_type.replace("_", " ")} — {te.severity}', S['H2']),
                Paragraph(f'<b>Risk Score:</b> {te.risk_score:.0f}/100 | '
                           f'<b>Confidence:</b> {(te.confidence or 0)*100:.0f}% | '
                           f'<b>Status:</b> {te.status}', S['Small']),
                Spacer(1, 0.1 * cm),
                Paragraph(f'<b>When:</b> {_fmt_dt(te.timestamp)}', S['Body']),
                Paragraph(f'<b>Source:</b> {te.source_ip or "N/A"} | '
                           f'<b>Destination:</b> {te.destination_ip or "N/A"} | '
                           f'<b>Protocol:</b> {te.protocol or "N/A"}', S['Body']),
                Spacer(1, 0.1 * cm),
                Paragraph('<b>Description:</b>', S['BodyBold']),
                Paragraph(escape(te.description or 'N/A'), S['Body']),
            ]

            if evidence:
                finding_block.append(Paragraph('<b>Evidence:</b>', S['BodyBold']))
                for k, v in evidence.items():
                    if k == 'reasons' and isinstance(v, list):
                        for reason in v:
                            finding_block.append(Paragraph(f'• {reason}', S['Body']))
                    elif k not in ('time_range_start', 'time_range_end'):
                        val_str = str(v)[:200] if not isinstance(v, list) else str(v[:5])
                        finding_block.append(Paragraph(f'• {k}: {val_str}', S['Body']))

            if pkt_numbers:
                finding_block.append(Paragraph(
                    f'<b>Related Packet Numbers:</b> {str(pkt_numbers[:20])[1:-1]}...',
                    S['Small']
                ))

            # Wireshark filter
            ws_filter = _wireshark_filter(te.event_type, te.source_ip, te.destination_ip)
            finding_block.append(Paragraph('<b>Wireshark Validation Filter:</b>', S['BodyBold']))
            finding_block.append(Paragraph(ws_filter, S['Code']))
            finding_block.append(HorizontalLine(content_w, color=LIGHT_GRAY))

            story.extend(finding_block)

        story.append(PageBreak())

        # ─── SECTION 6: AI INVESTIGATION ──────────────────────────────────
        story.append(Paragraph('6. AI-Assisted Investigation', S['H1']))
        story.append(HorizontalLine(content_w))
        story.append(Spacer(1, 0.2 * cm))

        if investigation:
            ai_label = 'AI-Generated' if investigation.ai_generated else 'Rule-Based Fallback'
            story.append(Paragraph(f'Investigation Method: <b>{ai_label}</b>', S['Small']))
            story.append(Spacer(1, 0.2 * cm))

            story.append(Paragraph('Attack Hypothesis:', S['H2']))
            story.append(Paragraph(escape(investigation.attack_hypothesis or 'N/A'), S['Body']))
            story.append(Spacer(1, 0.3 * cm))

            story.append(Paragraph('Risk Assessment:', S['H2']))
            story.append(Paragraph(escape(investigation.risk_assessment or 'N/A'), S['Body']))
        else:
            story.append(Paragraph('Investigation not yet generated.', S['Body']))

        story.append(PageBreak())

        # ─── SECTION 7: EVIDENCE vs INFERENCE ────────────────────────────
        story.append(Paragraph('7. Evidence vs. Inference', S['H1']))
        story.append(HorizontalLine(content_w))
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph(
            'This section explicitly separates directly observed PCAP evidence from analyst inferences.',
            S['Body']
        ))
        story.append(Spacer(1, 0.3 * cm))

        if investigation:
            obs = _safe_json_list(investigation.evidence_observed)
            inf = _safe_json_list(investigation.evidence_inferred)

            story.append(Paragraph('Observed Evidence (directly in PCAP):', S['H2']))
            if obs:
                for item in obs:
                    story.append(Paragraph(f'• {str(item)[:300]}', S['Body']))
            else:
                story.append(Paragraph('No specific observations recorded.', S['Body']))

            story.append(Spacer(1, 0.3 * cm))
            story.append(Paragraph('Analyst Inferences (interpretation):', S['H2']))
            if inf:
                for item in inf:
                    story.append(Paragraph(f'▶ {str(item)[:300]}', S['Warning']))
            else:
                story.append(Paragraph('No analyst inferences recorded.', S['Body']))

        story.append(PageBreak())

        # ─── SECTION 8: RECOMMENDATIONS ──────────────────────────────────
        story.append(Paragraph('8. Recommendations', S['H1']))
        story.append(HorizontalLine(content_w))
        story.append(Spacer(1, 0.2 * cm))

        if investigation:
            recs = _safe_json_list(investigation.recommendations)
            if recs:
                for i, rec in enumerate(recs, 1):
                    if isinstance(rec, dict):
                        priority = rec.get('priority', 'MEDIUM')
                        pcolor = _severity_color(priority)
                        story.append(KeepTogether([
                            Paragraph(
                                f'<b>{i}. {rec.get("action", "Recommendation")}</b> '
                                f'[Priority: {priority}]',
                                S['BodyBold']
                            ),
                            Paragraph(rec.get('detail', ''), S['Body']),
                            Spacer(1, 0.15 * cm),
                        ]))
                    else:
                        story.append(Paragraph(f'{i}. {str(rec)[:300]}', S['Body']))
            else:
                story.append(Paragraph('No recommendations generated.', S['Body']))

        story.append(PageBreak())

        # ─── SECTION 9: TECHNICAL APPENDIX ───────────────────────────────
        story.append(Paragraph('9. Technical Appendix', S['H1']))
        story.append(HorizontalLine(content_w))
        story.append(Spacer(1, 0.2 * cm))

        story.append(Paragraph('Top Source IP Addresses:', S['H2']))
        top_src = traffic_stats.get('top_src_ips', {})
        if top_src:
            src_data = [['Source IP', 'Packet Count']]
            for ip, count in sorted(top_src.items(), key=lambda x: -x[1])[:10]:
                src_data.append([ip, f"{count:,}"])
            story.append(_build_table(src_data, content_w))

        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph('Top Destination Ports:', S['H2']))
        top_ports = traffic_stats.get('top_dst_ports', {})
        if top_ports:
            port_data = [['Destination Port', 'Packet Count', 'Common Service']]
            for port, count in sorted(top_ports.items(), key=lambda x: -x[1])[:10]:
                port_data.append([str(port), f"{count:,}", _port_service(str(port))])
            story.append(_build_table(port_data, content_w))

        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph(
            'Disclaimer: This report was generated by an automated analysis tool. '
            'Findings should be validated by a qualified security analyst. '
            'The presence of threat indicators does not confirm malicious activity without '
            'additional investigation. Always comply with applicable laws and regulations '
            'when conducting network investigations.',
            S['Small']
        ))

        # Hybrid findings are additive; legacy report sections above remain available.
        from database.school_models import AnalysisContext, Incident, Anomaly, Flow
        context = __import__('database.database', fromlist=['db']).db.session.get(AnalysisContext, analysis.id)
        incidents = Incident.query.filter_by(analysis_id=analysis.id).all()
        story.append(PageBreak())
        story.append(Paragraph('10. SchoolNet Hybrid Investigation', S['H1']))
        if context:
            story.append(Paragraph('Capture provenance: ' + escape(context.provenance or 'unknown'), S['Body']))
            story.append(Paragraph('PCAP SHA-256: ' + escape(context.pcap_sha256 or 'Unavailable'), S['Small']))
            story.append(Paragraph('ML status: ' + escape(context.ml_status or 'Not evaluated'), S['Body']))
        story.append(Paragraph('Anomaly scores measure baseline deviation, not attack probability. Incident risk is separate from confirmation status.', S['Body']))
        for incident in incidents:
            story.append(Paragraph(escape(f'{incident.id[:8]} | {incident.risk} | {incident.source_ip} | {incident.confirmation}'), S['H2']))
            for reason in incident.reasons or []:
                story.append(Paragraph(escape(reason), S['Body']))
            for evidence in incident.evidence or []:
                story.append(Paragraph(escape(f'{evidence["reference"]}: {evidence["description"]}'), S['Small']))
            if incident.ai_result:
                story.append(Paragraph('Investigation interpretation: ' + escape(incident.ai_result.get('incident_summary', '')), S['Body']))
        story.append(Paragraph('Report hash and RSA signature are detached in the report manifest, computed after finalizing these PDF bytes.', S['Small']))

        doc.build(story)
        logger.info("PDF report generated: %s", output_path)
        return output_path

    except Exception as e:
        logger.error("PDF generation failed: %s", e, exc_info=True)
        raise


# ─── Helper functions ─────────────────────────────────────────────────────────

def _fmt_dt(dt) -> str:
    if dt is None:
        return 'N/A'
    if isinstance(dt, str):
        return dt
    return dt.strftime('%Y-%m-%d %H:%M:%S UTC')


def _fmt_duration(seconds) -> str:
    if not seconds:
        return '0s'
    s = float(seconds)
    if s < 60:
        return f'{s:.2f}s'
    if s < 3600:
        return f'{int(s//60)}m {int(s%60)}s'
    return f'{int(s//3600)}h {int((s%3600)//60)}m'


def _fmt_bytes(num) -> str:
    if not num:
        return '0 B'
    n = float(num)
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024:
            return f'{n:.1f} {unit}'
        n /= 1024
    return f'{n:.1f} TB'


def _severity_cell(label: str, count: int, color) -> Table:
    data = [[Paragraph(f'<b>{count}</b>', ParagraphStyle(
        'sc', fontName='Helvetica-Bold', fontSize=20, textColor=WHITE, alignment=TA_CENTER
    ))], [Paragraph(label, ParagraphStyle(
        'sl', fontName='Helvetica', fontSize=8, textColor=WHITE, alignment=TA_CENTER
    ))]]
    t = Table(data, colWidths=[3.5 * cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), color),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ROUNDEDCORNERS', [6]),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    return t


def _build_table(data, width, header_bg=HEADER_BG) -> Table:
    col_count = len(data[0])
    col_w = width / col_count
    t = Table(data, colWidths=[col_w] * col_count)
    style = [
        ('BACKGROUND', (0, 0), (-1, 0), header_bg),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, LIGHT_GRAY]),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e5e7eb')),
    ]
    t.setStyle(TableStyle(style))
    return t


def _build_severity_table(data, width) -> Table:
    col_widths = [width * 0.2, width * 0.1, width * 0.15, width * 0.2, width * 0.15, width * 0.1]
    # Normalize widths
    total = sum(col_widths)
    col_widths = [w * width / total for w in col_widths]
    t = Table(data, colWidths=col_widths)
    style = [
        ('BACKGROUND', (0, 0), (-1, 0), HEADER_BG),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 8),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e5e7eb')),
    ]
    # Color severity column
    for row_idx, row in enumerate(data[1:], 1):
        sev = str(row[1]).upper() if len(row) > 1 else 'LOW'
        bg = _severity_color(sev)
        style.append(('BACKGROUND', (1, row_idx), (1, row_idx), bg))
        style.append(('TEXTCOLOR', (1, row_idx), (1, row_idx), WHITE))
        style.append(('FONTNAME', (1, row_idx), (1, row_idx), 'Helvetica-Bold'))

    t.setStyle(TableStyle(style))
    return t


def _safe_json_list(val) -> list:
    if not val:
        return []
    if isinstance(val, list):
        return val
    try:
        result = json.loads(val)
        return result if isinstance(result, list) else [result]
    except Exception:
        return [str(val)]


def _wireshark_filter(event_type: str, src_ip: str, dst_ip: str) -> str:
    if event_type == 'PORT_SCAN':
        f = f'ip.src == {src_ip} && tcp.flags.syn == 1 && tcp.flags.ack == 0'
    elif event_type == 'SSH_BRUTE_FORCE':
        f = f'ip.src == {src_ip} && tcp.port == 22'
    elif event_type == 'DNS_ANOMALY':
        f = f'ip.src == {src_ip} && dns'
    elif event_type == 'ICMP_ANOMALY':
        f = f'ip.src == {src_ip} && icmp'
    elif event_type == 'HTTP_ANOMALY':
        f = f'ip.src == {src_ip} && http'
    else:
        f = f'ip.src == {src_ip}' if src_ip else 'ip'
    return f


def _port_service(port: str) -> str:
    mapping = {
        '22': 'SSH', '23': 'Telnet', '25': 'SMTP', '53': 'DNS',
        '80': 'HTTP', '110': 'POP3', '143': 'IMAP', '443': 'HTTPS',
        '445': 'SMB', '3306': 'MySQL', '3389': 'RDP', '5432': 'PostgreSQL',
        '6379': 'Redis', '8080': 'HTTP-Alt', '8443': 'HTTPS-Alt',
        '4444': 'Metasploit (common)', '31337': 'Back Orifice (common backdoor)',
    }
    return mapping.get(str(port), 'Unknown')
