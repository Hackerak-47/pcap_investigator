"""SchoolNet pages
Connects dashboard actions and browser requests to backend functions.
For example, receiving a PCAP upload or requesting an incident page.
and APIs extend the original Flask application."""
import ipaddress,io,json,os
from collections import Counter
from datetime import datetime,timezone
from flask import Blueprint,render_template,request,redirect,url_for,flash,jsonify,abort,session,send_file
from werkzeug.security import check_password_hash
from database.database import db
from database.models import Analysis,Packet,ThreatEvent
from database.school_models import *
from schoolnet.flows import ROLES
import config

bp=Blueprint('schoolnet',__name__,url_prefix='/schoolnet')

def selected():
    aid=request.args.get('analysis_id') or request.form.get('analysis_id')
    if aid:
        a=db.session.get(Analysis,aid)
        if not a: abort(404)
        session['selected_analysis_id'] = a.id
        return a
    remembered = session.get('selected_analysis_id')
    a = db.session.get(Analysis, remembered) if remembered else None
    return a or Analysis.query.order_by(Analysis.created_at.desc()).first()

def page(template,**kwargs):
    a=kwargs.pop('analysis',None) or selected()
    return render_template(template,analysis=a,analyses=Analysis.query.order_by(Analysis.created_at.desc()).all(),
        context=db.session.get(AnalysisContext,a.id) if a else None,**kwargs)

def require_analysis():
    a=selected()
    if not a: abort(400,description='Upload a capture first')
    return a

def serial(obj):
    return {c.name:(getattr(obj,c.name).isoformat() if isinstance(getattr(obj,c.name),datetime) else getattr(obj,c.name)) for c in obj.__table__.columns}

@bp.app_template_filter('epoch')
def epoch(value):
    if value is None:
        return 'Unknown'
    if isinstance(value, datetime):
        return value.strftime('%d %b %Y · %H:%M:%S UTC')
    try:
        return datetime.fromtimestamp(float(value), timezone.utc).strftime('%d %b %Y · %H:%M:%S UTC')
    except Exception:
        return str(value)

@bp.route('/')
def overview():
    a=selected();incidents=Incident.query.filter_by(analysis_id=a.id).all() if a else []
    flows=Flow.query.filter_by(analysis_id=a.id).all() if a else []
    anomalies=Anomaly.query.filter_by(analysis_id=a.id,unusual=True).count() if a else 0
    from schoolnet.protocols import protocol_summary
    protocols=protocol_summary(a.id)['protocols'] if a else {}
    devices=set(p[0] for p in db.session.query(Packet.src_ip).filter_by(analysis_id=a.id).distinct() if p[0]) | set(p[0] for p in db.session.query(Packet.dst_ip).filter_by(analysis_id=a.id).distinct() if p[0]) if a else set()
    activity=Counter()
    for f in flows: activity[f.src_ip]+=f.features['bytes_sent'];activity[f.dst_ip]+=f.features['bytes_received']
    source_available = bool(a and os.path.isfile(os.path.join(config.UPLOAD_FOLDER, a.filename)))
    return page('school_overview.html',analysis=a,incidents=sorted(incidents,key=lambda x:x.first_seen or 0,reverse=True),
        totals={'packets':a.packet_count if a else 0,'devices':len(devices),'incidents':len(incidents),'anomalies':anomalies,'high':sum(i.risk=='High' for i in incidents)},
        protocols=protocols,risk_counts=dict(Counter(i.risk for i in incidents)),activity=dict(activity.most_common(8)),flow_count=len(flows),
        source_available=source_available)

@bp.route('/analysis')
def analysis_page():
    a=selected();flows=Flow.query.filter_by(analysis_id=a.id).limit(200).all() if a else []
    return page('school_analysis.html',analysis=a,flows=flows,max_mb=config.MAX_UPLOAD_MB)

@bp.route('/status/<aid>')
def status(aid):
    a=db.session.get(Analysis,aid)
    if not a: abort(404)
    ctx=db.session.get(AnalysisContext,aid)
    return jsonify(status=a.status,stage=ctx.stage if ctx else a.status,progress=ctx.progress if ctx else 0,packets=a.packet_count,error=a.error_message)

@bp.route('/enrich',methods=['POST'])
def enrich():
    a=require_analysis()
    if a.status!='complete':
        flash('This capture is still processing. Wait for parsing to finish before extending the analysis.','warning')
        return redirect(url_for('schoolnet.overview',analysis_id=a.id))
    path=os.path.join(config.UPLOAD_FOLDER,a.filename)
    if not os.path.exists(path):
        flash('The raw PCAP for this imported demo is no longer in the local uploads folder. Stored packets and rule evidence remain available; re-upload the same PCAP to create a new analysis with flow and ML results.','warning')
    else:
        try:
            from schoolnet.pipeline import enrich_analysis
            from schoolnet.incidents import correlate_incidents
            enrich_analysis(a.id,path);correlate_incidents(a.id)
            ctx=db.session.get(AnalysisContext,a.id)
            if ctx:
                ctx.progress=100;ctx.stage='Complete'
            db.session.commit()
            flash('Flow, anomaly and incident analysis updated.','success')
        except Exception as exc:
            db.session.rollback()
            flash('Extended analysis could not finish: '+type(exc).__name__+'. Stored packet and rule evidence are unchanged.','error')
    return redirect(url_for('schoolnet.overview',analysis_id=a.id))

@bp.route('/devices',methods=['GET','POST'])
def devices():
    if request.method=='POST':
        try:
            if request.form.get('action')=='delete':
                d=db.session.get(Device,int(request.form['id']))
                if not d: abort(404)
                db.session.delete(d)
            else:
                ip=str(ipaddress.ip_address(request.form['ip'].strip()));role=request.form['role'];name=request.form['name'].strip()
                if role not in ROLES or not name or len(name)>100: raise ValueError('Valid device name and role required')
                ident=request.form.get('id');d=db.session.get(Device,int(ident)) if ident else Device()
                if d is None: abort(404)
                duplicate=Device.query.filter_by(ip=ip).first()
                if duplicate and duplicate.id!=d.id: raise ValueError('IP address already registered')
                d.ip=ip;d.name=name;d.role=role;d.notes=request.form.get('notes','')[:500];db.session.add(d)
            db.session.commit();flash('Device registry updated. Existing analysis role snapshots are preserved.','success')
        except (ValueError,KeyError) as exc: db.session.rollback();flash(str(exc),'error')
        return redirect(url_for('schoolnet.devices',analysis_id=request.form.get('analysis_id') or None))
    a=selected();registered={d.ip:d for d in Device.query.all()};activity={}
    if a:
        for p in Packet.query.filter_by(analysis_id=a.id).yield_per(500):
            for ip in set([p.src_ip,p.dst_ip])-{None}:
                x=activity.setdefault(ip,{'bytes':0,'protocols':set()});x['bytes']+=p.packet_length or 0;x['protocols'].add(p.protocol or 'Unknown')
    anomalies=set();risks={}
    if a:
        for anomaly in Anomaly.query.filter_by(analysis_id=a.id,unusual=True):
            f=db.session.get(Flow,anomaly.flow_id);anomalies.add(f.src_ip)
        for i in Incident.query.filter_by(analysis_id=a.id):
            if {'Low':0,'Medium':1,'High':2}[i.risk] > {'Low':0,'Medium':1,'High':2}.get(risks.get(i.source_ip),-1): risks[i.source_ip]=i.risk
    return page('school_devices.html',analysis=a,registered=registered,activity=activity,ips=sorted(set(registered)|set(activity)),roles=ROLES,anomalous=anomalies,risks=risks,policies=CommunicationPolicy.query.all())

@bp.route('/policies',methods=['POST'])
def policies():
    try:
        if request.form.get('action')=='delete':
            p=db.session.get(CommunicationPolicy,int(request.form['id']))
            if p: db.session.delete(p)
        else:
            ip=str(ipaddress.ip_address(request.form['destination_ip']));role=request.form['source_role'];port=request.form.get('destination_port')
            port=int(port) if port else None
            if role not in ROLES or (port is not None and not 1<=port<=65535): raise ValueError('Invalid role or port')
            db.session.add(CommunicationPolicy(source_role=role,destination_ip=ip,destination_port=port))
        db.session.commit()
        a=selected()
        if a:
            from schoolnet.flows import refresh_policy_findings
            from schoolnet.incidents import correlate_incidents
            changed=refresh_policy_findings(a.id);correlate_incidents(a.id)
            flash(f'Communication policy saved. Policy evaluation refreshed for this capture ({changed} flow finding(s) changed); rule and ML evidence were preserved.','success')
        else:
            flash('Communication policy saved. Select a capture to reevaluate its policy findings.','success')
    except ValueError as exc: flash(str(exc),'error')
    return redirect(url_for('schoolnet.devices',analysis_id=request.form.get('analysis_id') or None))

@bp.route('/anomalies')
def anomalies():
    a=selected();rows=[]
    if a:
        rows=[(x,db.session.get(Flow,x.flow_id)) for x in Anomaly.query.filter_by(analysis_id=a.id).order_by(Anomaly.score.desc()).all()]
    return page('school_anomalies.html',analysis=a,rows=rows,model=ModelRecord.query.filter_by(active=True).first())

@bp.route('/train',methods=['POST'])
def train():
    try:
        if request.form.get('baseline_confirm')!='yes': raise ValueError('Explicitly confirm the selected captures represent your normal baseline')
        from schoolnet.ml import train_baseline
        train_baseline(request.form.getlist('baseline_ids'),float(request.form.get('contamination','.05')),int(request.form.get('estimators','200')))
        flash('Baseline model trained and saved. Evaluate using a different capture.','success')
    except (ValueError,TypeError) as exc: flash(str(exc),'error')
    return redirect(url_for('schoolnet.anomalies',analysis_id=request.form.get('analysis_id') or None))

@bp.route('/incidents')
def incidents():
    a=selected();items=Incident.query.filter_by(analysis_id=a.id).all() if a else []
    if request.args.get('risk'): items=[i for i in items if i.risk==request.args['risk']]
    if request.args.get('status'): items=[i for i in items if i.status==request.args['status']]
    return page('school_incidents.html',analysis=a,incidents=items)

@bp.route('/incident/<iid>',methods=['GET','POST'])
def incident(iid):
    i=db.session.get(Incident,iid)
    if not i: abort(404)
    if request.method=='POST':
        if request.form.get('action')=='investigate':
            from schoolnet.ai_engine import investigate
            investigate(i)
        else:
            status=request.form.get('status');confirmation=request.form.get('confirmation')
            if status not in ('open','investigating','resolved') or confirmation not in ('unconfirmed','confirmed','benign'): abort(400)
            i.status=status;i.confirmation=confirmation;db.session.commit()
        return redirect(url_for('schoolnet.incident',iid=i.id))
    return page('school_incident.html',analysis=db.session.get(Analysis,i.analysis_id),incident=i)

@bp.route('/investigator')
def investigator():
    a=selected();items=Incident.query.filter_by(analysis_id=a.id).all() if a else []
    return page('school_investigator.html',analysis=a,incidents=items)

@bp.route('/assistant',methods=['GET','POST'])
def assistant():
    a=selected()
    if request.method=='POST':
        if not a: return jsonify(error='Upload a capture first'),400
        from schoolnet.ai_engine import chat
        try: return jsonify(chat(a.id,(request.get_json(silent=True) or {}).get('question','')))
        except ValueError as exc: return jsonify(error=str(exc)),400
    return page('school_assistant.html',analysis=a,messages=ChatMessage.query.filter_by(analysis_id=a.id).order_by(ChatMessage.id).all() if a else [])

@bp.route('/protocols')
def protocols():
    from schoolnet.protocols import protocol_summary
    a=selected();return page('school_protocols.html',analysis=a,protocols=protocol_summary(a.id) if a else None)

@bp.route('/reports',methods=['GET','POST'])
def reports():
    a=selected()
    if request.method=='POST':
        try:
            if not a: raise ValueError('Upload a capture first')
            from schoolnet.crypto import create_report
            create_report(a.id,request.form.get('encrypt')=='yes',request.form.get('sign')=='yes');flash('Report version finalized.','success')
        except Exception as exc: flash('Report generation failed: '+str(exc)[:200],'error')
        return redirect(url_for('schoolnet.reports',analysis_id=a.id if a else None))
    # Keep this workspace focused on the report currently being worked on.
    reports=SecureReport.query.filter_by(analysis_id=a.id).order_by(SecureReport.created_at.desc()).limit(1).all() if a else []
    return page('school_reports.html',analysis=a,reports=reports)

@bp.route('/report/<rid>/<action>',methods=['POST'])
def report_action(rid,action):
    r=db.session.get(SecureReport,rid)
    if not r: abort(404)
    from schoolnet.crypto import verify_report,report_bytes,simulate_tamper_test
    if action=='verify': return jsonify(verify_report(r))
    if action=='verify-upload':
        uploaded=request.files.get('report_file')
        if not uploaded or not uploaded.filename:
            return jsonify(valid=False,message='Choose a report file to verify.'),400
        limit=config.MAX_UPLOAD_MB*1024*1024
        blob=uploaded.stream.read(limit+1)
        if len(blob)>limit:
            return jsonify(valid=False,message=f'Report exceeds the {config.MAX_UPLOAD_MB} MB verification limit.'),400
        from schoolnet.crypto import verify_uploaded_report
        return jsonify(verify_uploaded_report(r,uploaded.filename,blob))
    if action=='tamper-test': return jsonify(simulate_tamper_test(r))
    if action=='download': return send_file(os.path.join(config.REPORTS_FOLDER,r.filename),as_attachment=True,download_name=r.filename,mimetype='application/octet-stream' if r.filename.endswith('.sna') else 'application/pdf')
    if action=='decrypt':
        try: return send_file(io.BytesIO(report_bytes(r)),as_attachment=True,download_name=r.id+'.pdf',mimetype='application/pdf')
        except Exception: abort(400,description='Cannot decrypt: key unavailable, incorrect or file altered')
    if action=='manifest':
        payload={'report_id':r.id,'sha256':r.sha256,'signature':r.signature,'public_key':r.public_key,'algorithm':'RSA-PSS/SHA-256'}
        return send_file(io.BytesIO(json.dumps(payload,indent=2).encode()),as_attachment=True,download_name=r.id+'.json',mimetype='application/json')
    abort(404)

@bp.route('/verify-pcap',methods=['POST'])
def verify_pcap():
    a=require_analysis();ctx=db.session.get(AnalysisContext,a.id)
    from schoolnet.pipeline import file_hash
    path=os.path.join(config.UPLOAD_FOLDER,a.filename)
    return jsonify(status='missing' if not ctx or not ctx.pcap_sha256 or not os.path.exists(path) else ('valid' if file_hash(path)==ctx.pcap_sha256 else 'invalid'))

@bp.route('/settings')
def settings():
    is_gemini = (config.AI_PROVIDER or 'gemini').lower() in ('gemini', 'google')
    api_ready = bool((is_gemini and config.GEMINI_API_KEY) or (config.AI_PROVIDER in ('openai', 'compatible') and config.OPENAI_API_KEY))
    active_model = config.GEMINI_MODEL if is_gemini else config.OPENAI_MODEL
    return page('school_settings.html', settings={
        'window': config.FLOW_WINDOW,
        'idle': config.FLOW_IDLE_TIMEOUT,
        'provider': 'Google Gemini' if is_gemini else (config.AI_PROVIDER or 'Offline').upper(),
        'model': active_model,
        'api_ready': api_ready,
        'encryption_ready': bool(config.REPORT_AES_KEY),
        'signing_ready': bool(config.SIGNING_KEY_PATH),
        'networks': config.SCHOOL_NETWORKS
    })

@bp.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        if config.ADMIN_PASSWORD_HASH and check_password_hash(config.ADMIN_PASSWORD_HASH,request.form.get('password','')):
            session.clear();session['admin']=True;return redirect(url_for('schoolnet.overview'))
        flash('Incorrect administrator password.','error')
    return render_template('school_login.html')

@bp.route('/logout',methods=['POST'])
def logout():
    session.clear();return redirect(url_for('schoolnet.login'))
