import hashlib
from database.database import db
from database.school_models import AnalysisContext
import config

def file_hash(path):
    h=hashlib.sha256()
    with open(path,'rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''): h.update(block)
    return h.hexdigest()

def initialize_context(analysis_id,filepath,provenance='uploaded'):
    ctx=db.session.get(AnalysisContext,analysis_id)
    if not ctx:
        ctx=AnalysisContext(analysis_id=analysis_id,pcap_sha256=file_hash(filepath),
                            provenance='synthetic' if provenance=='synthetic' else 'uploaded',window_seconds=config.FLOW_WINDOW)
        db.session.add(ctx);db.session.commit()
    return ctx

def enrich_analysis(analysis_id,filepath):
    ctx=initialize_context(analysis_id,filepath)
    ctx.stage='Aggregating flows';ctx.progress=45;db.session.commit()
    from schoolnet.flows import build_flows
    build_flows(analysis_id,ctx.window_seconds)
    ctx.stage='Evaluating baseline model';ctx.progress=65;db.session.commit()
    from schoolnet.ml import score_analysis
    try: score_analysis(analysis_id)
    except Exception as exc:
        db.session.rollback();ctx.ml_status='ML unavailable: '+type(exc).__name__;db.session.commit()
    ctx.stage='Rules and incident correlation';ctx.progress=80;db.session.commit()
