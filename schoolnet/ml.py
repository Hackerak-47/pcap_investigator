"""Separate baseline training and evaluation, with versioned trusted model artifacts."""
import hashlib, os, uuid
from datetime import datetime, timezone
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from database.database import db
from database.school_models import Flow, ModelRecord, Anomaly, AnalysisContext
from schoolnet.flows import FEATURES
import config

def matrix(flows):
    return np.array([[f.features.get(k,np.nan) if f.features.get(k) is not None else np.nan for k in FEATURES] for f in flows],dtype=float)

def train_baseline(analysis_ids, contamination=.05, estimators=200):
    if not 0 < contamination <= .5: raise ValueError('Contamination must be greater than 0 and at most 0.5')
    if not 50 <= estimators <= 1000: raise ValueError('Trees must be between 50 and 1000')
    flows=Flow.query.filter(Flow.analysis_id.in_(analysis_ids)).all()
    if len(flows)<20: raise ValueError('Select baseline captures with at least 20 flows')
    contexts=[db.session.get(AnalysisContext,i) for i in analysis_ids]
    if any(c is None or not c.pcap_sha256 for c in contexts): raise ValueError('Baseline requires original capture hashes')
    x=matrix(flows)
    pipe=Pipeline([('missing',SimpleImputer(strategy='median',keep_empty_features=True)),
                   ('scale',StandardScaler()),('forest',IsolationForest(n_estimators=estimators,contamination=contamination,random_state=42,n_jobs=1))])
    pipe.fit(x)
    med=np.nanmedian(x,axis=0);q=np.nanpercentile(x,[25,75],axis=0)
    model_id=str(uuid.uuid4());os.makedirs(config.MODEL_FOLDER,exist_ok=True)
    path=os.path.join(config.MODEL_FOLDER,model_id+'.joblib')
    joblib.dump({'pipeline':pipe,'median':med,'spread':np.maximum(q[1]-q[0],1),'features':FEATURES},path)
    import sklearn
    meta={'training_ids':analysis_ids,'training_hashes':[c.pcap_sha256 for c in contexts],
          'training_flows':len(flows),'contamination':contamination,'estimators':estimators,
          'features':FEATURES,'sklearn':sklearn.__version__,'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest(),
          'synthetic':any(c.provenance=='synthetic' for c in contexts),
          'window_seconds':contexts[0].window_seconds}
    if len({c.window_seconds for c in contexts})!=1: raise ValueError('Baseline captures must use the same feature window')
    ModelRecord.query.update({'active':False});db.session.add(ModelRecord(id=model_id,metadata_json=meta));db.session.commit()
    return meta

def score_analysis(analysis_id):
    ctx=db.session.get(AnalysisContext,analysis_id);model=ModelRecord.query.filter_by(active=True).first()
    if not model: ctx.ml_status='Model not trained';db.session.commit();return
    meta=model.metadata_json
    if analysis_id in meta['training_ids'] or ctx.pcap_sha256 in meta['training_hashes']:
        ctx.ml_status='Baseline capture — evaluation excluded to prevent data leakage';db.session.commit();return
    if ctx.window_seconds!=meta['window_seconds']:
        ctx.ml_status='Feature window differs from trained model';db.session.commit();return
    path=os.path.join(config.MODEL_FOLDER,model.id+'.joblib')
    if hashlib.sha256(open(path,'rb').read()).hexdigest()!=meta['sha256']: raise ValueError('Model artifact integrity failure')
    bundle=joblib.load(path)  # Only application-created artifacts; no model upload endpoint.
    flows=Flow.query.filter_by(analysis_id=analysis_id).all()
    if not flows: ctx.ml_status='No eligible IP flows';db.session.commit();return
    x=matrix(flows);pipe=bundle['pipeline'];scores=-pipe.score_samples(x);decisions=pipe.decision_function(x)
    Anomaly.query.filter_by(analysis_id=analysis_id).delete()
    for f,row,score,decision in zip(flows,x,scores,decisions):
        deviations=np.abs(row-bundle['median'])/bundle['spread']
        explanation=[{'feature':FEATURES[j],'observed':float(row[j]),'baseline_median':float(bundle['median'][j]),
                      'relative_deviation':round(float(deviations[j]),2)} for j in np.argsort(deviations)[-3:][::-1] if np.isfinite(row[j])]
        db.session.add(Anomaly(analysis_id=analysis_id,flow_id=f.id,model_id=model.id,score=float(score),decision=float(decision),unusual=bool(decision<0),explanation=explanation))
    ctx.ml_status='Scored against '+('synthetic demonstration baseline' if meta['synthetic'] else 'selected baseline')
    db.session.commit()
