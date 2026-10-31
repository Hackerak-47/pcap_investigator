"""Correlate evidence by source and bounded time; never automatically confirm attacks."""
import json,uuid,ipaddress
from database.database import db
from database.models import ThreatEvent
from database.school_models import Flow, Anomaly, Incident, Device

def correlate_incidents(analysis_id):
    observations=[]
    for e in ThreatEvent.query.filter_by(analysis_id=analysis_id).all():
        evidence=json.loads(e.evidence or '{}')
        observations.append(dict(kind='rule',reference=f'event:{e.id}',source=e.source_ip,destination=e.destination_ip,
            time=e.timestamp_epoch,end=evidence.get('time_range_end',e.timestamp_epoch),type=e.event_type,
            score=e.risk_score,description=e.description,packets=json.loads(e.packet_numbers or '[]')))
    anomalies={a.flow_id:a for a in Anomaly.query.filter_by(analysis_id=analysis_id,unusual=True).all()}
    for f in Flow.query.filter_by(analysis_id=analysis_id).all():
        a=anomalies.get(f.id)
        for kind,description in ([('ml','Unusual flow relative to baseline; not a confirmed attack')] if a else [])+([('policy',f.policy_finding)] if f.policy_finding else []):
            observations.append(dict(kind=kind,reference=f'flow:{f.id}',source=f.src_ip,destination=f.dst_ip,time=f.first_seen,
                end=f.last_seen,type='ML_ANOMALY' if kind=='ml' else 'ROLE_POLICY',score=a.score if kind=='ml' else None,
                description=description,packets=f.packet_numbers))
    observations.sort(key=lambda x:(x['source'] or '',x['time'] or 0,x['reference'],x['kind']))
    groups=[]
    for item in observations:
        if groups and item['source']==groups[-1][0]['source'] and item['time'] is not None and groups[-1][0]['time'] is not None and item['time']-groups[-1][0]['time']<=600:
            groups[-1].append(item)
        else: groups.append([item])
    devices={d.ip:d for d in Device.query.all()}
    for group in groups:
        unique={(x['kind'],x['reference']):x for x in group};group=list(unique.values())
        source=group[0]['source'];refs=sorted(x['kind']+x['reference'] for x in group)
        incident_id=str(uuid.uuid5(uuid.NAMESPACE_URL,analysis_id+'|'+str(source)+'|'+str(group[0]['time'])))
        rules=[x for x in group if x['kind']=='rule'];ml=any(x['kind']=='ml' for x in group);policy=any(x['kind']=='policy' for x in group)
        high=any((x['score'] or 0)>=60 for x in rules) or (len({x['type'] for x in rules})>=2 and (ml or policy))
        risk='High' if high else ('Medium' if rules or policy else 'Low')
        reasons=[]
        if rules: reasons.append(f'{len(rules)} rule-based indicator(s); highest rule score {max(x["score"] or 0 for x in rules):.0f}/100.')
        if ml: reasons.append('Baseline deviation adds investigation context; anomaly score is not severity or attack probability.')
        if policy: reasons.append('Repeated access outside an approved school-device relationship.')
        if not rules and not policy: reasons.append('ML-only observation remains low-priority and unconfirmed.')
        obj=db.session.get(Incident,incident_id)
        if not obj: obj=Incident(id=incident_id,analysis_id=analysis_id);db.session.add(obj)
        obj.source_ip=source;obj.destination_ip=', '.join(sorted({x['destination'] for x in group if x['destination']}))[:200]
        obj.device_role=devices[source].role if source in devices else 'Unknown'
        times=[x['time'] for x in group if x['time'] is not None];ends=[x['end'] for x in group if x['end'] is not None]
        obj.first_seen=min(times) if times else None;obj.last_seen=max(ends) if ends else obj.first_seen
        obj.risk=risk;obj.reasons=reasons;obj.evidence=group
    db.session.commit()
