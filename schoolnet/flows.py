"""Bidirectional, timeout-bounded flows retaining original packet references."""
from collections import defaultdict
from database.database import db
from database.models import Packet
from database.school_models import Flow, DeviceWindow, Device, CommunicationPolicy
import config

ROLES = ('Student PC', 'Teacher PC', 'Admin PC', 'School Server')
FEATURES = ['duration', 'packet_count', 'bytes_sent', 'bytes_received', 'unique_destination_ips',
            'unique_destination_ports', 'failed_connections', 'connection_frequency']

def flags(p):
    try: return int(p.tcp_flags or '0', 16)
    except ValueError: return 0

def build_flows(analysis_id, window=None):
    window = window or config.FLOW_WINDOW
    if not 5 <= window <= 3600: raise ValueError('Window must be between 5 and 3600 seconds')
    if Flow.query.filter_by(analysis_id=analysis_id).first():
        return Flow.query.filter_by(analysis_id=analysis_id).all()
    devices = {d.ip:d for d in Device.query.all()}
    policies = CommunicationPolicy.query.all()
    active, finished, windows = {}, [], {}
    packets = Packet.query.filter_by(analysis_id=analysis_id).order_by(Packet.timestamp_epoch, Packet.packet_number).yield_per(500)
    for p in packets:
        if not p.src_ip or not p.dst_ip or p.timestamp_epoch is None: continue
        transport = p.transport_protocol or ('TCP' if p.tcp_flags else ('UDP' if p.protocol == 'DNS' else p.protocol))
        ends = sorted([(p.src_ip,p.src_port or 0),(p.dst_ip,p.dst_port or 0)])
        bucket = int(p.timestamp_epoch // window) * window
        key = (tuple(ends),transport,bucket)
        f = active.get(key)
        if f and p.timestamp_epoch-f['last_seen'] > config.FLOW_IDLE_TIMEOUT:
            finished.append(f); f=None
        if not f:
            # SYN-ACK or a DNS response reveals initiator even in partial captures.
            reverse = flags(p)&18 == 18 or p.dns_is_response is True
            f = dict(analysis_id=analysis_id,src_ip=p.dst_ip if reverse else p.src_ip,
                     dst_ip=p.src_ip if reverse else p.dst_ip,src_port=p.dst_port if reverse else p.src_port,
                     dst_port=p.src_port if reverse else p.dst_port,protocol=transport,
                     first_seen=p.timestamp_epoch,last_seen=p.timestamp_epoch,packet_numbers=[],
                     features=dict(duration=0,packet_count=0,bytes_sent=0,bytes_received=0,
                                   failed_connections=0,connection_frequency=0),_bucket=bucket,_syn=False,_accepted=False)
            active[key]=f
        forward = p.src_ip == f['src_ip'] and p.src_port == f['src_port']
        f['last_seen']=p.timestamp_epoch; f['packet_numbers'].append(p.packet_number)
        x=f['features'];x['packet_count']+=1;x['bytes_sent' if forward else 'bytes_received']+=p.packet_length or 0
        if flags(p)&2 and not flags(p)&16 and forward: f['_syn']=True
        if flags(p)&18 == 18 and not forward: f['_accepted']=True
        if flags(p)&4 and not forward and f['_syn'] and not f['_accepted']: x['failed_connections']=1
    finished.extend(active.values())
    for f in finished:
        key=(f['src_ip'],f['_bucket'])
        w=windows.setdefault(key,dict(ips=set(),ports=set(),connections=0,packets=0,sent=0,received=0,failed=0))
        w['ips'].add(f['dst_ip']);w['ports'].add(f['dst_port']);w['connections']+=1
        for dest,src in [('packets','packet_count'),('sent','bytes_sent'),('received','bytes_received'),('failed','failed_connections')]: w[dest]+=f['features'][src]
    objects=[]
    for f in finished:
        bucket=f.pop('_bucket'); f.pop('_syn');f.pop('_accepted')
        w=windows[(f['src_ip'],bucket)];x=f['features']
        x.update(duration=f['last_seen']-f['first_seen'],unique_destination_ips=len(w['ips']),
                 unique_destination_ports=len(w['ports']-{None}),connection_frequency=w['connections']/window)
        src=devices.get(f['src_ip']);dst=devices.get(f['dst_ip'])
        f['source_role']=src.role if src else 'Unknown';f['destination_role']=dst.role if dst else 'Unknown'
        approved=any(p.source_role==f['source_role'] and p.destination_ip==f['dst_ip'] and
                     (p.destination_port is None or p.destination_port==f['dst_port']) for p in policies)
        if src and dst and src.role=='Student PC' and dst.role in ('Admin PC','School Server') and not approved:
            if w['connections']>=3:
                f['policy_finding']='Repeated student access to a registered sensitive device without an approved relationship; review legitimacy.'
        obj=Flow(**f);db.session.add(obj);objects.append(obj)
    for (ip,start),w in windows.items():
        db.session.add(DeviceWindow(analysis_id=analysis_id,ip=ip,start=start,features={
            'packet_count':w['packets'],'bytes_sent':w['sent'],'bytes_received':w['received'],
            'unique_destination_ips':len(w['ips']),'unique_destination_ports':len(w['ports']-{None}),
            'failed_connections':w['failed'],'connection_frequency':w['connections']/window}))
    db.session.commit()
    return objects
