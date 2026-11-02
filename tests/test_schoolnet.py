"""SchoolNet regression coverage: isolated databases, real synthetic PCAPs, failure cases."""
import base64,json,os,tempfile,uuid
from pathlib import Path
from unittest.mock import patch
import pytest
from flask import Flask
from database.database import db,init_app
from database.models import Analysis,Packet,ThreatEvent
from database.school_models import *
from schoolnet.flows import build_flows,refresh_policy_findings
from schoolnet.ml import train_baseline,score_analysis
from schoolnet.incidents import correlate_incidents
from schoolnet.crypto import encrypt,decrypt,sign,verify_signature
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidTag
import config

@pytest.fixture
def app(tmp_path,monkeypatch):
    a=Flask(__name__);a.config.update(TESTING=True,SQLALCHEMY_DATABASE_URI='sqlite:///:memory:',SECRET_KEY='tests')
    init_app(a)
    monkeypatch.setattr(config,'MODEL_FOLDER',str(tmp_path/'models'))
    monkeypatch.setattr(config,'REPORTS_FOLDER',str(tmp_path/'reports'));(tmp_path/'reports').mkdir()
    monkeypatch.setattr(config,'AI_PROVIDER','none')
    with a.app_context(): yield a

def analysis(name='test',digest=None):
    a=Analysis(id=name,filename='synthetic.pcap',original_filename='synthetic.pcap',status='complete',duration=10,packet_count=0)
    db.session.add(a);db.session.add(AnalysisContext(analysis_id=name,pcap_sha256=digest or name,provenance='synthetic',window_seconds=60));db.session.commit();return a

def packet(a,n,src='10.0.0.1',dst='10.0.0.2',sp=1000,dp=80,ts=100,flags='0x002',size=60,proto='TCP'):
    p=Packet(analysis_id=a,packet_number=n,src_ip=src,dst_ip=dst,src_port=sp,dst_port=dp,timestamp_epoch=ts,tcp_flags=flags,packet_length=size,protocol=proto,transport_protocol=proto)
    db.session.add(p);return p

def test_bidirectional_flow_and_idempotence(app):
    analysis();packet('test',1);packet('test',2,src='10.0.0.2',dst='10.0.0.1',sp=80,dp=1000,ts=101,flags='0x012',size=90);db.session.commit()
    f=build_flows('test')[0];assert f.features['packet_count']==2;assert f.features['bytes_sent']==60;assert f.features['bytes_received']==90;assert f.features['failed_connections']==0
    assert len(build_flows('test'))==1;assert f.packet_numbers==[1,2]

def test_reset_and_unanswered_not_equivalent(app):
    analysis();packet('test',1);packet('test',2,src='10.0.0.2',dst='10.0.0.1',sp=80,dp=1000,ts=101,flags='0x014');packet('test',3,sp=2000);db.session.commit()
    assert sorted(f.features['failed_connections'] for f in build_flows('test'))==[0,1]

def test_window_and_missing_time(app):
    analysis();packet('test',1,ts=59);packet('test',2,ts=60);packet('test',3,ts=None);db.session.commit();assert len(build_flows('test'))==2

def test_device_policy_and_snapshot(app):
    analysis();db.session.add_all([Device(ip='10.0.0.1',name='Lab',role='Student PC'),Device(ip='10.0.0.2',name='Office',role='Admin PC')]);db.session.commit()
    for n in range(3): packet('test',n+1,sp=1000+n)
    db.session.commit();flows=build_flows('test');assert all(f.policy_finding for f in flows)
    Device.query.filter_by(ip='10.0.0.1').first().role='Teacher PC';db.session.commit();assert flows[0].source_role=='Student PC'

def test_approved_policy(app):
    analysis();db.session.add_all([Device(ip='10.0.0.1',name='Lab',role='Student PC'),Device(ip='10.0.0.2',name='Office',role='Admin PC'),CommunicationPolicy(source_role='Student PC',destination_ip='10.0.0.2',destination_port=80)])
    for n in range(3): packet('test',n+1,sp=1000+n)
    db.session.commit();assert not any(f.policy_finding for f in build_flows('test'))

def test_policy_approval_reevaluates_current_incidents_without_deleting_evidence(app):
    analysis();db.session.add_all([Device(ip='10.0.0.1',name='Lab',role='Student PC'),Device(ip='10.0.0.2',name='Office',role='Admin PC')])
    for n in range(3): packet('test',n+1,sp=1000+n)
    db.session.commit();build_flows('test');correlate_incidents('test')
    before=Incident.query.one();before.status='investigating';db.session.commit()
    assert any(item['kind']=='policy' for item in before.evidence)
    db.session.add(CommunicationPolicy(source_role='Student PC',destination_ip='10.0.0.2'))
    db.session.commit();assert refresh_policy_findings('test')>0;correlate_incidents('test')
    after=db.session.get(Incident,before.id)
    assert after is not None and after.status=='investigating' and after.confirmation=='unconfirmed'
    assert not any(f.policy_finding for f in Flow.query.filter_by(analysis_id='test'))
    assert any(item['kind']=='policy-history' for item in after.evidence)

def test_training_separation_and_reload(app):
    for name in ['train','evaluate','duplicate']: analysis(name,'train' if name=='duplicate' else name)
    for n in range(40):
        packet('train',n+1,sp=1000+n,ts=120+n/10,size=60+n%5)
    packet('evaluate',1,sp=9000,size=100000);packet('duplicate',1)
    db.session.commit()
    for name in ['train','evaluate','duplicate']: build_flows(name)
    train_baseline(['train'],.05,50);score_analysis('evaluate');first=Anomaly.query.first().score
    score_analysis('evaluate');assert Anomaly.query.count()==1 and Anomaly.query.first().score==first
    score_analysis('duplicate');assert Anomaly.query.filter_by(analysis_id='duplicate').count()==0
    score_analysis('train');assert 'excluded' in db.session.get(AnalysisContext,'train').ml_status

def test_no_model_not_fake_scores(app):
    analysis();score_analysis('test');assert Anomaly.query.count()==0;assert db.session.get(AnalysisContext,'test').ml_status=='Model not trained'

def test_incident_dedup_time_boundary_and_status(app):
    analysis()
    for n,t in enumerate([100,110,1000]): db.session.add(ThreatEvent(analysis_id='test',source_ip='10.0.0.1',destination_ip='10.0.0.2',timestamp_epoch=t,event_type='PORT_SCAN',risk_score=70,evidence='{}',packet_numbers='[1]'))
    db.session.commit();correlate_incidents('test');assert Incident.query.count()==2
    i=Incident.query.first();i.status='investigating';db.session.commit();correlate_incidents('test');assert Incident.query.count()==2;assert db.session.get(Incident,i.id).status=='investigating';assert i.confirmation=='unconfirmed'

def test_protocol_missing_metadata(app):
    from schoolnet.protocols import protocol_summary
    analysis();packet('test',1,dp=443);db.session.commit();result=protocol_summary('test');assert not result['findings'];assert not result['versions']

def test_tls_serverhello_metadata(app):
    from analysis.pcap_parser import _extract_packet_data_scapy
    from scapy.all import Ether,IP,TCP,Raw
    from scapy.layers.tls.record import TLS
    from scapy.layers.tls.handshake import TLSServerHello
    p=Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP()/TCP(sport=443,dport=50000)/Raw(bytes(TLS(msg=[TLSServerHello(version=0x0301,cipher=0x002f)])))
    data=_extract_packet_data_scapy(p,1,'test');assert data['tls_version']=='0x0301';assert data['tls_handshake']=='2'

def test_crypto_tamper_wrong_key_and_signatures():
    data=b'SchoolNet evidence';key=os.urandom(32);blob=encrypt(data,key);assert decrypt(blob,key)==data
    with pytest.raises(InvalidTag): decrypt(blob[:-1]+bytes([blob[-1]^1]),key)
    with pytest.raises(InvalidTag): decrypt(blob,os.urandom(32))
    private=rsa.generate_private_key(public_exponent=65537,key_size=2048);public=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    signature=base64.b64encode(sign(data,private)).decode();assert verify_signature(data,signature,public)=='valid';assert verify_signature(data+b'x',signature,public)=='invalid';assert verify_signature(data,None,None)=='missing'

@pytest.mark.parametrize('error',[TimeoutError('timeout'),ValueError('invalid response'),RuntimeError('rate limited')])
def test_ai_failure_falls_back(app,error):
    from schoolnet.ai_engine import investigate,chat
    analysis();i=Incident(analysis_id='test',source_ip='10.0.0.1',risk='Low',evidence=[],reasons=['Unconfirmed']);db.session.add(i);db.session.commit()
    with patch('schoolnet.ai_engine.ask_provider',side_effect=error):
        assert 'fallback' in investigate(i)['mode'];assert 'offline' in chat('test','Why was this device flagged?')['answer']
    assert ChatMessage.query.count()==2

def test_ssh_data_packets_not_attempts(app):
    from analysis.threat_detector import detect_ssh_brute_force
    analysis()
    for n in range(30): packet('test',n+1,dp=22,flags='0x018',ts=100+n)
    db.session.commit();assert not detect_ssh_brute_force('test')

def test_malformed_capture_header(tmp_path):
    from utils.validators import validate_pcap_file
    for content in [b'',b'\xd4\xc3\xb2\xa1',b'not a capture'*5]:
        p=tmp_path/'bad.pcap';p.write_bytes(content);assert validate_pcap_file(str(p))[0] is False

def test_real_pcap_parser_and_rule_detection(app,tmp_path):
    from scapy.all import Ether,IP,TCP,wrpcap
    from analysis.pcap_parser import parse_pcap
    from analysis.threat_detector import detect_port_scans
    analysis();pkts=[]
    for n in range(15):
        p=Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src='10.0.0.1',dst='10.0.0.2')/TCP(sport=2000+n,dport=100+n,flags='S');p.time=100+n;pkts.append(p)
    path=tmp_path/'scan.pcap';wrpcap(str(path),pkts)
    summary=parse_pcap(str(path),'test',app);assert summary['packet_count']==15;assert Packet.query.count()==15;assert detect_port_scans('test')

def test_partial_primary_parser_fallback_no_duplicates(app,tmp_path):
    from scapy.all import Ether,IP,TCP,wrpcap
    from analysis.pcap_parser import parse_pcap
    analysis();path=tmp_path/'one.pcap';wrpcap(str(path),[Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP()/TCP()]);packet('test',1);db.session.commit()
    with patch('pyshark.FileCapture',side_effect=RuntimeError('primary failed')): parse_pcap(str(path),'test',app)
    assert Packet.query.count()==1
