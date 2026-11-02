"""Upload a separate capture and verify every page follows its analysis ID."""
import io,os,tempfile,subprocess,sys
from pathlib import Path

def test_uploaded_capture_replaces_demo_selection():
    with tempfile.TemporaryDirectory() as directory:
        env=os.environ.copy();env['DATABASE_URL']='sqlite:///'+str(Path(directory,'test.db')).replace('\\','/');env['AI_PROVIDER']='none';env['ADMIN_PASSWORD_HASH']=''
        script=r'''
import io,os
from pathlib import Path
from unittest.mock import patch
import config
config.UPLOAD_FOLDER=os.environ['TEST_UPLOADS']
config.MODEL_FOLDER=os.path.join(config.UPLOAD_FOLDER,'models')
config.REPORTS_FOLDER=config.UPLOAD_FOLDER
config.GEMINI_API_KEY=config.OPENAI_API_KEY=''
from app import app,run_analysis_pipeline
from database.database import db
from database.models import Analysis,Packet
from database.school_models import Incident,AnalysisContext
app.config['TESTING']=True
with app.app_context():
 db.session.add(Analysis(id='old-demo',filename='mixed_test.pcap',original_filename='mixed_test.pcap',status='complete'));db.session.commit()
client=app.test_client()
assert client.get('/check').status_code==200
with patch('schoolnet.ai_engine.ask_provider',return_value={'answer':'Synthetic TCP flow.','references':['flow:1']}):
 assert client.post('/check',follow_redirects=True).status_code==200
 assert b'Live response verified' in client.get('/check').data
with patch('schoolnet.ai_engine.ask_provider',side_effect=RuntimeError('AI quota or rate limit reached.')):
 assert b'AI quota or rate limit reached' in client.post('/check',follow_redirects=True).data
assert client.get('/schoolnet/?analysis_id=old-demo').status_code==200
with patch('app.threading.Thread'):
 response=client.post('/upload',data={'pcap_file':(io.BytesIO(Path('sample_data/schoolnet/mixed_test.pcap').read_bytes()),'my_uploaded_capture.pcap'),'provenance':'synthetic'},headers={'Accept':'application/json'})
assert response.status_code==202,response.data
new=response.json['id'];assert new!='old-demo'
with app.app_context():path=os.path.join(config.UPLOAD_FOLDER,db.session.get(Analysis,new).filename)
run_analysis_pipeline(new,path)
with app.app_context():
 assert db.session.get(Analysis,new).status=='complete'
 assert Packet.query.filter_by(analysis_id=new).count()>0
 assert Incident.query.filter_by(analysis_id=new).count()>0
for route in ['/schoolnet/','/schoolnet/analysis','/schoolnet/devices','/schoolnet/anomalies','/schoolnet/incidents','/schoolnet/investigator','/schoolnet/assistant','/schoolnet/protocols','/schoolnet/reports']:
 response=client.get(route)
 assert response.status_code==200,(route,response.status_code)
 assert b'<strong>my_uploaded_capture.pcap</strong>' in response.data,route
 assert b'<strong>mixed_test.pcap</strong>' not in response.data,route
bad=client.post('/upload',data={'pcap_file':(io.BytesIO(b'bad'),'bad.pcap')},headers={'Accept':'application/json'})
assert bad.status_code==400 and bad.json['error']
assert b'<strong>my_uploaded_capture.pcap</strong>' in client.get('/schoolnet/').data
with app.app_context():
 source_name=db.session.get(Analysis,new).filename
 db.session.add(Analysis(id='legacy-source',filename=source_name,original_filename='legacy-source.pcap',status='complete'))
 db.session.add(Analysis(id='legacy-missing',filename='no-longer-here.pcap',original_filename='legacy-missing.pcap',status='complete'))
 db.session.add(Analysis(id='remove-me',filename='remove-me.pcap',original_filename='remove-me.pcap',status='complete'))
 db.session.commit()
legacy_page=client.get('/schoolnet/?analysis_id=legacy-source')
assert legacy_page.status_code==200 and b'name="csrf_token"' in legacy_page.data and b'Extend this analysis' in legacy_page.data
missing_page=client.get('/schoolnet/?analysis_id=legacy-missing')
assert b'raw PCAP is not available' in missing_page.data and b'Extend this analysis' not in missing_page.data
assert client.post('/schoolnet/enrich',data={'analysis_id':'legacy-missing'}).status_code==302
with app.app_context(): assert db.session.get(AnalysisContext,'legacy-missing') is None
from database.school_models import Device,CommunicationPolicy,ModelRecord,Anomaly,SecureReport
assert client.post('/schoolnet/devices',data={'name':'Demo PC','ip':'10.20.0.10','role':'Student PC'}).status_code==302
with app.app_context():
 device=Device.query.filter_by(ip='10.20.0.10').one();did=device.id
assert client.post('/schoolnet/devices',data={'id':did,'name':'Updated PC','ip':'10.20.0.10','role':'Teacher PC'}).status_code==302
assert client.post('/schoolnet/policies',data={'source_role':'Student PC','destination_ip':'10.20.1.20','destination_port':'443'}).status_code==302
with app.app_context():
 assert db.session.get(Device,did).role=='Teacher PC'
 pid=CommunicationPolicy.query.one().id
assert client.post('/schoolnet/policies',data={'action':'delete','id':pid}).status_code==302
assert client.post('/schoolnet/devices',data={'action':'delete','id':did}).status_code==302
with patch('app.threading.Thread'):
 response=client.post('/upload',data={'pcap_file':(io.BytesIO(Path('sample_data/schoolnet/normal_train.pcap').read_bytes()),'baseline.pcap'),'provenance':'synthetic'},headers={'Accept':'application/json'})
baseline=response.json['id']
with app.app_context():path=os.path.join(config.UPLOAD_FOLDER,db.session.get(Analysis,baseline).filename)
run_analysis_pipeline(baseline,path)
assert client.post('/schoolnet/train',data={'baseline_ids':baseline,'baseline_confirm':'yes','estimators':'50','analysis_id':new}).status_code==302
assert client.post('/schoolnet/enrich',data={'analysis_id':new}).status_code==302
with app.app_context():
 assert ModelRecord.query.filter_by(active=True).count()==1
 assert Anomaly.query.filter_by(analysis_id=new).count()>0
 iid=Incident.query.filter_by(analysis_id=new).first().id
assert client.post('/schoolnet/incident/'+iid,data={'status':'investigating','confirmation':'unconfirmed'}).status_code==302
assert client.post('/schoolnet/incident/'+iid,data={'action':'investigate'}).status_code==302
with app.app_context():
 assert db.session.get(Incident,iid).status=='investigating'
 assert 'offline' in db.session.get(Incident,iid).ai_result['mode']
assert client.post('/schoolnet/assistant?analysis_id='+new,json={'question':'Explain the anomalies'}).json['answer']
assert client.post('/schoolnet/assistant',json={'question':''}).status_code==400
assert client.post('/schoolnet/verify-pcap',data={'analysis_id':new}).json['status']=='valid'
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
config.SIGNING_KEY_PATH=os.path.join(config.UPLOAD_FOLDER,'test-key.pem');config.SIGNING_KEY_PASSWORD=''
Path(config.SIGNING_KEY_PATH).write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
config.REPORT_AES_KEY=base64.b64encode(os.urandom(32)).decode()
assert client.post('/schoolnet/reports',data={'analysis_id':new,'encrypt':'yes','sign':'yes'}).status_code==302
with app.app_context():report=SecureReport.query.one();rid=report.id;filename=report.filename
assert b'CURRENT WORKING DOSSIER' in client.get('/schoolnet/reports?analysis_id='+new).data
assert client.post('/schoolnet/report/'+rid+'/verify').json=={'sha256':'valid','signature':'valid','encryption':'authenticated'}
report_path=Path(config.REPORTS_FOLDER,filename);original=report_path.read_bytes();original_digest=__import__('hashlib').sha256(original).hexdigest()
# A report copy is independent from the selected PCAP capture and is never written to the archive.
client.get('/schoolnet/?analysis_id='+baseline)
exact=client.post('/schoolnet/report/'+rid+'/verify-upload',data={'report_file':(io.BytesIO(original),filename)}).json
assert exact['valid'] is True and exact['sha256']=='valid' and exact['signature']=='valid'
modified=bytearray(original);modified[-1]^=1
changed=client.post('/schoolnet/report/'+rid+'/verify-upload',data={'report_file':(io.BytesIO(modified),filename)}).json
assert changed['valid'] is False and changed['encryption']=='failed'
different=client.post('/schoolnet/report/'+rid+'/verify-upload',data={'report_file':(io.BytesIO(b'SNA1'+os.urandom(28)),'different.sna')}).json
assert different['valid'] is False and different['encryption']=='failed'
assert client.post('/schoolnet/report/'+rid+'/verify-upload').status_code==400
assert client.post('/schoolnet/report/'+rid+'/verify-upload',data={'report_file':(io.BytesIO(original),'wrong.txt')}).json['valid'] is False
for _ in range(2): assert client.post('/schoolnet/report/'+rid+'/verify-upload',data={'report_file':(io.BytesIO(original),filename)}).json['valid'] is True
assert report_path.read_bytes()==original and __import__('hashlib').sha256(report_path.read_bytes()).hexdigest()==original_digest
assert b'<strong>baseline.pcap</strong>' in client.get('/schoolnet/').data
tamper_test=client.post('/schoolnet/report/'+rid+'/tamper-test').json
assert tamper_test['result']=='tampering detected'
assert tamper_test['encryption'].startswith('authentication failed')
assert tamper_test['stored_report']=='unchanged'
assert client.post('/schoolnet/report/'+rid+'/verify').json=={'sha256':'valid','signature':'valid','encryption':'authenticated'}
assert client.post('/schoolnet/report/'+rid+'/download').data.startswith(b'SNA1')
assert client.post('/schoolnet/report/'+rid+'/decrypt').data.startswith(b'%PDF')
assert client.post('/schoolnet/report/'+rid+'/manifest').json['report_id']==rid
app.config['TESTING']=False
assert client.post('/schoolnet/verify-pcap').status_code==400
with client.session_transaction() as session:token=session['csrf']
assert client.post('/schoolnet/verify-pcap',data={'analysis_id':new,'csrf_token':token}).json['status']=='valid'
assert client.post('/analyses/remove-me/delete',data={'csrf_token':token}).status_code==302
with app.app_context(): assert db.session.get(Analysis,'remove-me') is None
client.get('/schoolnet/?analysis_id=legacy-source')
with client.session_transaction() as session:token=session['csrf']
assert client.post('/schoolnet/enrich',data={'analysis_id':'legacy-source','csrf_token':token}).status_code==302
assert client.get('/schoolnet/',environ_overrides={'REMOTE_ADDR':'192.0.2.1'}).status_code==403
print('Upload parsed, detection ran, nine pages selected the new capture; invalid upload kept selection.')
'''
        env['TEST_UPLOADS']=directory
        result=subprocess.run([sys.executable,'-c',script],env=env,capture_output=True,text=True)
        assert result.returncode==0,result.stdout+result.stderr
