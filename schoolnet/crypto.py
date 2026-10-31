"""Authenticated report encryption and detached RSA-PSS signatures."""
import base64,hashlib,io,os,uuid
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import padding,rsa
from cryptography.exceptions import InvalidSignature
from database.database import db
from database.models import Analysis,ThreatEvent,TimelineEvent,Investigation
from database.school_models import SecureReport
import config

AAD=b'SchoolNet AI report v1'
def encrypt(data,key):
    if len(key)!=32: raise ValueError('AES key must contain 32 bytes')
    nonce=os.urandom(12);return b'SNA1'+nonce+AESGCM(key).encrypt(nonce,data,AAD)
def decrypt(data,key):
    if data[:4]!=b'SNA1': raise ValueError('Unsupported encrypted report format')
    return AESGCM(key).decrypt(data[4:16],data[16:],AAD)
def sign(data,key):
    return key.sign(data,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
def verify_signature(data,signature,public):
    if not signature or not public: return 'missing'
    try:
        key=serialization.load_pem_public_key(public.encode())
        key.verify(base64.b64decode(signature),data,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        return 'valid'
    except (InvalidSignature,ValueError,TypeError): return 'invalid'
def aes_key():
    if not config.REPORT_AES_KEY: raise ValueError('Configure REPORT_AES_KEY before encryption/decryption')
    key=base64.b64decode(config.REPORT_AES_KEY,validate=True)
    if len(key)!=32: raise ValueError('REPORT_AES_KEY must be a base64-encoded 32-byte key')
    return key

def create_report(analysis_id,encrypted=False,signed=False):
    from reports.pdf_report import generate_pdf_report
    from analysis.traffic_analyzer import get_traffic_stats
    a=db.session.get(Analysis,analysis_id)
    if not a or a.status!='complete': raise ValueError('Complete the analysis first')
    output=io.BytesIO()
    generate_pdf_report(a,ThreatEvent.query.filter_by(analysis_id=analysis_id).all(),TimelineEvent.query.filter_by(analysis_id=analysis_id).all(),Investigation.query.filter_by(analysis_id=analysis_id).first(),get_traffic_stats(analysis_id),output)
    data=output.getvalue();report=SecureReport(id=str(uuid.uuid4()),analysis_id=analysis_id,sha256=hashlib.sha256(data).hexdigest(),encrypted=encrypted)
    if signed:
        if not config.SIGNING_KEY_PATH: raise ValueError('Configure SIGNING_KEY_PATH before signing')
        key=serialization.load_pem_private_key(Path(config.SIGNING_KEY_PATH).read_bytes(),password=config.SIGNING_KEY_PASSWORD.encode() if config.SIGNING_KEY_PASSWORD else None)
        if not isinstance(key,rsa.RSAPrivateKey) or key.key_size<2048: raise ValueError('Use an RSA key of at least 2048 bits')
        report.signature=base64.b64encode(sign(data,key)).decode()
        report.public_key=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    blob=encrypt(data,aes_key()) if encrypted else data
    report.filename=report.id+('.sna' if encrypted else '.pdf')
    Path(config.REPORTS_FOLDER,report.filename).write_bytes(blob);db.session.add(report);db.session.commit();return report

def report_bytes(report):
    data=Path(config.REPORTS_FOLDER,report.filename).read_bytes()
    return decrypt(data,aes_key()) if report.encrypted else data

def verify_report(report):
    try:
        data=report_bytes(report)
        return {'sha256':'valid' if hashlib.sha256(data).hexdigest()==report.sha256 else 'invalid',
                'signature':verify_signature(data,report.signature,report.public_key),'encryption':'authenticated' if report.encrypted else 'not encrypted'}
    except Exception:
        return {'sha256':'unavailable','signature':'unavailable','encryption':'Decryption failed: key unavailable, incorrect or file altered'}
