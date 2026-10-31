"""SchoolNet administration and reproducible synthetic evaluation commands."""
import argparse,base64,json,os,random,uuid
from pathlib import Path

def fixtures(directory):
    from scapy.all import Ether,IP,TCP,UDP,DNS,DNSQR,Raw,wrpcap
    root=Path(directory);root.mkdir(parents=True,exist_ok=True)
    for name,seed in [('normal_train',42),('normal_test',84),('mixed_test',126)]:
        rng=random.Random(seed);packets=[]
        for n in range(120):
            src='10.20.0.'+str(10+n%5);dst='10.20.1.10';sp=20000+n;ts=1700000000+n*2
            size=rng.randint(50,300)
            for offset,p in [(0,IP(src=src,dst=dst)/TCP(sport=sp,dport=443,flags='S')),(.02,IP(src=dst,dst=src)/TCP(sport=443,dport=sp,flags='SA')),(.04,IP(src=src,dst=dst)/TCP(sport=sp,dport=443,flags='PA')/Raw(b'x'*size)),(.08,IP(src=dst,dst=src)/TCP(sport=443,dport=sp,flags='PA')/Raw(b'y'*rng.randint(100,800)))]:
                p=Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/p;p.time=ts+offset;packets.append(p)
        if name=='mixed_test':
            for n in range(25):
                p=Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src='10.20.0.99',dst='10.20.1.20')/TCP(sport=40000+n,dport=1000+n,flags='S');p.time=1700000010+n*.1;packets.append(p)
            for n in range(15):
                p=Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src='10.20.0.98',dst='10.20.1.20')/TCP(sport=41000+n,dport=22,flags='S');p.time=1700000050+n*.1;packets.append(p)
            for n in range(10):
                p=Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src='10.20.0.97',dst='10.20.1.53')/UDP(sport=42000+n,dport=53)/DNS(rd=1,qd=DNSQR(qname=('a1b2c3d4e5f6'*5)+str(n)+'.example.test'));p.time=1700000080+n;packets.append(p)
            # Unusual traffic not matching a fixed suspicious port: large transfer to 443.
            for n in range(35):
                p=Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src='10.20.0.96',dst='203.0.113.10')/TCP(sport=43000,dport=443,flags='PA')/Raw(b'z'*6000);p.time=1700000100+n*.1;packets.append(p)
            for n in range(8):
                p=Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src='10.20.0.95',dst='203.0.113.20')/TCP(sport=44000+n,dport=4444,flags='S');p.time=1700000130+n;packets.append(p)
        packets.sort(key=lambda p:float(p.time));wrpcap(str(root/(name+'.pcap')),packets)
    (root/'provenance.json').write_text(json.dumps({'synthetic':True,'purpose':'Academic testing only; not real school incidents','seeds':[42,84,126],
        'training':'normal_train.pcap','held_out':['normal_test.pcap','mixed_test.pcap'],'anomaly_ground_truth_sources':['10.20.0.99','10.20.0.98','10.20.0.97','10.20.0.96','10.20.0.95']},indent=2))
    print('Created separate synthetic training and held-out PCAPs in',root)

def analyze(path,synthetic=False):
    from app import app,run_analysis_pipeline
    from database.database import db
    from database.models import Analysis
    from schoolnet.pipeline import initialize_context
    import config,shutil
    aid=str(uuid.uuid4());src=Path(path);filename=aid+'_'+src.name;destination=Path(config.UPLOAD_FOLDER,filename);shutil.copyfile(src,destination)
    with app.app_context():
        db.session.add(Analysis(id=aid,filename=filename,original_filename=src.name,file_size=src.stat().st_size,status='pending'))
        db.session.commit();initialize_context(aid,str(destination),'synthetic' if synthetic else 'uploaded')
    run_analysis_pipeline(aid,str(destination))
    with app.app_context():
        a=db.session.get(Analysis,aid)
        if a.status!='complete': raise RuntimeError(a.error_message)
    print(aid);return aid

def evaluate(analysis_id,output):
    from app import app
    from database.school_models import Anomaly,Flow,AnalysisContext
    from database.database import db
    from sklearn.metrics import confusion_matrix,precision_score,recall_score,f1_score
    with app.app_context():
        ctx=db.session.get(AnalysisContext,analysis_id)
        if not ctx or ctx.provenance!='synthetic': raise ValueError('Built-in labels apply only to the supplied synthetic fixtures')
        rows=Anomaly.query.filter_by(analysis_id=analysis_id).all()
        if not rows: raise ValueError('No held-out model scores available')
        sources={'10.20.0.99','10.20.0.98','10.20.0.97','10.20.0.96','10.20.0.95'}
        truth=[int(db.session.get(Flow,a.flow_id).src_ip in sources) for a in rows];pred=[int(a.unusual) for a in rows]
        tn,fp,fn,tp=confusion_matrix(truth,pred,labels=[0,1]).ravel()
        result={'synthetic_only':True,'analysis_id':analysis_id,'model_id':rows[0].model_id,'flows':len(rows),'true_negative':int(tn),'false_positive':int(fp),'false_negative':int(fn),'true_positive':int(tp),'precision':float(precision_score(truth,pred,zero_division=0)),'recall':float(recall_score(truth,pred,zero_division=0)),'f1':float(f1_score(truth,pred,zero_division=0)),'limitation':'Scenario labels are synthetic. These metrics do not estimate real-school accuracy or guarantee zero-day detection.'}
        Path(output).write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))

def main():
    parser=argparse.ArgumentParser();sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('fixtures');p.add_argument('--directory',default='sample_data/schoolnet')
    p=sub.add_parser('analyze');p.add_argument('path');p.add_argument('--synthetic',action='store_true')
    p=sub.add_parser('train');p.add_argument('analysis_ids',nargs='+');p.add_argument('--contamination',type=float,default=.05)
    p=sub.add_parser('evaluate');p.add_argument('analysis_id');p.add_argument('--output',default='evaluation.json')
    p=sub.add_parser('password-hash')
    p=sub.add_parser('generate-keys');p.add_argument('directory')
    args=parser.parse_args()
    if args.command=='fixtures': fixtures(args.directory)
    elif args.command=='analyze': analyze(args.path,args.synthetic)
    elif args.command=='evaluate': evaluate(args.analysis_id,args.output)
    elif args.command=='train':
        from app import app
        from schoolnet.ml import train_baseline
        with app.app_context(): print(json.dumps(train_baseline(args.analysis_ids,args.contamination),indent=2))
    elif args.command=='password-hash':
        import getpass
        from werkzeug.security import generate_password_hash
        password=getpass.getpass('New administrator password: ')
        if len(password)<12: raise ValueError('Use at least 12 characters')
        print(generate_password_hash(password))
    elif args.command=='generate-keys':
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import getpass
        directory=Path(args.directory).resolve();project=Path(__file__).resolve().parent
        if directory==project or project in directory.parents: raise ValueError('Choose a protected key directory outside the project and report folders')
        password=getpass.getpass('Private-key passphrase (12+ characters): ')
        if len(password)<12: raise ValueError('Passphrase too short')
        directory.mkdir(parents=True,exist_ok=True)
        key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
        with (directory/'schoolnet-private.pem').open('xb') as f: f.write(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.BestAvailableEncryption(password.encode())))
        with (directory/'schoolnet-aes.key').open('x') as f: f.write(base64.b64encode(os.urandom(32)).decode())
        print('Keys created outside project. Set SIGNING_KEY_PATH, SIGNING_KEY_PASSWORD and REPORT_AES_KEY securely; see README.')

if __name__=='__main__': main()
