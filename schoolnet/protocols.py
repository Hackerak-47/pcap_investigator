"""Evidence-backed protocol inventory; missing handshake metadata is not insecurity."""
from collections import Counter
from database.models import Packet

VERSIONS={'0x0301':'TLS 1.0','0x0302':'TLS 1.1','0x0303':'TLS 1.2','0x0304':'TLS 1.3','769':'TLS 1.0','770':'TLS 1.1','771':'TLS 1.2','772':'TLS 1.3'}
def protocol_summary(analysis_id):
    protocols=Counter();versions=Counter();ciphers=Counter();findings=[];tls_packets=0;handshakes=0
    for p in Packet.query.filter_by(analysis_id=analysis_id).yield_per(500):
        protocols[p.protocol or 'Unknown']+=1
        if p.protocol=='HTTP' and p.http_method:
            findings.append({'packet':p.packet_number,'source':p.src_ip,'destination':p.dst_ip,'finding':'Unencrypted HTTP request observed','kind':'warning'})
        if p.protocol=='TLS': tls_packets+=1
        if p.tls_handshake: handshakes+=1
        if p.tls_version:
            v=VERSIONS.get(p.tls_version,p.tls_version);versions[v]+=1
            if v in ('TLS 1.0','TLS 1.1'):
                findings.append({'packet':p.packet_number,'source':p.src_ip,'destination':p.dst_ip,'finding':'Negotiated outdated '+v,'kind':'warning'})
        if p.tls_cipher: ciphers[p.tls_cipher]+=1
    return dict(protocols=dict(protocols),versions=dict(versions),ciphers=dict(ciphers),findings=findings,
                tls_packets=tls_packets,handshakes=handshakes,
                note='Only captured ServerHello metadata establishes negotiated TLS settings. Port 443 alone does not establish HTTPS. Missing metadata is unknown; encrypted contents are not inspected.')
