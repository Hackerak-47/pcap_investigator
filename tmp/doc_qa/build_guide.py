from pathlib import Path
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

ROOT=Path(__file__).resolve().parents[2]
d=Document(); sec=d.sections[0]
sec.page_height=Inches(11.7);sec.page_width=Inches(8.3)
sec.top_margin=sec.bottom_margin=Inches(.7)
sec.left_margin=sec.right_margin=Inches(.8)
for name in ['Normal','Title','Subtitle','Heading 1','Heading 2']:
 s=d.styles[name];s.font.name='Calibri';s.font.color.rgb=RGBColor(0,0,0)
d.styles['Normal'].font.size=Pt(11)
d.styles['Normal'].paragraph_format.space_after=Pt(7)
d.styles['Normal'].paragraph_format.line_spacing=1.08
d.styles['Title'].font.size=Pt(28)
d.styles['Heading 1'].font.size=Pt(20)
d.styles['Heading 2'].font.size=Pt(13)
for style in d.styles:
 for border in list(style.element.iter(qn('w:pBdr'))):border.getparent().remove(border)
def p(t='',style=None): return d.add_paragraph(t,style)
def h(t): d.add_heading(t,2)
def page(t): d.add_page_break();d.add_heading(t,1)
def step(n,title,text): h(f'{n}. {title}');p(text)
def table(headers,rows,widths=None):
 t=d.add_table(rows=1, cols=len(headers));t.style='Table Grid'
 for c,x in zip(t.rows[0].cells,headers):
  c.text=x
  for r in c.paragraphs[0].runs:r.bold=True
  shade=OxmlElement('w:shd');shade.set(qn('w:fill'),'EEEEEE');c._tc.get_or_add_tcPr().append(shade)
 for row in rows:
  for c,x in zip(t.add_row().cells,row):c.text=x
 for row in t.rows:
  for c in row.cells:
   for para in c.paragraphs:
    para.paragraph_format.space_after=Pt(5)
    for r in para.runs:r.font.size=Pt(10)
  props=row._tr.get_or_add_trPr();props.append(OxmlElement('w:cantSplit'))
 return t

p('SchoolNet AI', 'Title')
p('Network Threat Detection and Investigation', 'Subtitle')
p('Demonstration guide and viva preparation | 1 November 2026')
h('Project objective')
p('SchoolNet AI analyses uploaded network packet captures, extracts communication flows, detects rule-based indicators and unusual behaviour, groups evidence into incidents, and produces investigation reports. School device roles add context to the findings.')
h('Opening explanation for your sir')
p('“Sir, our project takes a PCAP file as input. It extracts packets and flows, applies security rules and an Isolation Forest model trained on separate normal traffic, and presents evidence for investigation. The analyst reviews the findings before confirming an attack. We can then generate, encrypt, sign and verify a report.”')
h('Processing flow')
for text in ['1  Upload PCAP or PCAPNG and record its SHA-256 hash.',
 '2  Parse packets, protocols, addresses, ports and timestamps.',
 '3  Build bidirectional flows and device activity features.',
 '4  Apply device-role policies, rules and available baseline ML scoring.',
 '5  Correlate related evidence into prioritised incidents.',
 '6  Review packet evidence, timeline and AI-assisted explanations.',
 '7  Record analyst decisions and generate a secure PDF report.']:p(text)
h('What is verified')
p('The local automated suite passed 30 tests, with 43 deprecation warnings. Coverage includes an actual PCAP upload, capture selection across nine pages, baseline training and scoring, device/policy actions, incident updates, live and offline AI response handling, and encrypted signed report verification. This supports a working academic demonstration; it is not a guarantee that every possible file or attack will be handled correctly.')
p('Working dashboard: http://127.0.0.1:5000/schoolnet/\nReadiness page: http://127.0.0.1:5000/check. It checks the database, model, report keys and live AI connection.')

page('Preparation and upload')
step(1,'Start the application','If the server is already running, open the dashboard. Otherwise, open PowerShell and run the commands below. Keep that terminal open during the demonstration.')
p('cd "F:\\Aastha\\IS LAB PROJECT\\pcap-investigator"\n.\\.venv\\Scripts\\python.exe app.py')
step(2,'Check Settings','Open Settings. Review the flow window, AI provider configuration and report encryption/signing readiness. A configured API key does not prove that the external provider is reachable. Never display private keys or .env contents during the presentation.')
step(3,'Prepare the test files','The sample captures are in F:\\Aastha\\IS LAB PROJECT\\TEST_PCAP_FILES. They are demonstration inputs; they do not establish real-world detection accuracy.')
table(['File','Use in the demonstration'],[
 ('01_normal_baseline_traffic_train.pcap','Upload first; use only as the normal training baseline.'),
 ('02_normal_evaluation_traffic_test.pcap','Evaluate normal traffic separately; discuss false positives.'),
 ('03_cyber_attack_incident_multistage.pcap','Show rule evidence and incident investigation.'),
 ('04_mixed_threat_and_school_anomalies.pcap','Show combined normal activity and suspicious indicators.')])
step(4,'Register device roles before analysis','In Device Monitoring, add the device name, IP address and role. For the school demonstration, example roles include Student PC and School Server. Add approved communication policies if needed. Roles and policy findings are captured during extraction; later registry edits do not rewrite historical flow snapshots.')
step(5,'Upload and wait for completion','Open PCAP Analysis, browse to the baseline file, select the synthetic/demo provenance where offered, and click Start analysis. Choosing a file alone does not analyse it. Wait for processing to complete. Verify that the selected filename and analysis ID match the new upload.')
h('Why the same filename appears on every page')
p('The header identifies the capture currently being investigated. “mixed_test.pcap” is a filename and “a8f80087” is its shortened analysis ID. Seeing them on all pages means the pages share the same selected capture. Use Switch capture to change it; a successful new upload should select its own results.')

page('Train the model and examine results')
step(6,'Train a normal baseline','Open Anomaly Detection and expand Train or replace the baseline model. Select only 01_normal_baseline_traffic_train.pcap, confirm it represents normal traffic, leave the demonstration defaults (contamination 0.05 and 200 trees), and click Train baseline. At least 20 extracted flows are required.')
p('Say: “Isolation Forest learns unusualness relative to our selected baseline. Contamination controls the model threshold; it is not a measured percentage of attacks in our network.”')
step(7,'Evaluate a separate normal capture','Upload 02_normal_evaluation_traffic_test.pcap and wait for completion. Open Anomaly Detection and review the score, decision and deviating features. If the capture was uploaded before training, use Evaluate selected capture. Some normal flows can be flagged; discuss them as possible false positives.')
p('Do not evaluate the training file as proof of accuracy. The application excludes training capture IDs and matching file hashes from evaluation to reduce data leakage.')
step(8,'Upload the mixed or multistage capture','Upload file 04 for combined behavioural and rule evidence, or file 03 for a multistage scenario. Confirm that the header changes to the new filename and ID. Keep this capture selected while navigating between pages.')
step(9,'Explain the Overview','Point out packet count, unique device endpoints, security incidents, ML anomalies, high-priority incidents, protocol distribution and timeline. Counts are calculated for the selected analysis. Capture timestamps represent the recorded traffic time and may differ from the upload date.')
p('Observed example: the saved mixed_test.pcap analysis a8f80087 showed 573 packets, 179 flows, 15 endpoints, 67 unusual flows and 10 incidents, including 2 high-priority incidents. A new run can differ when the model, device registry or policies change.')
step(10,'Inspect flows and device behaviour','In PCAP Analysis, inspect source/destination addresses, protocol and flow features. In Device Monitoring, explain IP-to-role mapping and activity. In Anomaly Detection, choose an unusual flow and explain its observed feature values compared with baseline medians.')
p('Say: “An unusual flow is a statistical deviation. It becomes useful evidence when combined with rules, device roles and the surrounding traffic.”')

page('Investigate and explain evidence')
step(11,'Open a security incident','Go to Security Incidents, filter by priority if useful, and open an incident. Explain source, destination, time range, reasons and evidence references. Follow the packet, rule-evidence and timeline links to show the underlying observations.')
p('Risk is investigation priority. Confirmation is a separate analyst decision. Repeated connections to port 22 do not, by themselves, prove failed SSH logins or a successful brute-force attack.')
step(12,'Run AI Investigator','Select an incident and request its investigation. Review the summary, observed behaviour, supporting evidence, possible explanation, potential impact, uncertainty and recommended next steps. Check the response mode before describing it as an external AI response.')
p('The configured Gemini connection was verified with a small synthetic test flow through the System Check page. If the provider is unavailable later, the app generates an evidence-based offline summary. AI output requires analyst review and cannot prove compromise.')
step(13,'Use AI Assistant','Ask “Explain the anomalies in this capture” or “Which incidents need attention?” Review the answer and evidence references. Ask about a specific IP that actually appears in the selected capture. Chat history belongs to that analysis.')
step(14,'Review protocol security','Open Protocol Security. Explain visible HTTP activity and any observed TLS handshake/version information. Missing TLS metadata means unknown, not automatically secure or insecure. Traffic on port 443 alone does not prove HTTPS or a particular negotiated TLS version.')
step(15,'Record the analyst decision','Move the incident status from open to investigating, then resolved when review is finished. Keep confirmation unconfirmed until supporting evidence is sufficient; use benign for explained legitimate activity. Status and confirmation answer different questions.')
h('Evidence vocabulary for the presentation')
table(['Term','Meaning'],[
 ('Packet','One captured network frame/record.'),
 ('Flow','Related bidirectional communication grouped within configured windows/timeouts.'),
 ('Rule indicator','Observed traffic matching a configured security rule.'),
 ('ML anomaly','Behaviour outside the baseline model threshold.'),
 ('Incident','Related evidence grouped for investigation.'),
 ('Confirmed attack','An analyst conclusion supported by additional validation, not an automatic consequence of an anomaly.')])

page('Create and verify a secure report')
step(16,'Verify the original capture','Open Secure Reports and use the capture verification control. A valid result means the stored capture hash matches the recorded SHA-256 value. It proves consistency with that recorded copy, not that the traffic itself is harmless.')
step(17,'Generate a report version','Select the intended capture. Enable encryption and signing only when the corresponding keys are configured, then generate the report. Each report is a saved version; generate another version after relevant investigation updates.')
step(18,'Verify and download','Use Verify to check the report digest, signature and encryption authentication. Download the encrypted .sna file for protected storage, use the decrypt/download action to obtain a readable PDF, and download the manifest when demonstrating detached signature metadata.')
table(['Mechanism','What to explain'],[
 ('SHA-256','Detects a change relative to a recorded digest. A hash alone does not establish trusted authorship.'),
 ('AES-256-GCM','Encrypts the PDF and authenticates the encrypted contents. The correct server-side key is required to decrypt.'),
 ('RSA-PSS with SHA-256','Signs the final PDF bytes. Verification uses the public key; trust also depends on knowing whose key it is.'),
 ('Manifest','Contains report ID, digest, signature and public key for verification. It does not contain the private signing key.')])
h('How to explain a failed verification')
p('Wrong keys or modified ciphertext cause decryption/authentication failure. Modified PDF bytes invalidate the expected digest or signature. The isolated integration check successfully decrypted a signed encrypted PDF, then deliberately changed a byte and confirmed that decryption failed. Do not damage the saved demonstration report to repeat this test.')
h('Finish the demonstration')
p('“Our result is a traceable investigation workflow: capture, extract, detect, correlate, review and report. We preserve evidence references and keep statistical anomalies separate from analyst-confirmed attacks. The next improvement is evaluation on broader labelled traffic and operational hardening for deployment.”')
h('Suggested presentation timing')
p('Use 1 minute for the objective, 2 minutes for upload and baseline training, 3 minutes for overview/anomalies/incidents, 2 minutes for investigation and protocols, and 2 minutes for report verification. Train the baseline before the live talk if processing time is limited.')

page('Verification and viva reference')
p('Verification date: 1 November 2026. Command: .\\.venv\\Scripts\\python.exe -m pytest tests -q. Result: 30 passed, 43 warnings. The expanded end-to-end test performs multiple checks within one test case and uses temporary data and keys.')
table(['Feature group','Verified scope'],[
 ('Upload and selection','Real PCAP parsing/detection; nine pages follow the new upload; invalid upload preserves selection.'),
 ('Devices and policies','Create/edit/delete device and add/delete policy; role snapshots and approved-policy behaviour.'),
 ('ML and correlation','Training/scoring, persistence, baseline exclusion, correlation grouping and incident status updates.'),
 ('AI and protocols','Offline investigation/chat, error fallback, TLS parsing fixture and missing metadata handling.'),
 ('Secure reports','PDF creation, encryption, signing, verification, download, decryption, manifest and tamper rejection.'),
 ('Access controls','Missing CSRF token rejected, valid token accepted, nonlocal access blocked when auth is unconfigured.'),
 ('Live interface','Dashboard and /check render. The readiness page verified a live Gemini response using a synthetic flow. Not every possible browser interaction is certified.')])
h('Likely questions and short answers')
for q,a in [
 ('Is it real-time monitoring?','This workflow analyses uploaded captures. It does not continuously capture or block live network traffic.'),
 ('Why combine rules and ML?','Rules identify known patterns; ML highlights deviations. Correlation adds context for an analyst.'),
 ('Can it detect every attack?','No. Visibility, capture quality, encryption, rules and baseline quality limit detection. False positives and false negatives remain possible.'),
 ('Why a separate normal test file?','It checks behaviour on unseen traffic instead of testing on the training data.'),
 ('What if no ML model or API is available?','Rules still run without a model. AI investigation/chat can return labelled offline evidence summaries.'),
 ('Is the project perfect or production-ready?','The checked academic workflows pass. Production use needs broader evaluation, deployment security, key management and performance testing.')]:
 para=p();r=para.add_run(q+' ');r.bold=True;para.add_run(a)
h('Quick troubleshooting')
p('Old filename: check the capture selector and wait for the new upload to complete. No ML scores: train a separate baseline and evaluate the selected capture. Form-token error: refresh and retry. Report failure: check key configuration. Unknown TLS: inspect whether handshake packets were captured. The 43 current warnings concern deprecated datetime/event-loop usage; they are maintenance work, not failed tests.')
d.core_properties.title='SchoolNet AI Demonstration Guide'
d.core_properties.subject='Step-by-step academic demonstration and verified feature scope'
d.core_properties.author='SchoolNet AI Project'
d.save(ROOT/'output'/'SchoolNet_AI_Demonstration_Guide.docx')
print(ROOT/'output'/'SchoolNet_AI_Demonstration_Guide.docx')
