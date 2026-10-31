# SchoolNet AI – Intelligent Network Threat Detection & Investigation System

See the complete master documentation and step-by-step academic demonstration guide in:
[../README.md](../README.md)

---

## Quick Start Reference

### 1. Environment & API Keys
Configure your environment in `.env`:
```env
# Optional AI Provider (none = offline deterministic fallback)
AI_PROVIDER=none
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini
OPENAI_BASE_URL=https://api.openai.com/v1

# Cryptography (Pre-Configured)
REPORT_AES_KEY=MquzNSVCCdZbbVGWa4FfQV6lJyOQtfOuoVMU5fxPs0Q=
SIGNING_KEY_PATH=F:/Aastha/IS LAB PROJECT/pcap-investigator/keys/signing_key.pem
```

### 2. Ready-to-Upload Test Files
Located in `../TEST_PCAP_FILES/`:
- `01_normal_baseline_traffic_train.pcap` – Baseline training
- `02_normal_evaluation_traffic_test.pcap` – Normal evaluation (no false positives)
- `03_cyber_attack_incident_multistage.pcap` – Port scan, brute-force & C2
- `04_mixed_threat_and_school_anomalies.pcap` – Hybrid detection & role policy violations

### 3. Run Application
```powershell
..\.venv\Scripts\activate
python app.py
```
Open **http://127.0.0.1:5000**
