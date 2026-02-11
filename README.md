# ADAMIF

Attack Detection, Analysis, and Malware Intelligence Framework (ADAMIF)

ADAMIF is a multi-phase cybersecurity project designed to simulate a SOC-style defensive security platform. The system evolves incrementally from log-based attack detection to intelligence-driven correlation and controlled automated response.

---

## Project Phases

### Phase 1 – Detection & Visibility Framework
- Linux log ingestion
- SSH brute-force detection
- Abnormal authentication detection
- Basic file activity monitoring
- Structured alerting and reporting (CLI-based)

### Phase 2 – Intelligence & Correlation
- Incident correlation engine
- Internal threat intelligence store
- Historical attacker tracking
- Context-aware risk scoring

### Phase 3 – Autonomous Defense Platform
- Rule-based response playbooks
- API layer
- Web-based SOC dashboard
- Purple team validation (lab-only)

---

## Design Philosophy

- Data-first architecture
- Explainable detection logic
- Evidence-based analysis
- Strict separation of detection, intelligence, and response layers
- No offensive or exploit-development functionality

---

## Current Status

Phase 1 – Data model design in progress.
