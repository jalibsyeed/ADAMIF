# Phase 1 Scope – Detection & Visibility Framework

## Included

- Linux authentication log ingestion
- SSH brute-force detection
- Abnormal authentication pattern detection
- Basic file activity monitoring (FIM-lite)
- CLI-based structured alerting
- Evidence-based reporting

---

## Explicitly Excluded

- Machine learning
- Automated blocking or retaliation
- External threat intelligence feeds
- Dashboard or web UI
- Reverse engineering
- Exploit development
- Cloud integrations

---

## Architectural Constraints

- All detection must operate on structured RawEvent objects.
- No interpretation logic inside RawEvent.
- All alerts must be explainable and evidence-backed.
- The system must remain modular and extendable.
---

## Known Phase 1 Detection Limitations

- SSH detection emits only one AttackEvent per IP per run.
- Multiple separate attack waves from the same IP are not individually emitted.
- No incident correlation across time windows.
- No cross-IP correlation.
- No username-based password spray detection (planned for later phase).
- No persistent state between executions.

These are intentional design constraints to preserve clean architectural layering for Phase 2.
---

## Additional Phase 1 Architectural Limitations

### 1. Overlapping Detection Events

In Phase 1, detection engines operate independently.

This means a single attacker IP may trigger multiple AttackEvents
(e.g., SSH_BRUTE_FORCE and PASSWORD_SPRAY) within the same time window.

These events are not merged or correlated in Phase 1.

Rationale:
Detection and correlation are intentionally separated.
Alert merging, deduplication, and incident-level grouping
will be introduced in Phase 2 (Intelligence & Correlation Layer).

---

### 2. No Cross-Engine Correlation

SSHDetectionEngine and AuthBehaviorDetectionEngine
do not share state or merge outputs.

Each rule emits its own AttackEvent independently.

This preserves deterministic replay and strict layer separation.

---

### 3. Single-Window Emission per Rule

Each detection rule emits only the first qualifying window
per source IP per run.

Multi-wave detection and historical tracking
will be introduced in Phase 2.
