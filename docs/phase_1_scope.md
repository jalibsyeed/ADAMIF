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
