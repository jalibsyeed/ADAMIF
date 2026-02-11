# Data Model – Phase 1

## RawEvent

RawEvent represents a single atomic fact observed from system telemetry.  
It must contain no interpretation, severity, or confidence scoring.

---

### Mandatory Fields

- event_id
- timestamp
- source_type
- event_type
- raw_message
- host
- log_source

---

### Optional Context Fields

- source_ip
- username
- process_name
- file_path
- file_hash
- service
- port

Optional fields may be null or absent depending on the event type.

---

## Design Constraints

- RawEvent must remain immutable once created.
- RawEvent must not contain attack classifications.
- RawEvent must not contain severity or confidence values.
- RawEvent must survive unchanged across all project phases.

---

AttackEvent schema will be defined after RawEvent is finalized.
