# ADAMIF Phase-1: Primitive Signal Extraction

## Overview

**ADAMIF (Attack Detection and Malware Intelligence Framework)** is a SOC-aligned defensive intelligence framework designed to extract security signals from multiple sources and later correlate them into actionable security incidents.

Phase-1 of ADAMIF focuses exclusively on **primitive signal extraction**.
These signals are intentionally simple, deterministic indicators that will later be correlated by the Phase-2 correlation engine.

Phase-1 contains **two independent intelligence engines**:

1. **Telemetry-based Attack Detection**
2. **Static Malware Intelligence Analysis**

Both engines produce **primitive security signals** that represent observable indicators of potentially malicious behavior.

Phase-1 does **not perform full incident detection or malware classification**.
Its role is to produce structured signals that Phase-2 will combine into meaningful security incidents.

---

# Phase-1 Architecture

The Phase-1 architecture consists of two signal generation pipelines:

```
System Telemetry ───────► Telemetry Detection Engine
                               │
                               ▼
                       Telemetry Attack Indicators
                               │
                               │
Suspicious Files ───────► Static Malware Intelligence Engine
                               │
                               ▼
                        File Intelligence Indicators
                               │
                               ▼
                        Primitive Signal Pool
```

These signals are later consumed by the **Phase-2 Correlation Engine**, which merges them into structured incidents.

---

# Telemetry Intelligence Engine

Telemetry intelligence processes **system-level events** and detects suspicious activity patterns.

Implemented modules:

```
src/ingestion/
src/detection/
```

Core capabilities include:

• Linux authentication log ingestion
• RawEvent generation
• SSH brute-force detection
• password spray detection
• username enumeration detection
• AttackEvent generation

These detections produce **telemetry attack indicators** that represent suspicious host activity.

Example signals may include:

```
SSH_BRUTE_FORCE_DETECTED
PASSWORD_SPRAY_ACTIVITY
USERNAME_ENUMERATION_ATTEMPT
```

These indicators describe **behavior observed on the host**, not files.

---

# Static Malware Intelligence Engine

The static malware intelligence engine analyzes suspicious files to extract deterministic indicators.

Implemented modules:

```
src/malware/
```

Capabilities include:

• file fingerprinting (SHA-256, size, permissions)
• file type identification
• deterministic string extraction
• URL/domain/IP detection
• base64 artifact decoding
• heuristic indicator generation
• deterministic suspicion scoring

These operations extract **file intelligence indicators** from suspicious binaries or scripts.

Example indicators include:

```
EXECUTABLE_PERMISSION
SUSPICIOUS_STRING_REFERENCE
EMBEDDED_URL
HARD_CODED_PUBLIC_IP
HIGH_ENTROPY_BINARY
```

These indicators describe **file characteristics**, not confirmed malicious behavior.

---

# Important Clarifications

The static malware engine is **not a malware classifier** and not a full malware scanning system.

It performs **static triage and signal extraction only**.

The engine intentionally avoids:

• dynamic execution
• sandbox analysis
• behavioral simulation
• machine learning
• external threat-intelligence APIs

Its sole purpose is to produce **primitive file intelligence indicators** that can later be correlated with telemetry signals.

---

# Primitive Signal Model

All Phase-1 outputs represent **signals rather than conclusions**.

Signals may originate from:

Telemetry Intelligence

```
host authentication events
login failures
network activity
process behavior
```

Static Malware Intelligence

```
binary structure indicators
command execution artifacts
network communication artifacts
obfuscation artifacts
```

Phase-1 therefore acts as a **signal generation layer** within the larger ADAMIF pipeline.

---

# Phase-2 Architecture (Preview)

Phase-2 introduces the **Correlation Engine**.

This engine merges signals from multiple sources:

• telemetry attack detection
• malware intelligence indicators
• host context

The correlation engine generates structured incident objects:

```
CompositeIncident
```

Example conceptual correlation:

```
SSH brute-force activity detected
        +
Suspicious downloader script discovered
        +
Outbound connection to unknown IP
        =
Composite security incident
```

This is the stage where ADAMIF evolves from **individual detectors** into a **defensive intelligence system capable of incident analysis**.

---

# Phase-1 Design Principles

Phase-1 is intentionally constrained to maintain stability and explainability.

The system prioritizes:

• deterministic analysis
• transparent detection logic
• reproducible results
• offline operation

Phase-1 intentionally avoids complex decision-making.
Instead, it produces **reliable primitive signals** that later phases can analyze in context.

---

# Current Implementation Status

Phase-1 Primitive Signal Extraction Engine

```
Telemetry Intelligence Engine      ✔ Implemented
Static Malware Intelligence Engine ✔ Implemented
Signal Generation                  ✔ Stable
Deterministic Scoring              ✔ Implemented
Dataset Validation                 ✔ Passing
Unit Tests                         ✔ Passing
```

Phase-1 is considered **stable and ready for Phase-2 correlation development**.

---

# ADAMIF Pipeline Summary

The full framework pipeline can be summarized as:

```
System Telemetry
        │
        ▼
Telemetry Detection Engine
        │
        ▼
Telemetry Attack Indicators
        │
        │
Suspicious Files
        │
        ▼
Static Malware Intelligence Engine
        │
        ▼
File Intelligence Indicators
        │
        ▼
Primitive Signal Pool
        │
        ▼
PHASE-2 CORRELATION ENGINE
        │
        ▼
CompositeIncident
        │
        ▼
PHASE-3 SOC Visualization Layer
```

This architecture allows ADAMIF to evolve from **signal extraction** to **security intelligence correlation and incident analysis**.
