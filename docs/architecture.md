# Architecture Overview

ADAMIF follows a layered architecture:

Raw Data → RawEvent → AttackEvent → Incident → (Optional) Response

---

## Core Principles

- RawEvent represents atomic, immutable facts.
- AttackEvent represents interpreted security-relevant behavior.
- Incidents group correlated attack events.
- Response actions must be rule-based and explainable.
- The core engine must remain separate from any UI or dashboard components.

---

## Architectural Rule

All detection and analysis logic must operate on structured events, not raw text logs.
