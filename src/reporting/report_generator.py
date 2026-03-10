"""
ADAMIF Phase 1
Structured SOC-Style Incident Report Generator

Professional SOC-grade presentation layer.
No detection logic.
No mutation.
Pure formatting + contextual enrichment.
"""

from typing import List
from datetime import datetime
import ipaddress

from src.core.attack_event import AttackEvent
from src.core.attack_types import AttackType


class ReportGenerator:

    def generate(self, attacks: List[AttackEvent]) -> str:
        if not attacks:
            return self._generate_no_incidents_report()

        return "\n\n".join(self._format_single_attack(a) for a in attacks)

    # -------------------------------------------------------
    # Core Report Sections
    # -------------------------------------------------------

    def _format_single_attack(self, attack: AttackEvent) -> str:

        return (
            self._header()
            + self._identity_section(attack)
            + self._mitre_section(attack)
            + self._timeline_section(attack)
            + self._attack_details_section(attack)
            + self._source_context_section(attack)
            + self._evidence_section(attack)
            + self._assessment_section(attack)
            + self._recommendations_section()
            + self._footer()
        )

    def _header(self) -> str:
        return (
            "============================================================\n"
            "                ADAMIF INCIDENT REPORT\n"
            "============================================================\n"
        )

    def _footer(self) -> str:
        return "\n============================================================"

    # -------------------------------------------------------

    def _identity_section(self, attack: AttackEvent) -> str:
        return (
            f"\nIncident ID      : {attack.attack_id}\n"
            f"Attack Type      : {attack.attack_type.value}\n"
            f"Severity         : {attack.severity.value}\n"
            f"Confidence Score : {attack.confidence:.2f}\n"
        )

    # -------------------------------------------------------
    # MITRE Mapping
    # -------------------------------------------------------

    def _mitre_section(self, attack: AttackEvent) -> str:

        if attack.attack_type == AttackType.SSH_BRUTE_FORCE:
            tactic = "Credential Access"
            technique = "T1110 – Brute Force"

        elif attack.attack_type == AttackType.PASSWORD_SPRAY:
            tactic = "Credential Access"
            technique = "T1110.003 – Password Spraying"

        else:
            tactic = "Unknown"
            technique = "Unknown"

        return (
            "\n--- MITRE ATT&CK Mapping -----------------------------------\n"
            f"Tactic            : {tactic}\n"
            f"Technique         : {technique}\n"
        )

    # -------------------------------------------------------

    def _timeline_section(self, attack: AttackEvent) -> str:
        duration = int((attack.end_time - attack.start_time).total_seconds())

        return (
            "\n--- Timeline -----------------------------------------------\n"
            f"Start Time (UTC) : {self._format_time(attack.start_time)}\n"
            f"End Time (UTC)   : {self._format_time(attack.end_time)}\n"
            f"Duration         : {duration} seconds\n"
        )

    # -------------------------------------------------------

    def _attack_details_section(self, attack: AttackEvent) -> str:
        return (
            "\n--- Attack Details -----------------------------------------\n"
            f"Source IP        : {attack.source_ip}\n"
            f"Target Service   : {attack.target_service}\n"
            f"Attempt Count    : {attack.frequency}\n"
        )

    # -------------------------------------------------------
    # Source Context Analysis
    # -------------------------------------------------------

    def _source_context_section(self, attack: AttackEvent) -> str:

        context = self._classify_ip(attack.source_ip)

        return (
            "\n--- Source Context -----------------------------------------\n"
            f"Network Classification : {context}\n"
        )

    def _classify_ip(self, ip: str) -> str:
        try:
            parsed = ipaddress.ip_address(ip)

            if parsed.is_loopback:
                return "Loopback / Localhost (Potential local compromise)"

            if parsed.is_private:
                return "Private Internal Network"

            return "Public / External Network"

        except ValueError:
            return "Unrecognized IP Format"

    # -------------------------------------------------------

    def _evidence_section(self, attack: AttackEvent) -> str:
        section = (
            "\n--- Evidence -----------------------------------------------\n"
            f"Related Events   : {len(attack.related_event_ids)} RawEvent(s)\n"
            "Event References :\n"
        )

        for event_id in attack.related_event_ids:
            section += f"  - {event_id}\n"

        return section

    # -------------------------------------------------------
    # Analyst Reasoning
    # -------------------------------------------------------

    def _assessment_section(self, attack: AttackEvent) -> str:

        risk_comment = self._risk_analysis(attack)

        return (
            "\n--- Analyst Assessment -------------------------------------\n"
            f"{attack.analysis_notes}\n\n"
            "Risk Impact Assessment:\n"
            f"{risk_comment}\n\n"
            "Confidence Explanation:\n"
            f"- Detection confidence score: {attack.confidence:.2f}\n"
            "- Derived from rule threshold satisfaction and event density.\n"
        )

    def _risk_analysis(self, attack: AttackEvent) -> str:

        if attack.source_ip in ("127.0.0.1", "::1"):
            return (
                "Authentication attempts originated from localhost. "
                "This may indicate automated local script abuse, "
                "credential harvesting malware, or misconfigured service loops."
            )

        if attack.confidence >= 0.9:
            return (
                "High-confidence brute-force activity. "
                "Repeated authentication failures suggest deliberate credential attack."
            )

        return (
            "Observed authentication anomalies require monitoring. "
            "Further investigation recommended to determine attacker intent."
        )

    # -------------------------------------------------------

    def _recommendations_section(self) -> str:
        return (
            "\n--- Recommended Actions ------------------------------------\n"
            "• Review authentication logs for further suspicious activity.\n"
            "• Consider temporary IP blocking at firewall level (manual action).\n"
            "• Verify whether targeted usernames are legitimate accounts.\n"
            "• Monitor for continued activity from the same source IP.\n"
            "• Preserve logs for forensic review if required.\n"
        )

    def _generate_no_incidents_report(self) -> str:
        return (
            "============================================================\n"
            "                ADAMIF INCIDENT REPORT\n"
            "============================================================\n\n"
            "Status: No security incidents detected.\n"
            "Telemetry processed successfully.\n"
            "All detection thresholds remained below trigger conditions.\n\n"
            "============================================================"
        )

    def _format_time(self, dt: datetime) -> str:
        return dt.strftime("%Y-%m-%d %H:%M:%S %Z")
