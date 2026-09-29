"""How SherLog's workflow maps to the forensic and incident-response standards it follows.

Standards are referenced generally, by name and topic, not by clause number:
clause numbering differs between editions and is easy to misquote.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Standard:
    ref: str
    title: str
    scope: str


STANDARDS = (
    Standard(
        "ISO/IEC 27037",
        "Guidelines for identification, collection, acquisition and preservation of digital "
        "evidence",
        "Evidence handling: hashing at intake, read-only access, chain of custody.",
    ),
    Standard(
        "ISO/IEC 27042",
        "Guidelines for the analysis and interpretation of digital evidence",
        "Analysis: reproducible, documented methods; separation of fact from interpretation.",
    ),
    Standard(
        "ISO/IEC 27043",
        "Incident investigation principles and processes",
        "Overall investigation process from readiness through closure.",
    ),
    Standard(
        "NIST SP 800-86",
        "Guide to Integrating Forensic Techniques into Incident Response",
        "Forensic process phases: collection, examination, analysis, reporting.",
    ),
    Standard(
        "NIST SP 800-61r3",
        "Incident Response Recommendations and Considerations for Cybersecurity Risk Management",
        "Response activities; structure of containment, eradication and recovery advice.",
    ),
    Standard(
        "RFC 3227",
        "Guidelines for Evidence Collection and Archiving",
        "Order of volatility and evidence-handling principles (logs are low-volatility "
        "artifacts collected after memory and network state).",
    ),
)


@dataclass(frozen=True)
class MethodStep:
    phase: str  # NIST SP 800-86 phase
    sherlog: str  # what SherLog did
    standards: tuple[str, ...]


METHODOLOGY = (
    MethodStep(
        "Collection",
        "Evidence referenced in place and opened read-only (O_RDONLY|O_NOFOLLOW, O_NOATIME "
        "where permitted); every file hashed with SHA-256 and MD5 at intake; symlinks and "
        "special files recorded but not followed or read; chain-of-custody record per item.",
        ("ISO/IEC 27037", "RFC 3227", "NIST SP 800-86"),
    ),
    MethodStep(
        "Examination",
        "Artifact types identified by content sampling, not file names; files parsed into a "
        "normalized, time-ordered event timeline; unparseable input kept as parse_error events "
        "and unrecognised files listed as unclassified.",
        ("ISO/IEC 27042", "NIST SP 800-86"),
    ),
    MethodStep(
        "Analysis",
        "Deterministic Sigma rules, correlation rules and built-in analytics applied to the "
        "timeline; every finding linked to the events supporting it and labelled with its "
        "provenance (rule, analyst or AI-proposed). Rule set versions recorded in the audit log.",
        ("ISO/IEC 27042", "ISO/IEC 27043", "NIST SP 800-86"),
    ),
    MethodStep(
        "Reporting",
        "Evidence re-hashed and compared with intake before this report was produced; findings "
        "mapped to MITRE ATT&CK; recommendations grouped by response activity; limitations "
        "stated; full audit log appended.",
        ("ISO/IEC 27037", "NIST SP 800-86", "NIST SP 800-61r3"),
    ),
)


# Response activity for a finding, derived from the ATT&CK tactics of its techniques.
RESPONSE_PHASES = ("containment", "eradication", "recovery", "long_term")
RESPONSE_PHASE_TITLES = {
    "containment": "Immediate containment",
    "eradication": "Eradication",
    "recovery": "Recovery",
    "long_term": "Long-term improvements",
}
_TACTIC_PHASE = {
    "initial_access": "containment",
    "credential_access": "containment",
    "execution": "containment",
    "command_and_control": "containment",
    "lateral_movement": "containment",
    "exfiltration": "containment",
    "persistence": "eradication",
    "privilege_escalation": "eradication",
    "defense_evasion": "recovery",
    "impact": "recovery",
    "collection": "recovery",
}


def response_phase(tactics: list[str]) -> str:
    """The earliest response activity any of the tactics calls for."""
    phases = {_TACTIC_PHASE.get(t, "long_term") for t in tactics} or {"long_term"}
    return min(phases, key=RESPONSE_PHASES.index)
