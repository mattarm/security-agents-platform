"""Pre-built cross-framework control mappings."""

from security_agents.core.grc_models import CrossMapping, RelationshipType

# =============================================================================
# NIST CSF 2.0 <-> ISO 27001:2022
# =============================================================================

NIST_TO_ISO27001 = [
    CrossMapping(source_control="GV.OC-03", source_framework="nist_csf_2_0", target_framework="iso_27001_2022",
                 target_controls=["A.5.31"], relationship=RelationshipType.EQUIVALENT, confidence=90.0),
    CrossMapping(source_control="GV.RR-01", source_framework="nist_csf_2_0", target_framework="iso_27001_2022",
                 target_controls=["A.5.2"], relationship=RelationshipType.EQUIVALENT, confidence=90.0),
    CrossMapping(source_control="GV.PO-01", source_framework="nist_csf_2_0", target_framework="iso_27001_2022",
                 target_controls=["A.5.1"], relationship=RelationshipType.EQUIVALENT, confidence=95.0),
    CrossMapping(source_control="GV.SC-01", source_framework="nist_csf_2_0", target_framework="iso_27001_2022",
                 target_controls=["A.5.19", "A.5.21"], relationship=RelationshipType.PARTIAL, confidence=85.0),
    CrossMapping(source_control="ID.AM-01", source_framework="nist_csf_2_0", target_framework="iso_27001_2022",
                 target_controls=["A.5.9"], relationship=RelationshipType.EQUIVALENT, confidence=90.0),
    CrossMapping(source_control="ID.AM-02", source_framework="nist_csf_2_0", target_framework="iso_27001_2022",
                 target_controls=["A.5.9"], relationship=RelationshipType.EQUIVALENT, confidence=90.0),
    CrossMapping(source_control="ID.RA-01", source_framework="nist_csf_2_0", target_framework="iso_27001_2022",
                 target_controls=["A.8.8"], relationship=RelationshipType.EQUIVALENT, confidence=85.0),
    CrossMapping(source_control="ID.RA-02", source_framework="nist_csf_2_0", target_framework="iso_27001_2022",
                 target_controls=["A.5.7"], relationship=RelationshipType.EQUIVALENT, confidence=90.0),
    CrossMapping(source_control="PR.AA-01", source_framework="nist_csf_2_0", target_framework="iso_27001_2022",
                 target_controls=["A.5.16"], relationship=RelationshipType.EQUIVALENT, confidence=90.0),
    CrossMapping(source_control="PR.AA-03", source_framework="nist_csf_2_0", target_framework="iso_27001_2022",
                 target_controls=["A.8.5"], relationship=RelationshipType.EQUIVALENT, confidence=90.0),
    CrossMapping(source_control="PR.AA-05", source_framework="nist_csf_2_0", target_framework="iso_27001_2022",
                 target_controls=["A.5.15", "A.5.18", "A.8.3"], relationship=RelationshipType.PARTIAL, confidence=85.0),
    CrossMapping(source_control="PR.DS-01", source_framework="nist_csf_2_0", target_framework="iso_27001_2022",
                 target_controls=["A.8.24"], relationship=RelationshipType.PARTIAL, confidence=80.0),
    CrossMapping(source_control="PR.DS-02", source_framework="nist_csf_2_0", target_framework="iso_27001_2022",
                 target_controls=["A.8.24"], relationship=RelationshipType.PARTIAL, confidence=80.0),
    CrossMapping(source_control="PR.AT-01", source_framework="nist_csf_2_0", target_framework="iso_27001_2022",
                 target_controls=["A.6.3"], relationship=RelationshipType.EQUIVALENT, confidence=90.0),
    CrossMapping(source_control="PR.PS-06", source_framework="nist_csf_2_0", target_framework="iso_27001_2022",
                 target_controls=["A.8.25", "A.8.28"], relationship=RelationshipType.EQUIVALENT, confidence=85.0),
    CrossMapping(source_control="DE.CM-01", source_framework="nist_csf_2_0", target_framework="iso_27001_2022",
                 target_controls=["A.8.16", "A.8.20"], relationship=RelationshipType.PARTIAL, confidence=85.0),
    CrossMapping(source_control="DE.AE-02", source_framework="nist_csf_2_0", target_framework="iso_27001_2022",
                 target_controls=["A.5.25"], relationship=RelationshipType.EQUIVALENT, confidence=85.0),
    CrossMapping(source_control="RS.MA-01", source_framework="nist_csf_2_0", target_framework="iso_27001_2022",
                 target_controls=["A.5.24", "A.5.26"], relationship=RelationshipType.EQUIVALENT, confidence=90.0),
    CrossMapping(source_control="RS.AN-07", source_framework="nist_csf_2_0", target_framework="iso_27001_2022",
                 target_controls=["A.5.28"], relationship=RelationshipType.EQUIVALENT, confidence=95.0),
    CrossMapping(source_control="RC.RP-01", source_framework="nist_csf_2_0", target_framework="iso_27001_2022",
                 target_controls=["A.5.29", "A.5.30"], relationship=RelationshipType.PARTIAL, confidence=80.0),
]

# =============================================================================
# NIST CSF 2.0 <-> MITRE ATT&CK
# =============================================================================

NIST_TO_MITRE = [
    CrossMapping(source_control="ID.RA-02", source_framework="nist_csf_2_0", target_framework="mitre_attack",
                 target_controls=["T1595", "T1592", "T1589", "T1590", "T1591"],
                 relationship=RelationshipType.RELATED, confidence=75.0),
    CrossMapping(source_control="PR.AA-01", source_framework="nist_csf_2_0", target_framework="mitre_attack",
                 target_controls=["T1078", "T1136"], relationship=RelationshipType.RELATED, confidence=80.0),
    CrossMapping(source_control="PR.AA-03", source_framework="nist_csf_2_0", target_framework="mitre_attack",
                 target_controls=["T1110", "T1003"], relationship=RelationshipType.RELATED, confidence=80.0),
    CrossMapping(source_control="PR.DS-01", source_framework="nist_csf_2_0", target_framework="mitre_attack",
                 target_controls=["T1486", "T1005"], relationship=RelationshipType.RELATED, confidence=70.0),
    CrossMapping(source_control="DE.CM-01", source_framework="nist_csf_2_0", target_framework="mitre_attack",
                 target_controls=["T1071", "T1572", "T1090"], relationship=RelationshipType.RELATED, confidence=80.0),
    CrossMapping(source_control="DE.CM-09", source_framework="nist_csf_2_0", target_framework="mitre_attack",
                 target_controls=["T1059", "T1053", "T1547"], relationship=RelationshipType.RELATED, confidence=75.0),
    CrossMapping(source_control="DE.AE-07", source_framework="nist_csf_2_0", target_framework="mitre_attack",
                 target_controls=["T1566", "T1190"], relationship=RelationshipType.RELATED, confidence=75.0),
    CrossMapping(source_control="RS.MI-01", source_framework="nist_csf_2_0", target_framework="mitre_attack",
                 target_controls=["T1021", "T1570"], relationship=RelationshipType.RELATED, confidence=70.0),
]

# =============================================================================
# ISO 27001:2022 <-> MITRE ATT&CK
# =============================================================================

ISO27001_TO_MITRE = [
    CrossMapping(source_control="A.5.7", source_framework="iso_27001_2022", target_framework="mitre_attack",
                 target_controls=["T1595", "T1566", "T1190"],
                 relationship=RelationshipType.RELATED, confidence=75.0),
    CrossMapping(source_control="A.8.7", source_framework="iso_27001_2022", target_framework="mitre_attack",
                 target_controls=["T1204", "T1203", "T1059"],
                 relationship=RelationshipType.RELATED, confidence=80.0),
    CrossMapping(source_control="A.8.2", source_framework="iso_27001_2022", target_framework="mitre_attack",
                 target_controls=["T1548", "T1134", "T1068"],
                 relationship=RelationshipType.RELATED, confidence=80.0),
    CrossMapping(source_control="A.8.15", source_framework="iso_27001_2022", target_framework="mitre_attack",
                 target_controls=["T1070"], relationship=RelationshipType.RELATED, confidence=85.0),
    CrossMapping(source_control="A.8.16", source_framework="iso_27001_2022", target_framework="mitre_attack",
                 target_controls=["T1562", "T1036", "T1027"],
                 relationship=RelationshipType.RELATED, confidence=80.0),
    CrossMapping(source_control="A.8.12", source_framework="iso_27001_2022", target_framework="mitre_attack",
                 target_controls=["T1041", "T1567", "T1048"],
                 relationship=RelationshipType.RELATED, confidence=85.0),
]

# =============================================================================
# ISO 42001:2023 <-> NIST CSF 2.0
# =============================================================================

ISO42001_TO_NIST = [
    CrossMapping(source_control="A.2.2", source_framework="iso_42001_2023", target_framework="nist_csf_2_0",
                 target_controls=["GV.PO-01"], relationship=RelationshipType.PARTIAL, confidence=75.0),
    CrossMapping(source_control="A.3.2", source_framework="iso_42001_2023", target_framework="nist_csf_2_0",
                 target_controls=["GV.RR-01"], relationship=RelationshipType.PARTIAL, confidence=75.0),
    CrossMapping(source_control="A.5.2", source_framework="iso_42001_2023", target_framework="nist_csf_2_0",
                 target_controls=["ID.RA-04", "ID.RA-05"], relationship=RelationshipType.RELATED, confidence=70.0),
    CrossMapping(source_control="A.6.4", source_framework="iso_42001_2023", target_framework="nist_csf_2_0",
                 target_controls=["PR.PS-06"], relationship=RelationshipType.RELATED, confidence=70.0),
    CrossMapping(source_control="A.9.2", source_framework="iso_42001_2023", target_framework="nist_csf_2_0",
                 target_controls=["GV.RM-01"], relationship=RelationshipType.RELATED, confidence=65.0),
    CrossMapping(source_control="A.10.5", source_framework="iso_42001_2023", target_framework="nist_csf_2_0",
                 target_controls=["RS.MA-01"], relationship=RelationshipType.RELATED, confidence=70.0),
]

# =============================================================================
# Aggregate accessors
# =============================================================================

ALL_MAPPINGS = NIST_TO_ISO27001 + NIST_TO_MITRE + ISO27001_TO_MITRE + ISO42001_TO_NIST


def get_mappings(source_framework: str, target_framework: str) -> list[CrossMapping]:
    """Get all mappings between two frameworks."""
    return [
        m for m in ALL_MAPPINGS
        if m.source_framework == source_framework and m.target_framework == target_framework
    ]


def get_control_mappings(control_id: str) -> list[CrossMapping]:
    """Get all mappings for a specific control."""
    return [m for m in ALL_MAPPINGS if m.source_control == control_id]
