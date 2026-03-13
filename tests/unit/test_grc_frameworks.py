#!/usr/bin/env python3
"""Tests for GRC framework knowledge base — data completeness."""

import pytest

from security_agents.core.grc_frameworks import get_framework, list_frameworks, get_all_frameworks
from security_agents.core.grc_frameworks.cross_mappings import (
    ALL_MAPPINGS, get_mappings, get_control_mappings,
    NIST_TO_ISO27001, NIST_TO_MITRE, ISO27001_TO_MITRE, ISO42001_TO_NIST,
)
from security_agents.core.grc_frameworks.mitre_attack import MITRE_TACTICS


class TestFrameworkRegistry:
    def test_four_frameworks_registered(self):
        frameworks = list_frameworks()
        assert len(frameworks) == 4
        ids = {f["id"] for f in frameworks}
        assert ids == {"nist_csf_2_0", "iso_27001_2022", "iso_42001_2023", "mitre_attack"}

    def test_get_framework_by_id(self):
        fw = get_framework("nist_csf_2_0")
        assert fw is not None
        assert fw.name == "NIST Cybersecurity Framework 2.0"

    def test_get_unknown_framework(self):
        assert get_framework("nonexistent") is None

    def test_get_all_frameworks(self):
        all_fw = get_all_frameworks()
        assert len(all_fw) == 4


class TestNISTCSF20:
    def test_has_controls(self):
        fw = get_framework("nist_csf_2_0")
        assert len(fw.controls) >= 90  # ~106 subcategories

    def test_six_functions_present(self):
        fw = get_framework("nist_csf_2_0")
        prefixes = set()
        for c in fw.controls:
            prefixes.add(c.id.split(".")[0])
        # GV, ID, PR, DE, RS, RC
        assert len(prefixes) >= 6

    def test_govern_function_exists(self):
        """CSF 2.0 added the Govern function."""
        fw = get_framework("nist_csf_2_0")
        gv_controls = [c for c in fw.controls if c.id.startswith("GV")]
        assert len(gv_controls) >= 15

    def test_control_has_required_fields(self):
        fw = get_framework("nist_csf_2_0")
        for control in fw.controls:
            assert control.id
            assert control.framework_id == "nist_csf_2_0"
            assert control.title


class TestISO270012022:
    def test_93_controls(self):
        fw = get_framework("iso_27001_2022")
        assert len(fw.controls) == 93

    def test_four_themes(self):
        fw = get_framework("iso_27001_2022")
        themes = set()
        for c in fw.controls:
            themes.add(c.parent_id)
        assert themes == {"A.5", "A.6", "A.7", "A.8"}

    def test_organizational_controls_count(self):
        fw = get_framework("iso_27001_2022")
        org = [c for c in fw.controls if c.parent_id == "A.5"]
        assert len(org) == 37

    def test_people_controls_count(self):
        fw = get_framework("iso_27001_2022")
        people = [c for c in fw.controls if c.parent_id == "A.6"]
        assert len(people) == 8

    def test_physical_controls_count(self):
        fw = get_framework("iso_27001_2022")
        physical = [c for c in fw.controls if c.parent_id == "A.7"]
        assert len(physical) == 14

    def test_technological_controls_count(self):
        fw = get_framework("iso_27001_2022")
        tech = [c for c in fw.controls if c.parent_id == "A.8"]
        assert len(tech) == 34


class TestISO420012023:
    def test_has_controls(self):
        fw = get_framework("iso_42001_2023")
        assert len(fw.controls) >= 30

    def test_nine_annex_groups(self):
        fw = get_framework("iso_42001_2023")
        groups = set()
        for c in fw.controls:
            groups.add(c.parent_id)
        # A.2 through A.10
        assert len(groups) >= 9

    def test_ai_specific_controls(self):
        fw = get_framework("iso_42001_2023")
        ai_controls = [c for c in fw.controls if "AI" in c.title or "ai" in c.description.lower()]
        assert len(ai_controls) >= 5


class TestMITREATTACK:
    def test_has_techniques(self):
        fw = get_framework("mitre_attack")
        assert len(fw.controls) >= 50

    def test_14_tactics(self):
        assert len(MITRE_TACTICS) >= 13

    def test_tactics_have_techniques(self):
        fw = get_framework("mitre_attack")
        tactics_with_techniques = set()
        for c in fw.controls:
            tactics_with_techniques.add(c.parent_id)
        assert len(tactics_with_techniques) >= 12

    def test_technique_ids_format(self):
        fw = get_framework("mitre_attack")
        for c in fw.controls:
            assert c.id.startswith("T"), f"Technique {c.id} should start with T"


class TestCrossMappings:
    def test_total_mappings(self):
        assert len(ALL_MAPPINGS) >= 30

    def test_nist_to_iso27001_mappings(self):
        assert len(NIST_TO_ISO27001) >= 15

    def test_nist_to_mitre_mappings(self):
        assert len(NIST_TO_MITRE) >= 5

    def test_iso27001_to_mitre_mappings(self):
        assert len(ISO27001_TO_MITRE) >= 5

    def test_iso42001_to_nist_mappings(self):
        assert len(ISO42001_TO_NIST) >= 5

    def test_get_mappings_filter(self):
        mappings = get_mappings("nist_csf_2_0", "iso_27001_2022")
        assert len(mappings) >= 10
        for m in mappings:
            assert m.source_framework == "nist_csf_2_0"
            assert m.target_framework == "iso_27001_2022"

    def test_get_control_mappings(self):
        mappings = get_control_mappings("GV.PO-01")
        assert len(mappings) >= 1
        assert mappings[0].target_controls[0] == "A.5.1"

    def test_mapping_confidence_range(self):
        for m in ALL_MAPPINGS:
            assert 0.0 <= m.confidence <= 100.0

    def test_empty_result_for_unknown_pair(self):
        mappings = get_mappings("nonexistent", "also_nonexistent")
        assert mappings == []
