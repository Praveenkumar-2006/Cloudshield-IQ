"""
CloudShield IQ — Playbook Catalog Tests
=======================================
Unit tests validating multi-cloud remediation playbook structures, step schemas,
multi-language automation snippets, and catalog completeness.
"""

import pytest

from app.core.taxonomy import CloudProvider
from app.recommendations import get_default_playbooks, get_playbook_by_id
from app.schemas.recommendations import ActionType, EffortLevel, RemediationPlaybook


class TestPlaybookCatalog:
    """Validates the standard remediation playbook catalog."""

    def test_catalog_not_empty(self):
        playbooks = get_default_playbooks()
        assert len(playbooks) >= 10

    def test_multi_cloud_coverage(self):
        playbooks = get_default_playbooks()
        providers = {pb.cloud_provider for pb in playbooks}
        assert CloudProvider.AWS in providers
        assert CloudProvider.AZURE in providers
        assert CloudProvider.GCP in providers

    def test_playbook_id_uniqueness(self):
        playbooks = get_default_playbooks()
        ids = [pb.playbook_id for pb in playbooks]
        assert len(ids) == len(set(ids)), "Playbook IDs must be strictly unique"

    def test_playbook_lookup_by_id(self):
        pb = get_playbook_by_id("PB-AWS-IAM-001")
        assert pb is not None
        assert pb.cloud_provider == CloudProvider.AWS
        assert pb.category == "IAM"
        assert pb.effort_level == EffortLevel.LOW
        assert pb.estimated_risk_reduction > 0

    def test_playbook_lookup_not_found(self):
        assert get_playbook_by_id("NON-EXISTENT-ID") is None

    def test_playbook_step_structure(self):
        playbooks = get_default_playbooks()
        for pb in playbooks:
            assert len(pb.steps) >= 1, f"{pb.playbook_id} must have at least 1 step"
            for step in pb.steps:
                assert step.step_number >= 1
                assert step.title
                assert step.command_or_code
                assert step.action_type in (
                    ActionType.CLI,
                    ActionType.TERRAFORM,
                    ActionType.PYTHON_SDK,
                    ActionType.MANUAL_STEP,
                )

    def test_multi_language_code_presence(self):
        playbooks = get_default_playbooks()
        for pb in playbooks:
            assert pb.cli_command, f"{pb.playbook_id} missing CLI command"
            assert pb.terraform_snippet, f"{pb.playbook_id} missing Terraform snippet"
            assert pb.python_script, f"{pb.playbook_id} missing Python script"
            assert "resource" in pb.terraform_snippet or "variable" in pb.terraform_snippet
            assert "def " in pb.python_script or "import " in pb.python_script
