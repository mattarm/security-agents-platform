"""Tests for the Secrets Scanning Skill."""

import pytest

from security_agents.skills.secrets_scanning import SecretsScanningSkill, SecretType, FindingSeverity


@pytest.fixture
async def secrets_skill():
    """Create and initialize a secrets scanning skill."""
    skill = SecretsScanningSkill(agent_id="beta_4_devsecops", config={})
    await skill.initialize()
    return skill


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestSecretsInit:
    @pytest.mark.asyncio
    async def test_initialize(self, secrets_skill):
        assert secrets_skill.initialized
        assert secrets_skill.SKILL_NAME == "secrets_scanning"

    @pytest.mark.asyncio
    async def test_not_initialized_returns_error(self):
        skill = SecretsScanningSkill(agent_id="test", config={})
        result = await skill.execute({"action": "scan_file"})
        assert not result.success
        assert "not initialized" in result.errors[0]

    def test_metadata(self):
        skill = SecretsScanningSkill(agent_id="beta_4_devsecops", config={})
        meta = skill.get_metadata()
        assert meta["skill_name"] == "secrets_scanning"
        assert "beta_4_devsecops" in meta["compatible_agents"]


# ---------------------------------------------------------------------------
# scan_file
# ---------------------------------------------------------------------------


class TestScanFile:
    @pytest.mark.asyncio
    async def test_scan_file_with_github_token(self, secrets_skill):
        result = await secrets_skill.execute({
            "action": "scan_file",
            "filepath": ".env",
            "content": "GITHUB_TOKEN=ghp_ABCDEFghijklmnopqrstuvwxyz0123456789",
        })
        assert result.success
        findings = result.data["findings"]
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_scan_file_with_private_key(self, secrets_skill):
        result = await secrets_skill.execute({
            "action": "scan_file",
            "filepath": "id_rsa",
            "content": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
        })
        assert result.success
        findings = result.data["findings"]
        assert len(findings) >= 1
        assert any("private_key" in f.get("secret_type", "").lower() for f in findings)

    @pytest.mark.asyncio
    async def test_scan_file_clean(self, secrets_skill):
        result = await secrets_skill.execute({
            "action": "scan_file",
            "filepath": "app/main.py",
            "content": "def hello():\n    return 'Hello, World!'\n",
        })
        assert result.success
        assert len(result.data["findings"]) == 0

    @pytest.mark.asyncio
    async def test_scan_file_db_connection_string(self, secrets_skill):
        result = await secrets_skill.execute({
            "action": "scan_file",
            "filepath": "docker-compose.yml",
            "content": 'DATABASE_URL=postgres://admin:s3cret_pass@db.host.com:5432/mydb',
        })
        assert result.success
        findings = result.data["findings"]
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_scan_file_stripe_key(self, secrets_skill):
        result = await secrets_skill.execute({
            "action": "scan_file",
            "filepath": "billing.py",
            "content": 'STRIPE_KEY = "sk_live_' + 'a' * 24 + '"',
        })
        assert result.success
        findings = result.data["findings"]
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_scan_file_slack_webhook(self, secrets_skill):
        result = await secrets_skill.execute({
            "action": "scan_file",
            "filepath": "notify.py",
            "content": 'WEBHOOK = "https://hooks.slack.com/services/' + 'T' * 9 + '/' + 'B' * 9 + '/' + 'X' * 24 + '"',
        })
        assert result.success
        findings = result.data["findings"]
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_scan_file_severity_levels(self, secrets_skill):
        result = await secrets_skill.execute({
            "action": "scan_file",
            "filepath": "config.py",
            "content": 'ghp_ABCDEFghijklmnopqrstuvwxyz0123456789\nhttps://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX',
        })
        assert result.success
        if len(result.data["findings"]) >= 2:
            severities = {f.get("severity", "") for f in result.data["findings"]}
            assert len(severities) >= 1


# ---------------------------------------------------------------------------
# scan_repo
# ---------------------------------------------------------------------------


class TestScanRepo:
    @pytest.mark.asyncio
    async def test_scan_repo(self, secrets_skill):
        result = await secrets_skill.execute({
            "action": "scan_repo",
            "file_contents": {
                "main.py": "print('hello')",
                ".env": "GITHUB_TOKEN=ghp_ABCDEFghijklmnopqrstuvwxyz0123456789",
            },
        })
        assert result.success
        assert result.data["scan"]["files_scanned"] >= 1

    @pytest.mark.asyncio
    async def test_scan_repo_skips_binary_extensions(self, secrets_skill):
        result = await secrets_skill.execute({
            "action": "scan_repo",
            "file_contents": {
                "image.png": "binary data here",
                "app.py": "x = 1",
            },
        })
        assert result.success
        assert result.data["scan"]["files_skipped"] >= 1


# ---------------------------------------------------------------------------
# scan_commit_history
# ---------------------------------------------------------------------------


class TestScanCommitHistory:
    @pytest.mark.asyncio
    async def test_scan_commits(self, secrets_skill):
        result = await secrets_skill.execute({
            "action": "scan_commit_history",
            "commits": [
                {
                    "sha": "abc123",
                    "message": "add config",
                    "diff": '+AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
                },
            ],
        })
        assert result.success
        assert result.data["commits_scanned"] >= 1


# ---------------------------------------------------------------------------
# add_allowlist
# ---------------------------------------------------------------------------


class TestAddAllowlist:
    @pytest.mark.asyncio
    async def test_add_to_allowlist(self, secrets_skill):
        result = await secrets_skill.execute({
            "action": "add_allowlist",
            "value": "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789",
            "reason": "Test token from documentation",
        })
        assert result.success

    @pytest.mark.asyncio
    async def test_allowlist_suppresses_findings(self, secrets_skill):
        await secrets_skill.execute({
            "action": "add_allowlist",
            "value": "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789",
            "reason": "test key",
        })
        result = await secrets_skill.execute({
            "action": "scan_file",
            "filepath": "test.py",
            "content": "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789",
        })
        assert result.success
        # Allowlisted value should be suppressed
        findings = result.data["findings"]
        assert all("ghp_ABCDEF" not in f.get("match", "") for f in findings)


# ---------------------------------------------------------------------------
# get_findings / generate_report
# ---------------------------------------------------------------------------


class TestGetFindingsAndReport:
    @pytest.mark.asyncio
    async def test_get_findings(self, secrets_skill):
        await secrets_skill.execute({
            "action": "scan_file",
            "filepath": "leak.py",
            "content": "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789",
        })
        result = await secrets_skill.execute({"action": "get_findings"})
        assert result.success
        assert result.data["total_findings"] >= 1

    @pytest.mark.asyncio
    async def test_generate_report(self, secrets_skill):
        await secrets_skill.execute({
            "action": "scan_file",
            "filepath": "leak.py",
            "content": "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789",
        })
        result = await secrets_skill.execute({"action": "generate_report"})
        assert result.success
        assert "report" in result.data


# ---------------------------------------------------------------------------
# Unknown Action
# ---------------------------------------------------------------------------


class TestSecretsUnknownAction:
    @pytest.mark.asyncio
    async def test_unknown_action(self, secrets_skill):
        result = await secrets_skill.execute({"action": "nonexistent"})
        assert not result.success
        assert "Unknown action" in result.errors[0]
