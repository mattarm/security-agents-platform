"""Tests for the AWS Infrastructure Assessment Skill."""

import pytest

from security_agents.skills.aws_infrastructure import AWSInfrastructureSkill


@pytest.fixture
async def aws_skill():
    """Create and initialize an AWS infrastructure skill."""
    skill = AWSInfrastructureSkill(agent_id="beta_4_devsecops", config={})
    await skill.initialize()
    return skill


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestAWSInfraInit:
    @pytest.mark.asyncio
    async def test_initialize(self, aws_skill):
        assert aws_skill.initialized
        assert aws_skill.SKILL_NAME == "aws_infrastructure"

    @pytest.mark.asyncio
    async def test_not_initialized_returns_error(self):
        skill = AWSInfrastructureSkill(agent_id="test", config={})
        result = await skill.execute({"action": "assess_vpc"})
        assert not result.success
        assert "not initialized" in result.errors[0]

    def test_metadata(self):
        skill = AWSInfrastructureSkill(agent_id="beta_4_devsecops", config={})
        meta = skill.get_metadata()
        assert meta["skill_name"] == "aws_infrastructure"
        assert "beta_4_devsecops" in meta["compatible_agents"]


# ---------------------------------------------------------------------------
# assess_vpc
# ---------------------------------------------------------------------------


class TestAssessVPC:
    @pytest.mark.asyncio
    async def test_vpc_no_flow_logs(self, aws_skill):
        result = await aws_skill.execute({
            "action": "assess_vpc",
            "vpc": {
                "vpc_id": "vpc-test123",
                "cidr_block": "10.0.0.0/16",
                "flow_logs_enabled": False,
            },
        })
        assert result.success
        issues = result.data["issues"]
        assert any("flow_logs" in i.get("finding_type", "") or "flow log" in i.get("description", "").lower() for i in issues)

    @pytest.mark.asyncio
    async def test_vpc_secure_config(self, aws_skill):
        result = await aws_skill.execute({
            "action": "assess_vpc",
            "vpc": {
                "vpc_id": "vpc-secure",
                "cidr_block": "10.0.0.0/16",
                "flow_logs_enabled": True,
                "dns_hostnames_enabled": True,
                "dns_support_enabled": True,
                "availability_zone_count": 3,
                "internet_gateway_attached": True,
                "private_subnets": ["subnet-priv1"],
                "public_subnets": ["subnet-pub1"],
            },
        })
        assert result.success
        assert len(result.data["checks_passed"]) >= 3

    @pytest.mark.asyncio
    async def test_vpc_oversized_cidr(self, aws_skill):
        result = await aws_skill.execute({
            "action": "assess_vpc",
            "vpc": {
                "vpc_id": "vpc-big",
                "cidr_block": "10.0.0.0/8",
                "flow_logs_enabled": True,
            },
        })
        assert result.success
        issues = result.data["issues"]
        assert any("cidr" in i.get("finding_type", "").lower() or "cidr" in i.get("description", "").lower() for i in issues)

    @pytest.mark.asyncio
    async def test_vpc_single_az(self, aws_skill):
        result = await aws_skill.execute({
            "action": "assess_vpc",
            "vpc": {
                "vpc_id": "vpc-1az",
                "cidr_block": "10.0.0.0/16",
                "flow_logs_enabled": True,
                "availability_zone_count": 1,
            },
        })
        assert result.success
        issues = result.data["issues"]
        assert any("az" in i.get("finding_type", "").lower() or "availability zone" in i.get("description", "").lower() for i in issues)

    @pytest.mark.asyncio
    async def test_vpc_permissive_nacl(self, aws_skill):
        result = await aws_skill.execute({
            "action": "assess_vpc",
            "vpc": {
                "vpc_id": "vpc-nacl",
                "cidr_block": "10.0.0.0/16",
                "flow_logs_enabled": True,
                "nacls": [{"nacl_id": "nacl-1", "allows_all_inbound": True}],
            },
        })
        assert result.success
        issues = result.data["issues"]
        assert any("nacl" in i.get("finding_type", "").lower() or "nacl" in i.get("description", "").lower() for i in issues)


# ---------------------------------------------------------------------------
# audit_iam
# ---------------------------------------------------------------------------


class TestAuditIAM:
    @pytest.mark.asyncio
    async def test_iam_wildcard_policy(self, aws_skill):
        result = await aws_skill.execute({
            "action": "audit_iam",
            "policies": [
                {
                    "policy_name": "AdminPolicy",
                    "statements": [
                        {"Effect": "Allow", "Action": ["iam:*"], "Resource": ["*"]},
                    ],
                },
            ],
        })
        assert result.success
        issues = result.data["issues"]
        assert len(issues) >= 1

    @pytest.mark.asyncio
    async def test_iam_least_privilege(self, aws_skill):
        result = await aws_skill.execute({
            "action": "audit_iam",
            "policies": [
                {
                    "policy_name": "ReadOnlyPolicy",
                    "statements": [
                        {"effect": "Allow", "actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::my-bucket/*"]},
                    ],
                },
            ],
        })
        assert result.success
        # Least privilege policy should have fewer/no issues
        assert len(result.data.get("issues", [])) == 0 or result.data.get("risk_level") in ("low", "none")


# ---------------------------------------------------------------------------
# check_s3_exposure
# ---------------------------------------------------------------------------


class TestCheckS3Exposure:
    @pytest.mark.asyncio
    async def test_public_bucket(self, aws_skill):
        result = await aws_skill.execute({
            "action": "check_s3_exposure",
            "buckets": [
                {
                    "bucket_name": "public-data",
                    "public_access": True,
                    "encryption_enabled": False,
                    "logging_enabled": False,
                    "versioning_enabled": False,
                },
            ],
        })
        assert result.success
        issues = result.data["issues"]
        assert len(issues) >= 1

    @pytest.mark.asyncio
    async def test_secure_bucket(self, aws_skill):
        result = await aws_skill.execute({
            "action": "check_s3_exposure",
            "buckets": [
                {
                    "bucket_name": "secure-bucket",
                    "public_access": False,
                    "encryption_enabled": True,
                    "logging_enabled": True,
                    "versioning_enabled": True,
                },
            ],
        })
        assert result.success


# ---------------------------------------------------------------------------
# scan_security_groups
# ---------------------------------------------------------------------------


class TestScanSecurityGroups:
    @pytest.mark.asyncio
    async def test_overly_permissive_sg(self, aws_skill):
        result = await aws_skill.execute({
            "action": "scan_security_groups",
            "security_groups": [
                {
                    "group_id": "sg-open",
                    "group_name": "wide-open",
                    "rules": [
                        {"direction": "inbound", "protocol": "tcp", "port": 22, "source": "0.0.0.0/0"},
                        {"direction": "inbound", "protocol": "tcp", "port": 3389, "source": "0.0.0.0/0"},
                    ],
                },
            ],
        })
        assert result.success
        issues = result.data["issues"]
        assert len(issues) >= 1

    @pytest.mark.asyncio
    async def test_restrictive_sg(self, aws_skill):
        result = await aws_skill.execute({
            "action": "scan_security_groups",
            "security_groups": [
                {
                    "group_id": "sg-locked",
                    "group_name": "locked-down",
                    "rules": [
                        {"direction": "inbound", "protocol": "tcp", "port": 443, "source": "10.0.0.0/8"},
                    ],
                },
            ],
        })
        assert result.success


# ---------------------------------------------------------------------------
# evaluate_encryption
# ---------------------------------------------------------------------------


class TestEvaluateEncryption:
    @pytest.mark.asyncio
    async def test_evaluate_encryption(self, aws_skill):
        result = await aws_skill.execute({
            "action": "evaluate_encryption",
            "resources": [
                {"resource_id": "vol-1", "type": "ebs", "encrypted": False},
                {"resource_id": "rds-1", "type": "rds", "encrypted": True, "kms_key": "aws/rds"},
            ],
        })
        assert result.success
        issues = result.data["issues"]
        # Unencrypted EBS should be flagged
        assert any("vol-1" in str(i) for i in issues)


# ---------------------------------------------------------------------------
# generate_findings
# ---------------------------------------------------------------------------


class TestGenerateFindings:
    @pytest.mark.asyncio
    async def test_generate_findings_after_assessments(self, aws_skill):
        await aws_skill.execute({
            "action": "assess_vpc",
            "vpc": {"vpc_id": "vpc-1", "flow_logs_enabled": False},
        })
        result = await aws_skill.execute({
            "action": "generate_findings",
        })
        assert result.success
        assert result.data["total_findings"] >= 1

    @pytest.mark.asyncio
    async def test_generate_findings_empty(self, aws_skill):
        result = await aws_skill.execute({
            "action": "generate_findings",
        })
        assert result.success
        assert result.data["total_findings"] == 0


# ---------------------------------------------------------------------------
# Unknown Action
# ---------------------------------------------------------------------------


class TestAWSUnknownAction:
    @pytest.mark.asyncio
    async def test_unknown_action(self, aws_skill):
        result = await aws_skill.execute({"action": "nonexistent"})
        assert not result.success
        assert "Unknown action" in result.errors[0]
