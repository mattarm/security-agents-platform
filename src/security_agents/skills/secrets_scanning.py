#!/usr/bin/env python3
"""
Secrets Scanning Skill — Detect leaked credentials and sensitive tokens in code.

Primary owner: Beta-4 (DevSecOps)

Capabilities:
  - Regex-based detection for 15+ secret types
  - Shannon entropy analysis for high-entropy strings
  - Git commit history scanning for leaked-then-removed secrets
  - Allowlist management for known safe patterns
  - Severity scoring based on secret type and exposure context
  - Per-file, per-repo, and commit-range scanning
  - Structured findings with remediation guidance
"""

import hashlib
import math
import re
import uuid
from collections import Counter
from datetime import datetime
from enum import Enum
from typing import Dict, List, Any, Optional, Tuple

from pathlib import Path

from security_agents.core.models import SkillResult, IntelligencePacket, IntelligenceType, Priority
from security_agents.skills.base_skill import BaseSecuritySkill

class SecretType(Enum):
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    GITHUB_TOKEN = "github_token"
    GITHUB_FINE_GRAINED_TOKEN = "github_fine_grained_token"
    GITLAB_TOKEN = "gitlab_token"
    PRIVATE_KEY = "private_key"
    DB_CONNECTION_STRING = "db_connection_string"
    GENERIC_API_KEY = "generic_api_key"
    JWT_SECRET = "jwt_secret"
    SLACK_TOKEN = "slack_token"
    SLACK_WEBHOOK = "slack_webhook"
    GOOGLE_API_KEY = "google_api_key"
    STRIPE_KEY = "stripe_key"
    SENDGRID_KEY = "sendgrid_key"
    TWILIO_KEY = "twilio_key"
    AZURE_SECRET = "azure_secret"
    OKTA_TOKEN = "okta_token"
    HEROKU_API_KEY = "heroku_api_key"
    NPM_TOKEN = "npm_token"
    PYPI_TOKEN = "pypi_token"
    DOCKER_AUTH = "docker_auth"
    SSH_PASSWORD = "ssh_password"
    HIGH_ENTROPY_STRING = "high_entropy_string"

class FindingSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

# Maps secret types to their severity and description
SECRET_METADATA: Dict[SecretType, Dict[str, Any]] = {
    SecretType.AWS_ACCESS_KEY: {
        "severity": FindingSeverity.CRITICAL,
        "description": "AWS Access Key ID",
        "remediation": "Rotate the key immediately in AWS IAM console. Revoke old key and audit CloudTrail for unauthorized usage.",
    },
    SecretType.AWS_SECRET_KEY: {
        "severity": FindingSeverity.CRITICAL,
        "description": "AWS Secret Access Key",
        "remediation": "Rotate immediately. Run `aws iam create-access-key` for replacement, then delete the compromised key. Audit CloudTrail.",
    },
    SecretType.GITHUB_TOKEN: {
        "severity": FindingSeverity.CRITICAL,
        "description": "GitHub Personal Access Token",
        "remediation": "Revoke token at github.com/settings/tokens immediately. Audit repo access logs for unauthorized activity.",
    },
    SecretType.GITHUB_FINE_GRAINED_TOKEN: {
        "severity": FindingSeverity.HIGH,
        "description": "GitHub Fine-Grained Personal Access Token",
        "remediation": "Revoke token at github.com/settings/tokens. Fine-grained tokens have limited scope but should still be rotated.",
    },
    SecretType.GITLAB_TOKEN: {
        "severity": FindingSeverity.CRITICAL,
        "description": "GitLab Personal/Project Access Token",
        "remediation": "Revoke token in GitLab settings. Audit project access logs.",
    },
    SecretType.PRIVATE_KEY: {
        "severity": FindingSeverity.CRITICAL,
        "description": "Private Key (RSA/EC/DSA/PGP)",
        "remediation": "Regenerate the key pair immediately. Replace public key on all services. Consider the private key fully compromised.",
    },
    SecretType.DB_CONNECTION_STRING: {
        "severity": FindingSeverity.CRITICAL,
        "description": "Database Connection String with Credentials",
        "remediation": "Rotate database password immediately. Audit database access logs. Move connection strings to a secret manager.",
    },
    SecretType.GENERIC_API_KEY: {
        "severity": FindingSeverity.HIGH,
        "description": "Generic API Key or Secret",
        "remediation": "Identify the service and rotate the key. Move to environment variables or a secret manager.",
    },
    SecretType.JWT_SECRET: {
        "severity": FindingSeverity.CRITICAL,
        "description": "JWT Signing Secret or HMAC Key",
        "remediation": "Rotate JWT secret immediately. Invalidate all existing tokens. This allows forging authentication tokens.",
    },
    SecretType.SLACK_TOKEN: {
        "severity": FindingSeverity.HIGH,
        "description": "Slack Bot or User OAuth Token",
        "remediation": "Revoke token in Slack app settings. Regenerate and store in secret manager.",
    },
    SecretType.SLACK_WEBHOOK: {
        "severity": FindingSeverity.MEDIUM,
        "description": "Slack Incoming Webhook URL",
        "remediation": "Delete and recreate the webhook. Webhooks allow posting to channels but have limited scope.",
    },
    SecretType.GOOGLE_API_KEY: {
        "severity": FindingSeverity.HIGH,
        "description": "Google Cloud / GCP API Key",
        "remediation": "Restrict or delete the key in Google Cloud Console. Add API key restrictions (HTTP referrer, IP, API scope).",
    },
    SecretType.STRIPE_KEY: {
        "severity": FindingSeverity.CRITICAL,
        "description": "Stripe Secret or Publishable Key",
        "remediation": "Roll the key in Stripe Dashboard immediately. Secret keys allow full payment API access.",
    },
    SecretType.SENDGRID_KEY: {
        "severity": FindingSeverity.HIGH,
        "description": "SendGrid API Key",
        "remediation": "Delete and recreate the key in SendGrid. Exposed keys can be used for spam/phishing campaigns.",
    },
    SecretType.TWILIO_KEY: {
        "severity": FindingSeverity.HIGH,
        "description": "Twilio API Key or Auth Token",
        "remediation": "Rotate in Twilio console. Exposed tokens allow sending SMS/calls at your expense.",
    },
    SecretType.AZURE_SECRET: {
        "severity": FindingSeverity.CRITICAL,
        "description": "Azure Client Secret or Storage Key",
        "remediation": "Rotate the secret in Azure AD or Azure Portal. Audit activity logs for unauthorized access.",
    },
    SecretType.OKTA_TOKEN: {
        "severity": FindingSeverity.CRITICAL,
        "description": "Okta API Token",
        "remediation": "Revoke the token in Okta Admin console immediately. Audit system log for unauthorized API calls.",
    },
    SecretType.HEROKU_API_KEY: {
        "severity": FindingSeverity.HIGH,
        "description": "Heroku API Key",
        "remediation": "Regenerate at dashboard.heroku.com/account. Audit app deployment logs.",
    },
    SecretType.NPM_TOKEN: {
        "severity": FindingSeverity.HIGH,
        "description": "NPM Authentication Token",
        "remediation": "Revoke at npmjs.com/settings/tokens. Exposed tokens allow publishing malicious package versions.",
    },
    SecretType.PYPI_TOKEN: {
        "severity": FindingSeverity.HIGH,
        "description": "PyPI API Token",
        "remediation": "Revoke at pypi.org/manage/account/token. Exposed tokens allow publishing malicious packages.",
    },
    SecretType.DOCKER_AUTH: {
        "severity": FindingSeverity.HIGH,
        "description": "Docker Registry Authentication",
        "remediation": "Run `docker logout` and re-authenticate. Remove .docker/config.json from repo.",
    },
    SecretType.SSH_PASSWORD: {
        "severity": FindingSeverity.HIGH,
        "description": "SSH or SFTP Password in Connection String",
        "remediation": "Change the password immediately. Switch to key-based authentication.",
    },
    SecretType.HIGH_ENTROPY_STRING: {
        "severity": FindingSeverity.MEDIUM,
        "description": "High-Entropy String (potential secret)",
        "remediation": "Review manually. If this is a secret, rotate and move to a secret manager. If not, add to allowlist.",
    },
}

class SecretsScanningSkill(BaseSecuritySkill):
    """Detect leaked secrets and credentials in source code and git history."""

    SKILL_NAME = "secrets_scanning"
    DESCRIPTION = (
        "Detect leaked credentials, API keys, private keys, and other secrets "
        "in source code, configuration files, and git commit history"
    )
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = ["beta_4_devsecops"]
    REQUIRED_INTEGRATIONS = []

    # ------------------------------------------------------------------
    # Regex patterns for secret detection
    # ------------------------------------------------------------------
    SECRET_PATTERNS: Dict[SecretType, List[re.Pattern]] = {
        SecretType.AWS_ACCESS_KEY: [
            re.compile(r'(?<![A-Z0-9])(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])'),
        ],
        SecretType.AWS_SECRET_KEY: [
            re.compile(r'(?i)(?:aws)?_?(?:secret)?_?(?:access)?_?key["\'\s:=]*["\']?([A-Za-z0-9/+=]{40})["\']?'),
        ],
        SecretType.GITHUB_TOKEN: [
            re.compile(r'ghp_[A-Za-z0-9]{36}'),
            re.compile(r'gho_[A-Za-z0-9]{36}'),
            re.compile(r'ghu_[A-Za-z0-9]{36}'),
            re.compile(r'ghs_[A-Za-z0-9]{36}'),
            re.compile(r'ghr_[A-Za-z0-9]{36}'),
        ],
        SecretType.GITHUB_FINE_GRAINED_TOKEN: [
            re.compile(r'github_pat_[A-Za-z0-9_]{82}'),
        ],
        SecretType.GITLAB_TOKEN: [
            re.compile(r'glpat-[A-Za-z0-9\-]{20,}'),
            re.compile(r'glft-[A-Za-z0-9\-]{20,}'),
        ],
        SecretType.PRIVATE_KEY: [
            re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?:\sBLOCK)?-----'),
        ],
        SecretType.DB_CONNECTION_STRING: [
            re.compile(r'(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|mssql|redis|amqp)://[^\s"\'<>]+:[^\s"\'<>]+@[^\s"\'<>]+'),
            re.compile(r'(?i)(?:server|data\s*source)=[^;]+;.*(?:password|pwd)=[^;]+', re.IGNORECASE),
        ],
        SecretType.GENERIC_API_KEY: [
            re.compile(r'(?i)(?:api[_-]?key|apikey|api[_-]?secret)["\'\s:=]+["\']?([A-Za-z0-9\-_]{20,64})["\']?'),
            re.compile(r'(?i)(?:access[_-]?token|auth[_-]?token|bearer)["\'\s:=]+["\']?([A-Za-z0-9\-_\.]{20,500})["\']?'),
        ],
        SecretType.JWT_SECRET: [
            re.compile(r'(?i)(?:jwt[_-]?secret|jwt[_-]?key|signing[_-]?secret|hmac[_-]?secret)["\'\s:=]+["\']?([^\s"\']{16,})["\']?'),
        ],
        SecretType.SLACK_TOKEN: [
            re.compile(r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}'),
            re.compile(r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}'),
            re.compile(r'xapp-[0-9]-[A-Z0-9]{10,}-[0-9]{10,}-[a-f0-9]{64}'),
            re.compile(r'xoxo-[0-9]{10,13}-[A-Za-z0-9-]{20,}'),
        ],
        SecretType.SLACK_WEBHOOK: [
            re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}'),
        ],
        SecretType.GOOGLE_API_KEY: [
            re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        ],
        SecretType.STRIPE_KEY: [
            re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
            re.compile(r'sk_test_[0-9a-zA-Z]{24,}'),
            re.compile(r'rk_live_[0-9a-zA-Z]{24,}'),
        ],
        SecretType.SENDGRID_KEY: [
            re.compile(r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}'),
        ],
        SecretType.TWILIO_KEY: [
            re.compile(r'SK[0-9a-fA-F]{32}'),
            re.compile(r'(?i)twilio[_-]?auth[_-]?token["\'\s:=]+["\']?([a-f0-9]{32})["\']?'),
        ],
        SecretType.AZURE_SECRET: [
            re.compile(r'(?i)(?:azure|client)[_-]?secret["\'\s:=]+["\']?([A-Za-z0-9\-_.~]{34,})["\']?'),
            re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,}'),
        ],
        SecretType.OKTA_TOKEN: [
            re.compile(r'(?i)(?:okta)[_-]?(?:api)?[_-]?token["\'\s:=]+["\']?([A-Za-z0-9\-_]{30,})["\']?'),
            re.compile(r'00[A-Za-z0-9\-_]{40}'),  # Okta API tokens start with 00
        ],
        SecretType.HEROKU_API_KEY: [
            re.compile(r'(?i)heroku[_-]?api[_-]?key["\'\s:=]+["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']?'),
        ],
        SecretType.NPM_TOKEN: [
            re.compile(r'npm_[A-Za-z0-9]{36}'),
            re.compile(r'//registry\.npmjs\.org/:_authToken=[A-Za-z0-9\-]{36,}'),
        ],
        SecretType.PYPI_TOKEN: [
            re.compile(r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}'),
        ],
        SecretType.DOCKER_AUTH: [
            re.compile(r'(?i)"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"'),
            re.compile(r'(?i)docker[_-]?(?:password|token|auth)["\'\s:=]+["\']?([^\s"\']{8,})["\']?'),
        ],
        SecretType.SSH_PASSWORD: [
            re.compile(r'(?i)sshpass\s+-p\s+["\']?([^\s"\']+)["\']?'),
            re.compile(r'(?i)ssh://[^:]+:([^@]+)@'),
        ],
    }

    # Files to skip by extension (binary/media/lock files)
    SKIP_EXTENSIONS = frozenset({
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".pyc", ".pyo", ".class", ".o", ".so", ".dylib", ".dll", ".exe",
        ".lock", ".sum",
        ".min.js", ".min.css", ".map",
    })

    # Files to skip by name
    SKIP_FILENAMES = frozenset({
        "package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock",
        "go.sum", "Cargo.lock", "composer.lock",
    })

    # Default entropy threshold for flagging high-entropy strings
    DEFAULT_ENTROPY_THRESHOLD = 4.5
    DEFAULT_MIN_SECRET_LENGTH = 16

    async def _setup(self):
        self.findings: List[Dict[str, Any]] = []
        self.allowlist: List[Dict[str, Any]] = []
        self.scan_history: List[Dict[str, Any]] = []

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        action = parameters.get("action", "scan_repo")

        dispatch = {
            "scan_repo": self._scan_repo,
            "scan_file": self._scan_file,
            "scan_commit_history": self._scan_commit_history,
            "add_allowlist": self._add_allowlist,
            "get_findings": self._get_findings,
            "generate_report": self._generate_report,
        }

        handler = dispatch.get(action)
        if not handler:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Unknown action '{action}'. Supported: {list(dispatch.keys())}"],
            )
        return await handler(parameters)

    # =========================================================================
    # Scan Repository
    # =========================================================================

    async def _scan_repo(self, params: Dict[str, Any]) -> SkillResult:
        """Scan an entire repository for secrets."""
        repo_path = params.get("repo_path", "")
        file_contents = params.get("file_contents", {})  # dict of path -> content
        include_entropy = params.get("include_entropy", True)
        entropy_threshold = params.get("entropy_threshold", self.DEFAULT_ENTROPY_THRESHOLD)
        scan_id = f"SCAN-{uuid.uuid4().hex[:8]}"

        if not file_contents and not repo_path:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["Provide 'repo_path' or 'file_contents' (dict of filepath -> content)"],
            )

        all_findings = []
        files_scanned = 0
        files_skipped = 0

        for filepath, content in file_contents.items():
            if self._should_skip_file(filepath):
                files_skipped += 1
                continue

            files_scanned += 1
            file_findings = self._scan_content(
                content, filepath, include_entropy, entropy_threshold
            )
            all_findings.extend(file_findings)

        # Deduplicate and filter allowlisted
        all_findings = self._deduplicate_findings(all_findings)
        all_findings = self._filter_allowlisted(all_findings)

        # Store findings
        self.findings.extend(all_findings)

        scan_record = {
            "scan_id": scan_id,
            "repo_path": repo_path,
            "timestamp": datetime.now().isoformat(),
            "files_scanned": files_scanned,
            "files_skipped": files_skipped,
            "findings_count": len(all_findings),
            "critical": sum(1 for f in all_findings if f["severity"] == "critical"),
            "high": sum(1 for f in all_findings if f["severity"] == "high"),
            "medium": sum(1 for f in all_findings if f["severity"] == "medium"),
            "low": sum(1 for f in all_findings if f["severity"] == "low"),
        }
        self.scan_history.append(scan_record)

        # Generate intelligence packets for critical findings
        packets = []
        critical_count = scan_record["critical"]
        if critical_count > 0:
            packets.append(IntelligencePacket(
                packet_id=f"PKT-SECRET-{scan_id}",
                source_agent=self.agent_id,
                target_agents=["all"],
                intelligence_type=IntelligenceType.VULNERABILITY,
                priority=Priority.CRITICAL,
                confidence=90.0,
                timestamp=datetime.now(),
                data={
                    "scan_id": scan_id,
                    "repo_path": repo_path,
                    "critical_secrets_found": critical_count,
                    "secret_types": list(set(f["secret_type"] for f in all_findings if f["severity"] == "critical")),
                    "message": f"CRITICAL: {critical_count} high-severity secrets found in {repo_path}",
                },
                correlation_keys=[repo_path, scan_id],
            ))

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "scan": scan_record,
                "findings": all_findings,
            },
            intelligence_packets=packets,
            warnings=[f"{critical_count} critical secrets require immediate rotation"] if critical_count else [],
        )

    # =========================================================================
    # Scan Single File
    # =========================================================================

    async def _scan_file(self, params: Dict[str, Any]) -> SkillResult:
        """Scan a single file for secrets."""
        filepath = params.get("filepath", "unknown")
        content = params.get("content", "")
        include_entropy = params.get("include_entropy", True)
        entropy_threshold = params.get("entropy_threshold", self.DEFAULT_ENTROPY_THRESHOLD)

        if not content:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'content' is required — the file text to scan"],
            )

        findings = self._scan_content(content, filepath, include_entropy, entropy_threshold)
        findings = self._filter_allowlisted(findings)
        self.findings.extend(findings)

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "filepath": filepath,
                "findings": findings,
                "findings_count": len(findings),
                "has_secrets": len(findings) > 0,
            },
        )

    # =========================================================================
    # Scan Commit History
    # =========================================================================

    async def _scan_commit_history(self, params: Dict[str, Any]) -> SkillResult:
        """Scan git commit diffs for secrets that may have been added then removed."""
        commits = params.get("commits", [])  # list of {sha, message, author, diff}
        include_entropy = params.get("include_entropy", True)
        entropy_threshold = params.get("entropy_threshold", self.DEFAULT_ENTROPY_THRESHOLD)

        if not commits:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'commits' required — list of {sha, message, author, diff} dicts"],
            )

        history_findings = []
        commits_scanned = 0

        for commit in commits:
            sha = commit.get("sha", "unknown")
            diff = commit.get("diff", "")
            author = commit.get("author", "unknown")
            message = commit.get("message", "")

            if not diff:
                continue

            commits_scanned += 1

            # Extract added lines from the diff (lines starting with +)
            added_lines = []
            current_file = "unknown"
            for line in diff.split("\n"):
                if line.startswith("+++ b/"):
                    current_file = line[6:]
                elif line.startswith("+") and not line.startswith("+++"):
                    added_lines.append((current_file, line[1:]))

            # Scan each added line
            for filepath, line_content in added_lines:
                line_findings = self._scan_content(
                    line_content, filepath, include_entropy, entropy_threshold
                )
                for finding in line_findings:
                    finding["commit_sha"] = sha
                    finding["commit_author"] = author
                    finding["commit_message"] = message
                    finding["in_current_code"] = False  # Was in diff, may have been removed
                    finding["exposure_type"] = "git_history"
                    history_findings.append(finding)

        history_findings = self._deduplicate_findings(history_findings)
        history_findings = self._filter_allowlisted(history_findings)
        self.findings.extend(history_findings)

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "commits_scanned": commits_scanned,
                "findings": history_findings,
                "findings_count": len(history_findings),
                "unique_secrets": len(set(f.get("fingerprint", "") for f in history_findings)),
                "warning": (
                    "Secrets found in git history remain exposed even after removal. "
                    "Consider using git-filter-repo or BFG Repo-Cleaner to purge, "
                    "then force-push and require all collaborators to re-clone."
                ) if history_findings else None,
            },
            warnings=(
                ["Secrets in git history are still recoverable — rotation required"]
                if history_findings else []
            ),
        )

    # =========================================================================
    # Allowlist Management
    # =========================================================================

    async def _add_allowlist(self, params: Dict[str, Any]) -> SkillResult:
        """Add a pattern or specific value to the allowlist."""
        entry_type = params.get("type", "value")  # "value", "pattern", "file", "fingerprint"
        value = params.get("value", "")
        reason = params.get("reason", "")
        added_by = params.get("added_by", self.agent_id)

        if not value:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'value' required — the string, regex pattern, filepath, or fingerprint to allowlist"],
            )

        if not reason:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'reason' required — document why this is allowlisted for audit trail"],
            )

        entry = {
            "id": f"AL-{uuid.uuid4().hex[:8]}",
            "type": entry_type,
            "value": value,
            "reason": reason,
            "added_by": added_by,
            "added_at": datetime.now().isoformat(),
        }

        # Validate regex patterns
        if entry_type == "pattern":
            try:
                re.compile(value)
            except re.error as e:
                return SkillResult(
                    success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                    errors=[f"Invalid regex pattern: {e}"],
                )

        self.allowlist.append(entry)

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "allowlist_entry": entry,
                "total_allowlist_entries": len(self.allowlist),
            },
        )

    # =========================================================================
    # Get Findings
    # =========================================================================

    async def _get_findings(self, params: Dict[str, Any]) -> SkillResult:
        """Retrieve findings with optional filtering."""
        severity_filter = params.get("severity")
        secret_type_filter = params.get("secret_type")
        filepath_filter = params.get("filepath")
        limit = params.get("limit", 100)

        filtered = self.findings

        if severity_filter:
            filtered = [f for f in filtered if f["severity"] == severity_filter]
        if secret_type_filter:
            filtered = [f for f in filtered if f["secret_type"] == secret_type_filter]
        if filepath_filter:
            filtered = [f for f in filtered if filepath_filter in f.get("filepath", "")]

        # Sort by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        filtered.sort(key=lambda f: severity_order.get(f["severity"], 5))

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "findings": filtered[:limit],
                "total_findings": len(filtered),
                "returned": min(limit, len(filtered)),
                "severity_breakdown": {
                    sev: sum(1 for f in filtered if f["severity"] == sev)
                    for sev in ["critical", "high", "medium", "low", "info"]
                },
            },
        )

    # =========================================================================
    # Generate Report
    # =========================================================================

    async def _generate_report(self, params: Dict[str, Any]) -> SkillResult:
        """Generate a comprehensive secrets scanning report."""
        include_details = params.get("include_details", True)

        severity_breakdown = {
            sev: sum(1 for f in self.findings if f["severity"] == sev)
            for sev in ["critical", "high", "medium", "low", "info"]
        }

        type_breakdown = {}
        for finding in self.findings:
            st = finding.get("secret_type", "unknown")
            type_breakdown[st] = type_breakdown.get(st, 0) + 1

        file_breakdown = {}
        for finding in self.findings:
            fp = finding.get("filepath", "unknown")
            file_breakdown[fp] = file_breakdown.get(fp, 0) + 1

        # Risk score: weighted sum
        risk_weights = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
        risk_score = sum(
            risk_weights.get(f["severity"], 0) for f in self.findings
        )
        # Normalize to 0-100
        max_possible = len(self.findings) * 10 if self.findings else 1
        normalized_risk = min(100.0, (risk_score / max_possible) * 100)

        # Top remediation priorities
        remediation_priorities = []
        for finding in sorted(self.findings, key=lambda f: risk_weights.get(f["severity"], 0), reverse=True)[:10]:
            if finding.get("remediation") and finding["remediation"] not in [r["action"] for r in remediation_priorities]:
                remediation_priorities.append({
                    "secret_type": finding["secret_type"],
                    "severity": finding["severity"],
                    "action": finding["remediation"],
                    "affected_files": [
                        f["filepath"] for f in self.findings
                        if f["secret_type"] == finding["secret_type"]
                    ][:5],
                })

        report = {
            "report_id": f"RPT-{uuid.uuid4().hex[:8]}",
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_findings": len(self.findings),
                "severity_breakdown": severity_breakdown,
                "type_breakdown": type_breakdown,
                "files_with_secrets": len(file_breakdown),
                "most_affected_files": sorted(
                    file_breakdown.items(), key=lambda x: x[1], reverse=True
                )[:10],
                "risk_score": round(normalized_risk, 1),
                "scans_performed": len(self.scan_history),
                "allowlist_entries": len(self.allowlist),
            },
            "remediation_priorities": remediation_priorities[:10],
            "recommendations": self._generate_recommendations(severity_breakdown),
        }

        if include_details:
            report["detailed_findings"] = self.findings

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={"report": report},
        )

    # =========================================================================
    # Internal Helpers
    # =========================================================================

    def _scan_content(
        self,
        content: str,
        filepath: str,
        include_entropy: bool,
        entropy_threshold: float,
    ) -> List[Dict[str, Any]]:
        """Scan text content for secrets using regex and optional entropy analysis."""
        findings = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            # Skip comments that are obviously documentation examples
            stripped = line.strip()
            if stripped.startswith("#") and any(
                kw in stripped.lower() for kw in ["example", "placeholder", "dummy", "replace with", "your_"]
            ):
                continue

            # Pattern-based detection
            for secret_type, patterns in self.SECRET_PATTERNS.items():
                for pattern in patterns:
                    match = pattern.search(line)
                    if match:
                        matched_text = match.group(0)
                        # Get the actual secret value (first group if present, else full match)
                        secret_value = match.group(1) if match.lastindex and match.lastindex >= 1 else matched_text

                        # Skip very short matches that are likely false positives
                        if len(secret_value) < 8:
                            continue

                        metadata = SECRET_METADATA.get(secret_type, {})
                        finding = self._create_finding(
                            secret_type=secret_type.value,
                            severity=metadata.get("severity", FindingSeverity.MEDIUM).value,
                            filepath=filepath,
                            line_number=line_num,
                            matched_text=self._redact_secret(matched_text),
                            description=metadata.get("description", "Unknown secret type"),
                            remediation=metadata.get("remediation", "Rotate the credential and move to a secret manager."),
                            detection_method="pattern",
                            secret_value=secret_value,
                        )
                        findings.append(finding)

            # Entropy-based detection
            if include_entropy:
                entropy_findings = self._entropy_scan_line(
                    line, line_num, filepath, entropy_threshold
                )
                findings.extend(entropy_findings)

        return findings

    def _entropy_scan_line(
        self, line: str, line_num: int, filepath: str, threshold: float
    ) -> List[Dict[str, Any]]:
        """Detect high-entropy strings that may be secrets."""
        findings = []

        # Look for string assignments: key = "value", key: "value", "key": "value"
        assignment_patterns = [
            re.compile(r'["\']([A-Za-z0-9+/=\-_]{16,256})["\']'),
            re.compile(r'=\s*["\']([A-Za-z0-9+/=\-_]{16,256})["\']'),
        ]

        for pattern in assignment_patterns:
            for match in pattern.finditer(line):
                candidate = match.group(1)

                # Skip if too short or looks like a path/URL/word
                if len(candidate) < self.DEFAULT_MIN_SECRET_LENGTH:
                    continue
                if "/" in candidate and candidate.count("/") > 2:
                    continue  # Probably a path
                if candidate.lower() in ("true", "false", "null", "none", "undefined"):
                    continue

                entropy = self._shannon_entropy(candidate)
                if entropy >= threshold:
                    # Check if this was already caught by pattern matching
                    # (avoid double-reporting)
                    already_caught = False
                    for stype, patterns in self.SECRET_PATTERNS.items():
                        for p in patterns:
                            if p.search(candidate):
                                already_caught = True
                                break
                        if already_caught:
                            break

                    if not already_caught:
                        metadata = SECRET_METADATA[SecretType.HIGH_ENTROPY_STRING]
                        findings.append(self._create_finding(
                            secret_type=SecretType.HIGH_ENTROPY_STRING.value,
                            severity=metadata["severity"].value,
                            filepath=filepath,
                            line_number=line_num,
                            matched_text=self._redact_secret(candidate),
                            description=f"{metadata['description']} (entropy: {entropy:.2f})",
                            remediation=metadata["remediation"],
                            detection_method="entropy",
                            secret_value=candidate,
                            extra={"entropy": round(entropy, 2), "length": len(candidate)},
                        ))

        return findings

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        return entropy

    def _create_finding(
        self,
        secret_type: str,
        severity: str,
        filepath: str,
        line_number: int,
        matched_text: str,
        description: str,
        remediation: str,
        detection_method: str,
        secret_value: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a standardized finding dict."""
        # Fingerprint for dedup: hash of type + redacted value + file
        raw_fingerprint = f"{secret_type}:{secret_value}:{filepath}"
        fingerprint = hashlib.sha256(raw_fingerprint.encode()).hexdigest()[:16]

        finding = {
            "finding_id": f"SEC-{uuid.uuid4().hex[:8]}",
            "fingerprint": fingerprint,
            "secret_type": secret_type,
            "severity": severity,
            "filepath": filepath,
            "line_number": line_number,
            "matched_text": matched_text,
            "description": description,
            "remediation": remediation,
            "detection_method": detection_method,
            "timestamp": datetime.now().isoformat(),
        }
        if extra:
            finding.update(extra)
        return finding

    @staticmethod
    def _redact_secret(text: str) -> str:
        """Redact the middle of a secret for safe display."""
        if len(text) <= 8:
            return text[:2] + "***"
        visible = max(4, len(text) // 5)
        return text[:visible] + "..." + text[-visible:]

    def _should_skip_file(self, filepath: str) -> bool:
        """Determine if a file should be skipped based on extension or name."""
        p = Path(filepath)
        if p.name in self.SKIP_FILENAMES:
            return True
        if p.suffix.lower() in self.SKIP_EXTENSIONS:
            return True
        # Skip vendor/node_modules directories
        parts = p.parts
        skip_dirs = {"node_modules", "vendor", ".git", "__pycache__", "dist", "build"}
        if any(part in skip_dirs for part in parts):
            return True
        return False

    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings based on fingerprint."""
        seen = set()
        deduped = []
        for finding in findings:
            fp = finding.get("fingerprint", "")
            if fp and fp not in seen:
                seen.add(fp)
                deduped.append(finding)
            elif not fp:
                deduped.append(finding)
        return deduped

    def _filter_allowlisted(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove findings that match allowlist entries."""
        filtered = []
        for finding in findings:
            if self._is_allowlisted(finding):
                continue
            filtered.append(finding)
        return filtered

    def _is_allowlisted(self, finding: Dict[str, Any]) -> bool:
        """Check if a finding matches any allowlist entry."""
        for entry in self.allowlist:
            entry_type = entry.get("type", "value")
            entry_value = entry.get("value", "")

            if entry_type == "fingerprint" and finding.get("fingerprint") == entry_value:
                return True
            if entry_type == "file" and entry_value in finding.get("filepath", ""):
                return True
            if entry_type == "value" and entry_value in finding.get("matched_text", ""):
                return True
            if entry_type == "pattern":
                try:
                    if re.search(entry_value, finding.get("matched_text", "")):
                        return True
                except re.error:
                    pass

        return False

    def _generate_recommendations(self, severity_breakdown: Dict[str, int]) -> List[str]:
        """Generate actionable recommendations based on findings."""
        recommendations = []

        if severity_breakdown.get("critical", 0) > 0:
            recommendations.append(
                "IMMEDIATE: Rotate all critical secrets (AWS keys, database credentials, "
                "private keys) before any other action. Assume they are compromised."
            )
        if severity_breakdown.get("high", 0) > 0:
            recommendations.append(
                "HIGH PRIORITY: Rotate high-severity tokens (GitHub, Slack, API keys) "
                "within 24 hours."
            )
        if sum(severity_breakdown.values()) > 0:
            recommendations.extend([
                "Implement pre-commit hooks using tools like detect-secrets or gitleaks to prevent future leaks.",
                "Move all secrets to a dedicated secrets manager (AWS Secrets Manager, HashiCorp Vault, or similar).",
                "Add .env, credentials files, and key files to .gitignore.",
                "If secrets were found in git history, use git-filter-repo to purge them and force-push.",
                "Implement CI/CD pipeline scanning to catch secrets before they reach the default branch.",
                "Enable GitHub Secret Scanning or GitLab Secret Detection for automated monitoring.",
            ])

        if not recommendations:
            recommendations.append("No secrets detected. Continue monitoring with regular scans.")

        return recommendations
