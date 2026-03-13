#!/usr/bin/env python3
"""
Phishing Analysis Skill — email threat detection, campaign tracking, and response.

Primary owner: Gamma (Blue Team)
Also usable by: Alpha-4 (campaign attribution), Sigma (metrics)

Capabilities:
  - Email header authentication validation (SPF, DKIM, DMARC)
  - URL reputation and suspicious pattern detection
  - Attachment risk assessment
  - Phishing campaign clustering and tracking
  - Business Email Compromise (BEC) detection
  - Automated triage and classification
"""

import hashlib
import re
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

from security_agents.core.models import (
    SkillResult, IntelligencePacket, IntelligenceType, Priority,
    PhishingIndicator, PhishingCampaign, EnrichedIOC, IOCType,
)
from security_agents.skills.base_skill import BaseSecuritySkill

class PhishingAnalysisSkill(BaseSecuritySkill):
    """Analyze emails for phishing indicators and track campaigns."""

    SKILL_NAME = "phishing_analysis"
    DESCRIPTION = "Email phishing detection, BEC detection, campaign tracking, and response automation"
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = ["gamma_blue_team", "alpha_4_threat_intel", "sigma_metrics"]
    REQUIRED_INTEGRATIONS = []  # No external deps for core analysis

    # -------------------------------------------------------------------------
    # Known-bad patterns and heuristics
    # -------------------------------------------------------------------------

    # Domains commonly abused for credential phishing
    SUSPICIOUS_TLD_PATTERNS = [
        r"\.xyz$", r"\.top$", r"\.click$", r"\.loan$", r"\.work$",
        r"\.gq$", r"\.cf$", r"\.tk$", r"\.ml$", r"\.ga$",
        r"\.buzz$", r"\.icu$", r"\.cam$",
    ]

    # URL patterns associated with credential harvesting
    CREDENTIAL_HARVEST_PATTERNS = [
        r"login[.-]", r"signin[.-]", r"verify[.-]", r"account[.-]",
        r"secure[.-]", r"update[.-]", r"confirm[.-]", r"authenticate[.-]",
        r"webmail[.-]", r"password[.-]", r"oauth[.-]",
        r"/wp-content/", r"/wp-admin/",
        r"\.php\?.*(?:user|login|email|pass)",
    ]

    # BEC / impersonation patterns
    BEC_SUBJECT_PATTERNS = [
        r"(?i)urgent.*wire\s*transfer",
        r"(?i)payment.*overdue",
        r"(?i)invoice.*attached",
        r"(?i)ceo.*request",
        r"(?i)confidential.*action\s*required",
        r"(?i)payroll.*update",
        r"(?i)w-?2\s*(?:form|request)",
        r"(?i)gift\s*card",
        r"(?i)change.*(?:bank|account|routing)",
    ]

    # Suspicious attachment extensions
    HIGH_RISK_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".hta", ".iso", ".img", ".lnk", ".dll", ".msi",
    }

    MEDIUM_RISK_EXTENSIONS = {
        ".docm", ".xlsm", ".pptm", ".dotm",  # Macro-enabled Office
        ".html", ".htm", ".svg",  # Can contain scripts
        ".zip", ".rar", ".7z", ".tar.gz",  # Archives hiding payloads
    }

    async def _setup(self):
        """Initialize tracking state."""
        self.active_campaigns: Dict[str, PhishingCampaign] = {}
        self.known_phishing_domains: set = set()
        self.ioc_cache: Dict[str, Dict[str, Any]] = {}

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        """
        Dispatch to the appropriate analysis mode.

        Supported actions:
          analyze_email  — full email analysis
          check_url      — URL reputation check
          track_campaign — add indicator to campaign tracking
          get_campaigns  — list active phishing campaigns
          triage_report  — triage a user-reported phishing email
        """
        action = parameters.get("action", "analyze_email")

        if action == "analyze_email":
            return await self._analyze_email(parameters)
        elif action == "check_url":
            return await self._check_url(parameters)
        elif action == "track_campaign":
            return await self._track_campaign(parameters)
        elif action == "get_campaigns":
            return await self._get_campaigns(parameters)
        elif action == "triage_report":
            return await self._triage_user_report(parameters)
        else:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[f"Unknown action '{action}'. Supported: analyze_email, check_url, track_campaign, get_campaigns, triage_report"],
            )

    # =========================================================================
    # Core Analysis
    # =========================================================================

    async def _analyze_email(self, params: Dict[str, Any]) -> SkillResult:
        """Perform full phishing analysis on an email."""
        headers = params.get("headers", {})
        subject = params.get("subject", "")
        sender = params.get("sender", "")
        body = params.get("body", "")
        urls = params.get("urls", [])
        attachments = params.get("attachments", [])  # [{"name": "...", "size": ..., "content_type": "..."}]
        recipients = params.get("recipients", [])

        # Extract sender domain
        sender_domain = self._extract_domain(sender)

        # 1) Authentication analysis
        auth_results = self._analyze_authentication(headers)
        auth_score = self._score_authentication(auth_results)

        # 2) URL analysis
        url_results = []
        url_risk_score = 0.0
        extracted_iocs = []
        for url in urls:
            url_analysis = self._analyze_url(url)
            url_results.append(url_analysis)
            url_risk_score = max(url_risk_score, url_analysis["risk_score"])
            if url_analysis["risk_score"] > 50:
                extracted_iocs.append(url)

        # 3) Attachment analysis
        attachment_results = []
        attachment_risk = 0.0
        for att in attachments:
            att_analysis = self._analyze_attachment(att)
            attachment_results.append(att_analysis)
            attachment_risk = max(attachment_risk, att_analysis["risk_score"])

        # 4) BEC / impersonation detection
        bec_score = self._detect_bec(subject, sender, body)

        # 5) Content analysis
        content_score = self._analyze_content(subject, body)

        # 6) Composite risk score
        risk_score = self._calculate_composite_risk(
            auth_score=auth_score,
            url_risk=url_risk_score,
            attachment_risk=attachment_risk,
            bec_score=bec_score,
            content_score=content_score,
        )

        # 7) Classification
        classification = self._classify(risk_score, bec_score, url_risk_score, attachment_risk)

        # Build indicator
        indicator = PhishingIndicator(
            indicator_id=f"PHI-{uuid.uuid4().hex[:8]}",
            email_subject=subject,
            sender_address=sender,
            sender_domain=sender_domain,
            recipient_count=len(recipients) if recipients else 1,
            urls_extracted=urls,
            attachments=[{"name": a.get("name", ""), "content_type": a.get("content_type", "")} for a in attachments],
            authentication_results=auth_results,
            risk_score=risk_score,
            classification=classification,
            confidence=min(95.0, risk_score + 10),
            iocs_extracted=extracted_iocs,
            timestamp=datetime.now(),
        )

        # Auto-track if high risk
        if risk_score >= 70:
            await self._auto_track(indicator)

        # Build intelligence packets
        packets = []
        if risk_score >= 50:
            packets.append(
                IntelligencePacket(
                    packet_id=f"PKT-PHISH-{indicator.indicator_id}",
                    source_agent=self.agent_id,
                    target_agents=["all"],
                    intelligence_type=IntelligenceType.PHISHING,
                    priority=Priority.HIGH if risk_score >= 80 else Priority.MEDIUM,
                    confidence=indicator.confidence,
                    timestamp=datetime.now(),
                    data={
                        "indicator_id": indicator.indicator_id,
                        "classification": classification,
                        "risk_score": risk_score,
                        "sender": sender,
                        "sender_domain": sender_domain,
                        "subject": subject,
                        "iocs": extracted_iocs,
                    },
                    correlation_keys=extracted_iocs + [sender_domain],
                )
            )

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "indicator": {
                    "indicator_id": indicator.indicator_id,
                    "classification": indicator.classification,
                    "risk_score": indicator.risk_score,
                    "confidence": indicator.confidence,
                },
                "authentication": auth_results,
                "auth_score": auth_score,
                "url_analysis": url_results,
                "attachment_analysis": attachment_results,
                "bec_score": bec_score,
                "content_score": content_score,
                "iocs_extracted": extracted_iocs,
                "recommended_actions": self._recommend_actions(classification, risk_score),
            },
            intelligence_packets=packets,
        )

    async def _check_url(self, params: Dict[str, Any]) -> SkillResult:
        """Analyze a single URL for phishing indicators."""
        url = params.get("url", "")
        if not url:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME,
                agent_id=self.agent_id, errors=["'url' parameter required"],
            )
        analysis = self._analyze_url(url)
        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={"url": url, "analysis": analysis},
        )

    async def _triage_user_report(self, params: Dict[str, Any]) -> SkillResult:
        """Triage a user-reported suspicious email."""
        # Perform full analysis
        result = await self._analyze_email(params)
        if not result.success:
            return result

        risk_score = result.data["indicator"]["risk_score"]
        classification = result.data["indicator"]["classification"]

        # Add triage-specific recommendations
        triage_action = "investigate"
        if risk_score >= 80:
            triage_action = "block_and_investigate"
        elif risk_score >= 50:
            triage_action = "investigate"
        elif risk_score >= 20:
            triage_action = "monitor"
        else:
            triage_action = "close_benign"

        result.data["triage"] = {
            "action": triage_action,
            "priority": "P1" if risk_score >= 80 else "P2" if risk_score >= 50 else "P3",
            "auto_response": risk_score >= 80,
            "user_feedback": self._generate_user_feedback(classification, risk_score),
        }
        return result

    # =========================================================================
    # Campaign Tracking
    # =========================================================================

    async def _track_campaign(self, params: Dict[str, Any]) -> SkillResult:
        """Add a phishing indicator to campaign tracking."""
        indicator_data = params.get("indicator", {})
        sender_domain = indicator_data.get("sender_domain", "")
        subject_pattern = indicator_data.get("subject", "")

        # Try to match to existing campaign
        campaign_id = self._find_matching_campaign(sender_domain, subject_pattern)

        if campaign_id and campaign_id in self.active_campaigns:
            campaign = self.active_campaigns[campaign_id]
            campaign.total_emails += 1
            campaign.last_seen = datetime.now()
            if sender_domain not in campaign.sender_infrastructure:
                campaign.sender_infrastructure.append(sender_domain)
        else:
            campaign_id = f"PHISH-CAMP-{uuid.uuid4().hex[:8]}"
            campaign = PhishingCampaign(
                campaign_id=campaign_id,
                name=f"Campaign: {subject_pattern[:50]}",
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                total_emails=1,
                unique_targets=1,
                sender_infrastructure=[sender_domain] if sender_domain else [],
                payload_type=indicator_data.get("classification", "unknown"),
                lure_theme=subject_pattern[:100],
            )
            self.active_campaigns[campaign_id] = campaign

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "campaign_id": campaign_id,
                "campaign_name": campaign.name,
                "total_emails": campaign.total_emails,
                "is_new": campaign.total_emails == 1,
            },
        )

    async def _get_campaigns(self, params: Dict[str, Any]) -> SkillResult:
        """List active phishing campaigns."""
        status_filter = params.get("status", "active")
        campaigns = [
            {
                "campaign_id": c.campaign_id,
                "name": c.name,
                "first_seen": c.first_seen.isoformat(),
                "last_seen": c.last_seen.isoformat(),
                "total_emails": c.total_emails,
                "unique_targets": c.unique_targets,
                "payload_type": c.payload_type,
                "lure_theme": c.lure_theme,
                "mitigation_status": c.mitigation_status,
            }
            for c in self.active_campaigns.values()
            if c.mitigation_status == status_filter or status_filter == "all"
        ]
        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={"campaigns": campaigns, "total": len(campaigns)},
        )

    # =========================================================================
    # Internal Analysis Helpers
    # =========================================================================

    def _extract_domain(self, email: str) -> str:
        if "@" in email:
            return email.split("@")[-1].strip().lower().rstrip(">")
        return ""

    def _analyze_authentication(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Analyze SPF, DKIM, DMARC authentication results."""
        auth_header = headers.get("Authentication-Results", headers.get("authentication-results", ""))
        received_spf = headers.get("Received-SPF", headers.get("received-spf", ""))

        results = {
            "spf": "none",
            "dkim": "none",
            "dmarc": "none",
        }

        auth_lower = auth_header.lower()
        spf_lower = received_spf.lower()

        # SPF
        if "spf=pass" in auth_lower or "pass" in spf_lower:
            results["spf"] = "pass"
        elif "spf=fail" in auth_lower or "fail" in spf_lower:
            results["spf"] = "fail"
        elif "spf=softfail" in auth_lower or "softfail" in spf_lower:
            results["spf"] = "softfail"

        # DKIM
        if "dkim=pass" in auth_lower:
            results["dkim"] = "pass"
        elif "dkim=fail" in auth_lower:
            results["dkim"] = "fail"

        # DMARC
        if "dmarc=pass" in auth_lower:
            results["dmarc"] = "pass"
        elif "dmarc=fail" in auth_lower:
            results["dmarc"] = "fail"

        return results

    def _score_authentication(self, auth: Dict[str, str]) -> float:
        """Score authentication results (0=all pass, 100=all fail)."""
        score = 0.0
        if auth["spf"] == "fail":
            score += 35
        elif auth["spf"] == "softfail":
            score += 20
        elif auth["spf"] == "none":
            score += 15

        if auth["dkim"] == "fail":
            score += 35
        elif auth["dkim"] == "none":
            score += 15

        if auth["dmarc"] == "fail":
            score += 30
        elif auth["dmarc"] == "none":
            score += 10

        return min(100.0, score)

    def _analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze a URL for phishing indicators."""
        risk_score = 0.0
        indicators = []

        try:
            parsed = urlparse(url)
            domain = parsed.hostname or ""
            path = parsed.path or ""
            full = url.lower()
        except Exception:
            return {"url": url, "risk_score": 50.0, "indicators": ["malformed_url"], "error": "parse_failed"}

        # Check suspicious TLDs
        for pattern in self.SUSPICIOUS_TLD_PATTERNS:
            if re.search(pattern, domain):
                risk_score += 25
                indicators.append(f"suspicious_tld:{domain}")
                break

        # Check credential harvesting patterns
        for pattern in self.CREDENTIAL_HARVEST_PATTERNS:
            if re.search(pattern, full):
                risk_score += 30
                indicators.append(f"credential_harvest_pattern:{pattern}")
                break

        # IP address in URL (common in phishing)
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            risk_score += 35
            indicators.append("ip_address_url")

        # Excessive subdomains (e.g., login.microsoft.com.evil.xyz)
        subdomain_count = domain.count(".")
        if subdomain_count >= 3:
            risk_score += 20
            indicators.append(f"excessive_subdomains:{subdomain_count}")

        # URL shorteners
        shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
        if domain in shorteners:
            risk_score += 15
            indicators.append("url_shortener")

        # Data URI
        if url.startswith("data:"):
            risk_score += 40
            indicators.append("data_uri")

        # Known phishing domain from our tracking
        if domain in self.known_phishing_domains:
            risk_score += 50
            indicators.append("known_phishing_domain")

        return {
            "url": url,
            "domain": domain,
            "risk_score": min(100.0, risk_score),
            "indicators": indicators,
        }

    def _analyze_attachment(self, attachment: Dict[str, Any]) -> Dict[str, Any]:
        """Assess attachment risk."""
        name = attachment.get("name", "").lower()
        content_type = attachment.get("content_type", "").lower()
        size = attachment.get("size", 0)
        risk_score = 0.0
        indicators = []

        # Check extension
        for ext in self.HIGH_RISK_EXTENSIONS:
            if name.endswith(ext):
                risk_score += 60
                indicators.append(f"high_risk_extension:{ext}")
                break

        if risk_score == 0:
            for ext in self.MEDIUM_RISK_EXTENSIONS:
                if name.endswith(ext):
                    risk_score += 35
                    indicators.append(f"medium_risk_extension:{ext}")
                    break

        # Double extension trick (e.g., invoice.pdf.exe)
        parts = name.rsplit(".", 2)
        if len(parts) >= 3:
            risk_score += 30
            indicators.append("double_extension")

        # Suspicious content type mismatch
        if name.endswith(".pdf") and "pdf" not in content_type:
            risk_score += 25
            indicators.append("content_type_mismatch")

        # Password-protected archives (common for malware delivery)
        if name.endswith((".zip", ".rar", ".7z")) and size < 500_000:
            risk_score += 15
            indicators.append("small_archive")

        return {
            "name": name,
            "risk_score": min(100.0, risk_score),
            "indicators": indicators,
        }

    def _detect_bec(self, subject: str, sender: str, body: str) -> float:
        """Detect Business Email Compromise patterns."""
        score = 0.0
        combined = f"{subject} {body}"

        for pattern in self.BEC_SUBJECT_PATTERNS:
            if re.search(pattern, combined):
                score += 25
                break

        # Urgency language
        urgency_terms = ["urgent", "immediately", "asap", "right away", "time sensitive", "act now"]
        body_lower = body.lower()
        urgency_count = sum(1 for term in urgency_terms if term in body_lower)
        score += min(30, urgency_count * 10)

        # Authority impersonation
        authority_terms = ["ceo", "cfo", "president", "director", "executive", "board"]
        if any(term in body_lower or term in subject.lower() for term in authority_terms):
            score += 20

        # Request for secrecy
        secrecy_terms = ["confidential", "don't tell", "keep this between", "do not share", "private matter"]
        if any(term in body_lower for term in secrecy_terms):
            score += 15

        return min(100.0, score)

    def _analyze_content(self, subject: str, body: str) -> float:
        """Analyze email content for phishing indicators."""
        score = 0.0
        combined = f"{subject} {body}".lower()

        # Generic greeting
        if re.search(r"(?i)dear\s+(customer|user|member|account\s*holder|sir|madam)", combined):
            score += 15

        # Threat/fear language
        threat_terms = ["suspended", "terminated", "locked", "compromised", "unauthorized", "unusual activity"]
        if any(term in combined for term in threat_terms):
            score += 20

        # Action required + link
        if "action required" in combined or "verify your" in combined or "confirm your" in combined:
            score += 15

        # Poor grammar indicators (simplified)
        if re.search(r"kindly\s+(click|verify|confirm|update)", combined):
            score += 10

        return min(100.0, score)

    def _calculate_composite_risk(
        self,
        auth_score: float,
        url_risk: float,
        attachment_risk: float,
        bec_score: float,
        content_score: float,
    ) -> float:
        """Calculate weighted composite phishing risk score."""
        # Weights reflect relative importance
        weighted = (
            auth_score * 0.20
            + url_risk * 0.30
            + attachment_risk * 0.25
            + bec_score * 0.15
            + content_score * 0.10
        )
        return round(min(100.0, weighted), 1)

    def _classify(
        self, risk_score: float, bec_score: float,
        url_risk: float, attachment_risk: float,
    ) -> str:
        """Classify the email based on analysis scores."""
        if risk_score < 20:
            return "clean"
        if bec_score >= 60:
            return "bec"
        if attachment_risk >= 60:
            return "malware_delivery"
        if url_risk >= 60:
            return "credential_harvest"
        if risk_score >= 60:
            return "phishing"
        if risk_score >= 30:
            return "suspicious"
        return "likely_clean"

    def _recommend_actions(self, classification: str, risk_score: float) -> List[str]:
        """Generate recommended response actions."""
        actions = []
        if classification in ("phishing", "credential_harvest", "malware_delivery", "bec"):
            actions.append("BLOCK sender domain in email gateway")
            actions.append("QUARANTINE email from all recipient mailboxes")
            actions.append("NOTIFY affected users")
            if classification == "credential_harvest":
                actions.append("FORCE password reset for users who clicked links")
                actions.append("CHECK authentication logs for compromised credentials")
            if classification == "malware_delivery":
                actions.append("SCAN endpoints for payload indicators")
                actions.append("UPDATE endpoint detection signatures")
            if classification == "bec":
                actions.append("VERIFY financial requests through out-of-band communication")
                actions.append("ALERT finance team to potential BEC campaign")
        elif classification == "suspicious":
            actions.append("MONITOR for additional similar emails")
            actions.append("ADD sender domain to watchlist")
        else:
            actions.append("No action required — email appears legitimate")
        return actions

    def _generate_user_feedback(self, classification: str, risk_score: float) -> str:
        """Generate feedback message for the reporting user."""
        if classification in ("phishing", "credential_harvest", "malware_delivery", "bec"):
            return (
                "Thank you for reporting this email. Our analysis confirms it is malicious. "
                "We are taking action to block the sender and protect other users. "
                "If you clicked any links or opened attachments, please contact the security team immediately."
            )
        elif classification == "suspicious":
            return (
                "Thank you for reporting this email. It has some suspicious characteristics "
                "and we are investigating further. Please do not interact with this email."
            )
        return (
            "Thank you for reporting this email. Our analysis indicates it appears to be legitimate. "
            "Your vigilance helps keep our organization safe."
        )

    def _find_matching_campaign(self, sender_domain: str, subject: str) -> Optional[str]:
        """Try to match to an existing campaign."""
        for cid, campaign in self.active_campaigns.items():
            if sender_domain and sender_domain in campaign.sender_infrastructure:
                return cid
            # Simple subject similarity
            if subject and campaign.lure_theme:
                common = set(subject.lower().split()) & set(campaign.lure_theme.lower().split())
                if len(common) >= 3:
                    return cid
        return None

    async def _auto_track(self, indicator: PhishingIndicator):
        """Automatically add high-risk indicators to campaign tracking."""
        await self._track_campaign({
            "indicator": {
                "sender_domain": indicator.sender_domain,
                "subject": indicator.email_subject,
                "classification": indicator.classification,
            }
        })
        # Track the sender domain
        if indicator.sender_domain:
            self.known_phishing_domains.add(indicator.sender_domain)
