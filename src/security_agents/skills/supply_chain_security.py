#!/usr/bin/env python3
"""
Supply Chain Security Skill — dependency analysis, SBOM, and risk assessment.

Primary owner: Beta-4 (DevSecOps)
Also usable by: Alpha-4 (threat intel for malicious packages and campaigns)

Capabilities:
  - Dependency tree analysis (direct + transitive)
  - Known vulnerability matching against dependency versions
  - License compliance checking (GPL, MIT, Apache, proprietary)
  - Typosquatting detection for package names
  - Maintainer reputation scoring
  - Dependency freshness analysis (age, update frequency)
  - Malicious package indicators
  - SBOM generation (CycloneDX-style)
"""

import hashlib
import re
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum

from security_agents.core.models import (
    SkillResult, IntelligencePacket, IntelligenceType, Priority,
)
from security_agents.skills.base_skill import BaseSecuritySkill

class LicenseRisk(Enum):
    HIGH = "high"          # Copyleft / incompatible
    MEDIUM = "medium"      # Weak copyleft
    LOW = "low"            # Permissive
    UNKNOWN = "unknown"    # No license found

class SupplyChainSecuritySkill(BaseSecuritySkill):
    """Software supply chain security analysis and SBOM generation."""

    SKILL_NAME = "supply_chain_security"
    DESCRIPTION = (
        "Dependency analysis, vulnerability matching, license compliance, "
        "typosquatting detection, maintainer reputation, freshness analysis, "
        "malicious package detection, and SBOM generation"
    )
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = ["beta_4_devsecops", "alpha_4_threat_intel"]
    REQUIRED_INTEGRATIONS = []

    # License classification
    LICENSE_CLASSIFICATION = {
        # Permissive (low risk)
        "MIT": LicenseRisk.LOW,
        "Apache-2.0": LicenseRisk.LOW,
        "BSD-2-Clause": LicenseRisk.LOW,
        "BSD-3-Clause": LicenseRisk.LOW,
        "ISC": LicenseRisk.LOW,
        "Unlicense": LicenseRisk.LOW,
        "0BSD": LicenseRisk.LOW,
        "CC0-1.0": LicenseRisk.LOW,
        # Weak copyleft (medium risk)
        "LGPL-2.1": LicenseRisk.MEDIUM,
        "LGPL-3.0": LicenseRisk.MEDIUM,
        "MPL-2.0": LicenseRisk.MEDIUM,
        "EPL-2.0": LicenseRisk.MEDIUM,
        "CDDL-1.0": LicenseRisk.MEDIUM,
        # Strong copyleft (high risk for proprietary use)
        "GPL-2.0": LicenseRisk.HIGH,
        "GPL-3.0": LicenseRisk.HIGH,
        "AGPL-3.0": LicenseRisk.HIGH,
        "SSPL-1.0": LicenseRisk.HIGH,
        "BSL-1.1": LicenseRisk.HIGH,
    }

    # Known popular package names used as typosquatting targets
    POPULAR_PACKAGES = {
        "npm": [
            "lodash", "express", "react", "axios", "webpack", "babel",
            "typescript", "eslint", "jest", "mocha", "chalk", "commander",
            "debug", "moment", "uuid", "dotenv", "cors", "body-parser",
            "jsonwebtoken", "bcrypt", "mongoose", "sequelize", "socket.io",
        ],
        "pypi": [
            "requests", "flask", "django", "numpy", "pandas", "boto3",
            "pytest", "setuptools", "pyyaml", "cryptography", "pillow",
            "sqlalchemy", "celery", "redis", "aiohttp", "httpx", "pydantic",
            "fastapi", "uvicorn", "black", "mypy", "scrapy", "beautifulsoup4",
        ],
    }

    # Typosquatting generation patterns
    TYPO_PATTERNS = [
        "swap_adjacent",    # lodash -> ldoash
        "missing_char",     # lodash -> lodsh
        "extra_char",       # lodash -> lodassh
        "replace_similar",  # requests -> reqeusts
        "hyphen_swap",      # body-parser -> bodyparser, body_parser
        "prefix_suffix",    # python-requests, requests-python
    ]

    # Malicious package indicators
    MALICIOUS_INDICATORS = {
        "install_script_network": "Package executes network calls during install",
        "obfuscated_code": "Package contains obfuscated or encoded source code",
        "env_variable_access": "Package reads sensitive environment variables",
        "file_system_write": "Package writes outside its own directory during install",
        "binary_payload": "Package contains pre-compiled binary payloads",
        "dynamic_import": "Package uses dynamic imports or eval() on external input",
        "credential_patterns": "Package contains patterns matching credential harvesting",
        "known_malicious_maintainer": "Package maintainer is linked to known malicious activity",
    }

    async def _setup(self):
        """Initialize supply chain tracking state."""
        self.analyzed_packages: Dict[str, Dict[str, Any]] = {}
        self.sboms: Dict[str, Dict[str, Any]] = {}
        self.known_vulnerabilities: Dict[str, List[Dict]] = {}  # package -> vulns

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        """
        Dispatch to the appropriate supply chain security action.

        Supported actions:
          analyze_dependencies — full dependency tree analysis
          check_vulnerabilities — match dependencies against known vulns
          check_licenses — license compliance analysis
          detect_typosquatting — check for typosquatting in package names
          score_maintainer — assess maintainer reputation
          check_freshness — analyze dependency age and update frequency
          generate_sbom — produce CycloneDX-style SBOM
        """
        action = parameters.get("action", "analyze_dependencies")

        dispatch = {
            "analyze_dependencies": self._analyze_dependencies,
            "check_vulnerabilities": self._check_vulnerabilities,
            "check_licenses": self._check_licenses,
            "detect_typosquatting": self._detect_typosquatting,
            "score_maintainer": self._score_maintainer,
            "check_freshness": self._check_freshness,
            "generate_sbom": self._generate_sbom,
        }

        handler = dispatch.get(action)
        if not handler:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=[f"Unknown action '{action}'. Supported: {list(dispatch.keys())}"],
            )
        return await handler(parameters)

    # =========================================================================
    # Dependency Analysis
    # =========================================================================

    async def _analyze_dependencies(self, params: Dict[str, Any]) -> SkillResult:
        """Perform comprehensive dependency tree analysis."""
        dependencies = params.get("dependencies", [])
        ecosystem = params.get("ecosystem", "npm")  # npm, pypi, maven, etc.
        project_name = params.get("project_name", "unknown")

        if not dependencies:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'dependencies' parameter required — list of {name, version, ...} dicts"],
            )

        direct_deps = [d for d in dependencies if d.get("direct", True)]
        transitive_deps = [d for d in dependencies if not d.get("direct", True)]

        # Analyze each dependency
        analysis_results = []
        total_risk_score = 0.0
        packets = []

        for dep in dependencies:
            result = self._analyze_single_dependency(dep, ecosystem)
            analysis_results.append(result)
            total_risk_score += result["risk_score"]

            # Track internally
            pkg_key = f"{dep.get('name', '')}@{dep.get('version', '')}"
            self.analyzed_packages[pkg_key] = result

        # Sort by risk score descending
        analysis_results.sort(key=lambda r: r["risk_score"], reverse=True)

        # Overall risk assessment
        avg_risk = total_risk_score / max(1, len(dependencies))
        high_risk = [r for r in analysis_results if r["risk_score"] >= 70]

        if high_risk:
            packets.append(IntelligencePacket(
                packet_id=f"PKT-SCS-{uuid.uuid4().hex[:8]}",
                source_agent=self.agent_id,
                target_agents=["all"],
                intelligence_type=IntelligenceType.SUPPLY_CHAIN,
                priority=Priority.HIGH if any(r["risk_score"] >= 90 for r in high_risk) else Priority.MEDIUM,
                confidence=85.0,
                timestamp=datetime.now(),
                data={
                    "event": "high_risk_dependencies",
                    "project": project_name,
                    "ecosystem": ecosystem,
                    "high_risk_count": len(high_risk),
                    "packages": [r["name"] for r in high_risk[:10]],
                },
                correlation_keys=[project_name, ecosystem],
            ))

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "project_name": project_name,
                "ecosystem": ecosystem,
                "summary": {
                    "total_dependencies": len(dependencies),
                    "direct": len(direct_deps),
                    "transitive": len(transitive_deps),
                    "average_risk_score": round(avg_risk, 1),
                    "high_risk_count": len(high_risk),
                    "max_depth": max((d.get("depth", 0) for d in dependencies), default=0),
                },
                "dependencies": analysis_results,
                "recommendations": self._dependency_recommendations(analysis_results),
            },
            intelligence_packets=packets,
        )

    def _analyze_single_dependency(self, dep: Dict[str, Any], ecosystem: str) -> Dict[str, Any]:
        """Analyze a single dependency for risk factors."""
        name = dep.get("name", "")
        version = dep.get("version", "")
        risk_score = 0.0
        risk_factors = []

        # Check for known vulnerabilities
        vuln_count = dep.get("known_vulnerabilities", 0)
        if vuln_count > 0:
            risk_score += min(40.0, vuln_count * 10.0)
            risk_factors.append(f"{vuln_count} known vulnerabilities")

        # Check license risk
        license_id = dep.get("license", "unknown")
        license_risk = self.LICENSE_CLASSIFICATION.get(license_id, LicenseRisk.UNKNOWN)
        if license_risk == LicenseRisk.HIGH:
            risk_score += 15.0
            risk_factors.append(f"High-risk license: {license_id}")
        elif license_risk == LicenseRisk.UNKNOWN:
            risk_score += 10.0
            risk_factors.append("Unknown or missing license")

        # Check freshness
        last_update = dep.get("last_updated", "")
        if last_update:
            try:
                last_dt = datetime.fromisoformat(last_update)
                days_since = (datetime.now() - last_dt).days
                if days_since > 730:  # 2 years
                    risk_score += 15.0
                    risk_factors.append(f"Stale: not updated in {days_since} days")
                elif days_since > 365:
                    risk_score += 8.0
                    risk_factors.append(f"Aging: last updated {days_since} days ago")
            except (ValueError, TypeError):
                pass

        # Check maintainer count
        maintainers = dep.get("maintainer_count", 1)
        if maintainers <= 1:
            risk_score += 10.0
            risk_factors.append("Single maintainer — bus factor risk")

        # Check download popularity (very low downloads may indicate a fake/malicious package)
        downloads = dep.get("weekly_downloads", -1)
        if 0 <= downloads < 100:
            risk_score += 12.0
            risk_factors.append(f"Very low download count: {downloads}/week")

        # Check for malicious indicators
        indicators = dep.get("malicious_indicators", [])
        for indicator in indicators:
            if indicator in self.MALICIOUS_INDICATORS:
                risk_score += 25.0
                risk_factors.append(f"Malicious indicator: {self.MALICIOUS_INDICATORS[indicator]}")

        # Transitive dependencies add risk
        if not dep.get("direct", True):
            risk_score *= 0.8  # Slightly discount transitive (less direct control)

        return {
            "name": name,
            "version": version,
            "ecosystem": ecosystem,
            "direct": dep.get("direct", True),
            "depth": dep.get("depth", 0),
            "license": license_id,
            "license_risk": license_risk.value,
            "risk_score": round(min(100.0, risk_score), 1),
            "risk_factors": risk_factors,
        }

    def _dependency_recommendations(self, results: List[Dict]) -> List[str]:
        """Generate recommendations based on dependency analysis."""
        recs = []
        high_risk = [r for r in results if r["risk_score"] >= 70]
        stale = [r for r in results if any("Stale" in f for f in r.get("risk_factors", []))]
        license_issues = [r for r in results if r.get("license_risk") == "high"]
        single_maintainer = [r for r in results if any("Single maintainer" in f for f in r.get("risk_factors", []))]

        if high_risk:
            recs.append(f"Replace or remediate {len(high_risk)} high-risk dependencies: {', '.join(r['name'] for r in high_risk[:5])}")
        if stale:
            recs.append(f"Upgrade {len(stale)} stale dependencies that have not been updated in over 2 years")
        if license_issues:
            recs.append(f"Review {len(license_issues)} dependencies with copyleft licenses for compliance with your project license")
        if single_maintainer:
            recs.append(f"{len(single_maintainer)} dependencies have a single maintainer — consider alternatives with broader community support")
        if not recs:
            recs.append("Dependency health is good. Continue regular monitoring.")
        return recs

    # =========================================================================
    # Vulnerability Checking
    # =========================================================================

    async def _check_vulnerabilities(self, params: Dict[str, Any]) -> SkillResult:
        """Match dependencies against known vulnerability databases."""
        dependencies = params.get("dependencies", [])
        vuln_database = params.get("vulnerability_database", [])

        if not dependencies:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'dependencies' parameter required"],
            )

        # Build vulnerability lookup
        vuln_index: Dict[str, List[Dict]] = {}
        for vuln in vuln_database:
            pkg = vuln.get("package", "")
            vuln_index.setdefault(pkg, []).append(vuln)

        affected = []
        safe = []

        for dep in dependencies:
            name = dep.get("name", "")
            version = dep.get("version", "")
            matching_vulns = []

            for vuln in vuln_index.get(name, []):
                if self._version_in_range(version, vuln.get("affected_versions", "")):
                    matching_vulns.append({
                        "cve": vuln.get("cve", ""),
                        "severity": vuln.get("severity", "unknown"),
                        "cvss": vuln.get("cvss_score", 0),
                        "title": vuln.get("title", ""),
                        "fixed_version": vuln.get("fixed_version", ""),
                        "published": vuln.get("published", ""),
                    })

            if matching_vulns:
                affected.append({
                    "name": name,
                    "version": version,
                    "vulnerabilities": matching_vulns,
                    "max_cvss": max(v["cvss"] for v in matching_vulns),
                    "actionable": any(v.get("fixed_version") for v in matching_vulns),
                })
            else:
                safe.append({"name": name, "version": version})

        # Sort affected by max CVSS descending
        affected.sort(key=lambda a: a["max_cvss"], reverse=True)

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "total_checked": len(dependencies),
                "affected": len(affected),
                "safe": len(safe),
                "affected_packages": affected,
                "total_vulnerabilities": sum(len(a["vulnerabilities"]) for a in affected),
            },
        )

    def _version_in_range(self, version: str, affected_range: str) -> bool:
        """
        Simplified version range check. Supports formats:
          "<2.0.0", ">=1.0.0,<1.5.0", "1.2.3" (exact match)
        """
        if not version or not affected_range:
            return False

        version_parts = self._parse_version(version)
        if version_parts is None:
            return False

        # Handle exact match
        if not any(c in affected_range for c in "<>=,"):
            return version == affected_range

        # Handle range constraints
        constraints = [c.strip() for c in affected_range.split(",")]
        for constraint in constraints:
            if constraint.startswith(">="):
                target = self._parse_version(constraint[2:])
                if target and version_parts < target:
                    return False
            elif constraint.startswith(">"):
                target = self._parse_version(constraint[1:])
                if target and version_parts <= target:
                    return False
            elif constraint.startswith("<="):
                target = self._parse_version(constraint[2:])
                if target and version_parts > target:
                    return False
            elif constraint.startswith("<"):
                target = self._parse_version(constraint[1:])
                if target and version_parts >= target:
                    return False

        return True

    def _parse_version(self, version: str) -> Optional[Tuple[int, ...]]:
        """Parse a semver-ish string into a comparable tuple."""
        try:
            # Strip leading 'v' and take only numeric parts
            cleaned = version.lstrip("v").split("-")[0].split("+")[0]
            parts = tuple(int(p) for p in cleaned.split("."))
            return parts
        except (ValueError, AttributeError):
            return None

    # =========================================================================
    # License Compliance
    # =========================================================================

    async def _check_licenses(self, params: Dict[str, Any]) -> SkillResult:
        """Check license compliance for all dependencies."""
        dependencies = params.get("dependencies", [])
        allowed_licenses = set(params.get("allowed_licenses", [
            "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense",
        ]))
        project_license = params.get("project_license", "proprietary")

        if not dependencies:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'dependencies' parameter required"],
            )

        compliant = []
        non_compliant = []
        unknown_license = []

        for dep in dependencies:
            name = dep.get("name", "")
            version = dep.get("version", "")
            license_id = dep.get("license", "unknown")

            risk = self.LICENSE_CLASSIFICATION.get(license_id, LicenseRisk.UNKNOWN)

            if license_id == "unknown" or not license_id:
                unknown_license.append({
                    "name": name,
                    "version": version,
                    "license": license_id,
                    "action": "Investigate and determine license before production use",
                })
            elif license_id in allowed_licenses:
                compliant.append({"name": name, "version": version, "license": license_id})
            else:
                incompatible_reason = self._check_license_compatibility(license_id, project_license)
                non_compliant.append({
                    "name": name,
                    "version": version,
                    "license": license_id,
                    "risk_level": risk.value,
                    "reason": incompatible_reason,
                    "action": self._license_remediation(license_id, risk),
                })

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "total_checked": len(dependencies),
                "compliant": len(compliant),
                "non_compliant": len(non_compliant),
                "unknown": len(unknown_license),
                "compliance_rate": round(len(compliant) / max(1, len(dependencies)) * 100, 1),
                "non_compliant_packages": non_compliant,
                "unknown_license_packages": unknown_license,
                "allowed_licenses": list(allowed_licenses),
            },
        )

    def _check_license_compatibility(self, dep_license: str, project_license: str) -> str:
        """Check if a dependency license is compatible with the project license."""
        if project_license == "proprietary":
            if dep_license in ("GPL-2.0", "GPL-3.0", "AGPL-3.0"):
                return f"{dep_license} is copyleft and incompatible with proprietary distribution"
            if dep_license == "SSPL-1.0":
                return "SSPL restricts service-based usage"
        if dep_license == "AGPL-3.0":
            return "AGPL requires source disclosure for network-accessible software"
        return f"{dep_license} is not in the approved license list"

    def _license_remediation(self, license_id: str, risk: LicenseRisk) -> str:
        if risk == LicenseRisk.HIGH:
            return f"Replace dependency with a permissively-licensed alternative, or obtain commercial license"
        if risk == LicenseRisk.MEDIUM:
            return f"Review {license_id} obligations. Weak copyleft may be acceptable depending on linking"
        return f"Add {license_id} to allowed list if approved by legal team"

    # =========================================================================
    # Typosquatting Detection
    # =========================================================================

    async def _detect_typosquatting(self, params: Dict[str, Any]) -> SkillResult:
        """Detect potential typosquatting in package names."""
        packages = params.get("packages", [])
        ecosystem = params.get("ecosystem", "npm")

        if not packages:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'packages' parameter required — list of package name strings"],
            )

        popular = set(self.POPULAR_PACKAGES.get(ecosystem, []))
        detections = []

        for pkg_name in packages:
            if pkg_name in popular:
                continue  # This IS the legitimate package

            matches = self._find_typosquat_matches(pkg_name, popular)
            if matches:
                detections.append({
                    "package": pkg_name,
                    "likely_intended": matches[0]["target"],
                    "similarity_score": matches[0]["similarity"],
                    "typo_type": matches[0]["typo_type"],
                    "all_matches": matches[:3],
                    "risk": "high" if matches[0]["similarity"] > 0.85 else "medium",
                })

        packets = []
        if detections:
            packets.append(IntelligencePacket(
                packet_id=f"PKT-TYPO-{uuid.uuid4().hex[:8]}",
                source_agent=self.agent_id,
                target_agents=["all"],
                intelligence_type=IntelligenceType.SUPPLY_CHAIN,
                priority=Priority.HIGH,
                confidence=80.0,
                timestamp=datetime.now(),
                data={
                    "event": "typosquatting_detected",
                    "packages": [d["package"] for d in detections],
                    "ecosystem": ecosystem,
                },
                correlation_keys=[d["package"] for d in detections],
            ))

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "packages_checked": len(packages),
                "typosquatting_detected": len(detections) > 0,
                "detections": detections,
                "recommended_action": (
                    "Remove suspected typosquatting packages and install the legitimate versions"
                    if detections else "No typosquatting detected"
                ),
            },
            intelligence_packets=packets,
        )

    def _find_typosquat_matches(self, candidate: str, popular: set) -> List[Dict]:
        """Find popular packages that a candidate might be typosquatting."""
        matches = []
        candidate_lower = candidate.lower()

        for target in popular:
            target_lower = target.lower()
            if candidate_lower == target_lower:
                continue

            similarity = self._string_similarity(candidate_lower, target_lower)
            typo_type = self._classify_typo(candidate_lower, target_lower)

            if similarity >= 0.75 and typo_type != "none":
                matches.append({
                    "target": target,
                    "similarity": round(similarity, 3),
                    "typo_type": typo_type,
                })

        matches.sort(key=lambda m: m["similarity"], reverse=True)
        return matches

    def _string_similarity(self, a: str, b: str) -> float:
        """Compute normalized Levenshtein similarity between two strings."""
        distance = self._levenshtein_distance(a, b)
        max_len = max(len(a), len(b))
        if max_len == 0:
            return 1.0
        return 1.0 - (distance / max_len)

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Compute Levenshtein edit distance."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row

        return prev_row[-1]

    def _classify_typo(self, candidate: str, target: str) -> str:
        """Classify the type of typo between candidate and target."""
        if len(candidate) == len(target) - 1:
            # Missing character
            for i in range(len(target)):
                if candidate == target[:i] + target[i + 1:]:
                    return "missing_char"

        if len(candidate) == len(target) + 1:
            # Extra character
            for i in range(len(candidate)):
                if target == candidate[:i] + candidate[i + 1:]:
                    return "extra_char"

        if len(candidate) == len(target):
            # Swapped adjacent characters
            diffs = [(i, candidate[i], target[i]) for i in range(len(candidate)) if candidate[i] != target[i]]
            if len(diffs) == 2 and diffs[1][0] - diffs[0][0] == 1:
                if diffs[0][1] == diffs[1][2] and diffs[0][2] == diffs[1][1]:
                    return "swap_adjacent"
            # Single character replacement
            if len(diffs) == 1:
                return "replace_similar"

        # Hyphen/underscore confusion
        if candidate.replace("-", "") == target.replace("-", ""):
            return "hyphen_swap"
        if candidate.replace("_", "-") == target or candidate.replace("-", "_") == target:
            return "hyphen_swap"

        # Prefix/suffix additions
        if candidate.startswith(target) or candidate.endswith(target):
            return "prefix_suffix"
        if target.startswith(candidate) or target.endswith(candidate):
            return "prefix_suffix"

        # If similarity is high but no specific pattern, classify as general
        if self._levenshtein_distance(candidate, target) <= 2:
            return "general_typo"

        return "none"

    # =========================================================================
    # Maintainer Reputation Scoring
    # =========================================================================

    async def _score_maintainer(self, params: Dict[str, Any]) -> SkillResult:
        """Assess maintainer reputation for a package."""
        maintainer = params.get("maintainer", {})
        if not maintainer:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'maintainer' parameter required"],
            )

        score = self._compute_maintainer_score(maintainer)

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "maintainer": maintainer.get("username", "unknown"),
                "reputation_score": score["score"],
                "risk_level": score["risk_level"],
                "factors": score["factors"],
            },
        )

    def _compute_maintainer_score(self, maintainer: Dict) -> Dict[str, Any]:
        """Compute maintainer reputation score (0-100, higher is more trustworthy)."""
        score = 50.0  # Base score
        factors = []

        # Account age
        account_created = maintainer.get("account_created", "")
        if account_created:
            try:
                age_days = (datetime.now() - datetime.fromisoformat(account_created)).days
                if age_days > 1825:  # 5+ years
                    score += 15
                    factors.append("Mature account (5+ years)")
                elif age_days > 365:
                    score += 8
                    factors.append("Established account (1+ year)")
                elif age_days < 30:
                    score -= 20
                    factors.append("Very new account (< 30 days)")
                elif age_days < 90:
                    score -= 10
                    factors.append("New account (< 90 days)")
            except (ValueError, TypeError):
                pass

        # Package count
        pkg_count = maintainer.get("package_count", 0)
        if pkg_count >= 10:
            score += 10
            factors.append(f"Maintains {pkg_count} packages")
        elif pkg_count >= 3:
            score += 5
        elif pkg_count <= 1:
            score -= 5
            factors.append("Maintains only 1 package")

        # Total downloads across packages
        total_downloads = maintainer.get("total_downloads", 0)
        if total_downloads > 1_000_000:
            score += 15
            factors.append("Highly downloaded packages (1M+)")
        elif total_downloads > 100_000:
            score += 8
        elif total_downloads < 1000:
            score -= 5
            factors.append("Very low total downloads")

        # GitHub activity
        has_github = maintainer.get("github_linked", False)
        if has_github:
            score += 5
            factors.append("GitHub account linked")
            github_stars = maintainer.get("github_stars", 0)
            if github_stars > 1000:
                score += 10
                factors.append(f"Popular GitHub projects ({github_stars} stars)")

        # 2FA enabled
        if maintainer.get("two_factor_enabled", False):
            score += 5
            factors.append("2FA enabled on registry account")
        else:
            score -= 5
            factors.append("No 2FA on registry account")

        # Security advisories published
        if maintainer.get("security_advisories_published", 0) > 0:
            score += 5
            factors.append("Has published security advisories (responsive to vulns)")

        final_score = round(max(0.0, min(100.0, score)), 1)

        if final_score >= 70:
            risk_level = "low"
        elif final_score >= 40:
            risk_level = "medium"
        else:
            risk_level = "high"

        return {"score": final_score, "risk_level": risk_level, "factors": factors}

    # =========================================================================
    # Freshness Analysis
    # =========================================================================

    async def _check_freshness(self, params: Dict[str, Any]) -> SkillResult:
        """Analyze dependency freshness — age, update frequency, and staleness."""
        dependencies = params.get("dependencies", [])
        if not dependencies:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'dependencies' parameter required"],
            )

        now = datetime.now()
        results = []

        for dep in dependencies:
            name = dep.get("name", "")
            version = dep.get("version", "")
            last_updated = dep.get("last_updated", "")
            latest_version = dep.get("latest_version", "")
            versions_behind = dep.get("versions_behind", 0)

            freshness = "current"
            days_since_update = None

            if last_updated:
                try:
                    last_dt = datetime.fromisoformat(last_updated)
                    days_since_update = (now - last_dt).days

                    if days_since_update > 730:
                        freshness = "abandoned"
                    elif days_since_update > 365:
                        freshness = "stale"
                    elif days_since_update > 180:
                        freshness = "aging"
                    else:
                        freshness = "active"
                except (ValueError, TypeError):
                    pass

            if version != latest_version and latest_version:
                if versions_behind > 5:
                    freshness = "outdated" if freshness == "active" else freshness

            results.append({
                "name": name,
                "current_version": version,
                "latest_version": latest_version or "unknown",
                "versions_behind": versions_behind,
                "days_since_update": days_since_update,
                "freshness": freshness,
                "update_recommended": freshness in ("stale", "abandoned", "outdated"),
            })

        # Summary
        freshness_counts = {}
        for r in results:
            f = r["freshness"]
            freshness_counts[f] = freshness_counts.get(f, 0) + 1

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "total_checked": len(results),
                "freshness_summary": freshness_counts,
                "dependencies": results,
                "update_recommended_count": sum(1 for r in results if r["update_recommended"]),
            },
        )

    # =========================================================================
    # SBOM Generation
    # =========================================================================

    async def _generate_sbom(self, params: Dict[str, Any]) -> SkillResult:
        """Generate a CycloneDX-style Software Bill of Materials."""
        project_name = params.get("project_name", "unknown")
        project_version = params.get("project_version", "0.0.0")
        dependencies = params.get("dependencies", [])

        if not dependencies:
            return SkillResult(
                success=False, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
                errors=["'dependencies' parameter required"],
            )

        sbom_id = f"SBOM-{uuid.uuid4().hex[:12]}"
        components = []

        for dep in dependencies:
            name = dep.get("name", "")
            version = dep.get("version", "")
            license_id = dep.get("license", "unknown")
            purl = self._generate_purl(dep)

            component = {
                "type": "library",
                "name": name,
                "version": version,
                "purl": purl,
                "licenses": [{"license": {"id": license_id}}] if license_id != "unknown" else [],
                "scope": "required" if dep.get("direct", True) else "optional",
                "hashes": [],
                "external_references": [],
            }

            # Add hash if available
            pkg_hash = dep.get("integrity_hash", "")
            if pkg_hash:
                component["hashes"].append({
                    "alg": "SHA-256",
                    "content": pkg_hash,
                })

            # Add repository URL if available
            repo_url = dep.get("repository_url", "")
            if repo_url:
                component["external_references"].append({
                    "type": "vcs",
                    "url": repo_url,
                })

            components.append(component)

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tools": [{"name": "SecurityAgents Platform", "version": self.VERSION}],
                "component": {
                    "type": "application",
                    "name": project_name,
                    "version": project_version,
                },
            },
            "components": components,
        }

        self.sboms[sbom_id] = sbom

        return SkillResult(
            success=True, skill_name=self.SKILL_NAME, agent_id=self.agent_id,
            data={
                "sbom_id": sbom_id,
                "format": "CycloneDX",
                "spec_version": "1.5",
                "total_components": len(components),
                "sbom": sbom,
            },
        )

    def _generate_purl(self, dep: Dict[str, Any]) -> str:
        """Generate Package URL (purl) for a dependency."""
        ecosystem = dep.get("ecosystem", "npm")
        name = dep.get("name", "")
        version = dep.get("version", "")

        purl_types = {
            "npm": "npm",
            "pypi": "pypi",
            "maven": "maven",
            "nuget": "nuget",
            "gem": "gem",
            "cargo": "cargo",
            "golang": "golang",
        }
        purl_type = purl_types.get(ecosystem, ecosystem)

        namespace = dep.get("namespace", "")
        if namespace:
            return f"pkg:{purl_type}/{namespace}/{name}@{version}"
        return f"pkg:{purl_type}/{name}@{version}"
