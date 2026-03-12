#!/usr/bin/env python3
"""
AI Confidence Scoring Skill — multi-factor confidence scoring for AI security decisions.

Primary owner: All agents
Wraps: secops-ai-orchestration/ai-engine/confidence_engine.py

Capabilities:
  - Score AI decisions with multi-factor confidence analysis
  - Calibrate confidence thresholds based on historical outcomes
  - Retrieve and analyze confidence history trends
  - Compare confidence across model providers
  - Set and manage per-agent confidence thresholds
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict

from security_agents.core.models import (
    SkillResult, IntelligencePacket, IntelligenceType, Priority,
)
from security_agents.skills.base_skill import BaseSecuritySkill

class AIConfidenceScoringSkill(BaseSecuritySkill):
    """Multi-factor AI confidence scoring, calibration, and threshold management."""

    SKILL_NAME = "ai_confidence_scoring"
    DESCRIPTION = (
        "AI confidence scoring with uncertainty quantification, bias detection, "
        "calibration tracking, model comparison, and threshold management"
    )
    VERSION = "1.0.0"
    COMPATIBLE_AGENTS = []  # Empty = all agents
    REQUIRED_INTEGRATIONS = []

    # -------------------------------------------------------------------------
    # Default factor weights (mirrors confidence_engine.py)
    # -------------------------------------------------------------------------

    DEFAULT_FACTOR_WEIGHTS = {
        "evidence_quality": 0.25,
        "pattern_match": 0.20,
        "context_alignment": 0.15,
        "model_uncertainty": 0.15,
        "cross_validation": 0.15,
        "bias_adjustment": 0.10,
    }

    # Default autonomy-tier thresholds
    DEFAULT_THRESHOLDS = {
        "tier_0_autonomous": 0.95,
        "tier_1_assisted": 0.80,
        "tier_2_supervised": 0.60,
        "tier_3_collaborative": 0.0,
    }

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    async def _setup(self):
        """Initialize internal state."""
        self.factor_weights: Dict[str, float] = dict(self.DEFAULT_FACTOR_WEIGHTS)
        self.thresholds: Dict[str, float] = dict(self.DEFAULT_THRESHOLDS)
        self.calibration_history: List[Dict[str, Any]] = []
        self.decision_outcomes: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.model_scores: Dict[str, List[float]] = defaultdict(list)

    # -------------------------------------------------------------------------
    # Action dispatch
    # -------------------------------------------------------------------------

    async def _execute(self, parameters: Dict[str, Any]) -> SkillResult:
        """
        Dispatch to the appropriate action.

        Supported actions:
          score_decision       -- score a single AI decision
          calibrate_confidence -- recalibrate based on actual outcomes
          get_confidence_history -- retrieve scoring history
          compare_models       -- compare confidence across models
          set_threshold        -- update autonomy-tier thresholds
        """
        action = parameters.get("action", "score_decision")
        dispatch = {
            "score_decision": self._score_decision,
            "calibrate_confidence": self._calibrate_confidence,
            "get_confidence_history": self._get_confidence_history,
            "compare_models": self._compare_models,
            "set_threshold": self._set_threshold,
        }
        handler = dispatch.get(action)
        if handler is None:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[
                    f"Unknown action '{action}'. "
                    f"Supported: {', '.join(dispatch.keys())}"
                ],
            )
        return await handler(parameters)

    # =========================================================================
    # score_decision
    # =========================================================================

    async def _score_decision(self, params: Dict[str, Any]) -> SkillResult:
        """Score an AI security decision with multi-factor confidence analysis."""
        decision_id = params.get("decision_id", f"DEC-{uuid.uuid4().hex[:8]}")
        analysis = params.get("analysis", {})
        evidence = params.get("evidence", {})
        model_id = params.get("model_id", "default")
        severity = params.get("severity", "medium")

        # --- Factor 1: Evidence quality ---
        evidence_score = self._assess_evidence_quality(evidence)

        # --- Factor 2: Pattern match ---
        pattern_score = self._assess_pattern_match(analysis, severity)

        # --- Factor 3: Context alignment ---
        context_score = self._assess_context_alignment(analysis, severity)

        # --- Factor 4: Model uncertainty ---
        model_score = self._assess_model_uncertainty(analysis)

        # --- Factor 5: Cross-validation ---
        crossval_score = self._assess_cross_validation(analysis)

        factors = [
            {"name": "evidence_quality", "score": evidence_score,
             "weight": self.factor_weights["evidence_quality"]},
            {"name": "pattern_match", "score": pattern_score,
             "weight": self.factor_weights["pattern_match"]},
            {"name": "context_alignment", "score": context_score,
             "weight": self.factor_weights["context_alignment"]},
            {"name": "model_uncertainty", "score": model_score,
             "weight": self.factor_weights["model_uncertainty"]},
            {"name": "cross_validation", "score": crossval_score,
             "weight": self.factor_weights["cross_validation"]},
        ]

        # Weighted combination
        total_weight = sum(f["weight"] for f in factors)
        overall = sum(f["score"] * f["weight"] for f in factors) / total_weight if total_weight else 0.5
        overall = max(0.0, min(1.0, overall))

        # Uncertainty estimation (spread of factor scores)
        scores = [f["score"] for f in factors]
        mean_s = sum(scores) / len(scores) if scores else 0.5
        variance = sum((s - mean_s) ** 2 for s in scores) / len(scores) if len(scores) > 1 else 0.0
        std_dev = variance ** 0.5
        margin = 1.96 * std_dev / (len(scores) ** 0.5) if scores else 0.5
        lower_bound = max(0.0, mean_s - margin)
        upper_bound = min(1.0, mean_s + margin)

        # Bias assessment
        bias_risk = "low"
        fairness_score = 0.9
        if severity == "critical" and overall < 0.5:
            bias_risk = "medium"
            fairness_score = 0.7
        adjustment_factor = 1.0 if bias_risk == "low" else (0.95 if bias_risk == "medium" else 0.90)
        adjusted = max(0.0, min(1.0, overall * adjustment_factor * fairness_score))

        # Recommend autonomy tier
        effective = adjusted - ((upper_bound - lower_bound) * 0.5)
        if effective >= self.thresholds["tier_0_autonomous"]:
            recommended_tier = 0
        elif effective >= self.thresholds["tier_1_assisted"]:
            recommended_tier = 1
        elif effective >= self.thresholds["tier_2_supervised"]:
            recommended_tier = 2
        else:
            recommended_tier = 3

        # Persist to history
        entry = {
            "decision_id": decision_id,
            "model_id": model_id,
            "raw_confidence": round(overall, 4),
            "adjusted_confidence": round(adjusted, 4),
            "confidence_interval": [round(lower_bound, 4), round(upper_bound, 4)],
            "recommended_tier": recommended_tier,
            "bias_risk": bias_risk,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.calibration_history.append(entry)
        self.model_scores[model_id].append(adjusted)

        # Keep bounded history
        if len(self.calibration_history) > 1000:
            self.calibration_history = self.calibration_history[-1000:]

        # Emit intelligence if confidence is very low on a high-severity item
        packets: List[IntelligencePacket] = []
        if severity in ("critical", "high") and adjusted < 0.5:
            packets.append(
                IntelligencePacket(
                    packet_id=f"PKT-CONF-{decision_id}",
                    source_agent=self.agent_id,
                    target_agents=["all"],
                    intelligence_type=IntelligenceType.CORRELATION,
                    priority=Priority.HIGH,
                    confidence=adjusted * 100,
                    timestamp=datetime.now(timezone.utc),
                    data={
                        "decision_id": decision_id,
                        "adjusted_confidence": adjusted,
                        "recommended_tier": recommended_tier,
                        "reason": "low_confidence_high_severity",
                    },
                    correlation_keys=[decision_id, model_id],
                )
            )

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "decision_id": decision_id,
                "raw_confidence": round(overall, 4),
                "adjusted_confidence": round(adjusted, 4),
                "confidence_interval": [round(lower_bound, 4), round(upper_bound, 4)],
                "factors": factors,
                "bias_metrics": {
                    "bias_risk": bias_risk,
                    "fairness_score": fairness_score,
                },
                "recommended_tier": recommended_tier,
                "tier_label": ["autonomous", "assisted", "supervised", "collaborative"][recommended_tier],
                "calibration_sample_size": len(self.calibration_history),
            },
            intelligence_packets=packets,
        )

    # =========================================================================
    # calibrate_confidence
    # =========================================================================

    async def _calibrate_confidence(self, params: Dict[str, Any]) -> SkillResult:
        """Recalibrate scoring based on actual decision outcomes."""
        outcomes = params.get("outcomes", [])
        # outcomes: [{"decision_id": "...", "predicted_confidence": 0.85, "actual_correct": true}]

        if not outcomes:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=["'outcomes' list is required and must not be empty"],
            )

        # Bucket by confidence decile and compute calibration error
        buckets: Dict[int, Dict[str, Any]] = {}
        for o in outcomes:
            conf = o.get("predicted_confidence", 0.5)
            correct = 1.0 if o.get("actual_correct", False) else 0.0
            decile = min(int(conf * 10), 9)
            if decile not in buckets:
                buckets[decile] = {"total": 0, "correct": 0.0, "sum_confidence": 0.0}
            buckets[decile]["total"] += 1
            buckets[decile]["correct"] += correct
            buckets[decile]["sum_confidence"] += conf

            # Track per-decision
            self.decision_outcomes[o.get("decision_id", "unknown")].append({
                "predicted": conf,
                "actual_correct": o.get("actual_correct", False),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        calibration_bins = []
        total_ece = 0.0
        total_samples = sum(b["total"] for b in buckets.values())

        for decile in sorted(buckets.keys()):
            b = buckets[decile]
            avg_conf = b["sum_confidence"] / b["total"]
            accuracy = b["correct"] / b["total"]
            bin_ece = abs(avg_conf - accuracy) * (b["total"] / total_samples)
            total_ece += bin_ece
            calibration_bins.append({
                "decile": decile,
                "sample_count": b["total"],
                "avg_confidence": round(avg_conf, 4),
                "actual_accuracy": round(accuracy, 4),
                "bin_calibration_error": round(bin_ece, 4),
            })

        calibration_quality = "good" if total_ece < 0.05 else ("fair" if total_ece < 0.10 else "poor")

        # Suggest weight adjustments if calibration is poor
        recommendations = []
        if calibration_quality == "poor":
            recommendations.append("Consider increasing evidence_quality weight to improve grounding")
            recommendations.append("Review high-confidence false positives for pattern_match bias")
        elif calibration_quality == "fair":
            recommendations.append("Monitor calibration over next 100 decisions for trends")

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "total_outcomes_processed": len(outcomes),
                "expected_calibration_error": round(total_ece, 4),
                "calibration_quality": calibration_quality,
                "calibration_bins": calibration_bins,
                "current_factor_weights": self.factor_weights,
                "recommendations": recommendations,
            },
        )

    # =========================================================================
    # get_confidence_history
    # =========================================================================

    async def _get_confidence_history(self, params: Dict[str, Any]) -> SkillResult:
        """Retrieve confidence scoring history with optional filters."""
        limit = params.get("limit", 50)
        model_filter = params.get("model_id")
        since = params.get("since")  # ISO date string

        history = list(self.calibration_history)

        if model_filter:
            history = [h for h in history if h.get("model_id") == model_filter]

        if since:
            try:
                cutoff = datetime.fromisoformat(since)
                history = [
                    h for h in history
                    if datetime.fromisoformat(h["timestamp"]) >= cutoff
                ]
            except (ValueError, KeyError):
                pass

        # Compute summary statistics
        confidences = [h["adjusted_confidence"] for h in history]
        avg_conf = sum(confidences) / len(confidences) if confidences else 0.0
        tier_distribution: Dict[int, int] = defaultdict(int)
        for h in history:
            tier_distribution[h.get("recommended_tier", 3)] += 1

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "total_records": len(history),
                "returned": min(limit, len(history)),
                "history": history[-limit:],
                "summary": {
                    "average_confidence": round(avg_conf, 4),
                    "min_confidence": round(min(confidences), 4) if confidences else 0.0,
                    "max_confidence": round(max(confidences), 4) if confidences else 0.0,
                    "tier_distribution": dict(tier_distribution),
                },
            },
        )

    # =========================================================================
    # compare_models
    # =========================================================================

    async def _compare_models(self, params: Dict[str, Any]) -> SkillResult:
        """Compare confidence distributions across AI model providers."""
        model_ids = params.get("model_ids", list(self.model_scores.keys()))

        if not model_ids:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=["No model data available. Score some decisions first."],
            )

        comparison = []
        for mid in model_ids:
            scores = self.model_scores.get(mid, [])
            if not scores:
                comparison.append({"model_id": mid, "sample_count": 0})
                continue
            avg = sum(scores) / len(scores)
            variance = sum((s - avg) ** 2 for s in scores) / len(scores)
            comparison.append({
                "model_id": mid,
                "sample_count": len(scores),
                "average_confidence": round(avg, 4),
                "std_dev": round(variance ** 0.5, 4),
                "min_confidence": round(min(scores), 4),
                "max_confidence": round(max(scores), 4),
            })

        # Rank by average confidence (descending)
        comparison.sort(key=lambda c: c.get("average_confidence", 0), reverse=True)

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "models_compared": len(comparison),
                "comparison": comparison,
                "recommendation": (
                    comparison[0]["model_id"] if comparison and comparison[0].get("sample_count", 0) > 0
                    else "insufficient_data"
                ),
            },
        )

    # =========================================================================
    # set_threshold
    # =========================================================================

    async def _set_threshold(self, params: Dict[str, Any]) -> SkillResult:
        """Update autonomy-tier confidence thresholds."""
        tier = params.get("tier")
        value = params.get("value")

        if tier is None or value is None:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=["Both 'tier' (str) and 'value' (float 0-1) are required"],
            )

        valid_tiers = list(self.thresholds.keys())
        if tier not in valid_tiers:
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=[f"Invalid tier '{tier}'. Valid: {valid_tiers}"],
            )

        if not (0.0 <= float(value) <= 1.0):
            return SkillResult(
                success=False,
                skill_name=self.SKILL_NAME,
                agent_id=self.agent_id,
                errors=["Threshold value must be between 0.0 and 1.0"],
            )

        previous = self.thresholds[tier]
        self.thresholds[tier] = float(value)

        return SkillResult(
            success=True,
            skill_name=self.SKILL_NAME,
            agent_id=self.agent_id,
            data={
                "tier": tier,
                "previous_value": previous,
                "new_value": float(value),
                "all_thresholds": dict(self.thresholds),
            },
        )

    # =========================================================================
    # Internal scoring helpers (mirrors ConfidenceEngine logic)
    # =========================================================================

    def _assess_evidence_quality(self, evidence: Dict[str, Any]) -> float:
        """Assess quality and completeness of evidence."""
        if not evidence:
            return 0.2

        required = ["source_ip", "destination_ip", "timestamp", "event_type"]
        present = sum(1 for f in required if f in evidence)
        completeness = present / len(required)

        richness = min(len(evidence) / 10, 1.0)

        # Consistency heuristic: penalise contradictory severity/risk pairs
        consistency = 1.0
        if "severity" in evidence and "risk_level" in evidence:
            sev = str(evidence["severity"]).lower()
            risk = str(evidence["risk_level"]).lower()
            if (sev == "critical" and risk == "low") or (sev == "low" and risk == "critical"):
                consistency = 0.4

        return completeness * 0.4 + richness * 0.3 + consistency * 0.3

    def _assess_pattern_match(self, analysis: Dict[str, Any], severity: str) -> float:
        """Assess similarity to known historical patterns."""
        category = analysis.get("category", "investigation_required")
        reasoning = analysis.get("reasoning_chain", [])

        # Base score from category-severity alignment
        expected = {
            "critical": ["containment_required", "novel_threat"],
            "high": ["containment_required", "investigation_required", "novel_threat"],
            "medium": ["investigation_required", "containment_required"],
            "low": ["false_positive", "investigation_required"],
        }
        alignment = 0.8 if category in expected.get(severity, []) else 0.4

        # Boost if reasoning is substantive
        if len(reasoning) >= 3:
            alignment = min(alignment + 0.15, 1.0)

        return alignment

    def _assess_context_alignment(self, analysis: Dict[str, Any], severity: str) -> float:
        """Assess alignment between alert context and AI analysis."""
        category = analysis.get("category", "investigation_required")
        reasoning = analysis.get("reasoning_chain", [])

        severity_score = 1.0 if category in {
            "critical": "containment_required",
            "high": "investigation_required",
            "medium": "investigation_required",
            "low": "false_positive",
        }.get(severity, "investigation_required") else 0.5

        # Check reasoning references evidence
        reasoning_text = " ".join(reasoning).lower()
        evidence_words = ["evidence", "log", "data", "source", "indicates", "shows"]
        citation_count = sum(1 for w in evidence_words if w in reasoning_text)
        evidence_score = min(citation_count / 4, 1.0)

        return severity_score * 0.5 + evidence_score * 0.5

    def _assess_model_uncertainty(self, analysis: Dict[str, Any]) -> float:
        """Assess the model's reported uncertainty."""
        model_conf = analysis.get("confidence", 0.5)
        reasoning = analysis.get("reasoning_chain", [])

        reasoning_quality = 0.2
        if reasoning:
            chain_len = len(reasoning)
            if 2 <= chain_len <= 8:
                reasoning_quality = 0.7
            elif chain_len <= 10:
                reasoning_quality = 0.5
            else:
                reasoning_quality = 0.3

        return model_conf * 0.7 + reasoning_quality * 0.3

    def _assess_cross_validation(self, analysis: Dict[str, Any]) -> float:
        """Assess internal consistency of the analysis."""
        confidence = analysis.get("confidence", 0.5)
        category = analysis.get("category", "investigation_required")

        expected_ranges = {
            "false_positive": (0.7, 1.0),
            "investigation_required": (0.3, 0.8),
            "containment_required": (0.6, 1.0),
            "novel_threat": (0.4, 0.9),
        }
        lo, hi = expected_ranges.get(category, (0.0, 1.0))
        if lo <= confidence <= hi:
            return 0.9
        deviation = max(lo - confidence, confidence - hi, 0)
        return max(0.0, 0.9 - deviation * 2)
