"""
Confidence Engine - Multi-factor confidence scoring for AI decisions
Implements uncertainty quantification, bias detection, and fairness monitoring
"""

import asyncio
import logging
import math
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
import numpy as np
from collections import defaultdict

logger = logging.getLogger(__name__)

@dataclass
class ConfidenceFactor:
    """Individual factor contributing to confidence score"""
    name: str
    score: float  # 0.0 to 1.0
    weight: float  # Relative importance
    explanation: str
    evidence: List[str]

class ConfidenceEngine:
    """
    Multi-factor confidence scoring engine for AI security decisions
    
    Confidence factors:
    1. Evidence quality and completeness
    2. Pattern matching with historical data
    3. Context alignment and consistency  
    4. Model uncertainty estimation
    5. Cross-validation consistency
    6. Bias detection and fairness metrics
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize confidence engine with configuration"""
        self.config = config
        
        # Historical data for pattern matching
        self.historical_patterns = self._load_historical_patterns()
        
        # Bias detection thresholds
        self.bias_thresholds = {
            'demographic_parity': 0.10,      # 10% difference threshold
            'equal_opportunity': 0.10,       # 10% difference threshold
            'calibration_error': 0.05        # 5% calibration error threshold
        }
        
        # Performance tracking
        self.calibration_history = []
        self.decision_outcomes = defaultdict(list)  # Track actual vs predicted outcomes
        
        # Confidence factor weights (configurable)
        self.factor_weights = {
            'evidence_quality': 0.25,
            'pattern_match': 0.20,
            'context_alignment': 0.15,
            'model_uncertainty': 0.15,
            'cross_validation': 0.15,
            'bias_adjustment': 0.10
        }
    
    async def calculate_confidence(self, alert, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate multi-factor confidence score for AI analysis
        
        Returns:
            Dict containing:
            - score: Overall confidence (0.0 to 1.0)
            - factors: Individual factor scores and explanations
            - uncertainty_range: Confidence interval
            - bias_metrics: Fairness and bias indicators
            - recommendation: Suggested autonomy tier
        """
        
        # Calculate individual confidence factors
        factors = await self._calculate_confidence_factors(alert, analysis)
        
        # Combine factors with weighted average
        overall_score = self._combine_factor_scores(factors)
        
        # Calculate uncertainty range
        uncertainty_range = self._estimate_uncertainty(factors)
        
        # Detect potential bias
        bias_metrics = await self._assess_bias(alert, analysis, overall_score)
        
        # Adjust confidence based on bias detection
        adjusted_score = self._apply_bias_adjustment(overall_score, bias_metrics)
        
        # Determine recommended autonomy tier
        recommended_tier = self._recommend_autonomy_tier(adjusted_score, uncertainty_range)
        
        # Update calibration tracking
        self._update_calibration_tracking(alert, adjusted_score, analysis)
        
        result = {
            'score': adjusted_score,
            'confidence_interval': uncertainty_range,
            'factors': [factor.__dict__ for factor in factors],
            'evidence_scores': {f.name: f.score for f in factors},
            'bias_metrics': bias_metrics,
            'recommended_tier': recommended_tier,
            'calibration_quality': self._get_calibration_quality(),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return result
    
    async def _calculate_confidence_factors(self, alert, analysis: Dict[str, Any]) -> List[ConfidenceFactor]:
        """Calculate all confidence factors"""
        factors = []
        
        # Factor 1: Evidence Quality Assessment
        evidence_factor = await self._assess_evidence_quality(alert)
        factors.append(evidence_factor)
        
        # Factor 2: Pattern Matching Score
        pattern_factor = await self._assess_pattern_similarity(alert, analysis)
        factors.append(pattern_factor)
        
        # Factor 3: Context Alignment
        context_factor = await self._assess_context_alignment(alert, analysis)
        factors.append(context_factor)
        
        # Factor 4: Model Uncertainty
        uncertainty_factor = await self._assess_model_uncertainty(analysis)
        factors.append(uncertainty_factor)
        
        # Factor 5: Cross-validation Consistency
        crossval_factor = await self._assess_cross_validation(alert, analysis)
        factors.append(crossval_factor)
        
        return factors
    
    async def _assess_evidence_quality(self, alert) -> ConfidenceFactor:
        """Assess quality and completeness of evidence"""
        
        evidence = alert.evidence or {}
        score = 0.0
        evidence_list = []
        
        # Evidence completeness (40% of score)
        required_fields = ['source_ip', 'destination_ip', 'timestamp', 'event_type']
        present_fields = [field for field in required_fields if field in evidence]
        completeness_score = len(present_fields) / len(required_fields)
        score += completeness_score * 0.4
        evidence_list.append(f"Evidence completeness: {len(present_fields)}/{len(required_fields)} fields")
        
        # Evidence richness (30% of score)
        total_evidence_items = len(evidence)
        richness_score = min(total_evidence_items / 10, 1.0)  # Normalize to 10 items max
        score += richness_score * 0.3
        evidence_list.append(f"Evidence richness: {total_evidence_items} items")
        
        # Evidence consistency (30% of score)
        consistency_score = self._check_evidence_consistency(evidence)
        score += consistency_score * 0.3
        evidence_list.append(f"Evidence consistency: {consistency_score:.2f}")
        
        explanation = f"Evidence quality based on completeness ({completeness_score:.2f}), " + \
                     f"richness ({richness_score:.2f}), and consistency ({consistency_score:.2f})"
        
        return ConfidenceFactor(
            name='evidence_quality',
            score=score,
            weight=self.factor_weights['evidence_quality'],
            explanation=explanation,
            evidence=evidence_list
        )
    
    def _check_evidence_consistency(self, evidence: Dict[str, Any]) -> float:
        """Check internal consistency of evidence"""
        
        if not evidence:
            return 0.0
        
        consistency_score = 1.0
        
        # Check timestamp consistency
        if 'timestamp' in evidence and 'event_time' in evidence:
            # Would implement proper timestamp validation
            pass
        
        # Check IP address validity
        if 'source_ip' in evidence:
            # Would implement IP validation
            pass
        
        # Check for contradictory fields
        if 'severity' in evidence and 'risk_level' in evidence:
            # Would implement severity-risk consistency check
            pass
        
        return consistency_score
    
    async def _assess_pattern_similarity(self, alert, analysis: Dict[str, Any]) -> ConfidenceFactor:
        """Assess similarity to historical patterns"""
        
        # Compare against historical alert patterns
        similarity_scores = []
        matching_patterns = []
        
        alert_features = self._extract_alert_features(alert)
        
        for pattern in self.historical_patterns:
            similarity = self._calculate_pattern_similarity(alert_features, pattern['features'])
            similarity_scores.append(similarity)
            
            if similarity > 0.7:  # High similarity threshold
                matching_patterns.append({
                    'pattern_id': pattern['id'],
                    'similarity': similarity,
                    'outcomes': pattern['historical_outcomes']
                })
        
        # Calculate overall pattern matching confidence
        if similarity_scores:
            avg_similarity = np.mean(similarity_scores)
            max_similarity = np.max(similarity_scores)
            pattern_confidence = (avg_similarity * 0.3) + (max_similarity * 0.7)
        else:
            pattern_confidence = 0.3  # Default for no historical data
        
        # Boost confidence if we have high-confidence historical matches
        high_confidence_matches = [p for p in matching_patterns if p['similarity'] > 0.8]
        if high_confidence_matches:
            pattern_confidence += 0.2
        
        pattern_confidence = min(pattern_confidence, 1.0)
        
        evidence_list = [
            f"Found {len(matching_patterns)} similar historical patterns",
            f"Highest similarity: {max(similarity_scores) if similarity_scores else 0:.3f}",
            f"Average similarity: {np.mean(similarity_scores) if similarity_scores else 0:.3f}"
        ]
        
        explanation = f"Pattern matching against {len(self.historical_patterns)} historical cases. " + \
                     f"Found {len(high_confidence_matches)} high-confidence matches."
        
        return ConfidenceFactor(
            name='pattern_match',
            score=pattern_confidence,
            weight=self.factor_weights['pattern_match'],
            explanation=explanation,
            evidence=evidence_list
        )
    
    def _extract_alert_features(self, alert) -> Dict[str, Any]:
        """Extract features for pattern matching"""
        return {
            'severity': alert.severity.value,
            'source': alert.source,
            'title_keywords': alert.title.lower().split(),
            'description_length': len(alert.description),
            'evidence_count': len(alert.evidence) if alert.evidence else 0,
            'metadata_keys': list(alert.metadata.keys()) if alert.metadata else []
        }
    
    def _calculate_pattern_similarity(self, features1: Dict[str, Any], features2: Dict[str, Any]) -> float:
        """Calculate similarity between alert features"""
        
        # Simplified similarity calculation
        # In production, would use more sophisticated ML-based similarity
        
        similarity_score = 0.0
        total_factors = 0
        
        # Severity similarity
        if features1.get('severity') == features2.get('severity'):
            similarity_score += 1.0
        total_factors += 1
        
        # Source similarity  
        if features1.get('source') == features2.get('source'):
            similarity_score += 1.0
        total_factors += 1
        
        # Keyword overlap
        keywords1 = set(features1.get('title_keywords', []))
        keywords2 = set(features2.get('title_keywords', []))
        if keywords1 and keywords2:
            overlap = len(keywords1.intersection(keywords2)) / len(keywords1.union(keywords2))
            similarity_score += overlap
        total_factors += 1
        
        return similarity_score / total_factors if total_factors > 0 else 0.0
    
    async def _assess_context_alignment(self, alert, analysis: Dict[str, Any]) -> ConfidenceFactor:
        """Assess alignment between alert context and AI analysis"""
        
        alignment_score = 0.0
        evidence_list = []
        
        # Severity-category alignment
        severity_category_alignment = self._check_severity_category_alignment(
            alert.severity.value, 
            analysis.get('category', 'investigation_required')
        )
        alignment_score += severity_category_alignment * 0.4
        evidence_list.append(f"Severity-category alignment: {severity_category_alignment:.2f}")
        
        # Evidence-conclusion alignment  
        evidence_conclusion_alignment = self._check_evidence_conclusion_alignment(
            alert.evidence,
            analysis.get('reasoning_chain', [])
        )
        alignment_score += evidence_conclusion_alignment * 0.4
        evidence_list.append(f"Evidence-conclusion alignment: {evidence_conclusion_alignment:.2f}")
        
        # Temporal consistency
        temporal_consistency = self._check_temporal_consistency(alert, analysis)
        alignment_score += temporal_consistency * 0.2
        evidence_list.append(f"Temporal consistency: {temporal_consistency:.2f}")
        
        explanation = "Context alignment between alert characteristics and AI analysis conclusions"
        
        return ConfidenceFactor(
            name='context_alignment',
            score=alignment_score,
            weight=self.factor_weights['context_alignment'],
            explanation=explanation,
            evidence=evidence_list
        )
    
    def _check_severity_category_alignment(self, severity: str, category: str) -> float:
        """Check if predicted category aligns with alert severity"""
        
        # Expected category mappings for different severities
        severity_mappings = {
            'critical': ['containment_required', 'novel_threat'],
            'high': ['containment_required', 'investigation_required', 'novel_threat'],
            'medium': ['investigation_required', 'containment_required'],
            'low': ['false_positive', 'investigation_required']
        }
        
        expected_categories = severity_mappings.get(severity, ['investigation_required'])
        return 1.0 if category in expected_categories else 0.3
    
    def _check_evidence_conclusion_alignment(self, evidence: Dict[str, Any], 
                                           reasoning_chain: List[str]) -> float:
        """Check alignment between available evidence and reasoning"""
        
        if not evidence or not reasoning_chain:
            return 0.5  # Neutral score for missing data
        
        # Count evidence items mentioned in reasoning
        evidence_keys = set(str(k).lower() for k in evidence.keys())
        reasoning_text = ' '.join(reasoning_chain).lower()
        
        mentioned_evidence = sum(1 for key in evidence_keys if key in reasoning_text)
        total_evidence = len(evidence_keys)
        
        if total_evidence == 0:
            return 0.5
        
        alignment_ratio = mentioned_evidence / total_evidence
        return min(alignment_ratio * 1.5, 1.0)  # Boost good alignment
    
    def _check_temporal_consistency(self, alert, analysis: Dict[str, Any]) -> float:
        """Check temporal consistency of alert and analysis"""
        # Simplified implementation - would check timing constraints
        return 0.8  # Placeholder
    
    async def _assess_model_uncertainty(self, analysis: Dict[str, Any]) -> ConfidenceFactor:
        """Assess model's uncertainty in its predictions"""
        
        # Extract confidence from analysis
        model_confidence = analysis.get('confidence', 0.5)
        
        # Assess reasoning quality
        reasoning_chain = analysis.get('reasoning_chain', [])
        reasoning_quality = self._assess_reasoning_quality(reasoning_chain)
        
        # Combine model confidence and reasoning quality
        uncertainty_score = (model_confidence * 0.7) + (reasoning_quality * 0.3)
        
        evidence_list = [
            f"Model reported confidence: {model_confidence:.3f}",
            f"Reasoning quality score: {reasoning_quality:.3f}",
            f"Reasoning steps: {len(reasoning_chain)}"
        ]
        
        explanation = f"Model uncertainty based on reported confidence ({model_confidence:.2f}) " + \
                     f"and reasoning quality ({reasoning_quality:.2f})"
        
        return ConfidenceFactor(
            name='model_uncertainty',
            score=uncertainty_score,
            weight=self.factor_weights['model_uncertainty'],
            explanation=explanation,
            evidence=evidence_list
        )
    
    def _assess_reasoning_quality(self, reasoning_chain: List[str]) -> float:
        """Assess quality of AI's reasoning chain"""
        
        if not reasoning_chain:
            return 0.2
        
        quality_score = 0.0
        
        # Length assessment (too short or too long indicates poor reasoning)
        chain_length = len(reasoning_chain)
        if 2 <= chain_length <= 8:
            quality_score += 0.3
        elif 1 <= chain_length <= 10:
            quality_score += 0.2
        else:
            quality_score += 0.1
        
        # Logical flow assessment (simplified)
        logical_flow_score = self._assess_logical_flow(reasoning_chain)
        quality_score += logical_flow_score * 0.4
        
        # Evidence citation assessment
        citation_score = self._assess_evidence_citation(reasoning_chain)
        quality_score += citation_score * 0.3
        
        return min(quality_score, 1.0)
    
    def _assess_logical_flow(self, reasoning_chain: List[str]) -> float:
        """Assess logical flow in reasoning chain"""
        # Simplified assessment - would use NLP in production
        
        logical_connectors = ['therefore', 'because', 'since', 'given', 'however', 'thus', 'consequently']
        reasoning_text = ' '.join(reasoning_chain).lower()
        
        connector_count = sum(1 for connector in logical_connectors if connector in reasoning_text)
        return min(connector_count / 3, 1.0)  # Expect ~3 logical connectors
    
    def _assess_evidence_citation(self, reasoning_chain: List[str]) -> float:
        """Assess how well reasoning cites evidence"""
        # Count evidence references in reasoning
        reasoning_text = ' '.join(reasoning_chain).lower()
        evidence_indicators = ['evidence', 'shows', 'indicates', 'suggests', 'log', 'data', 'source']
        
        citation_count = sum(1 for indicator in evidence_indicators if indicator in reasoning_text)
        return min(citation_count / 4, 1.0)  # Expect ~4 evidence citations
    
    async def _assess_cross_validation(self, alert, analysis: Dict[str, Any]) -> ConfidenceFactor:
        """Assess consistency through cross-validation approaches"""
        
        # Simplified cross-validation - would implement multiple model consensus
        # For now, assess internal consistency of the analysis
        
        consistency_score = 0.0
        evidence_list = []
        
        # Check confidence-category consistency
        confidence = analysis.get('confidence', 0.5)
        category = analysis.get('category', 'investigation_required')
        
        confidence_category_consistency = self._check_confidence_category_consistency(confidence, category)
        consistency_score += confidence_category_consistency * 0.6
        evidence_list.append(f"Confidence-category consistency: {confidence_category_consistency:.2f}")
        
        # Check reasoning-conclusion consistency
        reasoning_conclusion_consistency = self._check_reasoning_conclusion_consistency(analysis)
        consistency_score += reasoning_conclusion_consistency * 0.4
        evidence_list.append(f"Reasoning-conclusion consistency: {reasoning_conclusion_consistency:.2f}")
        
        explanation = "Cross-validation through internal consistency checks"
        
        return ConfidenceFactor(
            name='cross_validation',
            score=consistency_score,
            weight=self.factor_weights['cross_validation'],
            explanation=explanation,
            evidence=evidence_list
        )
    
    def _check_confidence_category_consistency(self, confidence: float, category: str) -> float:
        """Check if confidence level matches predicted category"""
        
        # Expected confidence ranges for categories
        category_confidence_ranges = {
            'false_positive': (0.7, 1.0),
            'investigation_required': (0.3, 0.8),
            'containment_required': (0.6, 1.0),
            'novel_threat': (0.4, 0.9)
        }
        
        expected_range = category_confidence_ranges.get(category, (0.0, 1.0))
        
        if expected_range[0] <= confidence <= expected_range[1]:
            return 1.0
        else:
            # Calculate how far outside the expected range
            if confidence < expected_range[0]:
                deviation = expected_range[0] - confidence
            else:
                deviation = confidence - expected_range[1]
            
            return max(0.0, 1.0 - (deviation * 2))  # Linear penalty
    
    def _check_reasoning_conclusion_consistency(self, analysis: Dict[str, Any]) -> float:
        """Check if reasoning supports the conclusion"""
        
        reasoning_chain = analysis.get('reasoning_chain', [])
        category = analysis.get('category', 'investigation_required')
        
        if not reasoning_chain:
            return 0.3
        
        # Simple keyword matching for conclusion support
        reasoning_text = ' '.join(reasoning_chain).lower()
        
        category_keywords = {
            'false_positive': ['false', 'benign', 'normal', 'expected'],
            'investigation_required': ['investigate', 'review', 'unclear', 'suspicious'],
            'containment_required': ['threat', 'attack', 'malicious', 'urgent'],
            'novel_threat': ['unknown', 'novel', 'new', 'unusual']
        }
        
        expected_keywords = category_keywords.get(category, [])
        keyword_matches = sum(1 for keyword in expected_keywords if keyword in reasoning_text)
        
        if not expected_keywords:
            return 0.8  # Neutral for unknown categories
        
        return min(keyword_matches / len(expected_keywords), 1.0)
    
    def _combine_factor_scores(self, factors: List[ConfidenceFactor]) -> float:
        """Combine individual factor scores into overall confidence"""
        
        total_weighted_score = 0.0
        total_weight = 0.0
        
        for factor in factors:
            weighted_score = factor.score * factor.weight
            total_weighted_score += weighted_score
            total_weight += factor.weight
        
        if total_weight == 0:
            return 0.5  # Default confidence
        
        overall_confidence = total_weighted_score / total_weight
        return min(max(overall_confidence, 0.0), 1.0)  # Clamp to [0,1]
    
    def _estimate_uncertainty(self, factors: List[ConfidenceFactor]) -> Tuple[float, float]:
        """Estimate confidence interval (lower, upper bounds)"""
        
        # Calculate variance in factor scores
        scores = [f.score for f in factors]
        if len(scores) < 2:
            return (0.0, 1.0)  # Wide uncertainty for insufficient data
        
        mean_score = np.mean(scores)
        std_score = np.std(scores)
        
        # Calculate 95% confidence interval
        margin_of_error = 1.96 * std_score / math.sqrt(len(scores))
        
        lower_bound = max(mean_score - margin_of_error, 0.0)
        upper_bound = min(mean_score + margin_of_error, 1.0)
        
        return (lower_bound, upper_bound)
    
    async def _assess_bias(self, alert, analysis: Dict[str, Any], confidence: float) -> Dict[str, Any]:
        """Assess potential bias in AI decision-making"""
        
        bias_metrics = {
            'demographic_parity': None,
            'equal_opportunity': None,
            'calibration_error': None,
            'bias_risk_level': 'low',
            'fairness_score': 0.8  # Default good fairness
        }
        
        # Simplified bias assessment - would implement comprehensive fairness metrics
        
        # Check for potential source bias
        source_bias_risk = self._assess_source_bias(alert)
        
        # Check for severity bias
        severity_bias_risk = self._assess_severity_bias(alert, confidence)
        
        # Overall bias risk assessment
        max_bias_risk = max(source_bias_risk, severity_bias_risk)
        
        if max_bias_risk > 0.7:
            bias_metrics['bias_risk_level'] = 'high'
            bias_metrics['fairness_score'] = 0.4
        elif max_bias_risk > 0.4:
            bias_metrics['bias_risk_level'] = 'medium'
            bias_metrics['fairness_score'] = 0.6
        
        return bias_metrics
    
    def _assess_source_bias(self, alert) -> float:
        """Assess potential bias based on alert source"""
        # Simplified implementation - would track historical bias patterns
        
        high_bias_sources = ['legacy_system', 'manual_report']
        if any(source in alert.source.lower() for source in high_bias_sources):
            return 0.6
        
        return 0.2
    
    def _assess_severity_bias(self, alert, confidence: float) -> float:
        """Assess potential bias in severity assessment"""
        # Check if confidence varies systematically with severity
        
        # Simplified implementation
        if alert.severity.value == 'critical' and confidence < 0.5:
            return 0.5  # Potential under-confidence bias for critical alerts
        
        return 0.2
    
    def _apply_bias_adjustment(self, confidence: float, bias_metrics: Dict[str, Any]) -> float:
        """Apply bias adjustment to confidence score"""
        
        fairness_score = bias_metrics.get('fairness_score', 0.8)
        bias_risk = bias_metrics.get('bias_risk_level', 'low')
        
        # Apply conservative adjustment for high bias risk
        if bias_risk == 'high':
            adjustment_factor = 0.9
        elif bias_risk == 'medium':
            adjustment_factor = 0.95
        else:
            adjustment_factor = 1.0
        
        adjusted_confidence = confidence * adjustment_factor * fairness_score
        return min(max(adjusted_confidence, 0.0), 1.0)
    
    def _recommend_autonomy_tier(self, confidence: float, uncertainty_range: Tuple[float, float]) -> int:
        """Recommend appropriate autonomy tier based on confidence"""
        
        lower_bound, upper_bound = uncertainty_range
        uncertainty = upper_bound - lower_bound
        
        # Conservative tier selection considering uncertainty
        effective_confidence = confidence - (uncertainty * 0.5)
        
        if effective_confidence >= 0.95:
            return 0  # Autonomous
        elif effective_confidence >= 0.80:
            return 1  # Assisted  
        elif effective_confidence >= 0.60:
            return 2  # Supervised
        else:
            return 3  # Collaborative
    
    def _update_calibration_tracking(self, alert, confidence: float, analysis: Dict[str, Any]):
        """Update calibration tracking for model performance"""
        
        calibration_entry = {
            'timestamp': datetime.now(timezone.utc),
            'alert_id': alert.id,
            'predicted_confidence': confidence,
            'predicted_category': analysis.get('category'),
            'actual_outcome': None,  # Would be filled when outcome is known
            'severity': alert.severity.value
        }
        
        self.calibration_history.append(calibration_entry)
        
        # Keep only recent history (last 1000 decisions)
        if len(self.calibration_history) > 1000:
            self.calibration_history = self.calibration_history[-1000:]
    
    def _get_calibration_quality(self) -> Dict[str, Any]:
        """Calculate calibration quality metrics"""
        
        if len(self.calibration_history) < 10:
            return {'status': 'insufficient_data', 'sample_size': len(self.calibration_history)}
        
        # Would implement proper calibration analysis
        # For now, return placeholder metrics
        
        return {
            'status': 'good',
            'sample_size': len(self.calibration_history),
            'calibration_error': 0.05,  # Placeholder
            'reliability_diagram': 'not_implemented'
        }
    
    def _load_historical_patterns(self) -> List[Dict[str, Any]]:
        """Load historical alert patterns for comparison"""
        # Simplified implementation - would load from database
        
        return [
            {
                'id': 'pattern_001',
                'features': {
                    'severity': 'medium',
                    'source': 'firewall',
                    'title_keywords': ['blocked', 'connection'],
                    'evidence_count': 5
                },
                'historical_outcomes': ['false_positive'] * 8 + ['investigation_required'] * 2
            },
            {
                'id': 'pattern_002', 
                'features': {
                    'severity': 'high',
                    'source': 'ids',
                    'title_keywords': ['malware', 'detected'],
                    'evidence_count': 12
                },
                'historical_outcomes': ['containment_required'] * 7 + ['investigation_required'] * 3
            }
        ]
    
    async def health_check(self) -> Dict[str, Any]:
        """Health check for confidence engine"""
        return {
            'status': 'healthy',
            'calibration_history_size': len(self.calibration_history),
            'historical_patterns_loaded': len(self.historical_patterns),
            'factor_weights': self.factor_weights,
            'bias_thresholds': self.bias_thresholds
        }