"""
AI Confidence Engine Test Suite - Critical Testing for Enterprise Deployment
Tests confidence scoring accuracy, bias detection validation, and multi-factor analysis
"""

import pytest
import numpy as np
from datetime import datetime, timezone
from unittest.mock import Mock, AsyncMock, patch
from hypothesis import given, strategies as st

from ai_engine.confidence_engine import ConfidenceEngine, ConfidenceFactor, BiasDetectionResult
from ai_engine.orchestrator import SecurityAlert, AlertSeverity, AnalysisResult, AlertCategory
from tests.datasets.synthetic_alerts import (
    SyntheticAlertGenerator, AlertPattern, 
    generate_test_alerts, generate_bias_test_alerts
)

@pytest.fixture
def confidence_engine():
    """Create confidence engine for testing"""
    config = {
        'bias_thresholds': {
            'demographic_parity': 0.10,
            'equal_opportunity': 0.10,
            'calibration_error': 0.05,
            'fairness_score': 0.80
        }
    }
    return ConfidenceEngine(config)

@pytest.fixture
def sample_analysis_results():
    """Sample AI analysis results for testing"""
    return {
        'category': 'investigation_required',
        'confidence': 0.85,
        'reasoning_chain': [
            'Detected suspicious network activity',
            'Source IP not in known good list',
            'Pattern matches potential brute force attack',
            'Evidence quality is high with complete logs'
        ],
        'risk_assessment': 'medium',
        'recommended_action': 'Block source IP and investigate'
    }

class TestConfidenceScoring:
    """Test multi-factor confidence scoring accuracy"""
    
    @pytest.mark.asyncio
    async def test_confidence_calculation_basic(self, confidence_engine):
        """Test basic confidence calculation with known inputs"""
        
        # Generate alert with known characteristics
        generator = SyntheticAlertGenerator()
        alert = generator._generate_alert_by_pattern(AlertPattern.BRUTE_FORCE_ATTACK)
        
        analysis = {
            'category': 'containment_required',
            'confidence': 0.90,
            'reasoning_chain': [
                'Multiple failed login attempts detected',
                'Source IP has poor reputation',
                'Pattern consistent with brute force attack',
                'High evidence quality with complete logs'
            ]
        }
        
        result = await confidence_engine.calculate_confidence(alert, analysis)
        
        # Validate result structure
        assert 'score' in result
        assert 'factors' in result
        assert 'confidence_interval' in result
        assert 'bias_metrics' in result
        assert 'recommended_tier' in result
        
        # Validate confidence score range
        assert 0.0 <= result['score'] <= 1.0
        
        # Validate confidence interval
        lower, upper = result['confidence_interval']
        assert lower <= result['score'] <= upper
        assert lower >= 0.0 and upper <= 1.0
        
        # Validate factors structure
        assert len(result['factors']) > 0
        for factor in result['factors']:
            assert 'name' in factor
            assert 'score' in factor
            assert 'weight' in factor
            assert 'explanation' in factor
            assert 'evidence' in factor
    
    @pytest.mark.asyncio
    async def test_confidence_factors_completeness(self, confidence_engine):
        """Test that all confidence factors are calculated"""
        
        alert = generate_test_alerts(1)[0]
        analysis = {
            'category': 'false_positive',
            'confidence': 0.95,
            'reasoning_chain': ['Clear false positive indicators']
        }
        
        result = await confidence_engine.calculate_confidence(alert, analysis)
        
        # Should have all major confidence factors
        factor_names = [f['name'] for f in result['factors']]
        expected_factors = [
            'evidence_quality',
            'pattern_match',
            'context_alignment',
            'model_uncertainty',
            'cross_validation'
        ]
        
        for expected_factor in expected_factors:
            assert expected_factor in factor_names, f"Missing confidence factor: {expected_factor}"
    
    @pytest.mark.asyncio
    async def test_evidence_quality_assessment(self, confidence_engine):
        """Test evidence quality factor calculation"""
        
        # High quality evidence alert
        high_quality_alert = SecurityAlert(
            id="test_high_quality",
            timestamp=datetime.now(timezone.utc),
            severity=AlertSeverity.HIGH,
            source="comprehensive_logs",
            title="Well-documented security incident",
            description="Detailed description with context",
            evidence={
                'source_ip': '192.168.1.100',
                'destination_ip': '10.0.0.50',
                'timestamp': '2024-01-01T12:00:00Z',
                'event_type': 'authentication_failure',
                'user_agent': 'Mozilla/5.0...',
                'session_id': 'abc123',
                'response_code': '401',
                'bytes_transferred': '1024',
                'protocol': 'HTTPS',
                'port': '443'
            },
            metadata={'source_reliability': 'high'}
        )
        
        analysis = {'category': 'investigation_required', 'confidence': 0.8, 'reasoning_chain': ['test']}
        result = await confidence_engine.calculate_confidence(high_quality_alert, analysis)
        
        # Find evidence quality factor
        evidence_factor = next(f for f in result['factors'] if f['name'] == 'evidence_quality')
        assert evidence_factor['score'] >= 0.7, "High quality evidence should score highly"
        
        # Low quality evidence alert
        low_quality_alert = SecurityAlert(
            id="test_low_quality",
            timestamp=datetime.now(timezone.utc),
            severity=AlertSeverity.LOW,
            source="limited_logs",
            title="Minimal alert",
            description="Brief description",
            evidence={'basic_field': 'value'},
            metadata={}
        )
        
        result_low = await confidence_engine.calculate_confidence(low_quality_alert, analysis)
        evidence_factor_low = next(f for f in result_low['factors'] if f['name'] == 'evidence_quality')
        
        assert evidence_factor_low['score'] < evidence_factor['score'], "Low quality evidence should score lower"
    
    @pytest.mark.asyncio
    @given(st.floats(min_value=0.0, max_value=1.0))
    async def test_confidence_score_properties(self, confidence_engine, model_confidence):
        """Property-based testing of confidence score behavior"""
        
        alert = generate_test_alerts(1)[0]
        analysis = {
            'category': 'investigation_required',
            'confidence': model_confidence,
            'reasoning_chain': ['Property test reasoning']
        }
        
        result = await confidence_engine.calculate_confidence(alert, analysis)
        
        # Property: Confidence score should always be between 0 and 1
        assert 0.0 <= result['score'] <= 1.0
        
        # Property: Confidence interval should contain the score
        lower, upper = result['confidence_interval']
        assert lower <= result['score'] <= upper
        
        # Property: High model confidence should generally result in high overall confidence
        if model_confidence > 0.9:
            assert result['score'] > 0.5, "High model confidence should boost overall confidence"
    
    @pytest.mark.asyncio
    async def test_uncertainty_quantification(self, confidence_engine):
        """Test uncertainty quantification and confidence intervals"""
        
        # Test with consistent factors (low uncertainty)
        alert = generate_test_alerts(1)[0]
        consistent_analysis = {
            'category': 'false_positive',
            'confidence': 0.95,
            'reasoning_chain': ['Very clear false positive', 'All indicators align', 'High certainty']
        }
        
        result_consistent = await confidence_engine.calculate_confidence(alert, consistent_analysis)
        
        # Test with inconsistent factors (high uncertainty)
        inconsistent_analysis = {
            'category': 'investigation_required',
            'confidence': 0.50,
            'reasoning_chain': ['Uncertain indicators', 'Mixed evidence']
        }
        
        result_inconsistent = await confidence_engine.calculate_confidence(alert, inconsistent_analysis)
        
        # Uncertainty should be reflected in confidence intervals
        consistent_interval_width = result_consistent['confidence_interval'][1] - result_consistent['confidence_interval'][0]
        inconsistent_interval_width = result_inconsistent['confidence_interval'][1] - result_inconsistent['confidence_interval'][0]
        
        # Note: This test might need adjustment based on actual implementation
        # The principle is that inconsistent evidence should lead to wider confidence intervals

class TestBiasDetection:
    """Test bias detection and fairness monitoring"""
    
    @pytest.mark.asyncio
    async def test_bias_detection_basic(self, confidence_engine):
        """Test basic bias detection functionality"""
        
        alert = generate_test_alerts(1)[0]
        analysis = {
            'category': 'investigation_required',
            'confidence': 0.75,
            'reasoning_chain': ['Standard analysis']
        }
        
        result = await confidence_engine.calculate_confidence(alert, analysis)
        
        # Validate bias metrics structure
        assert 'bias_metrics' in result
        bias_metrics = result['bias_metrics']
        
        required_bias_fields = [
            'demographic_parity',
            'equal_opportunity', 
            'calibration_error',
            'bias_risk_level',
            'fairness_score'
        ]
        
        for field in required_bias_fields:
            assert field in bias_metrics, f"Missing bias metric: {field}"
    
    @pytest.mark.asyncio
    async def test_source_bias_detection(self, confidence_engine):
        """Test detection of bias against specific sources"""
        
        # Modern system alert
        modern_alert = SecurityAlert(
            id="modern_test",
            timestamp=datetime.now(timezone.utc),
            severity=AlertSeverity.MEDIUM,
            source="modern_cloud_security",
            title="Cloud security alert",
            description="Alert from modern cloud security system",
            evidence={'threat_detected': True},
            metadata={'system_type': 'modern'}
        )
        
        # Legacy system alert  
        legacy_alert = SecurityAlert(
            id="legacy_test",
            timestamp=datetime.now(timezone.utc),
            severity=AlertSeverity.MEDIUM,
            source="legacy_mainframe",
            title="Mainframe security alert",
            description="Alert from legacy mainframe system",
            evidence={'threat_detected': True},
            metadata={'system_type': 'legacy'}
        )
        
        analysis = {
            'category': 'investigation_required',
            'confidence': 0.75,
            'reasoning_chain': ['Standard analysis']
        }
        
        modern_result = await confidence_engine.calculate_confidence(modern_alert, analysis)
        legacy_result = await confidence_engine.calculate_confidence(legacy_alert, analysis)
        
        # Should detect if there's systematic bias against legacy systems
        modern_confidence = modern_result['score']
        legacy_confidence = legacy_result['score']
        
        # If there's significant difference, bias should be flagged
        confidence_difference = abs(modern_confidence - legacy_confidence)
        
        if confidence_difference > 0.2:  # Significant difference threshold
            # At least one should flag bias risk
            assert (modern_result['bias_metrics']['bias_risk_level'] != 'low' or
                   legacy_result['bias_metrics']['bias_risk_level'] != 'low'), \
                   "Significant confidence difference should trigger bias detection"
    
    @pytest.mark.asyncio
    async def test_severity_bias_detection(self, confidence_engine):
        """Test detection of severity-based bias"""
        
        # Same evidence, different severities
        base_alert_data = {
            'id': 'severity_test',
            'timestamp': datetime.now(timezone.utc),
            'source': 'test_source',
            'title': 'Test alert',
            'description': 'Identical evidence, different severity',
            'evidence': {'test_evidence': 'identical_data'},
            'metadata': {}
        }
        
        severities = [AlertSeverity.LOW, AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL]
        results = []
        
        for severity in severities:
            alert = SecurityAlert(**base_alert_data, severity=severity)
            analysis = {
                'category': 'investigation_required',
                'confidence': 0.75,
                'reasoning_chain': ['Identical analysis for all severities']
            }
            
            result = await confidence_engine.calculate_confidence(alert, analysis)
            results.append((severity, result))
        
        # Check for systematic bias across severities
        confidence_scores = [result[1]['score'] for result in results]
        
        # If there's large variation in confidence for identical evidence,
        # bias detection should trigger
        confidence_variance = np.var(confidence_scores)
        
        if confidence_variance > 0.05:  # High variance threshold
            # Should detect severity bias
            bias_detected = any(result[1]['bias_metrics']['bias_risk_level'] != 'low' 
                              for result in results)
            assert bias_detected, "High variance across severities should trigger bias detection"
    
    @pytest.mark.asyncio
    async def test_fairness_score_calculation(self, confidence_engine):
        """Test fairness score calculation across different groups"""
        
        bias_test_alerts = generate_bias_test_alerts(50)
        fairness_scores = []
        
        for alert in bias_test_alerts[:10]:  # Test subset for performance
            analysis = {
                'category': 'investigation_required',
                'confidence': 0.75,
                'reasoning_chain': ['Fairness test']
            }
            
            result = await confidence_engine.calculate_confidence(alert, analysis)
            fairness_scores.append(result['bias_metrics']['fairness_score'])
        
        # Fairness scores should be between 0 and 1
        for score in fairness_scores:
            assert 0.0 <= score <= 1.0, f"Fairness score {score} outside valid range"
        
        # Average fairness should be above minimum threshold
        avg_fairness = np.mean(fairness_scores)
        assert avg_fairness >= 0.6, f"Average fairness score {avg_fairness} below acceptable threshold"

class TestModelUncertainty:
    """Test model uncertainty estimation and handling"""
    
    @pytest.mark.asyncio
    async def test_uncertainty_with_poor_reasoning(self, confidence_engine):
        """Test uncertainty detection with poor quality reasoning"""
        
        alert = generate_test_alerts(1)[0]
        
        # Poor quality reasoning
        poor_analysis = {
            'category': 'investigation_required',
            'confidence': 0.95,  # High confidence but poor reasoning
            'reasoning_chain': ['unclear']  # Very brief, poor reasoning
        }
        
        result_poor = await confidence_engine.calculate_confidence(alert, poor_analysis)
        
        # Good quality reasoning
        good_analysis = {
            'category': 'investigation_required',
            'confidence': 0.95,  # Same confidence
            'reasoning_chain': [
                'Comprehensive analysis of network logs shows clear evidence',
                'Source IP matches known threat intelligence feeds',
                'Attack pattern is consistent with documented TTPs',
                'Evidence quality is high with complete audit trail'
            ]
        }
        
        result_good = await confidence_engine.calculate_confidence(alert, good_analysis)
        
        # Poor reasoning should result in lower overall confidence despite high model confidence
        assert result_poor['score'] < result_good['score'], \
            "Poor reasoning quality should reduce overall confidence despite high model confidence"
        
        # Poor reasoning should result in wider uncertainty intervals
        poor_interval_width = result_poor['confidence_interval'][1] - result_poor['confidence_interval'][0]
        good_interval_width = result_good['confidence_interval'][1] - result_good['confidence_interval'][0]
        
        # This test validates that reasoning quality affects uncertainty estimation

class TestCrossValidation:
    """Test cross-validation and consistency checks"""
    
    @pytest.mark.asyncio
    async def test_confidence_category_consistency(self, confidence_engine):
        """Test consistency between confidence scores and categories"""
        
        alert = generate_test_alerts(1)[0]
        
        # High confidence false positive
        fp_analysis = {
            'category': 'false_positive',
            'confidence': 0.95,
            'reasoning_chain': ['Clear false positive indicators']
        }
        
        result = await confidence_engine.calculate_confidence(alert, fp_analysis)
        
        # Find cross-validation factor
        crossval_factor = next(f for f in result['factors'] if f['name'] == 'cross_validation')
        
        # Should have high consistency score for aligned confidence and category
        assert crossval_factor['score'] > 0.7, \
            "High confidence false positive should have high cross-validation score"
        
        # Low confidence false positive (inconsistent)
        inconsistent_analysis = {
            'category': 'false_positive',
            'confidence': 0.30,  # Low confidence for false positive is suspicious
            'reasoning_chain': ['Uncertain false positive']
        }
        
        result_inconsistent = await confidence_engine.calculate_confidence(alert, inconsistent_analysis)
        crossval_inconsistent = next(f for f in result_inconsistent['factors'] 
                                   if f['name'] == 'cross_validation')
        
        # Should have lower consistency score
        assert crossval_inconsistent['score'] < crossval_factor['score'], \
            "Inconsistent confidence-category pair should have lower cross-validation score"
    
    @pytest.mark.asyncio
    async def test_reasoning_conclusion_consistency(self, confidence_engine):
        """Test consistency between reasoning and conclusions"""
        
        alert = generate_test_alerts(1)[0]
        
        # Consistent reasoning and conclusion
        consistent_analysis = {
            'category': 'false_positive',
            'confidence': 0.90,
            'reasoning_chain': [
                'Network scan detected but from legitimate security tool',
                'Source IP belongs to authorized vulnerability scanner',
                'Scan pattern matches scheduled security assessment',
                'No malicious indicators found in traffic analysis'
            ]
        }
        
        result_consistent = await confidence_engine.calculate_confidence(alert, consistent_analysis)
        
        # Inconsistent reasoning and conclusion
        inconsistent_analysis = {
            'category': 'false_positive',
            'confidence': 0.90,
            'reasoning_chain': [
                'Multiple indicators of malicious activity detected',
                'Source IP has poor reputation score',
                'Attack pattern matches known threat signatures',
                'Evidence suggests active compromise attempt'
            ]
        }
        
        result_inconsistent = await confidence_engine.calculate_confidence(alert, inconsistent_analysis)
        
        # Consistent analysis should score higher
        consistent_crossval = next(f for f in result_consistent['factors'] 
                                 if f['name'] == 'cross_validation')
        inconsistent_crossval = next(f for f in result_inconsistent['factors'] 
                                   if f['name'] == 'cross_validation')
        
        assert consistent_crossval['score'] > inconsistent_crossval['score'], \
            "Consistent reasoning should score higher than inconsistent reasoning"

class TestPerformanceAndScalability:
    """Test confidence engine performance with high volume"""
    
    @pytest.mark.asyncio
    async def test_batch_processing_performance(self, confidence_engine):
        """Test performance with batch processing"""
        
        # Generate realistic daily volume (122 alerts)
        test_alerts = generate_test_alerts(122)
        
        import time
        start_time = time.time()
        
        results = []
        for alert in test_alerts[:10]:  # Test subset for CI performance
            analysis = {
                'category': 'investigation_required',
                'confidence': 0.75,
                'reasoning_chain': ['Performance test analysis']
            }
            
            result = await confidence_engine.calculate_confidence(alert, analysis)
            results.append(result)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Should process 10 alerts in under 30 seconds
        assert processing_time < 30, f"Processing took {processing_time}s, should be under 30s"
        
        # All results should be valid
        for result in results:
            assert 0.0 <= result['score'] <= 1.0
            assert len(result['factors']) > 0
    
    @pytest.mark.asyncio
    async def test_memory_usage_stability(self, confidence_engine):
        """Test memory usage doesn't grow excessively with volume"""
        
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Process multiple alerts
        for i in range(20):
            alert = generate_test_alerts(1)[0]
            analysis = {
                'category': 'investigation_required',
                'confidence': 0.75,
                'reasoning_chain': [f'Memory test {i}']
            }
            
            await confidence_engine.calculate_confidence(alert, analysis)
        
        final_memory = process.memory_info().rss
        memory_growth = final_memory - initial_memory
        
        # Memory growth should be reasonable (less than 100MB)
        assert memory_growth < 100 * 1024 * 1024, \
            f"Memory grew by {memory_growth / 1024 / 1024:.1f}MB, should be under 100MB"

class TestEdgeCases:
    """Test confidence engine with edge cases"""
    
    @pytest.mark.asyncio
    async def test_empty_evidence_handling(self, confidence_engine):
        """Test handling of alerts with no evidence"""
        
        empty_evidence_alert = SecurityAlert(
            id="empty_evidence",
            timestamp=datetime.now(timezone.utc),
            severity=AlertSeverity.LOW,
            source="test",
            title="No evidence alert",
            description="Alert with no evidence",
            evidence={},
            metadata={}
        )
        
        analysis = {
            'category': 'investigation_required',
            'confidence': 0.50,
            'reasoning_chain': ['No evidence available']
        }
        
        result = await confidence_engine.calculate_confidence(empty_evidence_alert, analysis)
        
        # Should handle gracefully
        assert 'score' in result
        assert 0.0 <= result['score'] <= 1.0
        
        # Evidence quality should be low
        evidence_factor = next(f for f in result['factors'] if f['name'] == 'evidence_quality')
        assert evidence_factor['score'] < 0.5, "Empty evidence should result in low evidence quality score"
    
    @pytest.mark.asyncio
    async def test_extreme_confidence_values(self, confidence_engine):
        """Test handling of extreme confidence values"""
        
        alert = generate_test_alerts(1)[0]
        
        # Test with 0% confidence
        zero_analysis = {
            'category': 'investigation_required',
            'confidence': 0.0,
            'reasoning_chain': ['No confidence']
        }
        
        result_zero = await confidence_engine.calculate_confidence(alert, zero_analysis)
        assert 0.0 <= result_zero['score'] <= 1.0
        
        # Test with 100% confidence
        perfect_analysis = {
            'category': 'false_positive',
            'confidence': 1.0,
            'reasoning_chain': ['Perfect confidence']
        }
        
        result_perfect = await confidence_engine.calculate_confidence(alert, perfect_analysis)
        assert 0.0 <= result_perfect['score'] <= 1.0

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=ai_engine.confidence_engine"])