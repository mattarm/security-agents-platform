"""
Test cases for AI Orchestrator - SecOps AI Platform
Tests the core AI orchestration engine with graduated autonomy
"""

import pytest
import asyncio
from datetime import datetime, timezone
from unittest.mock import Mock, AsyncMock, patch

from ai_engine.orchestrator import (
    AIOrchestrator, SecurityAlert, AlertSeverity, AlertCategory, AnalysisResult
)

@pytest.fixture
def sample_config():
    """Sample configuration for testing"""
    return {
        'bedrock_config': {
            'region': 'us-east-1',
            'vpc_endpoint_url': 'https://test-bedrock-endpoint.amazonaws.com',
            'access_key_id': 'test_key',
            'secret_access_key': 'test_secret'
        },
        'confidence_config': {
            'bias_thresholds': {
                'demographic_parity': 0.10,
                'equal_opportunity': 0.10,
                'calibration_error': 0.05
            }
        },
        'autonomy_config': {
            'slack_webhook': 'https://hooks.slack.com/test',
            'approval_groups': {
                'tier2': ['soc-analysts'],
                'tier3': ['soc-analysts', 'incident-response']
            }
        },
        'audit_config': {
            'audit_db_path': ':memory:',  # In-memory SQLite for testing
            'retention_days': 2555,
            'encryption_key': 'test_encryption_key'
        },
        'compliance_config': {
            'enabled_frameworks': ['SOC2', 'ISO27001']
        }
    }

@pytest.fixture
def sample_alert():
    """Sample security alert for testing"""
    return SecurityAlert(
        id="test_alert_001",
        timestamp=datetime.now(timezone.utc),
        severity=AlertSeverity.MEDIUM,
        source="firewall_logs",
        title="Suspicious network activity detected",
        description="Multiple failed connection attempts from external IP",
        evidence={
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.50", 
            "port": 22,
            "attempt_count": 15,
            "time_window": "5_minutes"
        },
        metadata={
            "detection_rule": "RULE_SSH_BRUTE_FORCE",
            "confidence": 0.85
        }
    )

@pytest.fixture
async def orchestrator(sample_config):
    """Create AI orchestrator instance for testing"""
    
    # Mock the external dependencies
    with patch('ai_engine.orchestrator.ModelRouter') as mock_router, \
         patch('ai_engine.orchestrator.ConfidenceEngine') as mock_confidence, \
         patch('ai_engine.orchestrator.AutonomyController') as mock_autonomy, \
         patch('ai_engine.orchestrator.AuditLogger') as mock_audit, \
         patch('ai_engine.orchestrator.ComplianceEngine') as mock_compliance:
        
        # Configure mocks
        mock_router.return_value.initialize = AsyncMock()
        mock_router.return_value.select_model = AsyncMock(return_value='haiku')
        mock_router.return_value.invoke_model = AsyncMock(return_value={
            'category': 'investigation_required',
            'confidence': 0.75,
            'reasoning_chain': [
                'Detected multiple SSH connection attempts',
                'Source IP not in whitelist',
                'Pattern consistent with brute force attack',
                'Recommend investigation and monitoring'
            ],
            'risk_assessment': 'medium',
            'recommended_action': 'Block source IP and investigate'
        })
        
        mock_confidence.return_value.calculate_confidence = AsyncMock(return_value={
            'score': 0.75,
            'confidence_interval': (0.70, 0.80),
            'factors': [
                {
                    'name': 'evidence_quality',
                    'score': 0.85,
                    'weight': 0.25,
                    'explanation': 'High quality evidence with complete network logs',
                    'evidence': ['Source IP logged', 'Port and protocol identified', 'Timestamp accurate']
                }
            ],
            'evidence_scores': {'evidence_quality': 0.85},
            'bias_metrics': {'bias_detected': False, 'severity': 'low'},
            'recommended_tier': 1,
            'calibration_quality': {'status': 'good', 'sample_size': 100}
        })
        
        mock_autonomy.return_value.execute_action = AsyncMock(return_value={
            'status': 'executed',
            'action_type': 'enrich_and_ticket',
            'ticket_id': 'SOC-1234'
        })
        
        mock_audit.return_value.log_decision = AsyncMock()
        mock_audit.return_value.health_check = AsyncMock(return_value={
            'status': 'healthy',
            'total_events': 0
        })
        
        mock_compliance.return_value.validate_decision = AsyncMock(return_value={
            'overall_status': 'compliant',
            'compliance_checks': [],
            'privacy_assessment': {'overall_privacy_score': 0.9},
            'bias_analysis': {'mitigation_required': False},
            'risk_assessment': {'risk_level': 'low'},
            'remediation_required': False
        })
        
        # Health check mocks for all components
        for mock_component in [mock_router, mock_confidence, mock_autonomy, mock_audit, mock_compliance]:
            mock_component.return_value.health_check = AsyncMock(return_value={'status': 'healthy'})
        
        orchestrator = AIOrchestrator(sample_config)
        await orchestrator.model_router.initialize()
        
        return orchestrator

class TestAIOrchestrator:
    """Test suite for AI Orchestrator"""
    
    @pytest.mark.asyncio
    async def test_process_security_alert_success(self, orchestrator, sample_alert):
        """Test successful processing of security alert"""
        
        result = await orchestrator.process_security_alert(sample_alert)
        
        # Verify result structure
        assert isinstance(result, AnalysisResult)
        assert result.alert_id == sample_alert.id
        assert result.category == AlertCategory.INVESTIGATION_REQUIRED
        assert 0.0 <= result.confidence_score <= 1.0
        assert len(result.reasoning_chain) > 0
        assert result.model_used == 'haiku'
        assert result.processing_time_ms > 0
    
    @pytest.mark.asyncio
    async def test_high_confidence_autonomous_action(self, orchestrator, sample_alert):
        """Test that high confidence alerts trigger autonomous actions"""
        
        # Mock high confidence response
        orchestrator.confidence_engine.calculate_confidence = AsyncMock(return_value={
            'score': 0.97,  # High confidence for autonomous action
            'confidence_interval': (0.95, 0.99),
            'factors': [],
            'evidence_scores': {},
            'bias_metrics': {'bias_detected': False},
            'recommended_tier': 0,
            'calibration_quality': {'status': 'good'}
        })
        
        result = await orchestrator.process_security_alert(sample_alert)
        
        # Verify high confidence result
        assert result.confidence_score >= 0.95
        
        # Verify autonomy controller was called
        orchestrator.autonomy_controller.execute_action.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_low_confidence_human_oversight(self, orchestrator, sample_alert):
        """Test that low confidence alerts require human oversight"""
        
        # Mock low confidence response  
        orchestrator.confidence_engine.calculate_confidence = AsyncMock(return_value={
            'score': 0.45,  # Low confidence requiring human collaboration
            'confidence_interval': (0.30, 0.60),
            'factors': [],
            'evidence_scores': {},
            'bias_metrics': {'bias_detected': False},
            'recommended_tier': 3,
            'calibration_quality': {'status': 'good'}
        })
        
        result = await orchestrator.process_security_alert(sample_alert)
        
        # Verify low confidence result
        assert result.confidence_score < 0.60
        
        # Verify human collaboration is triggered
        orchestrator.autonomy_controller.execute_action.assert_called_once()
    
    @pytest.mark.asyncio 
    async def test_model_routing_logic(self, orchestrator, sample_alert):
        """Test intelligent model routing based on complexity"""
        
        # Test simple alert routes to Haiku
        simple_alert = SecurityAlert(
            id="simple_001",
            timestamp=datetime.now(timezone.utc),
            severity=AlertSeverity.LOW,
            source="test_source",
            title="Simple test alert",
            description="Low complexity alert",
            evidence={"test": "data"},
            metadata={}
        )
        
        await orchestrator.process_security_alert(simple_alert)
        
        # Verify model selection was called
        orchestrator.model_router.select_model.assert_called()
        orchestrator.model_router.invoke_model.assert_called()
    
    @pytest.mark.asyncio
    async def test_audit_logging(self, orchestrator, sample_alert):
        """Test that all decisions are properly audited"""
        
        await orchestrator.process_security_alert(sample_alert)
        
        # Verify audit logging was called
        orchestrator.audit_logger.log_decision.assert_called_once()
        
        # Verify call includes required audit data
        call_args = orchestrator.audit_logger.log_decision.call_args
        assert call_args[0][0] == sample_alert  # First arg is alert
        assert isinstance(call_args[0][1], AnalysisResult)  # Second arg is result
        assert isinstance(call_args[0][2], dict)  # Third arg is additional context
    
    @pytest.mark.asyncio
    async def test_compliance_validation(self, orchestrator, sample_alert):
        """Test compliance validation for all decisions"""
        
        await orchestrator.process_security_alert(sample_alert)
        
        # Verify compliance validation was called
        orchestrator.compliance_engine.validate_decision.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_performance_metrics_tracking(self, orchestrator, sample_alert):
        """Test that performance metrics are tracked"""
        
        # Process multiple alerts
        await orchestrator.process_security_alert(sample_alert)
        await orchestrator.process_security_alert(sample_alert)
        
        # Check metrics are updated
        assert orchestrator.metrics['alerts_processed'] == 2
        assert orchestrator.metrics['model_usage']['haiku'] == 2
        assert orchestrator.metrics['average_processing_time'] > 0
    
    @pytest.mark.asyncio
    async def test_error_handling(self, orchestrator, sample_alert):
        """Test error handling and recovery"""
        
        # Mock an error in model invocation
        orchestrator.model_router.invoke_model = AsyncMock(
            side_effect=Exception("Model invocation failed")
        )
        
        # Verify error is handled properly
        with pytest.raises(Exception) as exc_info:
            await orchestrator.process_security_alert(sample_alert)
        
        assert "Model invocation failed" in str(exc_info.value)
        
        # Verify error is logged for audit
        orchestrator.audit_logger.log_error.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_health_check(self, orchestrator):
        """Test comprehensive health check"""
        
        health_status = await orchestrator.health_check()
        
        # Verify health check structure
        assert 'status' in health_status
        assert 'timestamp' in health_status
        assert 'components' in health_status
        assert 'metrics' in health_status
        
        # Verify all components are checked
        components = health_status['components']
        assert 'model_router' in components
        assert 'confidence_engine' in components
        assert 'autonomy_controller' in components
        assert 'audit_logger' in components
        assert 'compliance_engine' in components
    
    @pytest.mark.asyncio
    async def test_cost_optimization(self, orchestrator):
        """Test cost optimization and tracking"""
        
        metrics = await orchestrator.get_performance_metrics()
        
        # Verify cost metrics are included
        assert 'cost_efficiency' in metrics
        cost_data = metrics['cost_efficiency']
        
        assert 'total_cost_usd' in cost_data
        assert 'cost_per_alert_usd' in cost_data
        assert 'monthly_projection_usd' in cost_data
        assert 'model_cost_breakdown' in cost_data
    
    @pytest.mark.asyncio
    async def test_autonomy_tier_distribution(self, orchestrator):
        """Test autonomy tier usage distribution tracking"""
        
        metrics = await orchestrator.get_performance_metrics()
        
        # Verify autonomy distribution metrics
        assert 'autonomy_distribution' in metrics
        distribution = metrics['autonomy_distribution']
        
        # Should have percentage for each tier
        for i in range(4):
            assert f'tier_{i}_percent' in distribution

class TestSecurityAlert:
    """Test SecurityAlert data structure"""
    
    def test_alert_creation(self):
        """Test security alert creation and validation"""
        
        alert = SecurityAlert(
            id="test_001",
            timestamp=datetime.now(timezone.utc),
            severity=AlertSeverity.HIGH,
            source="test_source",
            title="Test Alert",
            description="Test description",
            evidence={"test": "evidence"},
            metadata={"test": "metadata"}
        )
        
        assert alert.id == "test_001"
        assert alert.severity == AlertSeverity.HIGH
        assert "test" in alert.evidence
        assert "test" in alert.metadata
    
    def test_alert_to_dict(self):
        """Test alert serialization to dictionary"""
        
        alert = SecurityAlert(
            id="test_001",
            timestamp=datetime.now(timezone.utc),
            severity=AlertSeverity.MEDIUM,
            source="test_source", 
            title="Test Alert",
            description="Test description",
            evidence={},
            metadata={}
        )
        
        alert_dict = alert.to_dict()
        
        assert isinstance(alert_dict, dict)
        assert alert_dict['id'] == "test_001"
        assert alert_dict['severity'] == 'medium'
        assert 'timestamp' in alert_dict

if __name__ == "__main__":
    pytest.main([__file__, "-v"])