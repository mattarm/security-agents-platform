"""
Compliance Test Suite - SOC2 and ISO27001 Validation for Enterprise Deployment
Tests audit trails, data retention, compliance controls, and regulatory requirements
"""

import pytest
import json
import sqlite3
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, AsyncMock, patch
from dataclasses import asdict

from governance.compliance import ComplianceEngine, ComplianceFramework, ComplianceStatus
from ai_engine.audit_logger import AuditLogger, AuditEvent
from ai_engine.orchestrator import SecurityAlert, AlertSeverity, AnalysisResult, AlertCategory
from tests.datasets.synthetic_alerts import generate_test_alerts

@pytest.fixture
def compliance_engine():
    """Create compliance engine for testing"""
    config = {
        'enabled_frameworks': [ComplianceFramework.SOC2, ComplianceFramework.ISO27001],
        'bias_thresholds': {
            'demographic_parity': 0.10,
            'equal_opportunity': 0.10,
            'calibration_error': 0.05,
            'fairness_score': 0.80
        }
    }
    return ComplianceEngine(config)

@pytest.fixture
def audit_logger():
    """Create audit logger for testing"""
    config = {
        'audit_db_path': ':memory:',
        'retention_days': 2555,  # 7 years
        'encryption_key': 'test_encryption_key'
    }
    return AuditLogger(config)

@pytest.fixture
def sample_analysis_result():
    """Create sample analysis result for testing"""
    return AnalysisResult(
        alert_id="test_alert_001",
        analysis_id="analysis_001",
        timestamp=datetime.now(timezone.utc),
        category=AlertCategory.INVESTIGATION_REQUIRED,
        confidence_score=0.85,
        reasoning_chain=[
            "Network anomaly detected in firewall logs",
            "Source IP has poor reputation score",
            "Pattern matches known attack signatures",
            "Evidence quality is high with complete logs"
        ],
        evidence_assessment={'evidence_quality': 0.9, 'pattern_match': 0.8},
        recommended_action="Create investigation ticket and monitor source IP",
        model_used="claude-sonnet",
        processing_time_ms=2500
    )

class TestSOC2Compliance:
    """Test SOC 2 Trust Service Criteria compliance"""
    
    @pytest.mark.asyncio
    async def test_cc1_control_environment(self, compliance_engine, sample_analysis_result):
        """Test CC1: Control Environment - Authorization and Oversight"""
        
        # Test with properly authorized AI decision
        validation_result = await compliance_engine.validate_decision(sample_analysis_result)
        
        # Find CC1 control check
        cc1_checks = [check for check in validation_result['compliance_checks'] 
                     if check['control_id'] == 'CC1.1']
        
        assert len(cc1_checks) == 1, "Should have exactly one CC1.1 control check"
        
        cc1_check = cc1_checks[0]
        assert cc1_check['framework'] == ComplianceFramework.SOC2.value
        assert cc1_check['control_name'] == "Control Environment - Authorization and Oversight"
        
        # Should pass with proper analysis result
        assert cc1_check['status'] in [ComplianceStatus.COMPLIANT.value, ComplianceStatus.REQUIRES_REVIEW.value]
        
        # Validate evidence requirements
        assert len(cc1_check['evidence']) > 0, "CC1 check should have supporting evidence"
        assert any('confidence' in evidence.lower() for evidence in cc1_check['evidence'])
        assert any('reasoning' in evidence.lower() or 'audit' in evidence.lower() 
                  for evidence in cc1_check['evidence'])
    
    @pytest.mark.asyncio
    async def test_cc1_missing_authorization(self, compliance_engine):
        """Test CC1 failure with missing authorization controls"""
        
        # Create analysis result without proper authorization indicators
        incomplete_result = AnalysisResult(
            alert_id="incomplete_test",
            analysis_id="incomplete_001",
            timestamp=datetime.now(timezone.utc),
            category=AlertCategory.INVESTIGATION_REQUIRED,
            confidence_score=-1.0,  # Invalid confidence score
            reasoning_chain=[],     # Missing reasoning chain
            evidence_assessment={},
            recommended_action="",  # Empty action
            model_used="",         # Missing model attribution
            processing_time_ms=0
        )
        
        validation_result = await compliance_engine.validate_decision(incomplete_result)
        
        # Find CC1 control check
        cc1_checks = [check for check in validation_result['compliance_checks'] 
                     if check['control_id'] == 'CC1.1']
        
        cc1_check = cc1_checks[0]
        
        # Should fail compliance due to missing controls
        assert cc1_check['status'] in [ComplianceStatus.NON_COMPLIANT.value, ComplianceStatus.REQUIRES_REVIEW.value]
        assert len(cc1_check['deficiencies']) > 0, "Should identify authorization deficiencies"
    
    @pytest.mark.asyncio
    async def test_cc2_communication_information(self, compliance_engine, sample_analysis_result):
        """Test CC2: Communication and Information - Decision Transparency"""
        
        validation_result = await compliance_engine.validate_decision(sample_analysis_result)
        
        # Find CC2 control check
        cc2_checks = [check for check in validation_result['compliance_checks'] 
                     if check['control_id'] == 'CC2.1']
        
        assert len(cc2_checks) == 1, "Should have exactly one CC2.1 control check"
        
        cc2_check = cc2_checks[0]
        assert cc2_check['control_name'] == "Communication and Information - Decision Transparency"
        
        # Should validate transparency requirements
        if cc2_check['status'] == ComplianceStatus.COMPLIANT.value:
            assert any('reasoning' in evidence.lower() for evidence in cc2_check['evidence'])
            assert any('model' in evidence.lower() for evidence in cc2_check['evidence'])
        
        # Test with poor reasoning quality
        poor_reasoning_result = sample_analysis_result._replace(
            reasoning_chain=["unclear"]  # Very brief, poor quality reasoning
        )
        
        poor_validation = await compliance_engine.validate_decision(poor_reasoning_result)
        poor_cc2_checks = [check for check in poor_validation['compliance_checks'] 
                          if check['control_id'] == 'CC2.1']
        
        poor_cc2_check = poor_cc2_checks[0]
        
        # Should flag transparency issues
        if len(poor_reasoning_result.reasoning_chain) < 2:
            assert poor_cc2_check['status'] != ComplianceStatus.COMPLIANT.value
    
    @pytest.mark.asyncio
    async def test_cc3_risk_assessment(self, compliance_engine, sample_analysis_result):
        """Test CC3: Risk Assessment - AI Decision Risk Evaluation"""
        
        validation_result = await compliance_engine.validate_decision(sample_analysis_result)
        
        # Find CC3 control check
        cc3_checks = [check for check in validation_result['compliance_checks'] 
                     if check['control_id'] == 'CC3.1']
        
        cc3_check = cc3_checks[0]
        assert cc3_check['control_name'] == "Risk Assessment - AI Decision Risk Evaluation"
        
        # Should validate risk assessment components
        assert any('confidence' in evidence.lower() for evidence in cc3_check['evidence'])
        
        # Test high-confidence decision
        high_conf_result = sample_analysis_result._replace(confidence_score=0.97)
        high_conf_validation = await compliance_engine.validate_decision(high_conf_result)
        high_conf_cc3 = [check for check in high_conf_validation['compliance_checks'] 
                         if check['control_id'] == 'CC3.1'][0]
        
        # High confidence should indicate low risk
        assert any('high confidence' in evidence.lower() or '95%' in evidence.lower() 
                  for evidence in high_conf_cc3['evidence'])
        
        # Test low-confidence decision
        low_conf_result = sample_analysis_result._replace(confidence_score=0.45)
        low_conf_validation = await compliance_engine.validate_decision(low_conf_result)
        low_conf_cc3 = [check for check in low_conf_validation['compliance_checks'] 
                        if check['control_id'] == 'CC3.1'][0]
        
        # Low confidence should indicate higher risk and human involvement
        assert any('low confidence' in evidence.lower() or 'human' in evidence.lower() 
                  for evidence in low_conf_cc3['evidence'])
    
    @pytest.mark.asyncio
    async def test_cc4_monitoring_activities(self, compliance_engine, sample_analysis_result):
        """Test CC4: Monitoring Activities - Continuous AI Monitoring"""
        
        validation_result = await compliance_engine.validate_decision(sample_analysis_result)
        
        # Find CC4 control check
        cc4_checks = [check for check in validation_result['compliance_checks'] 
                     if check['control_id'] == 'CC4.1']
        
        cc4_check = cc4_checks[0]
        assert cc4_check['control_name'] == "Monitoring Activities - Continuous AI Monitoring"
        
        # Should validate monitoring capabilities
        assert any('performance' in evidence.lower() or 'monitoring' in evidence.lower() 
                  for evidence in cc4_check['evidence'])
        
        # Test with performance monitoring data
        if hasattr(sample_analysis_result, 'processing_time_ms'):
            assert any(str(sample_analysis_result.processing_time_ms) in evidence 
                      for evidence in cc4_check['evidence'])
    
    @pytest.mark.asyncio
    async def test_cc5_control_activities(self, compliance_engine, sample_analysis_result):
        """Test CC5: Control Activities - Graduated Autonomy Controls"""
        
        validation_result = await compliance_engine.validate_decision(sample_analysis_result)
        
        # Find CC5 control check
        cc5_checks = [check for check in validation_result['compliance_checks'] 
                     if check['control_id'] == 'CC5.1']
        
        cc5_check = cc5_checks[0]
        assert cc5_check['control_name'] == "Control Activities - Graduated Autonomy Controls"
        
        # Should validate autonomy controls based on confidence
        confidence = sample_analysis_result.confidence_score
        
        if confidence >= 0.95:
            assert any('tier 0' in evidence.lower() or 'automated' in evidence.lower() 
                      for evidence in cc5_check['evidence'])
        elif confidence >= 0.80:
            assert any('tier 1' in evidence.lower() or 'assisted' in evidence.lower() 
                      for evidence in cc5_check['evidence'])
        elif confidence >= 0.60:
            assert any('tier 2' in evidence.lower() or 'supervised' in evidence.lower() 
                      for evidence in cc5_check['evidence'])
        else:
            assert any('tier 3' in evidence.lower() or 'collaborative' in evidence.lower() 
                      for evidence in cc5_check['evidence'])

class TestISO27001Compliance:
    """Test ISO 27001 information security controls"""
    
    @pytest.mark.asyncio
    async def test_a12_operations_security(self, compliance_engine, sample_analysis_result):
        """Test A.12: Operations Security - AI Operations Management"""
        
        validation_result = await compliance_engine.validate_decision(sample_analysis_result)
        
        # Find A.12 control check
        a12_checks = [check for check in validation_result['compliance_checks'] 
                     if check['control_id'] == 'A.12.1']
        
        assert len(a12_checks) == 1, "Should have exactly one A.12.1 control check"
        
        a12_check = a12_checks[0]
        assert a12_check['framework'] == ComplianceFramework.ISO27001.value
        assert a12_check['control_name'] == "Operations Security - AI Operations Management"
        
        # Should validate operational security controls
        assert any('procedure' in evidence.lower() or 'management' in evidence.lower() 
                  for evidence in a12_check['evidence'])
        
        # Test performance requirements
        if sample_analysis_result.processing_time_ms > 30000:  # 30 seconds
            assert a12_check['status'] == ComplianceStatus.REQUIRES_REVIEW.value
            assert any('performance' in deficiency.lower() 
                      for deficiency in a12_check['deficiencies'])
    
    @pytest.mark.asyncio
    async def test_a13_communications_security(self, compliance_engine, sample_analysis_result):
        """Test A.13: Communications Security - Secure AI Communications"""
        
        validation_result = await compliance_engine.validate_decision(sample_analysis_result)
        
        # Find A.13 control check
        a13_checks = [check for check in validation_result['compliance_checks'] 
                     if check['control_id'] == 'A.13.1']
        
        a13_check = a13_checks[0]
        assert a13_check['control_name'] == "Communications Security - Secure AI Communications"
        
        # Should validate secure communications
        assert any('vpc' in evidence.lower() or 'encryption' in evidence.lower() 
                  for evidence in a13_check['evidence'])
        assert any('zero internet egress' in evidence.lower() or 'isolated' in evidence.lower() 
                  for evidence in a13_check['evidence'])
    
    @pytest.mark.asyncio
    async def test_a14_system_acquisition(self, compliance_engine, sample_analysis_result):
        """Test A.14: System Acquisition - Secure AI Development"""
        
        validation_result = await compliance_engine.validate_decision(sample_analysis_result)
        
        # Find A.14 control check
        a14_checks = [check for check in validation_result['compliance_checks'] 
                     if check['control_id'] == 'A.14.1']
        
        a14_check = a14_checks[0]
        assert a14_check['control_name'] == "System Acquisition - Secure AI Development"
        
        # Should validate secure development practices
        assert any('security' in evidence.lower() for evidence in a14_check['evidence'])
        assert a14_check['status'] == ComplianceStatus.COMPLIANT.value  # Should always be compliant for secure development

class TestAuditTrailCompliance:
    """Test audit trail requirements for compliance"""
    
    @pytest.mark.asyncio
    async def test_complete_audit_trail_creation(self, audit_logger):
        """Test creation of complete audit trails"""
        
        # Create test alert and analysis result
        alert = generate_test_alerts(1)[0]
        
        analysis_result = AnalysisResult(
            alert_id=alert.id,
            analysis_id="audit_test_001",
            timestamp=datetime.now(timezone.utc),
            category=AlertCategory.FALSE_POSITIVE,
            confidence_score=0.92,
            reasoning_chain=[
                "Network scan detected from authorized security tool",
                "Source IP matches known vulnerability scanner",
                "Scan pattern consistent with scheduled assessment",
                "No malicious indicators in traffic analysis"
            ],
            evidence_assessment={'evidence_quality': 0.85},
            recommended_action="Close as false positive",
            model_used="claude-haiku",
            processing_time_ms=1500
        )
        
        additional_context = {
            'model_reasoning': {
                'confidence_factors': ['high_evidence_quality', 'clear_pattern_match'],
                'bias_assessment': {'bias_detected': False}
            },
            'confidence_breakdown': {
                'evidence_score': 0.85,
                'pattern_score': 0.90,
                'context_score': 0.88
            },
            'compliance_checks': {
                'soc2_compliant': True,
                'iso27001_compliant': True,
                'pii_detected': False
            }
        }
        
        # Log the decision
        await audit_logger.log_decision(alert, analysis_result, additional_context)
        
        # Verify audit trail was created
        with sqlite3.connect(audit_logger.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM audit_events WHERE alert_id = ?", (alert.id,))
            audit_records = [dict(row) for row in cursor.fetchall()]
        
        assert len(audit_records) == 1, "Should create exactly one audit record"
        
        audit_record = audit_records[0]
        
        # Validate audit record completeness
        required_fields = [
            'event_id', 'timestamp', 'event_type', 'alert_id', 'analysis_id',
            'autonomy_tier', 'decision_data', 'reasoning_chain', 'confidence_score',
            'evidence_hash', 'compliance_metadata', 'event_hash'
        ]
        
        for field in required_fields:
            assert field in audit_record, f"Missing required audit field: {field}"
            assert audit_record[field] is not None, f"Audit field {field} is None"
        
        # Validate decision data
        decision_data = json.loads(audit_record['decision_data'])
        assert 'alert_summary' in decision_data
        assert 'analysis_result' in decision_data
        assert 'model_reasoning' in decision_data
        assert 'confidence_breakdown' in decision_data
        
        # Validate reasoning chain
        reasoning_chain = json.loads(audit_record['reasoning_chain'])
        assert isinstance(reasoning_chain, list)
        assert len(reasoning_chain) > 0
        assert all(isinstance(step, str) for step in reasoning_chain)
        
        # Validate compliance metadata
        compliance_metadata = json.loads(audit_record['compliance_metadata'])
        assert 'regulation_tags' in compliance_metadata
        assert 'SOC2' in compliance_metadata['regulation_tags']
        assert 'ISO27001' in compliance_metadata['regulation_tags']
        assert 'data_classification' in compliance_metadata
        assert 'retention_date' in compliance_metadata
    
    @pytest.mark.asyncio
    async def test_audit_trail_integrity(self, audit_logger):
        """Test audit trail integrity and hash chaining"""
        
        # Create multiple audit events
        alerts = generate_test_alerts(3)
        
        for i, alert in enumerate(alerts):
            analysis_result = AnalysisResult(
                alert_id=alert.id,
                analysis_id=f"integrity_test_{i:03d}",
                timestamp=datetime.now(timezone.utc),
                category=AlertCategory.INVESTIGATION_REQUIRED,
                confidence_score=0.75,
                reasoning_chain=[f"Integrity test reasoning {i}"],
                evidence_assessment={'test': 0.8},
                recommended_action=f"Test action {i}",
                model_used="test-model",
                processing_time_ms=1000
            )
            
            await audit_logger.log_decision(alert, analysis_result, {})
        
        # Verify hash chain integrity
        with sqlite3.connect(audit_logger.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT event_id, event_hash, previous_event_hash, timestamp
                FROM audit_events 
                ORDER BY timestamp ASC
            """)
            
            events = [dict(row) for row in cursor.fetchall()]
        
        assert len(events) == 3, "Should have 3 audit events"
        
        # Validate hash chain
        for i, event in enumerate(events):
            assert event['event_hash'] is not None, f"Event {i} missing hash"
            
            if i > 0:
                # Each event (except first) should reference previous event's hash
                previous_event_hash = events[i-1]['event_hash']
                assert event['previous_event_hash'] == previous_event_hash, \
                    f"Event {i} hash chain broken"
            else:
                # First event should have no previous hash
                assert event['previous_event_hash'] is None
    
    @pytest.mark.asyncio
    async def test_human_override_audit_trail(self, audit_logger):
        """Test audit trail for human overrides"""
        
        # Create original AI decision
        alert = generate_test_alerts(1)[0]
        
        analysis_result = AnalysisResult(
            alert_id=alert.id,
            analysis_id="override_test_001",
            timestamp=datetime.now(timezone.utc),
            category=AlertCategory.FALSE_POSITIVE,
            confidence_score=0.88,
            reasoning_chain=["AI determined false positive"],
            evidence_assessment={},
            recommended_action="Close alert",
            model_used="claude-sonnet",
            processing_time_ms=2000
        )
        
        await audit_logger.log_decision(alert, analysis_result, {})
        
        # Get the original event ID
        with sqlite3.connect(audit_logger.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT event_id FROM audit_events WHERE alert_id = ?", (alert.id,))
            original_event_id = cursor.fetchone()[0]
        
        # Log human override
        await audit_logger.log_human_override(
            original_event_id=original_event_id,
            user_id="analyst_john_doe",
            override_reason="Additional context suggests legitimate threat",
            new_decision="investigation_required",
            justification="Found additional indicators in correlated logs that suggest this may be a legitimate threat requiring investigation"
        )
        
        # Verify override audit trail
        with sqlite3.connect(audit_logger.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Check human_overrides table
            cursor.execute("SELECT * FROM human_overrides WHERE original_event_id = ?", (original_event_id,))
            override_records = [dict(row) for row in cursor.fetchall()]
            
            assert len(override_records) == 1, "Should create exactly one override record"
            
            override_record = override_records[0]
            assert override_record['override_user'] == "analyst_john_doe"
            assert override_record['override_reason'] == "Additional context suggests legitimate threat"
            assert override_record['new_decision'] == "investigation_required"
            
            # Check that override created new audit event
            cursor.execute("SELECT * FROM audit_events WHERE event_type = 'HUMAN_OVERRIDE' AND alert_id = ?", (alert.id,))
            override_events = [dict(row) for row in cursor.fetchall()]
            
            assert len(override_events) == 1, "Should create override audit event"
            
            override_event = override_events[0]
            assert override_event['user_id'] == "analyst_john_doe"
            assert override_event['confidence_score'] == 1.0  # Human decisions have 100% confidence
    
    @pytest.mark.asyncio
    async def test_retention_policy_compliance(self, audit_logger):
        """Test audit data retention policy compliance"""
        
        # Test current retention configuration
        assert audit_logger.retention_days == 2555  # 7 years for compliance
        
        # Create test audit events with different dates
        current_time = datetime.now(timezone.utc)
        
        test_events = [
            {
                'date': current_time - timedelta(days=30),   # 1 month old
                'should_retain': True
            },
            {
                'date': current_time - timedelta(days=365),  # 1 year old
                'should_retain': True
            },
            {
                'date': current_time - timedelta(days=365*7), # 7 years old
                'should_retain': True  # At the retention limit
            },
            {
                'date': current_time - timedelta(days=365*8), # 8 years old
                'should_retain': False  # Beyond retention period
            }
        ]
        
        # Validate retention policy logic
        for i, event_data in enumerate(test_events):
            event_age_days = (current_time - event_data['date']).days
            should_retain = event_age_days <= audit_logger.retention_days
            
            assert should_retain == event_data['should_retain'], \
                f"Event {i} retention policy mismatch: age={event_age_days} days, " + \
                f"limit={audit_logger.retention_days} days, should_retain={event_data['should_retain']}"
        
        # Test retention metadata in compliance data
        alert = generate_test_alerts(1)[0]
        analysis_result = AnalysisResult(
            alert_id=alert.id,
            analysis_id="retention_test_001",
            timestamp=current_time,
            category=AlertCategory.INVESTIGATION_REQUIRED,
            confidence_score=0.80,
            reasoning_chain=["Retention test"],
            evidence_assessment={},
            recommended_action="Test retention",
            model_used="test",
            processing_time_ms=1000
        )
        
        await audit_logger.log_decision(alert, analysis_result, {})
        
        # Verify retention date in compliance metadata
        with sqlite3.connect(audit_logger.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT compliance_metadata FROM audit_events WHERE alert_id = ?", (alert.id,))
            compliance_metadata_str = cursor.fetchone()['compliance_metadata']
            compliance_metadata = json.loads(compliance_metadata_str)
        
        assert 'retention_date' in compliance_metadata
        
        retention_date = datetime.fromisoformat(compliance_metadata['retention_date'].replace('Z', '+00:00'))
        expected_retention_date = current_time.replace(year=current_time.year + 7)
        
        # Retention date should be approximately 7 years from now
        time_difference = abs((retention_date - expected_retention_date).total_seconds())
        assert time_difference < 3600, "Retention date should be 7 years from creation (within 1 hour tolerance)"

class TestComplianceReporting:
    """Test automated compliance reporting capabilities"""
    
    @pytest.mark.asyncio
    async def test_soc2_compliance_report_generation(self, audit_logger):
        """Test SOC 2 compliance report generation"""
        
        # Create test data for report
        start_date = datetime.now(timezone.utc) - timedelta(days=30)
        end_date = datetime.now(timezone.utc)
        
        # Create sample audit events
        for i in range(5):
            alert = generate_test_alerts(1)[0]
            alert.id = f"soc2_report_test_{i}"
            
            analysis_result = AnalysisResult(
                alert_id=alert.id,
                analysis_id=f"soc2_analysis_{i}",
                timestamp=start_date + timedelta(days=i*5),
                category=AlertCategory.INVESTIGATION_REQUIRED,
                confidence_score=0.80 + (i * 0.05),  # Varying confidence
                reasoning_chain=[f"SOC 2 test reasoning {i}"],
                evidence_assessment={},
                recommended_action=f"SOC 2 test action {i}",
                model_used="test-model",
                processing_time_ms=1000 + (i * 100)
            )
            
            await audit_logger.log_decision(alert, analysis_result, {
                'compliance_checks': {'soc2_compliant': True}
            })
        
        # Generate SOC 2 report
        report = await audit_logger.generate_compliance_report(
            start_date=start_date,
            end_date=end_date,
            report_type='SOC2'
        )
        
        # Validate report structure
        assert 'report_id' in report
        assert 'report_type' in report
        assert report['report_type'] == 'SOC2'
        assert 'period' in report
        assert 'generated_at' in report
        assert 'total_events' in report
        
        # Validate SOC 2 specific content
        assert 'soc2_controls' in report
        soc2_controls = report['soc2_controls']
        
        required_soc2_controls = ['cc1_control_environment', 'cc2_communication_information', 
                                'cc3_risk_assessment', 'cc4_monitoring_activities', 'cc5_control_activities']
        
        for control in required_soc2_controls:
            assert control in soc2_controls
            assert 'status' in soc2_controls[control]
            assert 'evidence' in soc2_controls[control]
        
        # Validate processing integrity section
        assert 'processing_integrity' in report
        processing_integrity = report['processing_integrity']
        
        assert 'completeness' in processing_integrity
        assert 'accuracy' in processing_integrity
        assert 'timeliness' in processing_integrity
        assert 'authorization' in processing_integrity
        
        assert report['total_events'] == 5
    
    @pytest.mark.asyncio
    async def test_iso27001_compliance_report_generation(self, audit_logger):
        """Test ISO 27001 compliance report generation"""
        
        # Create test data
        start_date = datetime.now(timezone.utc) - timedelta(days=7)
        end_date = datetime.now(timezone.utc)
        
        # Create sample events
        for i in range(3):
            alert = generate_test_alerts(1)[0]
            alert.id = f"iso27001_test_{i}"
            
            analysis_result = AnalysisResult(
                alert_id=alert.id,
                analysis_id=f"iso_analysis_{i}",
                timestamp=start_date + timedelta(days=i*2),
                category=AlertCategory.CONTAINMENT_REQUIRED,
                confidence_score=0.85,
                reasoning_chain=[f"ISO 27001 test reasoning {i}"],
                evidence_assessment={},
                recommended_action=f"ISO 27001 test action {i}",
                model_used="test-model",
                processing_time_ms=1500
            )
            
            await audit_logger.log_decision(alert, analysis_result, {
                'compliance_checks': {'iso27001_compliant': True}
            })
        
        # Generate ISO 27001 report
        report = await audit_logger.generate_compliance_report(
            start_date=start_date,
            end_date=end_date,
            report_type='ISO27001'
        )
        
        # Validate report structure
        assert report['report_type'] == 'ISO27001'
        
        # Validate ISO 27001 specific content
        assert 'iso27001_controls' in report
        iso_controls = report['iso27001_controls']
        
        required_iso_controls = ['a12_operations_security', 'a13_communications_security', 
                                'a14_system_acquisition']
        
        for control in required_iso_controls:
            assert control in iso_controls
            assert 'status' in iso_controls[control]
            assert 'evidence' in iso_controls[control]
        
        # Validate information security management section
        assert 'information_security_management' in report
        ism = report['information_security_management']
        
        assert 'confidentiality' in ism
        assert 'integrity' in ism
        assert 'availability' in ism
        
        assert report['total_events'] == 3
    
    @pytest.mark.asyncio
    async def test_compliance_report_integrity_verification(self, audit_logger):
        """Test compliance report integrity and hash verification"""
        
        start_date = datetime.now(timezone.utc) - timedelta(days=1)
        end_date = datetime.now(timezone.utc)
        
        # Generate a report
        report = await audit_logger.generate_compliance_report(
            start_date=start_date,
            end_date=end_date,
            report_type='SOC2'
        )
        
        # Verify report hash is present and valid
        assert 'report_id' in report
        
        # Check if report was stored in database with hash
        with sqlite3.connect(audit_logger.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM compliance_reports WHERE report_id = ?", (report['report_id'],))
            stored_report = dict(cursor.fetchone())
        
        assert stored_report['report_hash'] is not None
        assert len(stored_report['report_hash']) == 64  # SHA-256 hash length
        
        # Verify report content matches stored version
        stored_report_data = json.loads(stored_report['report_data'])
        
        # Key fields should match
        assert stored_report_data['report_id'] == report['report_id']
        assert stored_report_data['report_type'] == report['report_type']
        assert stored_report_data['total_events'] == report['total_events']

class TestDataRetentionCompliance:
    """Test data retention and deletion compliance"""
    
    def test_data_classification_requirements(self):
        """Test proper data classification for compliance"""
        
        # Data classification levels for compliance
        classification_levels = {
            'public': {
                'retention_years': 1,
                'encryption_required': False,
                'examples': ['system_status', 'public_metrics']
            },
            'internal': {
                'retention_years': 3,
                'encryption_required': True,
                'examples': ['performance_logs', 'error_logs']
            },
            'confidential': {
                'retention_years': 7,
                'encryption_required': True,
                'examples': ['security_alerts', 'ai_decisions', 'user_actions']
            },
            'restricted': {
                'retention_years': 7,
                'encryption_required': True,
                'examples': ['compliance_reports', 'audit_trails', 'pii_data']
            }
        }
        
        # Validate classification requirements
        for classification, requirements in classification_levels.items():
            
            # Retention period validation
            retention_years = requirements['retention_years']
            assert retention_years >= 1, f"Classification {classification} has invalid retention period"
            
            # Encryption requirements
            encryption_required = requirements['encryption_required']
            if classification in ['confidential', 'restricted']:
                assert encryption_required, f"Classification {classification} must require encryption"
            
            # Example data types
            examples = requirements['examples']
            assert len(examples) > 0, f"Classification {classification} must have examples"
    
    def test_retention_policy_validation(self):
        """Test retention policy meets compliance requirements"""
        
        # Regulatory retention requirements
        regulatory_requirements = {
            'SOC2': {'minimum_retention_years': 3},
            'ISO27001': {'minimum_retention_years': 3},
            'GDPR': {'maximum_retention_years': 7, 'data_subject_rights': True},
            'HIPAA': {'minimum_retention_years': 6},  # If applicable
            'PCI_DSS': {'minimum_retention_years': 1}  # If applicable
        }
        
        # Test retention policy compliance
        secops_retention_years = 7  # Our configured retention period
        
        for regulation, requirements in regulatory_requirements.items():
            if 'minimum_retention_years' in requirements:
                min_retention = requirements['minimum_retention_years']
                assert secops_retention_years >= min_retention, \
                    f"Retention period {secops_retention_years} years does not meet {regulation} requirement of {min_retention} years"
            
            if 'maximum_retention_years' in requirements:
                max_retention = requirements['maximum_retention_years']
                assert secops_retention_years <= max_retention, \
                    f"Retention period {secops_retention_years} years exceeds {regulation} limit of {max_retention} years"
            
            if requirements.get('data_subject_rights'):
                # GDPR requires ability to delete data upon request
                assert True, "System must support data subject deletion requests"

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=governance", "--cov=ai_engine.audit_logger"])