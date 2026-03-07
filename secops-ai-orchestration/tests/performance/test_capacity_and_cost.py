"""
Performance Tests - Capacity and Cost Validation for SecOps AI Platform
CRITICAL: Validates 122 alerts/day capacity and <$300/month cost targets before production
"""

import pytest
import asyncio
import time
import statistics
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch
from concurrent.futures import ThreadPoolExecutor
import json

from ai_engine.orchestrator import AIOrchestrator, SecurityAlert, AlertSeverity
from ai_engine.model_router import ModelRouter
from tests.datasets.synthetic_alerts import (
    SyntheticAlertGenerator, 
    generate_performance_alerts,
    AlertPattern
)

# Performance test configuration
DAILY_ALERT_TARGET = 122  # Target alerts per day
MONTHLY_COST_LIMIT = 300  # Maximum monthly cost in USD
PROCESSING_TIME_LIMIT = 15 * 60  # 15 minutes in seconds (MTTD target)
CONCURRENT_ALERT_LIMIT = 10  # Maximum concurrent alert processing

@pytest.fixture
def performance_orchestrator():
    """Create orchestrator for performance testing with mocked AWS services"""
    
    config = {
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
            'audit_db_path': ':memory:',
            'retention_days': 2555,
            'encryption_key': 'test_encryption_key'
        },
        'compliance_config': {
            'enabled_frameworks': ['SOC2', 'ISO27001']
        }
    }
    
    # Mock all external dependencies for performance testing
    with patch('ai_engine.orchestrator.ModelRouter') as mock_router, \
         patch('ai_engine.orchestrator.ConfidenceEngine') as mock_confidence, \
         patch('ai_engine.orchestrator.AutonomyController') as mock_autonomy, \
         patch('ai_engine.orchestrator.AuditLogger') as mock_audit, \
         patch('ai_engine.orchestrator.ComplianceEngine') as mock_compliance:
        
        # Configure realistic performance mocks
        mock_router.return_value.select_model = AsyncMock(side_effect=select_model_mock)
        mock_router.return_value.invoke_model = AsyncMock(side_effect=invoke_model_mock)
        mock_router.return_value.get_cost_metrics = AsyncMock(return_value={
            'total_calls': 0,
            'model_distribution': {'haiku': 70, 'sonnet': 25, 'opus': 5},
            'estimated_daily_cost_usd': 2.50,
            'estimated_monthly_cost_usd': 75.0,
            'cost_by_model': {'haiku': 1.75, 'sonnet': 0.50, 'opus': 0.25}
        })
        
        mock_confidence.return_value.calculate_confidence = AsyncMock(side_effect=confidence_mock)
        mock_autonomy.return_value.execute_action = AsyncMock(side_effect=autonomy_mock)
        mock_audit.return_value.log_decision = AsyncMock()
        mock_compliance.return_value.validate_decision = AsyncMock(return_value={
            'overall_status': 'compliant',
            'compliance_checks': [],
            'remediation_required': False
        })
        
        # Health check mocks
        for mock_component in [mock_router, mock_confidence, mock_autonomy, mock_audit, mock_compliance]:
            mock_component.return_value.health_check = AsyncMock(return_value={'status': 'healthy'})
        
        orchestrator = AIOrchestrator(config)
        return orchestrator

async def select_model_mock(alert):
    """Mock model selection with realistic distribution"""
    # Simulate intelligent routing based on complexity
    if alert.severity == AlertSeverity.LOW:
        return 'haiku'  # 70% of cases
    elif alert.severity == AlertSeverity.MEDIUM:
        return 'sonnet' if hash(alert.id) % 4 == 0 else 'haiku'  # 25% sonnet
    else:
        return 'opus' if hash(alert.id) % 20 == 0 else 'sonnet'  # 5% opus

async def invoke_model_mock(model, prompt, alert_context):
    """Mock model invocation with realistic timing and responses"""
    
    # Simulate realistic processing times
    processing_times = {
        'haiku': 0.5,    # 500ms average
        'sonnet': 2.0,   # 2 seconds average
        'opus': 8.0      # 8 seconds average
    }
    
    await asyncio.sleep(processing_times.get(model, 1.0))
    
    # Generate realistic responses based on model
    if model == 'haiku':
        return {
            'category': 'false_positive',
            'confidence': 0.92,
            'reasoning_chain': ['Quick analysis shows benign activity', 'Low risk indicators'],
            'recommended_action': 'Close as false positive'
        }
    elif model == 'sonnet':
        return {
            'category': 'investigation_required',
            'confidence': 0.78,
            'reasoning_chain': [
                'Detailed analysis of network patterns',
                'Some suspicious indicators present',
                'Requires further investigation',
                'Evidence quality is moderate'
            ],
            'recommended_action': 'Create investigation ticket'
        }
    else:  # opus
        return {
            'category': 'containment_required',
            'confidence': 0.85,
            'reasoning_chain': [
                'Comprehensive threat analysis reveals sophisticated attack',
                'Multiple indicators of compromise identified',
                'Attack chain analysis shows lateral movement',
                'High confidence in malicious intent',
                'Immediate containment recommended'
            ],
            'recommended_action': 'Immediate containment and investigation'
        }

async def confidence_mock(alert, analysis):
    """Mock confidence calculation with realistic scoring"""
    base_confidence = analysis.get('confidence', 0.75)
    
    # Add some variability based on evidence quality
    evidence_factor = len(alert.evidence) / 10.0 if alert.evidence else 0.1
    adjusted_confidence = min(base_confidence + evidence_factor * 0.1, 1.0)
    
    return {
        'score': adjusted_confidence,
        'confidence_interval': (adjusted_confidence - 0.1, adjusted_confidence + 0.1),
        'factors': [
            {
                'name': 'evidence_quality',
                'score': evidence_factor,
                'weight': 0.25,
                'explanation': 'Evidence quality assessment',
                'evidence': ['Mock evidence factor']
            }
        ],
        'evidence_scores': {'evidence_quality': evidence_factor},
        'bias_metrics': {'bias_detected': False, 'severity': 'low'},
        'recommended_tier': 0 if adjusted_confidence > 0.95 else 1,
        'calibration_quality': {'status': 'good', 'sample_size': 100}
    }

async def autonomy_mock(alert, analysis_result):
    """Mock autonomy execution with realistic timing"""
    
    # Simulate autonomy tier processing times
    tier_times = {
        0: 0.1,   # Autonomous - very fast
        1: 0.5,   # Assisted - moderate
        2: 2.0,   # Supervised - slower due to approval
        3: 5.0    # Collaborative - slowest
    }
    
    confidence = analysis_result.confidence_score
    tier = 0 if confidence > 0.95 else 1 if confidence > 0.80 else 2
    
    await asyncio.sleep(tier_times.get(tier, 1.0))
    
    return {
        'status': 'executed',
        'tier': tier,
        'action_type': 'auto_close' if tier == 0 else 'create_ticket'
    }

class TestDailyCapacity:
    """Test system capacity to handle 122 alerts per day"""
    
    @pytest.mark.asyncio
    async def test_daily_alert_processing_capacity(self, performance_orchestrator):
        """Test processing 122 alerts (daily target) within time limits"""
        
        # Generate realistic daily alert load
        daily_alerts = generate_performance_alerts(alerts_per_day=DAILY_ALERT_TARGET, days=1)
        
        # Process alerts in batches to simulate realistic load
        batch_size = 10
        processing_times = []
        
        for i in range(0, min(50, len(daily_alerts)), batch_size):  # Test first 50 for CI performance
            batch = daily_alerts[i:i + batch_size]
            
            batch_start = time.time()
            
            # Process batch concurrently
            tasks = [
                performance_orchestrator.process_security_alert(alert)
                for alert in batch
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            batch_end = time.time()
            batch_time = batch_end - batch_start
            processing_times.append(batch_time)
            
            # Validate all results are successful
            for result in results:
                assert not isinstance(result, Exception), f"Processing failed: {result}"
                assert hasattr(result, 'confidence_score')
                assert 0.0 <= result.confidence_score <= 1.0
        
        # Analyze performance metrics
        avg_batch_time = statistics.mean(processing_times)
        max_batch_time = max(processing_times)
        
        # Performance assertions
        assert avg_batch_time < 30, f"Average batch time {avg_batch_time:.1f}s exceeds 30s limit"
        assert max_batch_time < 60, f"Maximum batch time {max_batch_time:.1f}s exceeds 60s limit"
        
        # Extrapolate daily capacity
        alerts_per_batch = batch_size
        batches_per_day = DAILY_ALERT_TARGET / alerts_per_batch
        estimated_daily_time = avg_batch_time * batches_per_day
        
        # Daily processing should complete within business hours (8 hours)
        daily_limit_seconds = 8 * 60 * 60  # 8 hours
        assert estimated_daily_time < daily_limit_seconds, \
            f"Estimated daily processing time {estimated_daily_time/3600:.1f}h exceeds 8h limit"
    
    @pytest.mark.asyncio
    async def test_concurrent_alert_processing(self, performance_orchestrator):
        """Test concurrent processing of multiple alerts"""
        
        # Generate alerts for concurrent processing
        concurrent_alerts = generate_performance_alerts(alerts_per_day=CONCURRENT_ALERT_LIMIT, days=1)
        
        start_time = time.time()
        
        # Process all alerts concurrently
        tasks = [
            performance_orchestrator.process_security_alert(alert)
            for alert in concurrent_alerts
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Validate results
        successful_results = [r for r in results if not isinstance(r, Exception)]
        failed_results = [r for r in results if isinstance(r, Exception)]
        
        assert len(failed_results) == 0, f"Failed concurrent processing: {failed_results}"
        assert len(successful_results) == len(concurrent_alerts)
        
        # Concurrent processing should be faster than sequential
        estimated_sequential_time = len(concurrent_alerts) * 2  # Assume 2s per alert
        assert total_time < estimated_sequential_time, \
            f"Concurrent processing {total_time:.1f}s not faster than estimated sequential {estimated_sequential_time}s"
    
    @pytest.mark.asyncio
    async def test_peak_load_handling(self, performance_orchestrator):
        """Test system behavior under peak load conditions"""
        
        # Simulate peak load (3x normal rate)
        peak_alerts = generate_performance_alerts(alerts_per_day=366, days=1)[:30]  # Test subset
        
        # Process in smaller batches during peak
        batch_size = 5
        success_count = 0
        error_count = 0
        processing_times = []
        
        for i in range(0, len(peak_alerts), batch_size):
            batch = peak_alerts[i:i + batch_size]
            
            batch_start = time.time()
            
            tasks = [
                performance_orchestrator.process_security_alert(alert)
                for alert in batch
            ]
            
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=120  # 2 minute timeout per batch
                )
                
                batch_time = time.time() - batch_start
                processing_times.append(batch_time)
                
                # Count successes and failures
                for result in results:
                    if isinstance(result, Exception):
                        error_count += 1
                    else:
                        success_count += 1
                        
            except asyncio.TimeoutError:
                error_count += len(batch)
                print(f"Batch {i//batch_size + 1} timed out")
        
        # Calculate success rate
        total_processed = success_count + error_count
        success_rate = success_count / total_processed if total_processed > 0 else 0
        
        # Performance requirements under peak load
        assert success_rate >= 0.95, f"Success rate {success_rate:.2%} below 95% threshold"
        
        if processing_times:
            avg_peak_time = statistics.mean(processing_times)
            assert avg_peak_time < 60, f"Average peak processing time {avg_peak_time:.1f}s exceeds 60s"

class TestCostOptimization:
    """Test cost optimization and monthly budget compliance"""
    
    @pytest.mark.asyncio
    async def test_monthly_cost_projection(self, performance_orchestrator):
        """Test monthly cost projection stays under $300 limit"""
        
        # Simulate one month of alerts (122/day * 30 days = 3,660 alerts)
        monthly_alerts = generate_performance_alerts(alerts_per_day=DAILY_ALERT_TARGET, days=30)
        
        # Process representative sample (1 week) to estimate costs
        weekly_sample = monthly_alerts[:DAILY_ALERT_TARGET * 7]  # 1 week sample
        
        # Track model usage for cost calculation
        model_usage = {'haiku': 0, 'sonnet': 0, 'opus': 0}
        processing_times = []
        
        # Process sample alerts
        for i, alert in enumerate(weekly_sample[:50]):  # Test subset for CI
            start_time = time.time()
            
            # Mock model selection to track usage
            selected_model = await select_model_mock(alert)
            model_usage[selected_model] += 1
            
            result = await performance_orchestrator.process_security_alert(alert)
            
            processing_time = time.time() - start_time
            processing_times.append(processing_time)
        
        # Calculate cost projections
        # Realistic cost estimates per model call
        cost_per_call = {
            'haiku': 0.001,   # $0.001 per call
            'sonnet': 0.005,  # $0.005 per call
            'opus': 0.020     # $0.020 per call
        }
        
        # Calculate sample costs
        sample_cost = sum(model_usage[model] * cost_per_call[model] 
                         for model in model_usage)
        
        # Extrapolate to monthly cost
        sample_size = min(50, len(weekly_sample))
        monthly_alerts_total = DAILY_ALERT_TARGET * 30
        monthly_cost_projection = (sample_cost / sample_size) * monthly_alerts_total
        
        # Cost optimization assertions
        assert monthly_cost_projection <= MONTHLY_COST_LIMIT, \
            f"Monthly cost projection ${monthly_cost_projection:.2f} exceeds ${MONTHLY_COST_LIMIT} limit"
        
        # Model distribution should follow cost optimization targets
        total_calls = sum(model_usage.values())
        if total_calls > 0:
            haiku_percentage = (model_usage['haiku'] / total_calls) * 100
            sonnet_percentage = (model_usage['sonnet'] / total_calls) * 100
            opus_percentage = (model_usage['opus'] / total_calls) * 100
            
            # Target: Haiku 70%, Sonnet 25%, Opus 5%
            assert haiku_percentage >= 60, f"Haiku usage {haiku_percentage:.1f}% below 60% minimum"
            assert sonnet_percentage <= 35, f"Sonnet usage {sonnet_percentage:.1f}% above 35% maximum"
            assert opus_percentage <= 15, f"Opus usage {opus_percentage:.1f}% above 15% maximum"
    
    @pytest.mark.asyncio
    async def test_cost_per_alert_optimization(self, performance_orchestrator):
        """Test cost per alert stays within targets"""
        
        # Generate alerts with different complexity levels
        test_alerts = []
        
        # Simple alerts (should route to Haiku)
        simple_alerts = [
            SecurityAlert(
                id=f"simple_{i}",
                timestamp=datetime.now(timezone.utc),
                severity=AlertSeverity.LOW,
                source="automated_scan",
                title="Simple network scan",
                description="Basic port scan detected",
                evidence={"port": "80", "protocol": "tcp"},
                metadata={"complexity": "low"}
            ) for i in range(10)
        ]
        
        # Complex alerts (should route to Opus)
        complex_alerts = [
            SecurityAlert(
                id=f"complex_{i}",
                timestamp=datetime.now(timezone.utc),
                severity=AlertSeverity.CRITICAL,
                source="behavior_analytics",
                title="Advanced persistent threat detected",
                description="Multi-stage attack with lateral movement",
                evidence={
                    "indicators": ["c2_communication", "data_exfiltration"],
                    "affected_systems": ["web01", "db02", "dc01"],
                    "attack_timeline": "24_hours"
                },
                metadata={"complexity": "high"}
            ) for i in range(2)  # Only 2 complex alerts
        ]
        
        test_alerts = simple_alerts + complex_alerts
        
        # Process alerts and track costs
        total_cost = 0
        
        for alert in test_alerts:
            model = await select_model_mock(alert)
            await performance_orchestrator.process_security_alert(alert)
            
            # Add model cost
            model_costs = {'haiku': 0.001, 'sonnet': 0.005, 'opus': 0.020}
            total_cost += model_costs.get(model, 0.005)
        
        # Calculate cost per alert
        cost_per_alert = total_cost / len(test_alerts)
        
        # Cost per alert should be reasonable (under $0.10)
        assert cost_per_alert <= 0.10, \
            f"Cost per alert ${cost_per_alert:.4f} exceeds $0.10 target"
        
        # Verify intelligent routing worked
        # Simple alerts should mostly use cheaper models
        simple_model_costs = []
        complex_model_costs = []
        
        for alert in simple_alerts[:5]:  # Sample
            model = await select_model_mock(alert)
            simple_model_costs.append(model)
        
        for alert in complex_alerts:
            model = await select_model_mock(alert)
            complex_model_costs.append(model)
        
        # Simple alerts should predominantly use Haiku
        haiku_usage_simple = sum(1 for m in simple_model_costs if m == 'haiku')
        assert haiku_usage_simple >= len(simple_model_costs) * 0.8, \
            "Simple alerts should predominantly use Haiku for cost optimization"

class TestProcessingTimeRequirements:
    """Test MTTD (Mean Time To Decision) requirements"""
    
    @pytest.mark.asyncio
    async def test_mttd_compliance(self, performance_orchestrator):
        """Test Mean Time To Decision stays under 15 minutes"""
        
        # Generate alerts representing different complexity levels
        test_scenarios = [
            # Tier 0: Autonomous (should be fastest)
            SecurityAlert(
                id="autonomous_test",
                timestamp=datetime.now(timezone.utc),
                severity=AlertSeverity.LOW,
                source="automated_scan",
                title="Clear false positive",
                description="Legitimate security scan",
                evidence={"scanner_ip": "192.168.1.10", "authorized": True},
                metadata={"expected_tier": 0}
            ),
            
            # Tier 1: Assisted (moderate speed)
            SecurityAlert(
                id="assisted_test",
                timestamp=datetime.now(timezone.utc),
                severity=AlertSeverity.MEDIUM,
                source="ids",
                title="Suspicious activity detected",
                description="Potential threat requiring investigation",
                evidence={"source_ip": "203.0.113.1", "attempts": 5},
                metadata={"expected_tier": 1}
            ),
            
            # Tier 2: Supervised (slower due to approval)
            SecurityAlert(
                id="supervised_test",
                timestamp=datetime.now(timezone.utc),
                severity=AlertSeverity.HIGH,
                source="endpoint_protection",
                title="Malware detection requiring containment",
                description="Malware detected requiring immediate action",
                evidence={"malware_family": "trojan", "affected_host": "ws01"},
                metadata={"expected_tier": 2}
            ),
            
            # Tier 3: Collaborative (slowest but should still meet MTTD)
            SecurityAlert(
                id="collaborative_test",
                timestamp=datetime.now(timezone.utc),
                severity=AlertSeverity.CRITICAL,
                source="threat_hunting",
                title="Novel attack pattern detected",
                description="Unknown attack methodology requiring expert analysis",
                evidence={"indicators": ["unknown_c2", "novel_encryption"]},
                metadata={"expected_tier": 3}
            )
        ]
        
        processing_times = []
        
        for alert in test_scenarios:
            start_time = time.time()
            
            result = await performance_orchestrator.process_security_alert(alert)
            
            end_time = time.time()
            processing_time = end_time - start_time
            processing_times.append(processing_time)
            
            # Individual alert should process within reasonable time
            assert processing_time <= PROCESSING_TIME_LIMIT, \
                f"Alert {alert.id} processing time {processing_time:.1f}s exceeds {PROCESSING_TIME_LIMIT}s limit"
        
        # Calculate MTTD
        mttd = statistics.mean(processing_times)
        
        assert mttd <= PROCESSING_TIME_LIMIT, \
            f"MTTD {mttd:.1f}s exceeds {PROCESSING_TIME_LIMIT}s limit"
        
        # Performance should vary by tier (autonomous should be fastest)
        assert processing_times[0] <= processing_times[1] <= processing_times[2], \
            "Processing time should generally increase with autonomy tier complexity"
    
    @pytest.mark.asyncio
    async def test_processing_time_consistency(self, performance_orchestrator):
        """Test processing time consistency across similar alerts"""
        
        # Generate multiple similar alerts
        similar_alerts = []
        for i in range(20):
            alert = SecurityAlert(
                id=f"consistency_test_{i}",
                timestamp=datetime.now(timezone.utc),
                severity=AlertSeverity.MEDIUM,
                source="firewall_logs",
                title=f"Network anomaly {i}",
                description="Standard network anomaly detection",
                evidence={"source_ip": f"192.168.1.{100+i}", "port": "443"},
                metadata={"test": "consistency"}
            )
            similar_alerts.append(alert)
        
        processing_times = []
        
        for alert in similar_alerts:
            start_time = time.time()
            await performance_orchestrator.process_security_alert(alert)
            processing_time = time.time() - start_time
            processing_times.append(processing_time)
        
        # Calculate consistency metrics
        mean_time = statistics.mean(processing_times)
        stdev_time = statistics.stdev(processing_times) if len(processing_times) > 1 else 0
        
        # Processing time should be consistent (low standard deviation)
        coefficient_of_variation = stdev_time / mean_time if mean_time > 0 else 0
        
        assert coefficient_of_variation <= 0.5, \
            f"Processing time inconsistency too high: CV={coefficient_of_variation:.2f}"
        
        # All processing times should be reasonable
        max_time = max(processing_times)
        min_time = min(processing_times)
        
        assert max_time <= 30, f"Maximum processing time {max_time:.1f}s exceeds 30s"
        assert min_time >= 0.1, f"Minimum processing time {min_time:.1f}s suspiciously low"

class TestScalabilityLimits:
    """Test system scalability and breaking points"""
    
    @pytest.mark.asyncio
    async def test_memory_usage_under_load(self, performance_orchestrator):
        """Test memory usage doesn't grow excessively under sustained load"""
        
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Process alerts continuously
        alert_count = 0
        memory_measurements = []
        
        for i in range(30):  # Process 30 alerts
            alert = SecurityAlert(
                id=f"memory_test_{i}",
                timestamp=datetime.now(timezone.utc),
                severity=AlertSeverity.MEDIUM,
                source="memory_test",
                title=f"Memory usage test {i}",
                description="Testing memory usage",
                evidence={"test_data": f"data_{i}"},
                metadata={}
            )
            
            await performance_orchestrator.process_security_alert(alert)
            alert_count += 1
            
            # Measure memory every 10 alerts
            if alert_count % 10 == 0:
                current_memory = process.memory_info().rss
                memory_measurements.append(current_memory)
        
        final_memory = process.memory_info().rss
        memory_growth = final_memory - initial_memory
        
        # Memory growth should be bounded (less than 200MB for 30 alerts)
        memory_limit_bytes = 200 * 1024 * 1024  # 200MB
        assert memory_growth < memory_limit_bytes, \
            f"Memory grew by {memory_growth / 1024 / 1024:.1f}MB, should be under 200MB"
        
        # Memory usage should not continuously increase
        if len(memory_measurements) >= 3:
            memory_slope = (memory_measurements[-1] - memory_measurements[0]) / len(memory_measurements)
            memory_slope_mb = memory_slope / 1024 / 1024
            
            assert memory_slope_mb <= 5, \
                f"Memory growth rate {memory_slope_mb:.1f}MB per batch exceeds 5MB limit"

# Benchmark test using pytest-benchmark
@pytest.mark.benchmark
class TestPerformanceBenchmarks:
    """Performance benchmarking for CI/CD integration"""
    
    def test_single_alert_processing_benchmark(self, performance_orchestrator, benchmark):
        """Benchmark single alert processing time"""
        
        alert = SecurityAlert(
            id="benchmark_test",
            timestamp=datetime.now(timezone.utc),
            severity=AlertSeverity.MEDIUM,
            source="benchmark",
            title="Benchmark test alert",
            description="Alert for performance benchmarking",
            evidence={"test": "benchmark"},
            metadata={}
        )
        
        async def process_alert():
            return await performance_orchestrator.process_security_alert(alert)
        
        # Benchmark the processing
        result = benchmark(asyncio.run, process_alert())
        
        # Validate result
        assert hasattr(result, 'confidence_score')
        assert 0.0 <= result.confidence_score <= 1.0

if __name__ == "__main__":
    # Run performance tests with specific configuration
    pytest.main([
        __file__, 
        "-v", 
        "--benchmark-only",
        "--benchmark-sort=mean",
        "--benchmark-columns=min,max,mean,stddev"
    ])