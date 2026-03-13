"""
AI Orchestration Engine - Core system for SecOps AI Platform
Implements Claude multi-model routing with graduated autonomy
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum

from .model_router import ModelRouter
from .confidence_engine import ConfidenceEngine
from .audit_logger import AuditLogger
from ..autonomy_tiers.controller import AutonomyController
from ..governance.compliance import ComplianceEngine

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AlertSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertCategory(Enum):
    FALSE_POSITIVE = "false_positive"
    INVESTIGATION_REQUIRED = "investigation_required"
    CONTAINMENT_REQUIRED = "containment_required"
    NOVEL_THREAT = "novel_threat"

@dataclass
class SecurityAlert:
    """Security alert data structure"""
    id: str
    timestamp: datetime
    severity: AlertSeverity
    source: str
    title: str
    description: str
    evidence: Dict[str, Any]
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            'timestamp': self.timestamp.isoformat(),
            'severity': self.severity.value
        }

@dataclass
class AnalysisResult:
    """AI analysis result with confidence scoring"""
    alert_id: str
    analysis_id: str
    timestamp: datetime
    category: AlertCategory
    confidence_score: float
    reasoning_chain: List[str]
    evidence_assessment: Dict[str, float]
    recommended_action: str
    model_used: str
    processing_time_ms: int
    
class AIOrchestrator:
    """
    Main AI orchestration engine for SecOps platform
    Coordinates model routing, confidence scoring, and autonomy tiers
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize AI orchestration components"""
        self.config = config
        self.model_router = ModelRouter(config.get('bedrock_config', {}))
        self.confidence_engine = ConfidenceEngine(config.get('confidence_config', {}))
        self.autonomy_controller = AutonomyController(config.get('autonomy_config', {}))
        self.audit_logger = AuditLogger(config.get('audit_config', {}))
        self.compliance_engine = ComplianceEngine(config.get('compliance_config', {}))
        
        # Performance metrics
        self.metrics = {
            'alerts_processed': 0,
            'autonomy_tier_usage': {0: 0, 1: 0, 2: 0, 3: 0},
            'model_usage': {'haiku': 0, 'sonnet': 0, 'opus': 0},
            'average_processing_time': 0,
            'cost_tracking': {'daily': 0, 'monthly': 0}
        }
        
    async def process_security_alert(self, alert: SecurityAlert) -> AnalysisResult:
        """
        Main processing pipeline for security alerts
        1. Route to appropriate Claude model
        2. Generate AI analysis with reasoning
        3. Calculate confidence score
        4. Determine autonomy tier
        5. Execute appropriate action
        6. Log complete audit trail
        """
        start_time = datetime.now(timezone.utc)
        analysis_id = str(uuid.uuid4())
        
        try:
            # Step 1: Intelligent model routing based on complexity
            selected_model = await self.model_router.select_model(alert)
            logger.info(f"Alert {alert.id}: Routed to {selected_model}")
            
            # Step 2: Generate AI analysis
            analysis = await self._generate_analysis(alert, selected_model)
            
            # Step 3: Calculate multi-factor confidence score
            confidence_result = await self.confidence_engine.calculate_confidence(
                alert, analysis
            )
            
            # Step 4: Determine category and recommended action
            category, action = await self._determine_action(analysis, confidence_result)
            
            # Step 5: Create analysis result
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            
            result = AnalysisResult(
                alert_id=alert.id,
                analysis_id=analysis_id,
                timestamp=start_time,
                category=category,
                confidence_score=confidence_result['score'],
                reasoning_chain=analysis['reasoning_chain'],
                evidence_assessment=confidence_result['evidence_scores'],
                recommended_action=action,
                model_used=selected_model,
                processing_time_ms=int(processing_time)
            )
            
            # Step 6: Apply autonomy tier logic
            await self.autonomy_controller.execute_action(alert, result)
            
            # Step 7: Audit logging for compliance
            await self.audit_logger.log_decision(alert, result, {
                'model_reasoning': analysis,
                'confidence_breakdown': confidence_result,
                'compliance_checks': await self.compliance_engine.validate_decision(result)
            })
            
            # Update metrics
            self._update_metrics(result)
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing alert {alert.id}: {str(e)}")
            # Log error for audit trail
            await self.audit_logger.log_error(alert.id, analysis_id, str(e))
            raise
    
    async def _generate_analysis(self, alert: SecurityAlert, model: str) -> Dict[str, Any]:
        """Generate AI analysis using selected Claude model"""
        
        # Construct analysis prompt
        prompt = self._build_analysis_prompt(alert)
        
        # Call Claude model via Bedrock
        response = await self.model_router.invoke_model(
            model=model,
            prompt=prompt,
            alert_context=alert.to_dict()
        )
        
        return response
    
    def _build_analysis_prompt(self, alert: SecurityAlert) -> str:
        """Build comprehensive analysis prompt for Claude"""
        return f"""
You are an expert SOC analyst reviewing a security alert. Provide a comprehensive analysis with step-by-step reasoning.

ALERT DETAILS:
- ID: {alert.id}
- Severity: {alert.severity.value}
- Source: {alert.source}
- Title: {alert.title}
- Description: {alert.description}
- Evidence: {alert.evidence}

ANALYSIS REQUIREMENTS:
1. Assess if this is a legitimate security threat or false positive
2. Evaluate the quality and completeness of evidence
3. Identify any patterns or similarities to known threats
4. Consider the potential impact if this is a real threat
5. Recommend specific next steps

OUTPUT FORMAT:
- Category: [false_positive|investigation_required|containment_required|novel_threat]
- Confidence: [0-100]
- Reasoning: [Step-by-step analysis with evidence]
- Risk Assessment: [Low|Medium|High|Critical]
- Recommended Action: [Specific next steps]

Provide clear, actionable analysis with explicit reasoning for each conclusion.
"""
    
    async def _determine_action(self, analysis: Dict[str, Any], 
                               confidence_result: Dict[str, Any]) -> Tuple[AlertCategory, str]:
        """Determine alert category and recommended action based on analysis"""
        
        category_mapping = {
            'false_positive': AlertCategory.FALSE_POSITIVE,
            'investigation_required': AlertCategory.INVESTIGATION_REQUIRED,
            'containment_required': AlertCategory.CONTAINMENT_REQUIRED,
            'novel_threat': AlertCategory.NOVEL_THREAT
        }
        
        predicted_category = analysis.get('category', 'investigation_required')
        category = category_mapping.get(predicted_category, AlertCategory.INVESTIGATION_REQUIRED)
        
        action = analysis.get('recommended_action', 'Manual review required')
        
        return category, action
    
    def _update_metrics(self, result: AnalysisResult):
        """Update performance and usage metrics"""
        self.metrics['alerts_processed'] += 1
        self.metrics['model_usage'][result.model_used] += 1
        
        # Update average processing time
        current_avg = self.metrics['average_processing_time']
        total_alerts = self.metrics['alerts_processed']
        new_avg = ((current_avg * (total_alerts - 1)) + result.processing_time_ms) / total_alerts
        self.metrics['average_processing_time'] = new_avg
    
    async def get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance and cost metrics"""
        return {
            **self.metrics,
            'cost_efficiency': await self._calculate_cost_efficiency(),
            'autonomy_distribution': self._calculate_autonomy_distribution(),
            'compliance_status': await self.compliance_engine.get_status()
        }
    
    async def _calculate_cost_efficiency(self) -> Dict[str, float]:
        """Calculate cost efficiency metrics"""
        # Implementation would track actual AWS Bedrock costs
        # For now, return estimated costs based on usage
        model_costs = {
            'haiku': self.metrics['model_usage']['haiku'] * 0.001,  # $0.001 per call estimate
            'sonnet': self.metrics['model_usage']['sonnet'] * 0.005,  # $0.005 per call estimate  
            'opus': self.metrics['model_usage']['opus'] * 0.020     # $0.020 per call estimate
        }
        
        total_cost = sum(model_costs.values())
        alerts_processed = max(self.metrics['alerts_processed'], 1)
        cost_per_alert = total_cost / alerts_processed
        
        return {
            'total_cost_usd': total_cost,
            'cost_per_alert_usd': cost_per_alert,
            'monthly_projection_usd': total_cost * 30,
            'model_cost_breakdown': model_costs
        }
    
    def _calculate_autonomy_distribution(self) -> Dict[str, float]:
        """Calculate autonomy tier usage distribution"""
        total_usage = sum(self.metrics['autonomy_tier_usage'].values())
        if total_usage == 0:
            return {f'tier_{i}_percent': 0.0 for i in range(4)}
        
        return {
            f'tier_{tier}_percent': (usage / total_usage) * 100
            for tier, usage in self.metrics['autonomy_tier_usage'].items()
        }

    async def health_check(self) -> Dict[str, Any]:
        """Comprehensive system health check"""
        return {
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'components': {
                'model_router': await self.model_router.health_check(),
                'confidence_engine': await self.confidence_engine.health_check(),
                'autonomy_controller': await self.autonomy_controller.health_check(),
                'audit_logger': await self.audit_logger.health_check(),
                'compliance_engine': await self.compliance_engine.health_check()
            },
            'metrics': await self.get_performance_metrics()
        }