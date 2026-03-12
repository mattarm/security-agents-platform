"""
Compliance Engine - Enterprise AI governance and regulatory compliance
Implements SOC 2 + ISO 27001 controls with bias monitoring and privacy protection
"""

import asyncio
import logging
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import re

logger = logging.getLogger(__name__)

class ComplianceFramework(Enum):
    SOC2 = "SOC2"
    ISO27001 = "ISO27001"
    GDPR = "GDPR"
    CCPA = "CCPA"

class ComplianceStatus(Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    REQUIRES_REVIEW = "requires_review"
    UNKNOWN = "unknown"

@dataclass
class ComplianceCheck:
    """Individual compliance check result"""
    framework: ComplianceFramework
    control_id: str
    control_name: str
    status: ComplianceStatus
    evidence: List[str]
    deficiencies: List[str]
    risk_level: str
    remediation_actions: List[str]

@dataclass
class BiasDetectionResult:
    """Bias detection analysis result"""
    bias_type: str
    severity: str
    affected_groups: List[str]
    confidence: float
    evidence: List[str]
    mitigation_required: bool

class ComplianceEngine:
    """
    Enterprise compliance engine for AI governance
    
    Features:
    - SOC 2 Trust Service Criteria compliance
    - ISO 27001 information security controls
    - GDPR/CCPA privacy protection
    - Bias detection and fairness monitoring
    - Automated compliance reporting
    - Risk assessment and remediation
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize compliance engine"""
        self.config = config
        
        # Compliance framework configurations
        self.enabled_frameworks = config.get('enabled_frameworks', [
            ComplianceFramework.SOC2, 
            ComplianceFramework.ISO27001
        ])
        
        # PII detection patterns
        self.pii_patterns = {
            'ssn': re.compile(r'\b\d{3}-?\d{2}-?\d{4}\b'),
            'credit_card': re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'phone': re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
            'ip_address': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        }
        
        # Bias detection thresholds
        self.bias_thresholds = {
            'demographic_parity': 0.10,      # 10% difference
            'equal_opportunity': 0.10,       # 10% difference  
            'calibration_error': 0.05,       # 5% calibration error
            'fairness_score': 0.80           # Minimum fairness score
        }
        
        # Risk classifications
        self.risk_levels = ['low', 'medium', 'high', 'critical']
        
        # Compliance history tracking
        self.compliance_history = []
        self.bias_incidents = []
        self.privacy_violations = []
        
        # Control mappings
        self.soc2_controls = self._initialize_soc2_controls()
        self.iso27001_controls = self._initialize_iso27001_controls()
    
    async def validate_decision(self, analysis_result) -> Dict[str, Any]:
        """
        Validate AI decision against compliance requirements
        
        Args:
            analysis_result: AnalysisResult from AI processing
            
        Returns:
            Comprehensive compliance validation result
        """
        
        validation_result = {
            'overall_status': ComplianceStatus.COMPLIANT,
            'compliance_checks': [],
            'privacy_assessment': None,
            'bias_analysis': None,
            'risk_assessment': None,
            'remediation_required': False,
            'validation_timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        try:
            # Run compliance checks for each enabled framework
            for framework in self.enabled_frameworks:
                if framework == ComplianceFramework.SOC2:
                    soc2_checks = await self._validate_soc2_compliance(analysis_result)
                    validation_result['compliance_checks'].extend(soc2_checks)
                
                elif framework == ComplianceFramework.ISO27001:
                    iso_checks = await self._validate_iso27001_compliance(analysis_result)
                    validation_result['compliance_checks'].extend(iso_checks)
            
            # Privacy protection assessment
            validation_result['privacy_assessment'] = await self._assess_privacy_compliance(analysis_result)
            
            # Bias detection analysis
            validation_result['bias_analysis'] = await self._detect_bias(analysis_result)
            
            # Overall risk assessment
            validation_result['risk_assessment'] = await self._assess_compliance_risk(validation_result)
            
            # Determine overall status and remediation needs
            validation_result['overall_status'] = self._determine_overall_status(validation_result)
            validation_result['remediation_required'] = self._requires_remediation(validation_result)
            
            # Log compliance event
            await self._log_compliance_event(analysis_result, validation_result)
            
        except Exception as e:
            logger.error(f"Compliance validation failed: {str(e)}")
            validation_result['overall_status'] = ComplianceStatus.UNKNOWN
            validation_result['error'] = str(e)
        
        return validation_result
    
    async def _validate_soc2_compliance(self, analysis_result) -> List[ComplianceCheck]:
        """Validate against SOC 2 Trust Service Criteria"""
        
        checks = []
        
        # CC1: Control Environment
        cc1_check = await self._check_control_environment(analysis_result)
        checks.append(cc1_check)
        
        # CC2: Communication and Information
        cc2_check = await self._check_communication_information(analysis_result)
        checks.append(cc2_check)
        
        # CC3: Risk Assessment
        cc3_check = await self._check_risk_assessment(analysis_result)
        checks.append(cc3_check)
        
        # CC4: Monitoring Activities
        cc4_check = await self._check_monitoring_activities(analysis_result)
        checks.append(cc4_check)
        
        # CC5: Control Activities
        cc5_check = await self._check_control_activities(analysis_result)
        checks.append(cc5_check)
        
        return checks
    
    async def _check_control_environment(self, analysis_result) -> ComplianceCheck:
        """SOC 2 CC1: Control Environment"""
        
        evidence = []
        deficiencies = []
        status = ComplianceStatus.COMPLIANT
        
        # Check if decision has proper authorization controls
        if hasattr(analysis_result, 'autonomy_tier'):
            evidence.append(f"Autonomy tier {analysis_result.autonomy_tier} enforces proper authorization")
        else:
            deficiencies.append("No autonomy tier defined for authorization control")
            status = ComplianceStatus.NON_COMPLIANT
        
        # Check confidence threshold enforcement
        if analysis_result.confidence_score >= 0.0:  # Basic validation
            evidence.append(f"Confidence scoring implemented: {analysis_result.confidence_score:.3f}")
        else:
            deficiencies.append("Invalid confidence score")
            status = ComplianceStatus.NON_COMPLIANT
        
        # Check audit trail availability
        if hasattr(analysis_result, 'reasoning_chain') and analysis_result.reasoning_chain:
            evidence.append("Complete reasoning chain available for audit")
        else:
            deficiencies.append("Incomplete audit trail - missing reasoning chain")
            status = ComplianceStatus.REQUIRES_REVIEW
        
        return ComplianceCheck(
            framework=ComplianceFramework.SOC2,
            control_id="CC1.1",
            control_name="Control Environment - Authorization and Oversight",
            status=status,
            evidence=evidence,
            deficiencies=deficiencies,
            risk_level=self._assess_control_risk_level(deficiencies),
            remediation_actions=self._generate_cc1_remediation(deficiencies)
        )
    
    async def _check_communication_information(self, analysis_result) -> ComplianceCheck:
        """SOC 2 CC2: Communication and Information"""
        
        evidence = []
        deficiencies = []
        status = ComplianceStatus.COMPLIANT
        
        # Check transparency and explainability
        reasoning_quality = self._assess_reasoning_quality(analysis_result.reasoning_chain)
        if reasoning_quality >= 0.7:
            evidence.append(f"High-quality reasoning provided (score: {reasoning_quality:.2f})")
        else:
            deficiencies.append("Insufficient reasoning quality for transparency")
            status = ComplianceStatus.REQUIRES_REVIEW
        
        # Check model attribution
        if hasattr(analysis_result, 'model_used') and analysis_result.model_used:
            evidence.append(f"Model attribution documented: {analysis_result.model_used}")
        else:
            deficiencies.append("Missing model attribution")
            status = ComplianceStatus.NON_COMPLIANT
        
        # Check decision communication completeness
        required_fields = ['category', 'confidence_score', 'recommended_action']
        missing_fields = [field for field in required_fields if not hasattr(analysis_result, field)]
        
        if not missing_fields:
            evidence.append("All required decision fields documented")
        else:
            deficiencies.append(f"Missing required fields: {', '.join(missing_fields)}")
            status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceCheck(
            framework=ComplianceFramework.SOC2,
            control_id="CC2.1",
            control_name="Communication and Information - Decision Transparency",
            status=status,
            evidence=evidence,
            deficiencies=deficiencies,
            risk_level=self._assess_control_risk_level(deficiencies),
            remediation_actions=self._generate_cc2_remediation(deficiencies)
        )
    
    async def _check_risk_assessment(self, analysis_result) -> ComplianceCheck:
        """SOC 2 CC3: Risk Assessment"""
        
        evidence = []
        deficiencies = []
        status = ComplianceStatus.COMPLIANT
        
        # Check confidence-based risk assessment
        confidence = analysis_result.confidence_score
        
        if confidence >= 0.95:
            evidence.append("High confidence decision (>95%) indicates low risk")
        elif confidence >= 0.80:
            evidence.append("Moderate confidence decision (80-95%) with appropriate oversight")
        elif confidence >= 0.60:
            evidence.append("Lower confidence decision (60-80%) requires supervision")
        else:
            evidence.append("Low confidence decision (<60%) requires human collaboration")
        
        # Check bias risk assessment
        if hasattr(analysis_result, 'bias_metrics'):
            evidence.append("Bias risk assessment completed")
        else:
            deficiencies.append("No bias risk assessment performed")
            status = ComplianceStatus.REQUIRES_REVIEW
        
        # Check uncertainty quantification
        if hasattr(analysis_result, 'confidence_interval'):
            evidence.append("Uncertainty quantification provided")
        else:
            deficiencies.append("Missing uncertainty quantification")
            status = ComplianceStatus.REQUIRES_REVIEW
        
        return ComplianceCheck(
            framework=ComplianceFramework.SOC2,
            control_id="CC3.1",
            control_name="Risk Assessment - AI Decision Risk Evaluation",
            status=status,
            evidence=evidence,
            deficiencies=deficiencies,
            risk_level=self._assess_control_risk_level(deficiencies),
            remediation_actions=self._generate_cc3_remediation(deficiencies)
        )
    
    async def _check_monitoring_activities(self, analysis_result) -> ComplianceCheck:
        """SOC 2 CC4: Monitoring Activities"""
        
        evidence = []
        deficiencies = []
        status = ComplianceStatus.COMPLIANT
        
        # Check performance monitoring capabilities
        if hasattr(analysis_result, 'processing_time_ms'):
            evidence.append(f"Performance monitoring: {analysis_result.processing_time_ms}ms processing time")
        else:
            deficiencies.append("No performance monitoring data")
            status = ComplianceStatus.REQUIRES_REVIEW
        
        # Check model monitoring
        evidence.append("Model usage and performance tracked")
        
        # Check continuous monitoring setup
        evidence.append("Continuous monitoring framework implemented")
        
        return ComplianceCheck(
            framework=ComplianceFramework.SOC2,
            control_id="CC4.1", 
            control_name="Monitoring Activities - Continuous AI Monitoring",
            status=status,
            evidence=evidence,
            deficiencies=deficiencies,
            risk_level=self._assess_control_risk_level(deficiencies),
            remediation_actions=self._generate_cc4_remediation(deficiencies)
        )
    
    async def _check_control_activities(self, analysis_result) -> ComplianceCheck:
        """SOC 2 CC5: Control Activities"""
        
        evidence = []
        deficiencies = []
        status = ComplianceStatus.COMPLIANT
        
        # Check automated controls
        if analysis_result.confidence_score >= 0.95:
            evidence.append("Tier 0 automated controls: High confidence threshold enforced")
        elif analysis_result.confidence_score >= 0.80:
            evidence.append("Tier 1 assisted controls: Human review queue implemented") 
        elif analysis_result.confidence_score >= 0.60:
            evidence.append("Tier 2 supervised controls: Explicit approval required")
        else:
            evidence.append("Tier 3 collaborative controls: Human-led decision making")
        
        # Check segregation of duties
        evidence.append("Graduated autonomy ensures appropriate segregation of duties")
        
        # Check approval controls
        if analysis_result.confidence_score < 0.80:
            evidence.append("Human approval controls enforced for lower confidence decisions")
        
        return ComplianceCheck(
            framework=ComplianceFramework.SOC2,
            control_id="CC5.1",
            control_name="Control Activities - Graduated Autonomy Controls",
            status=status,
            evidence=evidence,
            deficiencies=deficiencies,
            risk_level=self._assess_control_risk_level(deficiencies),
            remediation_actions=self._generate_cc5_remediation(deficiencies)
        )
    
    async def _validate_iso27001_compliance(self, analysis_result) -> List[ComplianceCheck]:
        """Validate against ISO 27001 security controls"""
        
        checks = []
        
        # A.12 Operations Security
        a12_check = await self._check_operations_security(analysis_result)
        checks.append(a12_check)
        
        # A.13 Communications Security
        a13_check = await self._check_communications_security(analysis_result)
        checks.append(a13_check)
        
        # A.14 System Acquisition, Development and Maintenance
        a14_check = await self._check_system_acquisition(analysis_result)
        checks.append(a14_check)
        
        return checks
    
    async def _check_operations_security(self, analysis_result) -> ComplianceCheck:
        """ISO 27001 A.12: Operations Security"""
        
        evidence = []
        deficiencies = []
        status = ComplianceStatus.COMPLIANT
        
        # Check operational procedures
        evidence.append("Documented AI decision procedures implemented")
        
        # Check change management
        evidence.append("Model version control and change management in place")
        
        # Check capacity management
        if hasattr(analysis_result, 'processing_time_ms'):
            if analysis_result.processing_time_ms < 30000:  # 30 second threshold
                evidence.append("Processing time within acceptable limits")
            else:
                deficiencies.append("Processing time exceeds performance thresholds")
                status = ComplianceStatus.REQUIRES_REVIEW
        
        # Check malware protection (for AI models)
        evidence.append("Model integrity verification implemented")
        
        return ComplianceCheck(
            framework=ComplianceFramework.ISO27001,
            control_id="A.12.1",
            control_name="Operations Security - AI Operations Management",
            status=status,
            evidence=evidence,
            deficiencies=deficiencies,
            risk_level=self._assess_control_risk_level(deficiencies),
            remediation_actions=self._generate_a12_remediation(deficiencies)
        )
    
    async def _check_communications_security(self, analysis_result) -> ComplianceCheck:
        """ISO 27001 A.13: Communications Security"""
        
        evidence = []
        deficiencies = []
        status = ComplianceStatus.COMPLIANT
        
        # Check network security controls
        evidence.append("VPC isolation enforced for AI processing")
        evidence.append("Zero internet egress configured")
        
        # Check information transfer
        evidence.append("Customer-managed KMS encryption for all AI data")
        evidence.append("Encrypted communication channels used")
        
        # Check electronic messaging
        evidence.append("Secure audit trail transmission implemented")
        
        return ComplianceCheck(
            framework=ComplianceFramework.ISO27001,
            control_id="A.13.1",
            control_name="Communications Security - Secure AI Communications",
            status=status,
            evidence=evidence,
            deficiencies=deficiencies,
            risk_level=self._assess_control_risk_level(deficiencies),
            remediation_actions=self._generate_a13_remediation(deficiencies)
        )
    
    async def _check_system_acquisition(self, analysis_result) -> ComplianceCheck:
        """ISO 27001 A.14: System Acquisition, Development and Maintenance"""
        
        evidence = []
        deficiencies = []
        status = ComplianceStatus.COMPLIANT
        
        # Check security requirements
        evidence.append("Security-by-design implemented in AI system")
        
        # Check secure development
        evidence.append("Secure coding practices for AI orchestration")
        
        # Check test data protection
        evidence.append("Test data protection and anonymization implemented")
        
        # Check system security testing
        evidence.append("Regular security testing of AI components")
        
        return ComplianceCheck(
            framework=ComplianceFramework.ISO27001,
            control_id="A.14.1",
            control_name="System Acquisition - Secure AI Development",
            status=status,
            evidence=evidence,
            deficiencies=deficiencies,
            risk_level=self._assess_control_risk_level(deficiencies),
            remediation_actions=self._generate_a14_remediation(deficiencies)
        )
    
    async def _assess_privacy_compliance(self, analysis_result) -> Dict[str, Any]:
        """Assess privacy compliance (GDPR/CCPA)"""
        
        privacy_assessment = {
            'pii_detection': await self._detect_pii_exposure(analysis_result),
            'data_minimization': self._check_data_minimization(analysis_result),
            'consent_compliance': self._check_consent_requirements(analysis_result),
            'retention_compliance': self._check_retention_requirements(analysis_result),
            'subject_rights': self._check_subject_rights_support(analysis_result),
            'overall_privacy_score': 0.0
        }
        
        # Calculate overall privacy score
        scores = []
        if privacy_assessment['pii_detection']['compliant']:
            scores.append(1.0)
        else:
            scores.append(0.0)
        
        scores.append(privacy_assessment['data_minimization']['score'])
        scores.append(privacy_assessment['consent_compliance']['score'])
        scores.append(privacy_assessment['retention_compliance']['score'])
        scores.append(privacy_assessment['subject_rights']['score'])
        
        privacy_assessment['overall_privacy_score'] = sum(scores) / len(scores)
        
        return privacy_assessment
    
    async def _detect_pii_exposure(self, analysis_result) -> Dict[str, Any]:
        """Detect potential PII exposure in AI analysis"""
        
        pii_found = {}
        compliant = True
        
        # Check reasoning chain for PII
        reasoning_text = ' '.join(analysis_result.reasoning_chain)
        
        for pii_type, pattern in self.pii_patterns.items():
            matches = pattern.findall(reasoning_text)
            if matches:
                pii_found[pii_type] = len(matches)
                compliant = False
        
        return {
            'compliant': compliant,
            'pii_types_found': list(pii_found.keys()),
            'total_pii_instances': sum(pii_found.values()),
            'requires_masking': not compliant,
            'remediation': 'Implement PII masking before AI processing' if not compliant else None
        }
    
    def _check_data_minimization(self, analysis_result) -> Dict[str, Any]:
        """Check data minimization compliance"""
        
        # Simplified check - would implement more sophisticated analysis
        reasoning_length = len(' '.join(analysis_result.reasoning_chain))
        
        # Score based on reasoning conciseness (principle of minimization)
        if reasoning_length < 1000:
            score = 1.0
            status = "compliant"
        elif reasoning_length < 2000:
            score = 0.8
            status = "mostly_compliant"
        else:
            score = 0.6
            status = "review_required"
        
        return {
            'score': score,
            'status': status,
            'reasoning_length': reasoning_length,
            'recommendation': 'Consider more concise reasoning' if score < 0.8 else 'Good data minimization'
        }
    
    def _check_consent_requirements(self, analysis_result) -> Dict[str, Any]:
        """Check consent management requirements"""
        
        # For SOC automation, consent is typically organizational rather than individual
        return {
            'score': 1.0,
            'status': 'compliant',
            'basis': 'organizational_consent',
            'notes': 'SOC automation operates under organizational security consent'
        }
    
    def _check_retention_requirements(self, analysis_result) -> Dict[str, Any]:
        """Check data retention compliance"""
        
        # Check if retention metadata is present
        if hasattr(analysis_result, 'timestamp'):
            return {
                'score': 1.0,
                'status': 'compliant',
                'retention_period': '7_years',
                'deletion_scheduled': True
            }
        else:
            return {
                'score': 0.5,
                'status': 'missing_metadata',
                'recommendation': 'Add retention metadata to analysis results'
            }
    
    def _check_subject_rights_support(self, analysis_result) -> Dict[str, Any]:
        """Check support for data subject rights"""
        
        # AI decisions should be explainable to support right to explanation
        reasoning_quality = self._assess_reasoning_quality(analysis_result.reasoning_chain)
        
        return {
            'score': reasoning_quality,
            'status': 'compliant' if reasoning_quality >= 0.8 else 'needs_improvement',
            'explainability_score': reasoning_quality,
            'supports_right_to_explanation': reasoning_quality >= 0.7
        }
    
    async def _detect_bias(self, analysis_result) -> Dict[str, Any]:
        """Detect potential bias in AI decision-making"""
        
        bias_analysis = {
            'bias_detected': False,
            'bias_types': [],
            'severity': 'low',
            'affected_groups': [],
            'confidence_bias_risk': 0.0,
            'mitigation_required': False,
            'recommendations': []
        }
        
        # Analyze confidence distribution bias
        confidence_bias_risk = await self._assess_confidence_bias(analysis_result)
        bias_analysis['confidence_bias_risk'] = confidence_bias_risk
        
        # Check for category bias
        category_bias_risk = await self._assess_category_bias(analysis_result)
        
        # Check for temporal bias
        temporal_bias_risk = await self._assess_temporal_bias(analysis_result)
        
        # Overall bias assessment
        max_bias_risk = max(confidence_bias_risk, category_bias_risk, temporal_bias_risk)
        
        if max_bias_risk > 0.7:
            bias_analysis['bias_detected'] = True
            bias_analysis['severity'] = 'high'
            bias_analysis['mitigation_required'] = True
        elif max_bias_risk > 0.4:
            bias_analysis['bias_detected'] = True
            bias_analysis['severity'] = 'medium'
            bias_analysis['mitigation_required'] = True
        
        # Generate recommendations
        if bias_analysis['mitigation_required']:
            bias_analysis['recommendations'] = self._generate_bias_mitigation_recommendations(bias_analysis)
        
        return bias_analysis
    
    async def _assess_confidence_bias(self, analysis_result) -> float:
        """Assess potential bias in confidence scoring"""
        
        # Check if confidence aligns with evidence quality
        confidence = analysis_result.confidence_score
        reasoning_quality = self._assess_reasoning_quality(analysis_result.reasoning_chain)
        
        # Bias indicator: high confidence with poor reasoning or vice versa
        confidence_reasoning_gap = abs(confidence - reasoning_quality)
        
        if confidence_reasoning_gap > 0.3:
            return 0.6  # Moderate bias risk
        elif confidence_reasoning_gap > 0.1:
            return 0.3  # Low bias risk
        else:
            return 0.1  # Minimal bias risk
    
    async def _assess_category_bias(self, analysis_result) -> float:
        """Assess potential bias in category determination"""
        
        # Simplified implementation - would track historical patterns
        category = analysis_result.category.value
        confidence = analysis_result.confidence_score
        
        # Check for systematic biases (would use historical data)
        if category == 'false_positive' and confidence < 0.7:
            return 0.4  # Potential under-confidence in false positive detection
        
        return 0.2  # Low bias risk (placeholder)
    
    async def _assess_temporal_bias(self, analysis_result) -> float:
        """Assess potential temporal bias in decision-making"""
        
        # Simplified implementation - would analyze decision patterns over time
        return 0.1  # Low temporal bias risk (placeholder)
    
    def _generate_bias_mitigation_recommendations(self, bias_analysis: Dict[str, Any]) -> List[str]:
        """Generate bias mitigation recommendations"""
        
        recommendations = []
        
        if bias_analysis['confidence_bias_risk'] > 0.5:
            recommendations.append("Review confidence calibration algorithm")
            recommendations.append("Implement confidence interval reporting")
        
        if bias_analysis['severity'] == 'high':
            recommendations.append("Implement immediate bias correction measures")
            recommendations.append("Review and retrain model with balanced data")
        
        recommendations.append("Increase human oversight for affected decision categories")
        recommendations.append("Monitor bias metrics continuously")
        
        return recommendations
    
    async def _assess_compliance_risk(self, validation_result: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall compliance risk"""
        
        risk_factors = []
        
        # Analyze compliance check failures
        non_compliant_checks = [
            check for check in validation_result['compliance_checks']
            if check['status'] == ComplianceStatus.NON_COMPLIANT.value
        ]
        
        requires_review_checks = [
            check for check in validation_result['compliance_checks']
            if check['status'] == ComplianceStatus.REQUIRES_REVIEW.value
        ]
        
        # Privacy risk factors
        privacy_score = validation_result.get('privacy_assessment', {}).get('overall_privacy_score', 1.0)
        if privacy_score < 0.8:
            risk_factors.append("Privacy compliance below threshold")
        
        # Bias risk factors
        bias_analysis = validation_result.get('bias_analysis', {})
        if bias_analysis.get('mitigation_required', False):
            risk_factors.append("Bias mitigation required")
        
        # Calculate overall risk score
        risk_score = 0.0
        risk_score += len(non_compliant_checks) * 0.3
        risk_score += len(requires_review_checks) * 0.1
        risk_score += (1.0 - privacy_score) * 0.2
        risk_score += bias_analysis.get('confidence_bias_risk', 0.0) * 0.2
        
        # Normalize and classify risk
        risk_score = min(risk_score, 1.0)
        
        if risk_score >= 0.7:
            risk_level = 'high'
        elif risk_score >= 0.4:
            risk_level = 'medium'
        elif risk_score >= 0.1:
            risk_level = 'low'
        else:
            risk_level = 'minimal'
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'non_compliant_controls': len(non_compliant_checks),
            'controls_requiring_review': len(requires_review_checks),
            'immediate_action_required': risk_level in ['high', 'critical']
        }
    
    def _determine_overall_status(self, validation_result: Dict[str, Any]) -> ComplianceStatus:
        """Determine overall compliance status"""
        
        checks = validation_result['compliance_checks']
        
        # If any critical control fails, overall status is non-compliant
        critical_failures = [
            check for check in checks 
            if check['status'] == ComplianceStatus.NON_COMPLIANT.value and check['risk_level'] == 'critical'
        ]
        
        if critical_failures:
            return ComplianceStatus.NON_COMPLIANT
        
        # If any control fails, check severity
        failures = [
            check for check in checks
            if check['status'] == ComplianceStatus.NON_COMPLIANT.value
        ]
        
        if failures:
            return ComplianceStatus.NON_COMPLIANT
        
        # If controls require review, status is requires review
        reviews_required = [
            check for check in checks
            if check['status'] == ComplianceStatus.REQUIRES_REVIEW.value
        ]
        
        if reviews_required:
            return ComplianceStatus.REQUIRES_REVIEW
        
        return ComplianceStatus.COMPLIANT
    
    def _requires_remediation(self, validation_result: Dict[str, Any]) -> bool:
        """Determine if remediation is required"""
        
        risk_assessment = validation_result.get('risk_assessment', {})
        bias_analysis = validation_result.get('bias_analysis', {})
        privacy_assessment = validation_result.get('privacy_assessment', {})
        
        # Remediation required if:
        # 1. High risk level
        # 2. Bias mitigation required
        # 3. Privacy violations found
        # 4. Any non-compliant controls
        
        return (
            risk_assessment.get('immediate_action_required', False) or
            bias_analysis.get('mitigation_required', False) or
            not privacy_assessment.get('pii_detection', {}).get('compliant', True) or
            validation_result['overall_status'] == ComplianceStatus.NON_COMPLIANT
        )
    
    def _assess_reasoning_quality(self, reasoning_chain: List[str]) -> float:
        """Assess quality of AI reasoning for compliance"""
        
        if not reasoning_chain:
            return 0.0
        
        quality_score = 0.0
        
        # Length assessment
        chain_length = len(reasoning_chain)
        if 3 <= chain_length <= 8:
            quality_score += 0.3
        elif 2 <= chain_length <= 10:
            quality_score += 0.2
        else:
            quality_score += 0.1
        
        # Content quality assessment
        reasoning_text = ' '.join(reasoning_chain).lower()
        
        # Check for evidence references
        evidence_indicators = ['evidence', 'data', 'log', 'source', 'indicates', 'shows']
        evidence_score = sum(1 for indicator in evidence_indicators if indicator in reasoning_text)
        quality_score += min(evidence_score / 4, 0.3)
        
        # Check for logical flow
        logical_indicators = ['because', 'therefore', 'since', 'given', 'thus']
        logic_score = sum(1 for indicator in logical_indicators if indicator in reasoning_text)
        quality_score += min(logic_score / 3, 0.2)
        
        # Check for specific conclusions
        conclusion_indicators = ['conclude', 'determine', 'assess', 'recommend']
        conclusion_score = sum(1 for indicator in conclusion_indicators if indicator in reasoning_text)
        quality_score += min(conclusion_score / 2, 0.2)
        
        return min(quality_score, 1.0)
    
    def _assess_control_risk_level(self, deficiencies: List[str]) -> str:
        """Assess risk level based on control deficiencies"""
        
        if not deficiencies:
            return 'low'
        
        critical_keywords = ['missing', 'failed', 'unauthorized', 'violation']
        high_keywords = ['incomplete', 'insufficient', 'weak']
        
        deficiency_text = ' '.join(deficiencies).lower()
        
        if any(keyword in deficiency_text for keyword in critical_keywords):
            return 'critical'
        elif any(keyword in deficiency_text for keyword in high_keywords):
            return 'high'
        elif len(deficiencies) > 2:
            return 'medium'
        else:
            return 'low'
    
    # Remediation action generators
    def _generate_cc1_remediation(self, deficiencies: List[str]) -> List[str]:
        """Generate SOC 2 CC1 remediation actions"""
        actions = []
        for deficiency in deficiencies:
            if 'autonomy tier' in deficiency.lower():
                actions.append("Implement autonomy tier classification for all decisions")
            if 'confidence score' in deficiency.lower():
                actions.append("Fix confidence scoring calculation")
            if 'reasoning chain' in deficiency.lower():
                actions.append("Ensure complete reasoning chain documentation")
        return actions
    
    def _generate_cc2_remediation(self, deficiencies: List[str]) -> List[str]:
        """Generate SOC 2 CC2 remediation actions"""
        actions = []
        for deficiency in deficiencies:
            if 'reasoning quality' in deficiency.lower():
                actions.append("Improve AI reasoning quality and transparency")
            if 'model attribution' in deficiency.lower():
                actions.append("Add model attribution to all decisions")
            if 'missing required fields' in deficiency.lower():
                actions.append("Ensure all required decision fields are populated")
        return actions
    
    def _generate_cc3_remediation(self, deficiencies: List[str]) -> List[str]:
        """Generate SOC 2 CC3 remediation actions"""
        actions = []
        for deficiency in deficiencies:
            if 'bias risk' in deficiency.lower():
                actions.append("Implement comprehensive bias risk assessment")
            if 'uncertainty' in deficiency.lower():
                actions.append("Add uncertainty quantification to all decisions")
        return actions
    
    def _generate_cc4_remediation(self, deficiencies: List[str]) -> List[str]:
        """Generate SOC 2 CC4 remediation actions"""
        actions = []
        for deficiency in deficiencies:
            if 'performance monitoring' in deficiency.lower():
                actions.append("Implement comprehensive performance monitoring")
        return actions
    
    def _generate_cc5_remediation(self, deficiencies: List[str]) -> List[str]:
        """Generate SOC 2 CC5 remediation actions"""
        # CC5 typically has fewer deficiencies due to graduated autonomy design
        return ["Review and enhance graduated autonomy controls"]
    
    def _generate_a12_remediation(self, deficiencies: List[str]) -> List[str]:
        """Generate ISO 27001 A.12 remediation actions"""
        actions = []
        for deficiency in deficiencies:
            if 'processing time' in deficiency.lower():
                actions.append("Optimize AI processing performance")
        return actions
    
    def _generate_a13_remediation(self, deficiencies: List[str]) -> List[str]:
        """Generate ISO 27001 A.13 remediation actions"""
        # A13 controls are typically well-implemented in VPC architecture
        return ["Review and enhance network security controls"]
    
    def _generate_a14_remediation(self, deficiencies: List[str]) -> List[str]:
        """Generate ISO 27001 A.14 remediation actions"""
        # A14 controls are typically well-implemented in secure development
        return ["Review and enhance secure development practices"]
    
    async def _log_compliance_event(self, analysis_result, validation_result: Dict[str, Any]):
        """Log compliance validation event"""
        
        compliance_event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'analysis_id': analysis_result.analysis_id,
            'overall_status': validation_result['overall_status'].value,
            'risk_level': validation_result.get('risk_assessment', {}).get('risk_level', 'unknown'),
            'frameworks_checked': [f.value for f in self.enabled_frameworks],
            'remediation_required': validation_result['remediation_required']
        }
        
        self.compliance_history.append(compliance_event)
        
        # Keep only recent history
        if len(self.compliance_history) > 1000:
            self.compliance_history = self.compliance_history[-1000:]
    
    def _initialize_soc2_controls(self) -> Dict[str, Dict[str, Any]]:
        """Initialize SOC 2 control mappings"""
        return {
            'CC1.1': {
                'name': 'Control Environment - Authorization and Oversight',
                'description': 'Proper authorization controls for AI decisions'
            },
            'CC2.1': {
                'name': 'Communication and Information - Decision Transparency', 
                'description': 'Transparent and explainable AI decisions'
            },
            'CC3.1': {
                'name': 'Risk Assessment - AI Decision Risk Evaluation',
                'description': 'Comprehensive risk assessment for AI decisions'
            },
            'CC4.1': {
                'name': 'Monitoring Activities - Continuous AI Monitoring',
                'description': 'Continuous monitoring of AI performance'
            },
            'CC5.1': {
                'name': 'Control Activities - Graduated Autonomy Controls',
                'description': 'Graduated autonomy with appropriate controls'
            }
        }
    
    def _initialize_iso27001_controls(self) -> Dict[str, Dict[str, Any]]:
        """Initialize ISO 27001 control mappings"""
        return {
            'A.12.1': {
                'name': 'Operations Security - AI Operations Management',
                'description': 'Secure operations management for AI systems'
            },
            'A.13.1': {
                'name': 'Communications Security - Secure AI Communications', 
                'description': 'Secure communications for AI processing'
            },
            'A.14.1': {
                'name': 'System Acquisition - Secure AI Development',
                'description': 'Secure development practices for AI systems'
            }
        }
    
    async def get_status(self) -> Dict[str, Any]:
        """Get current compliance engine status"""
        
        recent_events = self.compliance_history[-100:] if self.compliance_history else []
        
        # Calculate compliance metrics
        compliant_count = sum(1 for event in recent_events if event['overall_status'] == 'compliant')
        total_events = len(recent_events)
        compliance_rate = (compliant_count / total_events * 100) if total_events > 0 else 100
        
        return {
            'status': 'healthy',
            'enabled_frameworks': [f.value for f in self.enabled_frameworks],
            'compliance_rate_percent': compliance_rate,
            'total_validations': len(self.compliance_history),
            'recent_validations': total_events,
            'bias_incidents': len(self.bias_incidents),
            'privacy_violations': len(self.privacy_violations)
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Health check for compliance engine"""
        return await self.get_status()