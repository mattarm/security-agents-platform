#!/usr/bin/env python3
"""
Intelligence Fusion Engine - Cross-Agent Communication and Correlation
Real-time intelligence sharing between Alpha-4 and Beta-4 agents
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from collections import defaultdict
import hashlib
import uuid
from enum import Enum

class IntelligenceType(Enum):
    THREAT_CAMPAIGN = "threat_campaign"
    VULNERABILITY = "vulnerability"
    INFRASTRUCTURE = "infrastructure"
    ACTOR_PROFILE = "actor_profile"
    IOC_ENRICHMENT = "ioc_enrichment"
    SUPPLY_CHAIN = "supply_chain"
    CORRELATION = "correlation"

class Priority(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class IntelligencePacket:
    """Standardized intelligence packet for cross-agent communication"""
    packet_id: str
    source_agent: str
    target_agents: List[str]
    intelligence_type: IntelligenceType
    priority: Priority
    confidence: float  # 0-100
    timestamp: datetime
    data: Dict[str, Any]
    correlation_keys: List[str]
    expiry: Optional[datetime] = None
    processed_by: List[str] = None
    
    def __post_init__(self):
        if self.processed_by is None:
            self.processed_by = []

@dataclass
class CorrelationResult:
    """Result of cross-domain intelligence correlation"""
    correlation_id: str
    correlation_type: str
    confidence: float
    risk_score: float
    involved_packets: List[str]
    evidence: List[Dict[str, Any]]
    business_impact: str
    recommendations: List[str]
    created_at: datetime

class IntelligenceFusionEngine:
    """Real-time intelligence fusion and correlation across security agents"""
    
    def __init__(self):
        self.intelligence_store = {}  # packet_id -> IntelligencePacket
        self.correlation_index = defaultdict(list)  # correlation_key -> packet_ids
        self.agent_subscriptions = defaultdict(set)  # agent_id -> intelligence_types
        self.correlation_rules = self.load_correlation_rules()
        self.fusion_metrics = {
            'packets_processed': 0,
            'correlations_found': 0,
            'agents_connected': 0,
            'last_activity': datetime.now()
        }
        
        print("🧠 Intelligence Fusion Engine initialized")

    def load_correlation_rules(self) -> List[Dict]:
        """Load correlation rules for cross-domain intelligence fusion"""
        return [
            {
                'rule_id': 'THREAT_VULN_CORRELATION',
                'description': 'Correlate threat campaigns with vulnerabilities',
                'source_types': [IntelligenceType.THREAT_CAMPAIGN, IntelligenceType.VULNERABILITY],
                'correlation_keys': ['domain', 'ip_address', 'file_hash'],
                'confidence_threshold': 70.0,
                'risk_multiplier': 1.5
            },
            {
                'rule_id': 'INFRASTRUCTURE_THREAT_CORRELATION',
                'description': 'Correlate infrastructure findings with threat intelligence',
                'source_types': [IntelligenceType.INFRASTRUCTURE, IntelligenceType.IOC_ENRICHMENT],
                'correlation_keys': ['ip_address', 'domain', 'certificate_hash'],
                'confidence_threshold': 60.0,
                'risk_multiplier': 1.3
            },
            {
                'rule_id': 'SUPPLY_CHAIN_THREAT_CORRELATION',
                'description': 'Correlate supply chain risks with known threats',
                'source_types': [IntelligenceType.SUPPLY_CHAIN, IntelligenceType.THREAT_CAMPAIGN],
                'correlation_keys': ['package_name', 'domain', 'repository_url'],
                'confidence_threshold': 80.0,
                'risk_multiplier': 1.7
            },
            {
                'rule_id': 'ACTOR_INFRASTRUCTURE_CORRELATION',
                'description': 'Correlate threat actors with infrastructure',
                'source_types': [IntelligenceType.ACTOR_PROFILE, IntelligenceType.INFRASTRUCTURE],
                'correlation_keys': ['domain', 'ip_address', 'tls_certificate'],
                'confidence_threshold': 75.0,
                'risk_multiplier': 2.0
            }
        ]

    async def process_intelligence(self, packet: IntelligencePacket) -> List[CorrelationResult]:
        """Process incoming intelligence packet and perform correlations"""
        
        print(f"📥 Processing intelligence: {packet.intelligence_type.value} from {packet.source_agent}")
        
        # Store the packet
        self.intelligence_store[packet.packet_id] = packet
        self.fusion_metrics['packets_processed'] += 1
        self.fusion_metrics['last_activity'] = datetime.now()
        
        # Index by correlation keys
        for key in packet.correlation_keys:
            self.correlation_index[key].append(packet.packet_id)
        
        # Mark as processed by this engine
        packet.processed_by.append('fusion_engine')
        
        # Perform correlation analysis
        correlations = await self.correlate_intelligence(packet)
        
        # Distribute to subscribed agents
        await self.distribute_intelligence(packet, correlations)
        
        # Update metrics
        if correlations:
            self.fusion_metrics['correlations_found'] += len(correlations)
        
        return correlations

    async def correlate_intelligence(self, new_packet: IntelligencePacket) -> List[CorrelationResult]:
        """Correlate new intelligence with existing intelligence"""
        correlations = []
        
        for rule in self.correlation_rules:
            # Check if this packet type is relevant to the rule
            if new_packet.intelligence_type not in rule['source_types']:
                continue
            
            # Find potentially correlated packets
            related_packets = await self.find_related_packets(new_packet, rule)
            
            if related_packets:
                correlation = await self.create_correlation(
                    new_packet, related_packets, rule
                )
                if correlation and correlation.confidence >= rule['confidence_threshold']:
                    correlations.append(correlation)
        
        return correlations

    async def find_related_packets(self, packet: IntelligencePacket, rule: Dict) -> List[IntelligencePacket]:
        """Find packets related to the given packet based on correlation rule"""
        related = []
        
        # Get packets that share correlation keys
        candidate_packet_ids = set()
        for key in packet.correlation_keys:
            if key in rule['correlation_keys']:
                candidate_packet_ids.update(self.correlation_index[key])
        
        # Filter by rule criteria
        for packet_id in candidate_packet_ids:
            if packet_id == packet.packet_id:
                continue
                
            candidate = self.intelligence_store.get(packet_id)
            if not candidate:
                continue
                
            # Check if candidate matches rule source types
            if candidate.intelligence_type in rule['source_types']:
                # Check temporal relevance (within last 24 hours)
                time_diff = abs((packet.timestamp - candidate.timestamp).total_seconds())
                if time_diff <= 86400:  # 24 hours
                    related.append(candidate)
        
        return related

    async def create_correlation(self, 
                               primary_packet: IntelligencePacket,
                               related_packets: List[IntelligencePacket],
                               rule: Dict) -> Optional[CorrelationResult]:
        """Create a correlation result from related packets"""
        
        if not related_packets:
            return None
        
        # Calculate correlation confidence
        confidence = await self.calculate_correlation_confidence(
            primary_packet, related_packets, rule
        )
        
        # Calculate risk score
        risk_score = await self.calculate_correlation_risk(
            primary_packet, related_packets, rule
        )
        
        # Extract correlation evidence
        evidence = await self.extract_correlation_evidence(
            primary_packet, related_packets
        )
        
        # Generate recommendations
        recommendations = await self.generate_correlation_recommendations(
            primary_packet, related_packets, rule
        )
        
        # Determine business impact
        business_impact = await self.assess_business_impact(
            risk_score, primary_packet, related_packets
        )
        
        correlation = CorrelationResult(
            correlation_id=f"CORR-{hashlib.md5(f'{primary_packet.packet_id}:{rule["rule_id"]}'.encode()).hexdigest()[:8]}",
            correlation_type=rule['rule_id'],
            confidence=confidence,
            risk_score=risk_score,
            involved_packets=[primary_packet.packet_id] + [p.packet_id for p in related_packets],
            evidence=evidence,
            business_impact=business_impact,
            recommendations=recommendations,
            created_at=datetime.now()
        )
        
        return correlation

    async def calculate_correlation_confidence(self,
                                             primary: IntelligencePacket,
                                             related: List[IntelligencePacket],
                                             rule: Dict) -> float:
        """Calculate confidence score for correlation"""
        
        # Base confidence from rule
        base_confidence = rule.get('confidence_threshold', 50.0)
        
        # Boost based on number of matching correlation keys
        matching_keys = 0
        total_keys = len(rule['correlation_keys'])
        
        for related_packet in related:
            for key in primary.correlation_keys:
                if (key in rule['correlation_keys'] and 
                    key in related_packet.correlation_keys):
                    matching_keys += 1
        
        key_confidence_boost = (matching_keys / max(total_keys, 1)) * 20
        
        # Boost based on packet confidence scores
        avg_packet_confidence = (primary.confidence + 
                               sum(p.confidence for p in related)) / (len(related) + 1)
        
        confidence_boost = (avg_packet_confidence - 50) / 2  # Scale to ±25
        
        # Temporal proximity bonus
        time_deltas = [abs((primary.timestamp - p.timestamp).total_seconds()) for p in related]
        avg_time_delta = sum(time_deltas) / len(time_deltas) if time_deltas else 3600
        temporal_bonus = max(0, (3600 - avg_time_delta) / 3600 * 10)  # Up to 10 points
        
        final_confidence = min(
            base_confidence + key_confidence_boost + confidence_boost + temporal_bonus,
            95.0  # Cap at 95%
        )
        
        return final_confidence

    async def calculate_correlation_risk(self,
                                       primary: IntelligencePacket,
                                       related: List[IntelligencePacket],
                                       rule: Dict) -> float:
        """Calculate risk score for correlation"""
        
        # Get individual risk scores from packet data
        primary_risk = self.extract_risk_score(primary)
        related_risks = [self.extract_risk_score(p) for p in related]
        
        # Calculate base risk as weighted average
        all_risks = [primary_risk] + related_risks
        avg_risk = sum(all_risks) / len(all_risks)
        
        # Apply rule multiplier
        multiplier = rule.get('risk_multiplier', 1.0)
        
        # Correlation amplification (multiple related findings increase risk)
        correlation_amplification = min(1.0 + (len(related) - 1) * 0.1, 1.5)
        
        # Priority amplification
        priority_multipliers = {
            Priority.CRITICAL: 1.3,
            Priority.HIGH: 1.1,
            Priority.MEDIUM: 1.0,
            Priority.LOW: 0.9,
            Priority.INFO: 0.8
        }
        
        max_priority = max([primary.priority] + [p.priority for p in related],
                          key=lambda p: list(Priority).index(p))
        priority_multiplier = priority_multipliers[max_priority]
        
        final_risk = min(
            avg_risk * multiplier * correlation_amplification * priority_multiplier,
            100.0
        )
        
        return final_risk

    def extract_risk_score(self, packet: IntelligencePacket) -> float:
        """Extract risk score from intelligence packet"""
        data = packet.data
        
        # Look for common risk score fields
        risk_fields = ['risk_score', 'cvss_score', 'severity_score', 'threat_score']
        
        for field in risk_fields:
            if field in data:
                score = data[field]
                if isinstance(score, (int, float)):
                    return float(score)
                elif isinstance(score, str):
                    try:
                        return float(score)
                    except ValueError:
                        continue
        
        # Fallback: estimate risk from severity or priority
        severity_scores = {
            'CRITICAL': 90.0,
            'HIGH': 75.0,
            'MEDIUM': 50.0,
            'LOW': 25.0,
            'INFO': 10.0
        }
        
        severity = data.get('severity', '').upper()
        if severity in severity_scores:
            return severity_scores[severity]
        
        # Default based on packet priority
        priority_scores = {
            Priority.CRITICAL: 85.0,
            Priority.HIGH: 70.0,
            Priority.MEDIUM: 45.0,
            Priority.LOW: 20.0,
            Priority.INFO: 5.0
        }
        
        return priority_scores.get(packet.priority, 30.0)

    async def extract_correlation_evidence(self,
                                         primary: IntelligencePacket,
                                         related: List[IntelligencePacket]) -> List[Dict[str, Any]]:
        """Extract evidence supporting the correlation"""
        evidence = []
        
        # Primary packet evidence
        evidence.append({
            'source': 'primary',
            'packet_id': primary.packet_id,
            'type': primary.intelligence_type.value,
            'key_indicators': primary.correlation_keys,
            'confidence': primary.confidence,
            'timestamp': primary.timestamp.isoformat(),
            'summary': self.summarize_packet(primary)
        })
        
        # Related packets evidence
        for related_packet in related:
            evidence.append({
                'source': 'related',
                'packet_id': related_packet.packet_id,
                'type': related_packet.intelligence_type.value,
                'key_indicators': related_packet.correlation_keys,
                'confidence': related_packet.confidence,
                'timestamp': related_packet.timestamp.isoformat(),
                'summary': self.summarize_packet(related_packet),
                'correlation_strength': self.calculate_pair_correlation(primary, related_packet)
            })
        
        return evidence

    def summarize_packet(self, packet: IntelligencePacket) -> str:
        """Generate a brief summary of an intelligence packet"""
        data = packet.data
        packet_type = packet.intelligence_type.value
        
        if packet_type == 'threat_campaign':
            return f"Threat campaign: {data.get('name', 'Unknown')} (Actor: {data.get('threat_actor', 'Unknown')})"
        elif packet_type == 'vulnerability':
            return f"Vulnerability: {data.get('title', 'Unknown')} (Severity: {data.get('severity', 'Unknown')})"
        elif packet_type == 'infrastructure':
            return f"Infrastructure: {data.get('resource_type', 'Unknown')} security finding"
        elif packet_type == 'actor_profile':
            return f"Threat actor: {data.get('name', 'Unknown')} (Sophistication: {data.get('sophistication', 'Unknown')})"
        elif packet_type == 'ioc_enrichment':
            return f"IOC: {data.get('indicator', 'Unknown')} (Reputation: {data.get('reputation_score', 'Unknown')})"
        elif packet_type == 'supply_chain':
            return f"Supply chain risk: {data.get('component_name', 'Unknown')} (Risk: {data.get('risk_level', 'Unknown')})"
        else:
            return f"Intelligence: {packet_type}"

    def calculate_pair_correlation(self, packet1: IntelligencePacket, packet2: IntelligencePacket) -> float:
        """Calculate correlation strength between two packets"""
        
        # Check for shared correlation keys
        shared_keys = set(packet1.correlation_keys) & set(packet2.correlation_keys)
        if not shared_keys:
            return 0.0
        
        # Base correlation from shared keys
        key_correlation = len(shared_keys) / max(len(packet1.correlation_keys), len(packet2.correlation_keys))
        
        # Temporal correlation (closer in time = higher correlation)
        time_diff = abs((packet1.timestamp - packet2.timestamp).total_seconds())
        temporal_correlation = max(0, (86400 - time_diff) / 86400)  # 24 hour window
        
        # Confidence correlation
        confidence_correlation = min(packet1.confidence, packet2.confidence) / 100.0
        
        # Weighted average
        correlation_strength = (
            key_correlation * 0.5 +
            temporal_correlation * 0.3 +
            confidence_correlation * 0.2
        ) * 100
        
        return correlation_strength

    async def generate_correlation_recommendations(self,
                                                 primary: IntelligencePacket,
                                                 related: List[IntelligencePacket],
                                                 rule: Dict) -> List[str]:
        """Generate actionable recommendations based on correlation"""
        recommendations = []
        
        correlation_type = rule['rule_id']
        
        if correlation_type == 'THREAT_VULN_CORRELATION':
            recommendations.extend([
                "Prioritize patching of vulnerabilities associated with active threat campaigns",
                "Implement additional monitoring for affected systems",
                "Consider blocking known IOCs associated with this threat",
                "Review access controls for systems with these vulnerabilities"
            ])
        
        elif correlation_type == 'INFRASTRUCTURE_THREAT_CORRELATION':
            recommendations.extend([
                "Investigate infrastructure for signs of compromise",
                "Implement additional network monitoring and segmentation",
                "Review firewall rules and access controls",
                "Consider isolating affected infrastructure components"
            ])
        
        elif correlation_type == 'SUPPLY_CHAIN_THREAT_CORRELATION':
            recommendations.extend([
                "Audit supply chain components for compromise indicators",
                "Implement software composition analysis (SCA) scanning",
                "Review and update dependency management policies",
                "Consider alternative components with better security posture"
            ])
        
        elif correlation_type == 'ACTOR_INFRASTRUCTURE_CORRELATION':
            recommendations.extend([
                "Block known threat actor infrastructure at network perimeter",
                "Implement threat hunting for this actor's TTPs",
                "Review logs for historical compromise indicators",
                "Enhance detection rules for this threat actor's methods"
            ])
        
        # Add priority-specific recommendations
        max_priority = max([primary.priority] + [p.priority for p in related],
                          key=lambda p: list(Priority).index(p))
        
        if max_priority in [Priority.CRITICAL, Priority.HIGH]:
            recommendations.append("Initiate incident response procedures immediately")
            recommendations.append("Notify security leadership and stakeholders")
        
        return recommendations

    async def assess_business_impact(self,
                                   risk_score: float,
                                   primary: IntelligencePacket,
                                   related: List[IntelligencePacket]) -> str:
        """Assess business impact of correlation"""
        
        # Extract business context from packets
        business_contexts = []
        for packet in [primary] + related:
            context = packet.data.get('business_impact', '')
            if context:
                business_contexts.append(context)
        
        # Determine impact level from risk score
        if risk_score >= 80:
            impact_level = "CRITICAL"
            impact_desc = "Severe business disruption possible, immediate action required"
        elif risk_score >= 60:
            impact_level = "HIGH"
            impact_desc = "Significant business impact likely, urgent response needed"
        elif risk_score >= 40:
            impact_level = "MEDIUM"
            impact_desc = "Moderate business impact possible, timely response required"
        else:
            impact_level = "LOW"
            impact_desc = "Limited business impact expected, standard response procedures"
        
        # Combine with specific business contexts if available
        if business_contexts:
            unique_contexts = list(set(business_contexts))
            context_desc = ", ".join(unique_contexts[:3])
            return f"{impact_level}: {impact_desc}. Specific impacts: {context_desc}"
        
        return f"{impact_level}: {impact_desc}"

    async def distribute_intelligence(self, 
                                    packet: IntelligencePacket, 
                                    correlations: List[CorrelationResult]):
        """Distribute intelligence to subscribed agents"""
        
        # Distribute original packet to target agents
        for agent_id in packet.target_agents:
            if agent_id in self.agent_subscriptions:
                subscribed_types = self.agent_subscriptions[agent_id]
                if packet.intelligence_type in subscribed_types:
                    await self.send_to_agent(agent_id, packet)
        
        # Distribute correlations to all relevant agents
        for correlation in correlations:
            correlation_packet = IntelligencePacket(
                packet_id=f"CORR-{correlation.correlation_id}",
                source_agent="fusion_engine",
                target_agents=["all"],
                intelligence_type=IntelligenceType.CORRELATION,
                priority=Priority.HIGH if correlation.risk_score > 70 else Priority.MEDIUM,
                confidence=correlation.confidence,
                timestamp=datetime.now(),
                data=asdict(correlation),
                correlation_keys=[]
            )
            
            await self.broadcast_correlation(correlation_packet)

    async def send_to_agent(self, agent_id: str, packet: IntelligencePacket):
        """Send intelligence packet to specific agent"""
        print(f"📤 Sending {packet.intelligence_type.value} to {agent_id}")
        # Implementation would send via message queue, websocket, etc.

    async def broadcast_correlation(self, correlation_packet: IntelligencePacket):
        """Broadcast correlation to all agents"""
        print(f"📢 Broadcasting correlation: {correlation_packet.data['correlation_type']}")
        # Implementation would broadcast to all connected agents

    def subscribe_agent(self, agent_id: str, intelligence_types: List[IntelligenceType]):
        """Subscribe agent to specific intelligence types"""
        self.agent_subscriptions[agent_id].update(intelligence_types)
        self.fusion_metrics['agents_connected'] = len(self.agent_subscriptions)
        print(f"📡 Agent {agent_id} subscribed to {[t.value for t in intelligence_types]}")

    def unsubscribe_agent(self, agent_id: str):
        """Unsubscribe agent from all intelligence"""
        if agent_id in self.agent_subscriptions:
            del self.agent_subscriptions[agent_id]
        self.fusion_metrics['agents_connected'] = len(self.agent_subscriptions)
        print(f"📡 Agent {agent_id} unsubscribed")

    async def get_fusion_metrics(self) -> Dict[str, Any]:
        """Get fusion engine performance metrics"""
        return {
            **self.fusion_metrics,
            'intelligence_store_size': len(self.intelligence_store),
            'correlation_index_size': len(self.correlation_index),
            'subscribed_agents': len(self.agent_subscriptions),
            'active_correlations': len([p for p in self.intelligence_store.values() 
                                      if p.intelligence_type == IntelligenceType.CORRELATION]),
            'packet_types_distribution': self.get_packet_type_distribution()
        }

    def get_packet_type_distribution(self) -> Dict[str, int]:
        """Get distribution of packet types in store"""
        distribution = defaultdict(int)
        for packet in self.intelligence_store.values():
            distribution[packet.intelligence_type.value] += 1
        return dict(distribution)

    async def cleanup_expired_intelligence(self):
        """Remove expired intelligence packets"""
        current_time = datetime.now()
        expired_packets = []
        
        for packet_id, packet in self.intelligence_store.items():
            if packet.expiry and current_time > packet.expiry:
                expired_packets.append(packet_id)
        
        for packet_id in expired_packets:
            packet = self.intelligence_store.pop(packet_id)
            # Remove from correlation index
            for key in packet.correlation_keys:
                if key in self.correlation_index:
                    if packet_id in self.correlation_index[key]:
                        self.correlation_index[key].remove(packet_id)
        
        if expired_packets:
            print(f"🧹 Cleaned up {len(expired_packets)} expired intelligence packets")

# Example usage and integration
async def demo_intelligence_fusion():
    """Demonstrate intelligence fusion capabilities"""
    
    print("🚀 Intelligence Fusion Engine Demo")
    
    # Initialize fusion engine
    fusion = IntelligenceFusionEngine()
    
    # Subscribe mock agents
    fusion.subscribe_agent("alpha_4_threat_intel", [
        IntelligenceType.THREAT_CAMPAIGN,
        IntelligenceType.ACTOR_PROFILE,
        IntelligenceType.IOC_ENRICHMENT
    ])
    
    fusion.subscribe_agent("beta_4_devsecops", [
        IntelligenceType.VULNERABILITY,
        IntelligenceType.SUPPLY_CHAIN,
        IntelligenceType.INFRASTRUCTURE
    ])
    
    # Create sample threat intelligence
    threat_packet = IntelligencePacket(
        packet_id=str(uuid.uuid4()),
        source_agent="alpha_4_threat_intel",
        target_agents=["beta_4_devsecops", "fusion_engine"],
        intelligence_type=IntelligenceType.THREAT_CAMPAIGN,
        priority=Priority.HIGH,
        confidence=85.0,
        timestamp=datetime.now(),
        data={
            'name': 'Operation DarkCloud',
            'threat_actor': 'APT-2024',
            'ttps': ['T1566.001', 'T1055', 'T1071.001'],
            'target_industries': ['technology', 'finance'],
            'risk_score': 82.0
        },
        correlation_keys=['malicious-domain.com', '185.244.25.12', 'sha256:abc123...']
    )
    
    # Create related vulnerability
    vuln_packet = IntelligencePacket(
        packet_id=str(uuid.uuid4()),
        source_agent="beta_4_devsecops",
        target_agents=["alpha_4_threat_intel", "fusion_engine"],
        intelligence_type=IntelligenceType.VULNERABILITY,
        priority=Priority.HIGH,
        confidence=90.0,
        timestamp=datetime.now() - timedelta(minutes=30),
        data={
            'title': 'SQL Injection in Web Application',
            'cwe_id': 'CWE-89',
            'cvss_score': 8.5,
            'severity': 'HIGH',
            'file_path': '/src/api/database.py',
            'business_impact': 'Customer data exposure possible'
        },
        correlation_keys=['malicious-domain.com', 'web-app-server']
    )
    
    # Process intelligence through fusion engine
    print("\n📡 Processing threat campaign intelligence...")
    threat_correlations = await fusion.process_intelligence(threat_packet)
    
    print("\n📡 Processing vulnerability intelligence...")
    vuln_correlations = await fusion.process_intelligence(vuln_packet)
    
    # Show correlation results
    all_correlations = threat_correlations + vuln_correlations
    if all_correlations:
        print(f"\n🔗 Found {len(all_correlations)} correlations:")
        for corr in all_correlations:
            print(f"  • {corr.correlation_type}: {corr.confidence:.1f}% confidence, {corr.risk_score:.1f} risk")
            print(f"    Business Impact: {corr.business_impact}")
            print(f"    Recommendations: {len(corr.recommendations)} actions")
    
    # Show fusion metrics
    metrics = await fusion.get_fusion_metrics()
    print(f"\n📊 Fusion Engine Metrics:")
    print(f"  • Packets Processed: {metrics['packets_processed']}")
    print(f"  • Correlations Found: {metrics['correlations_found']}")
    print(f"  • Connected Agents: {metrics['agents_connected']}")
    print(f"  • Intelligence Store Size: {metrics['intelligence_store_size']}")

if __name__ == "__main__":
    asyncio.run(demo_intelligence_fusion())