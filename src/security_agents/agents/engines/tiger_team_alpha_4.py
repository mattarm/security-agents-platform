#!/usr/bin/env python3
"""
Tiger Team Alpha-4: Threat Intelligence Platform Specialist
Advanced OSINT automation and threat hunting capabilities
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import hashlib
import re

@dataclass
class ThreatCampaign:
    """Advanced threat campaign tracking"""
    campaign_id: str
    name: str
    threat_actor: str
    confidence: float  # 0-100
    first_seen: datetime
    last_seen: datetime
    ttps: List[str]  # MITRE ATT&CK techniques
    iocs: List[str]
    target_industries: List[str]
    target_regions: List[str]
    attribution_evidence: List[Dict]
    risk_score: float

@dataclass
class ThreatActor:
    """Threat actor profiling and attribution"""
    actor_id: str
    name: str
    aliases: List[str]
    sophistication_level: str  # LOW, MEDIUM, HIGH, ADVANCED
    motivation: str  # FINANCIAL, ESPIONAGE, DISRUPTION, IDEOLOGY
    origin_country: Optional[str]
    active_since: Optional[datetime]
    preferred_ttps: List[str]
    known_campaigns: List[str]
    targeting_pattern: Dict[str, Any]
    attribution_confidence: float

class AdvancedThreatIntelligence:
    """Enhanced threat intelligence with campaign tracking and actor profiling"""
    
    def __init__(self):
        self.campaigns = {}
        self.threat_actors = {}
        self.ioc_database = {}
        self.attribution_engine = AttributionEngine()
        self.hunting_engine = ThreatHuntingEngine()
        
        print("🕵️ Tiger Team Alpha-4: Advanced Threat Intelligence Platform")

    async def analyze_threat_campaign(self, iocs: List[str], context: str = "") -> ThreatCampaign:
        """Analyze IOCs to identify threat campaigns"""
        
        print(f"🎯 Analyzing potential threat campaign from {len(iocs)} indicators")
        
        # Cluster IOCs by temporal and technical patterns
        clusters = await self.cluster_iocs_by_campaign(iocs)
        
        if not clusters:
            return None
            
        # Analyze the largest cluster
        primary_cluster = max(clusters, key=lambda c: len(c['iocs']))
        
        # Generate campaign profile
        campaign = ThreatCampaign(
            campaign_id=f"CAMP-{hashlib.md5(str(primary_cluster['iocs']).encode()).hexdigest()[:8]}",
            name=await self.generate_campaign_name(primary_cluster),
            threat_actor=await self.attribute_threat_actor(primary_cluster),
            confidence=await self.calculate_attribution_confidence(primary_cluster),
            first_seen=primary_cluster.get('first_seen', datetime.now()),
            last_seen=primary_cluster.get('last_seen', datetime.now()),
            ttps=await self.extract_ttps_from_cluster(primary_cluster),
            iocs=primary_cluster['iocs'],
            target_industries=await self.identify_target_industries(primary_cluster, context),
            target_regions=await self.identify_target_regions(primary_cluster),
            attribution_evidence=await self.gather_attribution_evidence(primary_cluster),
            risk_score=await self.calculate_campaign_risk(primary_cluster, context)
        )
        
        # Store campaign for future correlation
        self.campaigns[campaign.campaign_id] = campaign
        
        print(f"✅ Campaign analysis complete: {campaign.name} (Risk: {campaign.risk_score:.1f}/100)")
        return campaign

    async def cluster_iocs_by_campaign(self, iocs: List[str]) -> List[Dict]:
        """Cluster IOCs by campaign patterns"""
        clusters = []
        
        # Group by infrastructure patterns
        domain_clusters = self.cluster_by_domain_patterns(iocs)
        ip_clusters = self.cluster_by_ip_patterns(iocs)
        
        # Combine and deduplicate clusters
        all_clusters = domain_clusters + ip_clusters
        
        # Merge overlapping clusters
        merged_clusters = self.merge_overlapping_clusters(all_clusters)
        
        return merged_clusters

    def cluster_by_domain_patterns(self, iocs: List[str]) -> List[Dict]:
        """Cluster domains by registration and infrastructure patterns"""
        domain_iocs = [ioc for ioc in iocs if self.is_domain(ioc)]
        clusters = []
        
        # Group by TLD patterns
        tld_groups = {}
        for domain in domain_iocs:
            tld = domain.split('.')[-1]
            if tld not in tld_groups:
                tld_groups[tld] = []
            tld_groups[tld].append(domain)
        
        # Create clusters for suspicious TLD groups
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'top', 'click', 'buzz']
        for tld in suspicious_tlds:
            if tld in tld_groups and len(tld_groups[tld]) > 1:
                clusters.append({
                    'cluster_type': 'suspicious_tld',
                    'pattern': f'.{tld} domains',
                    'iocs': tld_groups[tld],
                    'confidence': 70.0
                })
        
        # Group by domain generation algorithms (DGA) patterns
        dga_domains = self.detect_dga_domains(domain_iocs)
        if len(dga_domains) > 2:
            clusters.append({
                'cluster_type': 'dga',
                'pattern': 'domain_generation_algorithm',
                'iocs': dga_domains,
                'confidence': 85.0
            })
        
        return clusters

    def cluster_by_ip_patterns(self, iocs: List[str]) -> List[Dict]:
        """Cluster IPs by network and hosting patterns"""
        ip_iocs = [ioc for ioc in iocs if self.is_ip(ioc)]
        clusters = []
        
        # Group by /24 subnets
        subnet_groups = {}
        for ip in ip_iocs:
            try:
                import ipaddress
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private:  # Skip private IPs
                    subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False))
                    if subnet not in subnet_groups:
                        subnet_groups[subnet] = []
                    subnet_groups[subnet].append(ip)
            except:
                continue
        
        # Create clusters for subnets with multiple IPs
        for subnet, ips in subnet_groups.items():
            if len(ips) > 1:
                clusters.append({
                    'cluster_type': 'ip_subnet',
                    'pattern': f'subnet_{subnet}',
                    'iocs': ips,
                    'confidence': 75.0
                })
        
        return clusters

    def detect_dga_domains(self, domains: List[str]) -> List[str]:
        """Detect domains generated by domain generation algorithms"""
        dga_domains = []
        
        for domain in domains:
            # Check for DGA characteristics
            domain_part = domain.split('.')[0]
            
            # High entropy (randomness) check
            entropy = self.calculate_entropy(domain_part)
            
            # Length and character patterns
            has_numbers = any(c.isdigit() for c in domain_part)
            has_consonant_clusters = self.has_consonant_clusters(domain_part)
            length_suspicious = len(domain_part) > 10 and len(domain_part) < 20
            
            # DGA scoring
            dga_score = 0
            if entropy > 3.5:
                dga_score += 30
            if has_numbers:
                dga_score += 20
            if has_consonant_clusters:
                dga_score += 25
            if length_suspicious:
                dga_score += 15
            
            if dga_score > 50:
                dga_domains.append(domain)
        
        return dga_domains

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        import math
        from collections import Counter
        
        if not text:
            return 0
            
        counts = Counter(text.lower())
        total = len(text)
        
        entropy = 0
        for count in counts.values():
            probability = count / total
            entropy -= probability * math.log2(probability)
        
        return entropy

    def has_consonant_clusters(self, text: str) -> bool:
        """Check for unusual consonant clusters (DGA indicator)"""
        vowels = 'aeiou'
        consonants = 'bcdfghjklmnpqrstvwxyz'
        
        consonant_runs = []
        current_run = 0
        
        for char in text.lower():
            if char in consonants:
                current_run += 1
            else:
                if current_run > 0:
                    consonant_runs.append(current_run)
                current_run = 0
        
        # Add final run if exists
        if current_run > 0:
            consonant_runs.append(current_run)
        
        # Check for runs of 3+ consonants
        return any(run >= 3 for run in consonant_runs)

    async def generate_campaign_name(self, cluster: Dict) -> str:
        """Generate descriptive campaign name"""
        cluster_type = cluster.get('cluster_type', 'unknown')
        pattern = cluster.get('pattern', '')
        ioc_count = len(cluster.get('iocs', []))
        
        if cluster_type == 'suspicious_tld':
            return f"SuspiciousTLD-{pattern.replace('.', '').upper()}-{datetime.now().strftime('%Y%m')}"
        elif cluster_type == 'dga':
            return f"DGA-Campaign-{datetime.now().strftime('%Y%m%d')}"
        elif cluster_type == 'ip_subnet':
            subnet = pattern.split('_')[1] if '_' in pattern else 'Unknown'
            return f"IPCluster-{subnet.replace('/', '-').replace('.', '-')}"
        else:
            return f"ThreatCampaign-{hashlib.md5(str(cluster).encode()).hexdigest()[:8]}"

    async def attribute_threat_actor(self, cluster: Dict) -> str:
        """Attempt to attribute cluster to known threat actor"""
        
        # Check against known threat actor patterns
        known_actors = {
            'APT28': {
                'tlds': ['tk', 'ml'],
                'patterns': ['dga'],
                'confidence_threshold': 70
            },
            'Lazarus': {
                'tlds': ['cf', 'ga'],
                'patterns': ['suspicious_tld'],
                'confidence_threshold': 65
            }
        }
        
        cluster_type = cluster.get('cluster_type', '')
        pattern = cluster.get('pattern', '')
        confidence = cluster.get('confidence', 0)
        
        for actor_name, actor_data in known_actors.items():
            score = 0
            
            # Check TLD patterns
            if any(tld in pattern for tld in actor_data['tlds']):
                score += 30
            
            # Check behavior patterns
            if cluster_type in actor_data['patterns']:
                score += 40
            
            # Check confidence threshold
            if confidence >= actor_data['confidence_threshold']:
                score += 20
            
            if score >= 60:
                return f"{actor_name} (Suspected)"
        
        return "Unknown Threat Actor"

    async def calculate_attribution_confidence(self, cluster: Dict) -> float:
        """Calculate confidence in threat actor attribution"""
        
        base_confidence = cluster.get('confidence', 0)
        ioc_count = len(cluster.get('iocs', []))
        cluster_type = cluster.get('cluster_type', '')
        
        # Confidence modifiers
        count_modifier = min(ioc_count * 5, 30)  # More IOCs = higher confidence
        
        type_modifiers = {
            'dga': 20,
            'suspicious_tld': 15,
            'ip_subnet': 10
        }
        type_modifier = type_modifiers.get(cluster_type, 0)
        
        final_confidence = min(base_confidence + count_modifier + type_modifier, 100)
        return final_confidence

    async def extract_ttps_from_cluster(self, cluster: Dict) -> List[str]:
        """Extract MITRE ATT&CK TTPs from cluster characteristics"""
        ttps = []
        
        cluster_type = cluster.get('cluster_type', '')
        
        # Map cluster types to likely TTPs
        ttp_mapping = {
            'dga': [
                'T1568.002',  # Domain Generation Algorithms
                'T1071.001',  # Web Protocols
                'T1105'       # Ingress Tool Transfer
            ],
            'suspicious_tld': [
                'T1583.001',  # Acquire Infrastructure: Domains
                'T1071.001',  # Web Protocols
                'T1132.001'   # Data Encoding: Standard Encoding
            ],
            'ip_subnet': [
                'T1583.002',  # Acquire Infrastructure: DNS Server
                'T1090',      # Proxy
                'T1071.001'   # Web Protocols
            ]
        }
        
        return ttp_mapping.get(cluster_type, [])

    async def identify_target_industries(self, cluster: Dict, context: str) -> List[str]:
        """Identify likely target industries based on context and patterns"""
        
        # Analyze context for industry indicators
        industry_keywords = {
            'financial': ['bank', 'finance', 'payment', 'credit', 'trading'],
            'healthcare': ['health', 'medical', 'hospital', 'pharma', 'patient'],
            'government': ['gov', 'military', 'defense', 'public', 'federal'],
            'technology': ['tech', 'software', 'cloud', 'api', 'database'],
            'manufacturing': ['industrial', 'factory', 'production', 'supply'],
            'energy': ['power', 'energy', 'oil', 'gas', 'utility']
        }
        
        detected_industries = []
        context_lower = context.lower()
        
        for industry, keywords in industry_keywords.items():
            if any(keyword in context_lower for keyword in keywords):
                detected_industries.append(industry)
        
        # Default targets based on cluster type
        if not detected_industries:
            cluster_type = cluster.get('cluster_type', '')
            default_targets = {
                'dga': ['technology', 'financial'],
                'suspicious_tld': ['government', 'healthcare'],
                'ip_subnet': ['technology', 'manufacturing']
            }
            detected_industries = default_targets.get(cluster_type, ['technology'])
        
        return detected_industries

    async def identify_target_regions(self, cluster: Dict) -> List[str]:
        """Identify likely target geographic regions"""
        
        # Analyze IP geolocation patterns
        iocs = cluster.get('iocs', [])
        regions = set()
        
        # This would typically use GeoIP databases
        # For demo, we'll use simple heuristics
        
        for ioc in iocs:
            if self.is_ip(ioc):
                # Simple region mapping (would use real GeoIP in production)
                if ioc.startswith('192.168.') or ioc.startswith('10.') or ioc.startswith('172.'):
                    continue  # Skip private IPs
                else:
                    regions.add('Global')  # Default for public IPs
        
        # Check for region-specific TLD patterns
        cluster_pattern = cluster.get('pattern', '')
        if '.ru' in cluster_pattern or '.su' in cluster_pattern:
            regions.add('Russia/CIS')
        elif '.cn' in cluster_pattern:
            regions.add('China')
        elif '.ir' in cluster_pattern:
            regions.add('Iran')
        elif '.kp' in cluster_pattern:
            regions.add('North Korea')
        
        return list(regions) if regions else ['Unknown']

    async def gather_attribution_evidence(self, cluster: Dict) -> List[Dict]:
        """Gather evidence supporting threat actor attribution"""
        
        evidence = []
        
        # Technical evidence
        evidence.append({
            'type': 'technical',
            'category': 'infrastructure_pattern',
            'description': f"Cluster shows {cluster.get('cluster_type')} pattern",
            'confidence': cluster.get('confidence', 0),
            'source': 'pattern_analysis'
        })
        
        # Behavioral evidence
        ioc_count = len(cluster.get('iocs', []))
        if ioc_count > 5:
            evidence.append({
                'type': 'behavioral',
                'category': 'infrastructure_scale',
                'description': f"Large infrastructure footprint ({ioc_count} indicators)",
                'confidence': 70.0,
                'source': 'scale_analysis'
            })
        
        # Temporal evidence
        evidence.append({
            'type': 'temporal',
            'category': 'activity_timeframe',
            'description': f"Cluster activity detected {datetime.now().strftime('%Y-%m-%d')}",
            'confidence': 90.0,
            'source': 'detection_timestamp'
        })
        
        return evidence

    async def calculate_campaign_risk(self, cluster: Dict, context: str) -> float:
        """Calculate overall risk score for the campaign"""
        
        # Base risk from cluster confidence
        base_risk = cluster.get('confidence', 0)
        
        # Scale factor based on IOC count
        ioc_count = len(cluster.get('iocs', []))
        scale_factor = min(1.0 + (ioc_count - 1) * 0.1, 2.0)
        
        # Cluster type risk multipliers
        type_multipliers = {
            'dga': 1.3,           # DGA is sophisticated
            'suspicious_tld': 1.1, # Moderately suspicious
            'ip_subnet': 1.2      # Infrastructure clustering
        }
        
        cluster_type = cluster.get('cluster_type', '')
        type_multiplier = type_multipliers.get(cluster_type, 1.0)
        
        # Context risk (if targeting critical sectors)
        context_risk = 0
        critical_contexts = ['financial', 'government', 'healthcare', 'critical infrastructure']
        if any(ctx in context.lower() for ctx in critical_contexts):
            context_risk = 20
        
        # Calculate final risk score
        final_risk = min(
            (base_risk * scale_factor * type_multiplier) + context_risk,
            100.0
        )
        
        return final_risk

    def is_domain(self, ioc: str) -> bool:
        """Check if IOC is a domain"""
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$'
        return bool(re.match(domain_pattern, ioc))

    def is_ip(self, ioc: str) -> bool:
        """Check if IOC is an IP address"""
        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        return bool(re.match(ip_pattern, ioc))

    def merge_overlapping_clusters(self, clusters: List[Dict]) -> List[Dict]:
        """Merge clusters that have overlapping IOCs"""
        
        if not clusters:
            return []
        
        merged = []
        used_indices = set()
        
        for i, cluster1 in enumerate(clusters):
            if i in used_indices:
                continue
                
            merged_cluster = cluster1.copy()
            used_indices.add(i)
            
            # Check for overlaps with remaining clusters
            for j, cluster2 in enumerate(clusters[i+1:], i+1):
                if j in used_indices:
                    continue
                
                iocs1 = set(cluster1.get('iocs', []))
                iocs2 = set(cluster2.get('iocs', []))
                
                # If more than 30% overlap, merge clusters
                overlap = len(iocs1 & iocs2)
                min_size = min(len(iocs1), len(iocs2))
                
                if min_size > 0 and (overlap / min_size) > 0.3:
                    # Merge clusters
                    merged_cluster['iocs'] = list(iocs1 | iocs2)
                    merged_cluster['confidence'] = max(
                        cluster1.get('confidence', 0),
                        cluster2.get('confidence', 0)
                    )
                    used_indices.add(j)
            
            merged.append(merged_cluster)
        
        return merged

class AttributionEngine:
    """Advanced threat actor attribution engine"""
    
    def __init__(self):
        self.actor_database = self.load_actor_database()
    
    def load_actor_database(self) -> Dict:
        """Load known threat actor patterns and signatures"""
        return {
            'APT1': {
                'aliases': ['Comment Crew', 'PLA Unit 61398'],
                'origin': 'China',
                'sophistication': 'HIGH',
                'motivation': 'ESPIONAGE',
                'infrastructure_patterns': {
                    'domains': ['.tk', '.ml'],
                    'naming_conventions': ['*-update', '*-service'],
                    'certificate_patterns': ['self-signed', 'invalid_ca']
                },
                'ttps': ['T1566.001', 'T1055', 'T1071.001'],
                'target_industries': ['technology', 'defense', 'government']
            }
            # Additional actors would be loaded from threat intelligence feeds
        }

class ThreatHuntingEngine:
    """Proactive threat hunting automation"""
    
    def __init__(self):
        self.hunting_rules = self.load_hunting_rules()
        
    def load_hunting_rules(self) -> List[Dict]:
        """Load threat hunting rules and hypotheses"""
        return [
            {
                'rule_id': 'HUNT-001',
                'name': 'DGA Domain Detection',
                'hypothesis': 'Identify domains generated by algorithms',
                'indicators': ['high_entropy', 'random_subdomains', 'short_lived'],
                'ttps': ['T1568.002']
            },
            {
                'rule_id': 'HUNT-002', 
                'name': 'C2 Beacon Detection',
                'hypothesis': 'Detect periodic command and control communications',
                'indicators': ['regular_intervals', 'encrypted_payloads', 'persistence'],
                'ttps': ['T1071.001', 'T1573']
            }
        ]

# Example usage
async def demo_campaign_analysis():
    """Demonstrate advanced threat intelligence capabilities"""
    
    print("🚀 Tiger Team Alpha-4 Demo: Advanced Threat Campaign Analysis")
    
    # Initialize advanced threat intelligence
    threat_intel = AdvancedThreatIntelligence()
    
    # Sample IOCs representing a threat campaign
    sample_iocs = [
        'malicious-update.tk',
        'secure-service.ml', 
        'system-check.tk',
        '185.244.25.12',
        '185.244.25.28',
        '185.244.25.45',
        'random12abc.ga',
        'xyz89def.cf'
    ]
    
    # Context about the environment being analyzed
    context = "Financial services company with cloud infrastructure and customer data"
    
    # Analyze the campaign
    campaign = await threat_intel.analyze_threat_campaign(sample_iocs, context)
    
    if campaign:
        print(f"\n🎯 Campaign Analysis Results:")
        print(f"Campaign: {campaign.name}")
        print(f"Threat Actor: {campaign.threat_actor}")
        print(f"Risk Score: {campaign.risk_score:.1f}/100")
        print(f"Attribution Confidence: {campaign.confidence:.1f}%")
        print(f"Target Industries: {', '.join(campaign.target_industries)}")
        print(f"TTPs: {', '.join(campaign.ttps)}")
        print(f"IOCs: {len(campaign.iocs)} indicators")
        
        print(f"\n📋 Attribution Evidence:")
        for evidence in campaign.attribution_evidence:
            print(f"  • {evidence['category']}: {evidence['description']} ({evidence['confidence']:.0f}% confidence)")

if __name__ == "__main__":
    asyncio.run(demo_campaign_analysis())