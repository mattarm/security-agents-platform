#!/usr/bin/env python3
"""
Cross-Domain Intelligence Correlation Engine
Correlates security findings across GitHub, AWS, and threat intelligence sources
"""

import json
import asyncio
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
import hashlib
import re
from collections import defaultdict
import ipaddress

@dataclass
class CorrelatedIntelligence:
    """Correlated security intelligence across multiple domains"""
    correlation_id: str
    primary_indicator: str
    domains: List[str]  # github, aws, threat_intel
    risk_score: float  # 0-100, aggregated across domains
    confidence_score: float  # 0-100, confidence in correlation
    correlation_type: str  # infrastructure, code, supply_chain, threat_actor
    title: str
    description: str
    evidence: List[Dict]
    business_impact: str
    recommendations: List[str]
    timeline: List[Dict]
    related_indicators: List[str]

@dataclass 
class BusinessContext:
    """Business context for risk prioritization"""
    asset_criticality: str  # CRITICAL, HIGH, MEDIUM, LOW
    data_classification: str  # CONFIDENTIAL, INTERNAL, PUBLIC
    compliance_scope: List[str]  # SOX, PCI, HIPAA, GDPR
    business_function: str
    estimated_impact_cost: float

class IntelligenceCorrelator:
    """Cross-domain intelligence correlation and analysis engine"""
    
    def __init__(self):
        self.correlations = []
        self.indicators_cache = defaultdict(list)  # Track all indicators by type
        self.business_context = {}
        
        # Correlation patterns
        self.correlation_patterns = {
            'infrastructure_code': [
                # AWS infrastructure referenced in code
                {'pattern': r'\.amazonaws\.com', 'type': 'aws_endpoint'},
                {'pattern': r'us-[a-z]+-\d+', 'type': 'aws_region'},
                {'pattern': r'arn:aws:[a-z0-9\-]+:', 'type': 'aws_arn'},
                {'pattern': r's3://[a-z0-9\-\.]+', 'type': 's3_bucket'},
            ],
            'threat_infrastructure': [
                # Known threat actor infrastructure patterns
                {'pattern': r'\.onion', 'type': 'tor_hidden_service'},
                {'pattern': r'\.tk|\.ml|\.ga|\.cf', 'type': 'suspicious_tld'},
                {'pattern': r'duckdns\.org|noip\.com', 'type': 'dynamic_dns'},
            ],
            'supply_chain': [
                # Supply chain compromise indicators
                {'pattern': r'npm.*malicious', 'type': 'npm_malicious'},
                {'pattern': r'pypi.*typosquat', 'type': 'pypi_typosquat'},
                {'pattern': r'github\.com/[^/]+/[^/]+\.git', 'type': 'git_repo'},
            ]
        }
        
        print("🧠 Intelligence Correlation Engine initialized")

    async def correlate_intelligence(self, 
                                   github_findings: List[Dict] = None,
                                   aws_findings: List[Dict] = None, 
                                   threat_intel: List[Dict] = None) -> List[CorrelatedIntelligence]:
        """Main correlation function - analyze findings across all domains"""
        
        print("🔗 Starting cross-domain intelligence correlation")
        
        # Normalize and index all findings
        await self.index_findings(github_findings, aws_findings, threat_intel)
        
        # Perform different types of correlation
        correlations = []
        
        # Infrastructure correlations (AWS + GitHub)
        correlations.extend(await self.correlate_infrastructure())
        
        # Threat actor correlations (Threat Intel + GitHub/AWS)
        correlations.extend(await self.correlate_threat_actors())
        
        # Supply chain correlations (GitHub dependencies + Threat Intel)
        correlations.extend(await self.correlate_supply_chain())
        
        # Domain overlap correlations (common domains/IPs across sources)
        correlations.extend(await self.correlate_domain_overlap())
        
        # Business impact correlations
        correlations = await self.enhance_with_business_context(correlations)
        
        # Risk scoring and prioritization
        correlations = await self.calculate_correlation_risks(correlations)
        
        print(f"✅ Correlation complete: {len(correlations)} high-confidence correlations found")
        return correlations

    async def index_findings(self, github_findings: List[Dict], 
                           aws_findings: List[Dict], 
                           threat_intel: List[Dict]):
        """Index all findings by indicator type for fast correlation"""
        
        # Index GitHub findings
        if github_findings:
            for finding in github_findings:
                indicators = self.extract_indicators_from_finding(finding, 'github')
                for indicator_type, indicators_list in indicators.items():
                    for indicator in indicators_list:
                        self.indicators_cache[indicator_type].append({
                            'value': indicator,
                            'source': 'github',
                            'finding': finding
                        })
        
        # Index AWS findings  
        if aws_findings:
            for finding in aws_findings:
                indicators = self.extract_indicators_from_finding(finding, 'aws')
                for indicator_type, indicators_list in indicators.items():
                    for indicator in indicators_list:
                        self.indicators_cache[indicator_type].append({
                            'value': indicator,
                            'source': 'aws', 
                            'finding': finding
                        })
        
        # Index threat intelligence
        if threat_intel:
            for intel in threat_intel:
                if hasattr(intel, 'indicator') or 'indicator' in intel:
                    indicator_value = intel.get('indicator') or getattr(intel, 'indicator')
                    indicator_type = intel.get('indicator_type') or getattr(intel, 'indicator_type', 'unknown')
                    
                    self.indicators_cache[indicator_type].append({
                        'value': indicator_value,
                        'source': 'threat_intel',
                        'finding': intel if isinstance(intel, dict) else asdict(intel)
                    })
        
        print(f"📋 Indexed {sum(len(v) for v in self.indicators_cache.values())} indicators")

    def extract_indicators_from_finding(self, finding: Dict, source: str) -> Dict[str, List[str]]:
        """Extract indicators from a security finding"""
        indicators = defaultdict(list)
        
        # Convert finding to text for pattern matching
        finding_text = json.dumps(finding, default=str).lower()
        
        # Extract IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, finding_text)
        for ip in ips:
            try:
                ipaddress.ip_address(ip)  # Validate IP
                indicators['ip'].append(ip)
            except:
                pass
        
        # Extract domains
        domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, finding_text)
        for match in domains:
            domain = ''.join(match)  # Reconstruct domain from regex groups
            if '.' in domain and len(domain) > 3:
                indicators['domain'].append(domain)
        
        # Extract URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+[^\s<>"{}|\\^`\[\].,)]'
        urls = re.findall(url_pattern, finding_text)
        for url in urls:
            indicators['url'].append(url)
        
        # Extract file hashes
        hash_patterns = {
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b', 
            'sha256': r'\b[a-fA-F0-9]{64}\b'
        }
        for hash_type, pattern in hash_patterns.items():
            hashes = re.findall(pattern, finding_text)
            for hash_val in hashes:
                indicators['hash'].append(hash_val.lower())
        
        # Extract AWS-specific indicators
        if source == 'aws':
            # ARNs
            arn_pattern = r'arn:aws:[a-zA-Z0-9\-]+:[a-zA-Z0-9\-]*:[0-9]*:[a-zA-Z0-9\-/\._]+'
            arns = re.findall(arn_pattern, finding_text)
            indicators['arn'].extend(arns)
            
            # S3 bucket names
            s3_pattern = r's3://[a-z0-9][a-z0-9\-\.]*[a-z0-9]'
            s3_buckets = re.findall(s3_pattern, finding_text)
            indicators['s3_bucket'].extend([b.replace('s3://', '') for b in s3_buckets])
        
        # Extract GitHub-specific indicators
        if source == 'github':
            # Repository URLs
            repo_pattern = r'github\.com/([a-zA-Z0-9\-\_]+)/([a-zA-Z0-9\-\_\.]+)'
            repos = re.findall(repo_pattern, finding_text)
            for owner, repo in repos:
                indicators['github_repo'].append(f"{owner}/{repo}")
            
            # Package names (npm, pypi)
            npm_pattern = r'"([a-z0-9\-_@/]+)"\s*:\s*"[\^~]?[0-9]'
            npm_packages = re.findall(npm_pattern, finding_text)
            indicators['npm_package'].extend(npm_packages)
        
        return dict(indicators)

    async def correlate_infrastructure(self) -> List[CorrelatedIntelligence]:
        """Correlate infrastructure indicators between AWS and GitHub"""
        correlations = []
        
        # Find common domains/IPs between AWS findings and GitHub code
        aws_domains = {item['value'] for item in self.indicators_cache['domain'] if item['source'] == 'aws'}
        github_domains = {item['value'] for item in self.indicators_cache['domain'] if item['source'] == 'github'}
        
        common_domains = aws_domains & github_domains
        
        for domain in common_domains:
            # Get related findings
            aws_findings = [item['finding'] for item in self.indicators_cache['domain'] 
                           if item['value'] == domain and item['source'] == 'aws']
            github_findings = [item['finding'] for item in self.indicators_cache['domain']
                             if item['value'] == domain and item['source'] == 'github']
            
            correlation = CorrelatedIntelligence(
                correlation_id=f"INFRA-{hashlib.md5(domain.encode()).hexdigest()[:8]}",
                primary_indicator=domain,
                domains=['aws', 'github'],
                risk_score=0,  # Will be calculated later
                confidence_score=85.0,  # High confidence for exact domain match
                correlation_type='infrastructure',
                title=f"Domain {domain} found in both AWS infrastructure and GitHub code",
                description=f"Domain {domain} is referenced in both AWS infrastructure configurations and GitHub repository code, indicating potential infrastructure-code coupling",
                evidence=[
                    {'source': 'aws', 'findings': aws_findings},
                    {'source': 'github', 'findings': github_findings}
                ],
                business_impact='Medium',
                recommendations=[
                    'Review if this domain reference is intentional and secure',
                    'Ensure proper access controls for infrastructure referenced in code',
                    'Consider using environment variables instead of hardcoded domains'
                ],
                timeline=[],
                related_indicators=[domain]
            )
            correlations.append(correlation)
        
        # Correlate S3 buckets mentioned in GitHub code with AWS S3 findings
        s3_github = {item['value'] for item in self.indicators_cache['s3_bucket'] if item['source'] == 'github'}
        s3_aws = {item['finding'].get('resource_id', '') for item in self.indicators_cache['s3_bucket'] if item['source'] == 'aws'}
        
        common_s3 = s3_github & s3_aws
        
        for bucket in common_s3:
            github_findings = [item['finding'] for item in self.indicators_cache['s3_bucket']
                             if item['value'] == bucket and item['source'] == 'github']
            aws_findings = [item['finding'] for item in self.indicators_cache['s3_bucket']
                          if item['finding'].get('resource_id') == bucket and item['source'] == 'aws']
            
            # Check if AWS finding indicates security issue
            aws_risk_score = max([f.get('risk_score', 0) for f in aws_findings], default=0)
            
            correlation = CorrelatedIntelligence(
                correlation_id=f"S3-{hashlib.md5(bucket.encode()).hexdigest()[:8]}",
                primary_indicator=bucket,
                domains=['aws', 'github'],
                risk_score=aws_risk_score,
                confidence_score=95.0,  # Very high confidence for exact bucket match
                correlation_type='infrastructure',
                title=f"S3 bucket {bucket} referenced in code has security findings",
                description=f"S3 bucket {bucket} is referenced in GitHub code and has security configuration issues in AWS",
                evidence=[
                    {'source': 'aws', 'findings': aws_findings},
                    {'source': 'github', 'findings': github_findings}
                ],
                business_impact='High' if aws_risk_score > 70 else 'Medium',
                recommendations=[
                    'Review S3 bucket security configuration',
                    'Ensure code accessing bucket uses proper authentication',
                    'Implement least-privilege access policies',
                    'Consider bucket encryption if not enabled'
                ],
                timeline=[],
                related_indicators=[bucket]
            )
            correlations.append(correlation)
        
        return correlations

    async def correlate_threat_actors(self) -> List[CorrelatedIntelligence]:
        """Correlate threat intelligence with infrastructure and code findings"""
        correlations = []
        
        # Get high-risk threat intelligence indicators
        high_risk_intel = [item for item in self.indicators_cache.get('ip', []) + 
                          self.indicators_cache.get('domain', []) +
                          self.indicators_cache.get('url', [])
                          if item['source'] == 'threat_intel' and 
                          item['finding'].get('reputation_score', 0) > 60]
        
        for intel_item in high_risk_intel:
            indicator = intel_item['value']
            indicator_type = 'ip' if indicator in [i['value'] for i in self.indicators_cache.get('ip', [])] else \
                           'domain' if indicator in [i['value'] for i in self.indicators_cache.get('domain', [])] else 'url'
            
            # Check if this indicator appears in AWS or GitHub
            aws_matches = [item for item in self.indicators_cache.get(indicator_type, [])
                          if item['value'] == indicator and item['source'] == 'aws']
            github_matches = [item for item in self.indicators_cache.get(indicator_type, [])
                            if item['value'] == indicator and item['source'] == 'github']
            
            if aws_matches or github_matches:
                threat_data = intel_item['finding']
                risk_score = threat_data.get('reputation_score', 0)
                
                domains = ['threat_intel']
                evidence = [{'source': 'threat_intel', 'findings': [threat_data]}]
                
                if aws_matches:
                    domains.append('aws')
                    evidence.append({'source': 'aws', 'findings': [item['finding'] for item in aws_matches]})
                
                if github_matches:
                    domains.append('github')
                    evidence.append({'source': 'github', 'findings': [item['finding'] for item in github_matches]})
                
                correlation = CorrelatedIntelligence(
                    correlation_id=f"THREAT-{hashlib.md5(indicator.encode()).hexdigest()[:8]}",
                    primary_indicator=indicator,
                    domains=domains,
                    risk_score=risk_score,
                    confidence_score=90.0,
                    correlation_type='threat_actor',
                    title=f"Known threat indicator {indicator} found in infrastructure/code",
                    description=f"Threat intelligence indicator {indicator} (risk: {risk_score:.1f}/100) found in your infrastructure or code repositories",
                    evidence=evidence,
                    business_impact='Critical' if risk_score > 80 else 'High',
                    recommendations=[
                        f'Immediately investigate all connections to {indicator}',
                        'Block the indicator at network and application levels',
                        'Check logs for historical connections to this indicator',
                        'Review any code or infrastructure that references this indicator',
                        'Consider incident response procedures if active threat confirmed'
                    ],
                    timeline=[],
                    related_indicators=[indicator]
                )
                correlations.append(correlation)
        
        return correlations

    async def correlate_supply_chain(self) -> List[CorrelatedIntelligence]:
        """Correlate supply chain security issues"""
        correlations = []
        
        # Find GitHub packages that have known vulnerabilities in threat intelligence
        github_packages = self.indicators_cache.get('npm_package', []) + \
                         self.indicators_cache.get('pypi_package', [])
        
        # For each package, check if it's flagged in threat intelligence
        for package_item in github_packages:
            if package_item['source'] != 'github':
                continue
                
            package_name = package_item['value']
            
            # Check if any threat intelligence mentions this package
            threat_matches = []
            for intel_item in self.indicators_cache.get('domain', []) + \
                             self.indicators_cache.get('url', []):
                if intel_item['source'] == 'threat_intel':
                    threat_data = intel_item['finding']
                    if package_name.lower() in json.dumps(threat_data, default=str).lower():
                        threat_matches.append(intel_item)
            
            if threat_matches:
                max_risk = max([item['finding'].get('reputation_score', 0) for item in threat_matches])
                
                correlation = CorrelatedIntelligence(
                    correlation_id=f"SUPPLY-{hashlib.md5(package_name.encode()).hexdigest()[:8]}",
                    primary_indicator=package_name,
                    domains=['github', 'threat_intel'],
                    risk_score=max_risk,
                    confidence_score=75.0,
                    correlation_type='supply_chain',
                    title=f"Package {package_name} flagged in threat intelligence",
                    description=f"Package {package_name} used in GitHub repositories is mentioned in threat intelligence reports",
                    evidence=[
                        {'source': 'github', 'findings': [package_item['finding']]},
                        {'source': 'threat_intel', 'findings': [item['finding'] for item in threat_matches]}
                    ],
                    business_impact='High' if max_risk > 70 else 'Medium',
                    recommendations=[
                        f'Review usage of package {package_name} in all repositories',
                        'Check for alternative packages with better security reputation',
                        'Update to latest version if vulnerabilities are patched',
                        'Consider removing package if not essential',
                        'Implement dependency scanning in CI/CD pipeline'
                    ],
                    timeline=[],
                    related_indicators=[package_name]
                )
                correlations.append(correlation)
        
        return correlations

    async def correlate_domain_overlap(self) -> List[CorrelatedIntelligence]:
        """Find domain/IP overlaps that indicate shared infrastructure"""
        correlations = []
        
        # Find IPs that appear in multiple sources
        ip_sources = defaultdict(list)
        for ip_item in self.indicators_cache.get('ip', []):
            ip_sources[ip_item['value']].append(ip_item)
        
        for ip, items in ip_sources.items():
            sources = list(set(item['source'] for item in items))
            if len(sources) > 1:  # IP appears in multiple sources
                
                # Calculate risk based on threat intelligence if present
                risk_score = 30.0  # Base risk for infrastructure sharing
                for item in items:
                    if item['source'] == 'threat_intel':
                        risk_score = max(risk_score, item['finding'].get('reputation_score', 0))
                
                correlation = CorrelatedIntelligence(
                    correlation_id=f"OVERLAP-{hashlib.md5(ip.encode()).hexdigest()[:8]}",
                    primary_indicator=ip,
                    domains=sources,
                    risk_score=risk_score,
                    confidence_score=70.0,
                    correlation_type='infrastructure',
                    title=f"IP {ip} shared across multiple domains",
                    description=f"IP address {ip} appears in {', '.join(sources)} indicating shared infrastructure",
                    evidence=[{'source': source, 'findings': [item['finding'] for item in items if item['source'] == source]}
                             for source in sources],
                    business_impact='Medium',
                    recommendations=[
                        f'Verify if shared use of IP {ip} is intentional',
                        'Review security implications of shared infrastructure',
                        'Consider network segmentation if appropriate'
                    ],
                    timeline=[],
                    related_indicators=[ip]
                )
                correlations.append(correlation)
        
        return correlations

    async def enhance_with_business_context(self, correlations: List[CorrelatedIntelligence]) -> List[CorrelatedIntelligence]:
        """Enhance correlations with business context for prioritization"""
        
        # Business context mapping (would typically come from CMDB/asset inventory)
        default_business_context = {
            'github': BusinessContext('HIGH', 'INTERNAL', ['SOC2'], 'Development', 50000),
            'aws_production': BusinessContext('CRITICAL', 'CONFIDENTIAL', ['SOC2', 'GDPR'], 'Production', 500000),
            'aws_development': BusinessContext('MEDIUM', 'INTERNAL', ['SOC2'], 'Development', 10000)
        }
        
        for correlation in correlations:
            # Determine business impact based on domains involved
            business_impact_score = 0
            
            if 'threat_intel' in correlation.domains:
                business_impact_score += 30  # Any threat intelligence adds significant risk
            
            if 'aws' in correlation.domains:
                business_impact_score += 40  # AWS infrastructure is critical
                
            if 'github' in correlation.domains:
                business_impact_score += 20  # Code repositories are important
            
            # Adjust business impact based on risk score
            risk_multiplier = correlation.risk_score / 100
            final_business_impact = business_impact_score * risk_multiplier
            
            if final_business_impact > 70:
                correlation.business_impact = 'Critical'
            elif final_business_impact > 50:
                correlation.business_impact = 'High'
            elif final_business_impact > 30:
                correlation.business_impact = 'Medium'
            else:
                correlation.business_impact = 'Low'
        
        return correlations

    async def calculate_correlation_risks(self, correlations: List[CorrelatedIntelligence]) -> List[CorrelatedIntelligence]:
        """Calculate comprehensive risk scores for correlations"""
        
        for correlation in correlations:
            # Base risk score from individual finding
            base_risk = correlation.risk_score
            
            # Correlation multipliers
            domain_count_multiplier = 1 + (len(correlation.domains) - 1) * 0.2  # More domains = higher risk
            
            # Correlation type multipliers
            type_multipliers = {
                'threat_actor': 1.5,
                'supply_chain': 1.3,
                'infrastructure': 1.1
            }
            type_multiplier = type_multipliers.get(correlation.correlation_type, 1.0)
            
            # Business impact multiplier
            business_multipliers = {
                'Critical': 1.4,
                'High': 1.2,
                'Medium': 1.0,
                'Low': 0.8
            }
            business_multiplier = business_multipliers.get(correlation.business_impact, 1.0)
            
            # Calculate final risk score
            final_risk = min(
                base_risk * domain_count_multiplier * type_multiplier * business_multiplier,
                100.0
            )
            
            correlation.risk_score = final_risk
            
            # Add timeline entry
            correlation.timeline.append({
                'timestamp': datetime.now().isoformat(),
                'event': 'correlation_analysis_complete',
                'risk_score': final_risk
            })
        
        # Sort by risk score descending
        correlations.sort(key=lambda x: x.risk_score, reverse=True)
        
        return correlations

    async def generate_correlation_report(self, correlations: List[CorrelatedIntelligence]) -> Dict[str, Any]:
        """Generate comprehensive correlation report"""
        
        if not correlations:
            return {
                'summary': 'No correlations found',
                'risk_level': 'LOW',
                'recommendations': ['Continue monitoring for cross-domain indicators']
            }
        
        # Summary statistics
        total_correlations = len(correlations)
        avg_risk_score = sum(c.risk_score for c in correlations) / total_correlations
        
        risk_distribution = {
            'critical': len([c for c in correlations if c.risk_score > 80]),
            'high': len([c for c in correlations if 60 < c.risk_score <= 80]),
            'medium': len([c for c in correlations if 40 < c.risk_score <= 60]),
            'low': len([c for c in correlations if c.risk_score <= 40])
        }
        
        # Correlation type breakdown
        correlation_types = defaultdict(int)
        for c in correlations:
            correlation_types[c.correlation_type] += 1
        
        # Domain involvement
        domain_involvement = defaultdict(int)
        for c in correlations:
            for domain in c.domains:
                domain_involvement[domain] += 1
        
        # Top recommendations
        all_recommendations = []
        for c in correlations:
            all_recommendations.extend(c.recommendations)
        
        # Count recommendation frequency
        rec_counts = defaultdict(int)
        for rec in all_recommendations:
            rec_counts[rec] += 1
        
        top_recommendations = sorted(rec_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'analysis_timestamp': datetime.now().isoformat(),
            'summary': {
                'total_correlations': total_correlations,
                'average_risk_score': avg_risk_score,
                'highest_risk_correlation': max(correlations, key=lambda x: x.risk_score) if correlations else None,
                'risk_distribution': dict(risk_distribution),
                'correlation_types': dict(correlation_types),
                'domain_involvement': dict(domain_involvement)
            },
            'top_correlations': [asdict(c) for c in correlations[:5]],
            'recommendations': {
                'immediate': [rec for rec, _ in top_recommendations[:3]],
                'strategic': [rec for rec, _ in top_recommendations[3:6]],
                'monitoring': [rec for rec, _ in top_recommendations[6:10]]
            },
            'risk_level': 'CRITICAL' if avg_risk_score > 80 else 
                         'HIGH' if avg_risk_score > 60 else
                         'MEDIUM' if avg_risk_score > 40 else 'LOW'
        }

# Example usage and testing
async def main():
    """Test the correlation engine"""
    correlator = IntelligenceCorrelator()
    
    # Sample data for testing
    sample_github = [
        {
            'finding_id': 'GH-001',
            'description': 'Found domain google.com in configuration file',
            'file_path': 'config/production.yml',
            'content': 'api_endpoint: https://api.google.com'
        }
    ]
    
    sample_aws = [
        {
            'finding_id': 'AWS-001', 
            'service': 'S3',
            'resource_id': 'my-production-bucket',
            'description': 'S3 bucket not encrypted',
            'risk_score': 75.0
        }
    ]
    
    sample_threat_intel = [
        {
            'indicator': 'malicious-domain.com',
            'indicator_type': 'domain',
            'reputation_score': 85.0,
            'threat_types': ['malware_c2'],
            'sources': ['VirusTotal']
        }
    ]
    
    correlations = await correlator.correlate_intelligence(
        sample_github, sample_aws, sample_threat_intel
    )
    
    report = await correlator.generate_correlation_report(correlations)
    
    print(f"📊 Correlation analysis complete:")
    print(f"Total correlations: {report['summary']['total_correlations']}")
    print(f"Average risk score: {report['summary']['average_risk_score']:.1f}")
    print(f"Risk level: {report['risk_level']}")

if __name__ == "__main__":
    asyncio.run(main())