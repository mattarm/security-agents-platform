#!/usr/bin/env python3
"""
Enhanced Threat Intelligence Enrichment Module
Integrates multiple OSINT sources for comprehensive security intelligence
"""

import os
import json
import time
import hashlib
import requests
import asyncio
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import vt  # virustotal-python
import shodan
import dns.resolver
from urllib.parse import urlparse

@dataclass
class ThreatIntelligence:
    """Structured threat intelligence data"""
    indicator: str
    indicator_type: str  # ip, domain, url, hash
    reputation_score: float  # 0-100, higher = more malicious
    confidence_score: float  # 0-100, higher = more confident
    sources: List[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    threat_types: List[str]
    campaigns: List[str]
    attribution: Optional[str]
    raw_data: Dict

class ThreatIntelEnrichment:
    """Multi-source threat intelligence enrichment engine"""
    
    def __init__(self):
        self.vt_client = None
        self.shodan_client = None
        self.setup_apis()
        self.cache = {}
        self.rate_limits = {
            'virustotal': {'calls': 0, 'reset_time': 0, 'limit': 500},  # Free tier: 500/day
            'shodan': {'calls': 0, 'reset_time': 0, 'limit': 100},     # Free tier: 100/month
        }
    
    def setup_apis(self):
        """Initialize API clients with environment variables"""
        vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        shodan_api_key = os.getenv('SHODAN_API_KEY')
        
        if vt_api_key:
            self.vt_client = vt.Client(vt_api_key)
            print("✅ VirusTotal API configured")
        else:
            print("⚠️ VirusTotal API key not found in VIRUSTOTAL_API_KEY")
            
        if shodan_api_key:
            self.shodan_client = shodan.Shodan(shodan_api_key)
            print("✅ Shodan API configured")
        else:
            print("⚠️ Shodan API key not found in SHODAN_API_KEY")

    def check_rate_limit(self, service: str) -> bool:
        """Check if we're within rate limits for a service"""
        limits = self.rate_limits[service]
        now = time.time()
        
        # Reset daily counters
        if now > limits['reset_time']:
            limits['calls'] = 0
            if service == 'virustotal':
                limits['reset_time'] = now + 24 * 3600  # 24 hours
            elif service == 'shodan':
                limits['reset_time'] = now + 30 * 24 * 3600  # 30 days
        
        return limits['calls'] < limits['limit']

    def increment_rate_limit(self, service: str):
        """Increment rate limit counter"""
        self.rate_limits[service]['calls'] += 1

    async def enrich_ioc(self, indicator: str, indicator_type: str = None) -> ThreatIntelligence:
        """Enrich a single IOC with multi-source intelligence"""
        
        # Auto-detect indicator type if not provided
        if not indicator_type:
            indicator_type = self.detect_indicator_type(indicator)
        
        # Check cache first
        cache_key = f"{indicator_type}:{indicator}"
        if cache_key in self.cache:
            cache_entry = self.cache[cache_key]
            if datetime.now() - cache_entry['timestamp'] < timedelta(hours=6):
                print(f"📋 Using cached intelligence for {indicator}")
                return cache_entry['data']
        
        print(f"🔍 Enriching {indicator_type}: {indicator}")
        
        # Gather intelligence from multiple sources
        intelligence_data = {
            'indicator': indicator,
            'indicator_type': indicator_type,
            'sources': [],
            'reputation_scores': [],
            'threat_types': set(),
            'campaigns': set(),
            'raw_data': {}
        }
        
        # VirusTotal enrichment
        if self.vt_client and self.check_rate_limit('virustotal'):
            vt_data = await self.enrich_with_virustotal(indicator, indicator_type)
            if vt_data:
                intelligence_data['sources'].append('VirusTotal')
                intelligence_data['reputation_scores'].append(vt_data['reputation_score'])
                intelligence_data['threat_types'].update(vt_data['threat_types'])
                intelligence_data['raw_data']['virustotal'] = vt_data
                self.increment_rate_limit('virustotal')
        
        # Shodan enrichment (for IPs and domains)
        if (self.shodan_client and indicator_type in ['ip', 'domain'] 
            and self.check_rate_limit('shodan')):
            shodan_data = await self.enrich_with_shodan(indicator, indicator_type)
            if shodan_data:
                intelligence_data['sources'].append('Shodan')
                intelligence_data['reputation_scores'].append(shodan_data['reputation_score'])
                intelligence_data['threat_types'].update(shodan_data['threat_types'])
                intelligence_data['raw_data']['shodan'] = shodan_data
                self.increment_rate_limit('shodan')
        
        # DNS enrichment (free)
        if indicator_type in ['domain', 'url']:
            dns_data = await self.enrich_with_dns(indicator, indicator_type)
            if dns_data:
                intelligence_data['sources'].append('DNS')
                intelligence_data['reputation_scores'].append(dns_data['reputation_score'])
                intelligence_data['raw_data']['dns'] = dns_data
        
        # WHOIS enrichment (free, but rate limited)
        if indicator_type in ['ip', 'domain']:
            whois_data = await self.enrich_with_whois(indicator, indicator_type)
            if whois_data:
                intelligence_data['sources'].append('WHOIS')
                intelligence_data['raw_data']['whois'] = whois_data
        
        # Calculate aggregate scores
        reputation_score = self.calculate_reputation_score(intelligence_data['reputation_scores'])
        confidence_score = self.calculate_confidence_score(intelligence_data['sources'])
        
        # Create threat intelligence object
        threat_intel = ThreatIntelligence(
            indicator=indicator,
            indicator_type=indicator_type,
            reputation_score=reputation_score,
            confidence_score=confidence_score,
            sources=intelligence_data['sources'],
            first_seen=None,  # TODO: Extract from source data
            last_seen=datetime.now(),
            threat_types=list(intelligence_data['threat_types']),
            campaigns=list(intelligence_data['campaigns']),
            attribution=None,  # TODO: Extract from source data
            raw_data=intelligence_data['raw_data']
        )
        
        # Cache the result
        self.cache[cache_key] = {
            'data': threat_intel,
            'timestamp': datetime.now()
        }
        
        print(f"✅ Enrichment complete: {indicator} (Score: {reputation_score:.1f}/100, Confidence: {confidence_score:.1f}/100)")
        return threat_intel

    async def enrich_with_virustotal(self, indicator: str, indicator_type: str) -> Optional[Dict]:
        """Enrich with VirusTotal data"""
        try:
            if indicator_type == 'ip':
                obj = await asyncio.to_thread(self.vt_client.get_object, f"/ip_addresses/{indicator}")
            elif indicator_type == 'domain':
                obj = await asyncio.to_thread(self.vt_client.get_object, f"/domains/{indicator}")
            elif indicator_type == 'url':
                url_id = vt.url_id(indicator)
                obj = await asyncio.to_thread(self.vt_client.get_object, f"/urls/{url_id}")
            elif indicator_type == 'hash':
                obj = await asyncio.to_thread(self.vt_client.get_object, f"/files/{indicator}")
            else:
                return None
            
            # Extract reputation data
            stats = obj.last_analysis_stats
            total_engines = sum(stats.values())
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            
            reputation_score = ((malicious_count * 100 + suspicious_count * 50) / total_engines) if total_engines > 0 else 0
            
            threat_types = []
            if hasattr(obj, 'last_analysis_results'):
                for engine, result in obj.last_analysis_results.items():
                    if result['result'] and result['result'] != 'clean':
                        threat_types.append(result['result'])
            
            return {
                'reputation_score': reputation_score,
                'threat_types': threat_types[:10],  # Limit to top 10
                'analysis_stats': stats,
                'total_engines': total_engines,
                'detection_ratio': f"{malicious_count + suspicious_count}/{total_engines}"
            }
            
        except Exception as e:
            print(f"⚠️ VirusTotal enrichment failed for {indicator}: {str(e)}")
            return None

    async def enrich_with_shodan(self, indicator: str, indicator_type: str) -> Optional[Dict]:
        """Enrich with Shodan data"""
        try:
            if indicator_type == 'ip':
                host_info = await asyncio.to_thread(self.shodan_client.host, indicator)
            elif indicator_type == 'domain':
                # Use Shodan's DNS resolve to get IP, then query
                dns_info = await asyncio.to_thread(self.shodan_client.dns.resolve, indicator)
                if dns_info:
                    host_info = await asyncio.to_thread(self.shodan_client.host, dns_info[0])
                else:
                    return None
            else:
                return None
            
            # Analyze open ports and services for threat indicators
            open_ports = host_info.get('ports', [])
            services = []
            vulnerabilities = []
            
            for item in host_info.get('data', []):
                if 'product' in item:
                    services.append(f"{item.get('port', 'unknown')}/{item.get('product', 'unknown')}")
                if 'vulns' in item:
                    vulnerabilities.extend(item['vulns'])
            
            # Calculate reputation based on open ports and vulnerabilities
            reputation_score = 0
            if vulnerabilities:
                reputation_score += len(vulnerabilities) * 20  # 20 points per vulnerability
            
            # Suspicious ports
            suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 5432, 5900]
            suspicious_open = len(set(open_ports) & set(suspicious_ports))
            reputation_score += suspicious_open * 10
            
            reputation_score = min(reputation_score, 100)  # Cap at 100
            
            threat_types = []
            if vulnerabilities:
                threat_types.append('vulnerable_services')
            if suspicious_open > 0:
                threat_types.append('suspicious_ports')
            
            return {
                'reputation_score': reputation_score,
                'threat_types': threat_types,
                'open_ports': open_ports,
                'services': services,
                'vulnerabilities': vulnerabilities,
                'country': host_info.get('country_name', 'unknown'),
                'organization': host_info.get('org', 'unknown')
            }
            
        except Exception as e:
            print(f"⚠️ Shodan enrichment failed for {indicator}: {str(e)}")
            return None

    async def enrich_with_dns(self, indicator: str, indicator_type: str) -> Optional[Dict]:
        """Enrich with DNS data (free)"""
        try:
            domain = indicator
            if indicator_type == 'url':
                domain = urlparse(indicator).netloc
            
            # DNS lookups
            a_records = []
            mx_records = []
            txt_records = []
            
            try:
                for record in dns.resolver.resolve(domain, 'A'):
                    a_records.append(str(record))
            except:
                pass
            
            try:
                for record in dns.resolver.resolve(domain, 'MX'):
                    mx_records.append(str(record))
            except:
                pass
                
            try:
                for record in dns.resolver.resolve(domain, 'TXT'):
                    txt_records.append(str(record))
            except:
                pass
            
            # Basic reputation scoring
            reputation_score = 0
            if not a_records:
                reputation_score += 30  # No A records is suspicious
            
            # Check for suspicious TXT records (like verification codes left behind)
            suspicious_txt_patterns = ['v=spf1', 'google-site-verification', '_dmarc']
            for txt in txt_records:
                for pattern in suspicious_txt_patterns:
                    if pattern not in txt.lower():
                        reputation_score += 5
            
            return {
                'reputation_score': min(reputation_score, 50),  # DNS data provides limited reputation info
                'a_records': a_records,
                'mx_records': mx_records,
                'txt_records': txt_records
            }
            
        except Exception as e:
            print(f"⚠️ DNS enrichment failed for {indicator}: {str(e)}")
            return None

    async def enrich_with_whois(self, indicator: str, indicator_type: str) -> Optional[Dict]:
        """Enrich with WHOIS data (free, rate limited)"""
        try:
            import whois
            
            if indicator_type == 'ip':
                # IP WHOIS is complex, skip for now
                return None
            elif indicator_type == 'domain':
                whois_data = whois.whois(indicator)
                
                # Extract key information
                creation_date = whois_data.creation_date
                expiration_date = whois_data.expiration_date
                registrar = whois_data.registrar
                
                # Convert single dates to lists for consistency
                if isinstance(creation_date, list) and creation_date:
                    creation_date = creation_date[0]
                if isinstance(expiration_date, list) and expiration_date:
                    expiration_date = expiration_date[0]
                
                return {
                    'creation_date': creation_date.isoformat() if creation_date else None,
                    'expiration_date': expiration_date.isoformat() if expiration_date else None,
                    'registrar': registrar,
                    'name_servers': whois_data.name_servers
                }
            
        except Exception as e:
            print(f"⚠️ WHOIS enrichment failed for {indicator}: {str(e)}")
            return None

    def detect_indicator_type(self, indicator: str) -> str:
        """Auto-detect indicator type"""
        import re
        
        # IP address
        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        if re.match(ip_pattern, indicator):
            return 'ip'
        
        # URL
        if indicator.startswith(('http://', 'https://')):
            return 'url'
        
        # Hash (MD5, SHA1, SHA256)
        if len(indicator) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in indicator):
            return 'hash'
        
        # Domain (default)
        return 'domain'

    def calculate_reputation_score(self, scores: List[float]) -> float:
        """Calculate weighted average reputation score"""
        if not scores:
            return 0.0
        
        # Weight VirusTotal higher than other sources
        # TODO: Implement proper weighting based on source reliability
        return sum(scores) / len(scores)

    def calculate_confidence_score(self, sources: List[str]) -> float:
        """Calculate confidence score based on number and quality of sources"""
        if not sources:
            return 0.0
        
        # Base confidence
        confidence = min(len(sources) * 25, 75)  # 25 points per source, max 75
        
        # Bonus for high-quality sources
        if 'VirusTotal' in sources:
            confidence += 20
        if 'Shodan' in sources:
            confidence += 15
        
        return min(confidence, 100)

    async def bulk_enrich_iocs(self, indicators: List[str]) -> List[ThreatIntelligence]:
        """Enrich multiple IOCs in parallel with rate limiting"""
        print(f"🔍 Starting bulk enrichment of {len(indicators)} indicators")
        
        # Process in batches to respect rate limits
        batch_size = 10
        results = []
        
        for i in range(0, len(indicators), batch_size):
            batch = indicators[i:i + batch_size]
            print(f"📦 Processing batch {i//batch_size + 1}/{(len(indicators) + batch_size - 1)//batch_size}")
            
            # Process batch in parallel
            batch_tasks = [self.enrich_ioc(indicator) for indicator in batch]
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, Exception):
                    print(f"⚠️ Error in batch processing: {str(result)}")
                else:
                    results.append(result)
            
            # Rate limiting delay
            await asyncio.sleep(1)
        
        print(f"✅ Bulk enrichment complete: {len(results)}/{len(indicators)} successful")
        return results

# Example usage and testing
async def main():
    """Test the threat intelligence enrichment"""
    enricher = ThreatIntelEnrichment()
    
    # Test indicators
    test_indicators = [
        '8.8.8.8',  # Google DNS (should be clean)
        'google.com',  # Should be clean
        'https://www.google.com',  # Should be clean
        '44d88612fea8a8f36de82e1278abb02f',  # MD5 hash of "hello"
    ]
    
    print("🚀 Starting threat intelligence enrichment test")
    
    for indicator in test_indicators:
        try:
            threat_intel = await enricher.enrich_ioc(indicator)
            print(f"\n📊 Results for {indicator}:")
            print(f"  Type: {threat_intel.indicator_type}")
            print(f"  Reputation: {threat_intel.reputation_score:.1f}/100")
            print(f"  Confidence: {threat_intel.confidence_score:.1f}/100")
            print(f"  Sources: {', '.join(threat_intel.sources)}")
            print(f"  Threat types: {', '.join(threat_intel.threat_types)}")
        except Exception as e:
            print(f"❌ Failed to enrich {indicator}: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())