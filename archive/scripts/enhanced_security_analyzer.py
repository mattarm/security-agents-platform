#!/usr/bin/env python3
"""
Enhanced Security Analyzer - Multi-Domain Security Intelligence Platform
Integrates GitHub, AWS, and Threat Intelligence for comprehensive security analysis
"""

import os
import sys
import json
import asyncio
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

# Add project modules to path
sys.path.append(str(Path(__file__).parent))

# Import our enhanced modules
from osint.threat_intel_enrichment import ThreatIntelEnrichment
from aws_security.infrastructure_analyzer import AWSSecurityAnalyzer
from correlation.intelligence_correlator import IntelligenceCorrelator

class EnhancedSecurityAnalyzer:
    """Main orchestrator for multi-domain security analysis"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.output_dir = Path(self.config.get('output_dir', './security-analysis-results'))
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize analysis engines
        self.threat_intel = ThreatIntelEnrichment()
        self.aws_analyzer = AWSSecurityAnalyzer(
            profile_name=self.config.get('aws_profile')
        )
        self.correlator = IntelligenceCorrelator()
        
        # Analysis results storage
        self.results = {
            'analysis_id': f"SA-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'timestamp': datetime.now().isoformat(),
            'scope': [],
            'findings': {
                'github': [],
                'aws': [],
                'threat_intel': [],
                'correlations': []
            },
            'metrics': {},
            'recommendations': []
        }
        
        print("🚀 Enhanced Security Analyzer initialized")
        print(f"📁 Output directory: {self.output_dir}")

    async def analyze_organization(self, 
                                 github_org: Optional[str] = None,
                                 aws_profile: Optional[str] = None,
                                 threat_intel_scope: List[str] = None) -> Dict[str, Any]:
        """Comprehensive security analysis across all domains"""
        
        print("🔍 Starting comprehensive multi-domain security analysis...")
        analysis_start = datetime.now()
        
        # Phase 1: GitHub Repository Analysis
        github_findings = []
        if github_org or self.config.get('github_enabled', True):
            print("\n📚 Phase 1: GitHub Repository Security Analysis")
            github_findings = await self.analyze_github_repositories(github_org)
            self.results['findings']['github'] = github_findings
            self.results['scope'].append('github')
        
        # Phase 2: AWS Infrastructure Analysis  
        aws_findings = []
        if aws_profile or self.config.get('aws_enabled', True):
            print("\n🏗️ Phase 2: AWS Infrastructure Security Analysis")
            try:
                aws_analysis = await self.aws_analyzer.analyze_infrastructure()
                aws_findings = aws_analysis.get('security_findings', [])
                self.results['findings']['aws'] = aws_findings
                self.results['scope'].append('aws')
                
                # Store additional AWS analysis data
                self.results['aws_inventory'] = aws_analysis.get('inventory_summary', {})
                self.results['aws_compliance'] = aws_analysis.get('compliance_results', {})
                
            except Exception as e:
                print(f"⚠️ AWS analysis failed: {str(e)}")
                print("Continuing with other analysis...")
        
        # Phase 3: Threat Intelligence Enrichment
        threat_intel_data = []
        print("\n🕵️ Phase 3: Threat Intelligence Enrichment")
        
        # Extract indicators from GitHub and AWS findings for enrichment
        indicators_to_enrich = self.extract_indicators_for_enrichment(
            github_findings, aws_findings
        )
        
        if indicators_to_enrich or threat_intel_scope:
            all_indicators = indicators_to_enrich + (threat_intel_scope or [])
            threat_intel_data = await self.threat_intel.bulk_enrich_iocs(all_indicators)
            self.results['findings']['threat_intel'] = [
                dict(indicator=ti.indicator, 
                     indicator_type=ti.indicator_type,
                     reputation_score=ti.reputation_score,
                     confidence_score=ti.confidence_score,
                     sources=ti.sources,
                     threat_types=ti.threat_types,
                     campaigns=ti.campaigns)
                for ti in threat_intel_data
            ]
            self.results['scope'].append('threat_intel')
        
        # Phase 4: Cross-Domain Intelligence Correlation
        print("\n🧠 Phase 4: Cross-Domain Intelligence Correlation")
        correlations = await self.correlator.correlate_intelligence(
            github_findings, aws_findings, self.results['findings']['threat_intel']
        )
        self.results['findings']['correlations'] = [
            {
                'correlation_id': c.correlation_id,
                'primary_indicator': c.primary_indicator,
                'domains': c.domains,
                'risk_score': c.risk_score,
                'confidence_score': c.confidence_score,
                'correlation_type': c.correlation_type,
                'title': c.title,
                'description': c.description,
                'business_impact': c.business_impact,
                'recommendations': c.recommendations
            }
            for c in correlations
        ]
        
        # Phase 5: Generate Comprehensive Report
        print("\n📊 Phase 5: Generating Comprehensive Security Report")
        
        analysis_duration = (datetime.now() - analysis_start).total_seconds()
        self.results['analysis_duration_seconds'] = analysis_duration
        
        # Calculate overall metrics
        self.calculate_security_metrics()
        
        # Generate recommendations
        self.generate_strategic_recommendations()
        
        # Save results
        await self.save_analysis_results()
        
        print(f"✅ Analysis complete in {analysis_duration:.1f} seconds")
        print(f"📋 Results saved to {self.output_dir}")
        
        return self.results

    async def analyze_github_repositories(self, org_name: Optional[str] = None) -> List[Dict]:
        """Enhanced GitHub repository analysis"""
        findings = []
        
        try:
            # Use GitHub CLI to get repositories
            import subprocess
            
            if org_name:
                cmd = f"gh repo list {org_name} --json name,url,visibility,language --limit 50"
            else:
                cmd = "gh repo list --json name,url,visibility,language --limit 20"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"⚠️ GitHub CLI error: {result.stderr}")
                return []
            
            repositories = json.loads(result.stdout)
            print(f"📚 Found {len(repositories)} repositories to analyze")
            
            for repo in repositories:
                repo_name = repo['name']
                repo_url = repo['url']
                print(f"  🔍 Analyzing repository: {repo_name}")
                
                # Basic repository analysis (enhanced from original sprint)
                repo_findings = await self.analyze_single_repository(repo)
                findings.extend(repo_findings)
                
        except Exception as e:
            print(f"❌ GitHub analysis failed: {str(e)}")
        
        return findings

    async def analyze_single_repository(self, repo: Dict) -> List[Dict]:
        """Analyze a single repository for security issues"""
        findings = []
        repo_name = repo['name']
        
        try:
            # Clone repository to temporary location for analysis
            import subprocess
            import tempfile
            
            with tempfile.TemporaryDirectory() as temp_dir:
                clone_path = Path(temp_dir) / repo_name
                
                # Clone repository
                clone_cmd = f"gh repo clone {repo['url']} {clone_path}"
                result = subprocess.run(clone_cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode != 0:
                    print(f"    ⚠️ Failed to clone {repo_name}: {result.stderr}")
                    return findings
                
                # Analyze repository contents
                findings.extend(await self.scan_secrets(clone_path, repo))
                findings.extend(await self.scan_dependencies(clone_path, repo))
                findings.extend(await self.scan_configuration(clone_path, repo))
                findings.extend(await self.scan_infrastructure_references(clone_path, repo))
                
        except Exception as e:
            print(f"    ❌ Repository analysis failed for {repo_name}: {str(e)}")
        
        return findings

    async def scan_secrets(self, repo_path: Path, repo: Dict) -> List[Dict]:
        """Scan for secrets and sensitive information"""
        findings = []
        
        # Common secret patterns
        secret_patterns = [
            (r'aws_access_key_id\s*=\s*["\']?([A-Z0-9]{20})["\']?', 'AWS Access Key ID'),
            (r'aws_secret_access_key\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?', 'AWS Secret Access Key'),
            (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API Key'),
            (r'ghp_[A-Za-z0-9]{36}', 'GitHub Personal Access Token'),
            (r'password\s*=\s*["\']([^"\']+)["\']', 'Hardcoded Password'),
            (r'api_key\s*=\s*["\']([^"\']+)["\']', 'API Key'),
            (r'-----BEGIN [A-Z ]+-----', 'Private Key'),
        ]
        
        try:
            for file_path in repo_path.rglob('*'):
                if file_path.is_file() and file_path.suffix in ['.py', '.js', '.yml', '.yaml', '.json', '.env', '.config']:
                    try:
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                        
                        for pattern, secret_type in secret_patterns:
                            import re
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            
                            for match in matches:
                                relative_path = file_path.relative_to(repo_path)
                                
                                findings.append({
                                    'finding_id': f"GH-SECRET-{len(findings)+1}",
                                    'repository': repo['name'],
                                    'file_path': str(relative_path),
                                    'line_number': content[:match.start()].count('\n') + 1,
                                    'severity': 'CRITICAL',
                                    'category': 'Secrets Management',
                                    'title': f'{secret_type} found in code',
                                    'description': f'Potential {secret_type.lower()} found in {relative_path}',
                                    'remediation': f'Remove {secret_type.lower()} from code and use environment variables or secrets management',
                                    'risk_score': 90.0,
                                    'metadata': {
                                        'secret_type': secret_type,
                                        'pattern_matched': pattern
                                    }
                                })
                    except Exception:
                        continue  # Skip files that can't be read
        except Exception as e:
            print(f"      ⚠️ Secret scanning failed: {str(e)}")
        
        return findings

    async def scan_dependencies(self, repo_path: Path, repo: Dict) -> List[Dict]:
        """Scan dependencies for known vulnerabilities"""
        findings = []
        
        # Check for dependency files
        dependency_files = {
            'package.json': 'npm',
            'requirements.txt': 'pip',
            'Pipfile': 'pipenv',
            'go.mod': 'go',
            'Gemfile': 'bundler',
            'pom.xml': 'maven',
            'build.gradle': 'gradle'
        }
        
        for dep_file, package_manager in dependency_files.items():
            dep_file_path = repo_path / dep_file
            if dep_file_path.exists():
                print(f"      📦 Found {dep_file} - analyzing {package_manager} dependencies")
                
                try:
                    content = dep_file_path.read_text()
                    
                    # Extract package names (simplified extraction)
                    if package_manager == 'npm' and dep_file == 'package.json':
                        import json
                        data = json.loads(content)
                        dependencies = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                        
                        for package_name, version in dependencies.items():
                            # Flag commonly vulnerable packages (this would normally use a vulnerability database)
                            vulnerable_packages = ['lodash', 'axios', 'express', 'moment', 'request']
                            if package_name in vulnerable_packages:
                                findings.append({
                                    'finding_id': f"GH-DEP-{len(findings)+1}",
                                    'repository': repo['name'],
                                    'file_path': dep_file,
                                    'severity': 'HIGH',
                                    'category': 'Dependency Vulnerability',
                                    'title': f'Potentially vulnerable dependency: {package_name}',
                                    'description': f'Package {package_name} may have known vulnerabilities',
                                    'remediation': f'Update {package_name} to latest version and check security advisories',
                                    'risk_score': 70.0,
                                    'metadata': {
                                        'package_name': package_name,
                                        'version': version,
                                        'package_manager': package_manager
                                    }
                                })
                    
                    elif package_manager == 'pip':
                        # Extract pip packages
                        lines = content.split('\n')
                        for line in lines:
                            if '==' in line:
                                package_name = line.split('==')[0].strip()
                                version = line.split('==')[1].strip()
                                
                                # Flag commonly vulnerable Python packages
                                vulnerable_packages = ['django', 'flask', 'requests', 'urllib3', 'jinja2']
                                if package_name.lower() in vulnerable_packages:
                                    findings.append({
                                        'finding_id': f"GH-DEP-{len(findings)+1}",
                                        'repository': repo['name'],
                                        'file_path': dep_file,
                                        'severity': 'HIGH',
                                        'category': 'Dependency Vulnerability',
                                        'title': f'Potentially vulnerable dependency: {package_name}',
                                        'description': f'Package {package_name} may have known vulnerabilities',
                                        'remediation': f'Update {package_name} to latest version and check security advisories',
                                        'risk_score': 70.0,
                                        'metadata': {
                                            'package_name': package_name,
                                            'version': version,
                                            'package_manager': package_manager
                                        }
                                    })
                
                except Exception as e:
                    print(f"        ⚠️ Failed to analyze {dep_file}: {str(e)}")
        
        return findings

    async def scan_configuration(self, repo_path: Path, repo: Dict) -> List[Dict]:
        """Scan configuration files for security issues"""
        findings = []
        
        # Configuration files to check
        config_patterns = [
            ('docker-compose.yml', 'Docker Compose'),
            ('Dockerfile', 'Docker'),
            ('.env', 'Environment Variables'),
            ('*.yml', 'YAML Configuration'),
            ('*.yaml', 'YAML Configuration'),
            ('config.json', 'JSON Configuration')
        ]
        
        for pattern, config_type in config_patterns:
            config_files = list(repo_path.rglob(pattern))
            
            for config_file in config_files:
                try:
                    content = config_file.read_text(encoding='utf-8', errors='ignore')
                    relative_path = config_file.relative_to(repo_path)
                    
                    # Check for insecure configurations
                    insecure_patterns = [
                        (r'debug\s*[:=]\s*true', 'Debug mode enabled'),
                        (r'ssl\s*[:=]\s*false', 'SSL disabled'),
                        (r'verify\s*[:=]\s*false', 'Certificate verification disabled'),
                        (r'http://(?!localhost)', 'Insecure HTTP URL'),
                        (r'0\.0\.0\.0', 'Bind to all interfaces'),
                    ]
                    
                    for pattern_regex, issue_type in insecure_patterns:
                        import re
                        if re.search(pattern_regex, content, re.IGNORECASE):
                            findings.append({
                                'finding_id': f"GH-CONFIG-{len(findings)+1}",
                                'repository': repo['name'],
                                'file_path': str(relative_path),
                                'severity': 'MEDIUM',
                                'category': 'Configuration Security',
                                'title': f'{issue_type} in {config_type.lower()}',
                                'description': f'Insecure configuration found: {issue_type.lower()}',
                                'remediation': f'Review and secure {config_type.lower()} configuration',
                                'risk_score': 50.0,
                                'metadata': {
                                    'config_type': config_type,
                                    'issue_type': issue_type
                                }
                            })
                
                except Exception:
                    continue  # Skip files that can't be read
        
        return findings

    async def scan_infrastructure_references(self, repo_path: Path, repo: Dict) -> List[Dict]:
        """Scan for infrastructure references (AWS, domains, IPs)"""
        findings = []
        
        infrastructure_patterns = [
            (r'[a-zA-Z0-9\-\.]+\.amazonaws\.com', 'AWS Service Endpoint'),
            (r'arn:aws:[a-zA-Z0-9\-]+:[a-zA-Z0-9\-]*:[0-9]*:[a-zA-Z0-9\-/\._]+', 'AWS ARN'),
            (r's3://[a-z0-9][a-z0-9\-\.]*[a-z0-9]', 'S3 Bucket Reference'),
            (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', 'IP Address'),
            (r'[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}', 'Domain Reference')
        ]
        
        try:
            for file_path in repo_path.rglob('*'):
                if (file_path.is_file() and 
                    file_path.suffix in ['.py', '.js', '.yml', '.yaml', '.json', '.env', '.config', '.tf']):
                    
                    try:
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                        relative_path = file_path.relative_to(repo_path)
                        
                        for pattern, ref_type in infrastructure_patterns:
                            import re
                            matches = re.finditer(pattern, content)
                            
                            for match in matches:
                                matched_value = match.group(0)
                                
                                # Filter out common false positives
                                if ref_type == 'Domain Reference':
                                    false_positives = ['example.com', 'localhost', 'test.com', '.git', '.json', '.yml']
                                    if any(fp in matched_value.lower() for fp in false_positives):
                                        continue
                                
                                findings.append({
                                    'finding_id': f"GH-INFRA-{len(findings)+1}",
                                    'repository': repo['name'],
                                    'file_path': str(relative_path),
                                    'line_number': content[:match.start()].count('\n') + 1,
                                    'severity': 'INFO',
                                    'category': 'Infrastructure Reference',
                                    'title': f'{ref_type} found in code',
                                    'description': f'{ref_type} "{matched_value}" referenced in {relative_path}',
                                    'remediation': f'Verify {ref_type.lower()} reference is intentional and secure',
                                    'risk_score': 20.0,
                                    'metadata': {
                                        'reference_type': ref_type,
                                        'value': matched_value
                                    }
                                })
                    except Exception:
                        continue
        except Exception as e:
            print(f"      ⚠️ Infrastructure scanning failed: {str(e)}")
        
        return findings

    def extract_indicators_for_enrichment(self, github_findings: List[Dict], 
                                        aws_findings: List[Dict]) -> List[str]:
        """Extract indicators from findings for threat intelligence enrichment"""
        indicators = set()
        
        # Extract from GitHub findings
        for finding in github_findings:
            if finding.get('category') == 'Infrastructure Reference':
                value = finding.get('metadata', {}).get('value', '')
                if value and len(value) > 3:
                    indicators.add(value)
        
        # Extract from AWS findings  
        for finding in aws_findings:
            # Extract domains, IPs from AWS findings
            description = finding.get('description', '')
            import re
            
            # Extract IPs
            ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', description)
            indicators.update(ips)
            
            # Extract domains
            domains = re.findall(r'[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}', description)
            indicators.update(domains)
        
        # Filter and limit indicators
        filtered_indicators = []
        for indicator in indicators:
            # Skip obvious false positives
            false_positives = ['localhost', 'example.com', '127.0.0.1', '0.0.0.0']
            if indicator not in false_positives and len(indicator) > 3:
                filtered_indicators.append(indicator)
        
        return list(filtered_indicators)[:50]  # Limit to 50 indicators for API limits

    def calculate_security_metrics(self):
        """Calculate overall security metrics"""
        all_findings = (
            self.results['findings']['github'] +
            self.results['findings']['aws'] + 
            self.results['findings']['correlations']
        )
        
        if not all_findings:
            self.results['metrics'] = {
                'overall_risk_score': 0,
                'total_findings': 0,
                'risk_distribution': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
            }
            return
        
        # Risk distribution
        risk_distribution = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        total_risk = 0
        
        for finding in all_findings:
            severity = finding.get('severity', 'INFO')
            risk_score = finding.get('risk_score', 0)
            
            risk_distribution[severity] = risk_distribution.get(severity, 0) + 1
            total_risk += risk_score
        
        # Overall risk score
        avg_risk_score = total_risk / len(all_findings) if all_findings else 0
        
        # Domain-specific metrics
        domain_metrics = {}
        for domain in self.results['scope']:
            domain_findings = self.results['findings'].get(domain, [])
            if domain_findings:
                domain_risk = sum(f.get('risk_score', 0) for f in domain_findings) / len(domain_findings)
                domain_metrics[domain] = {
                    'finding_count': len(domain_findings),
                    'avg_risk_score': domain_risk
                }
        
        # Threat intelligence metrics
        threat_intel_metrics = {}
        if self.results['findings']['threat_intel']:
            threat_data = self.results['findings']['threat_intel']
            high_risk_indicators = [t for t in threat_data if t.get('reputation_score', 0) > 70]
            threat_intel_metrics = {
                'total_indicators_analyzed': len(threat_data),
                'high_risk_indicators': len(high_risk_indicators),
                'avg_reputation_score': sum(t.get('reputation_score', 0) for t in threat_data) / len(threat_data)
            }
        
        self.results['metrics'] = {
            'overall_risk_score': avg_risk_score,
            'total_findings': len(all_findings),
            'risk_distribution': risk_distribution,
            'domain_metrics': domain_metrics,
            'threat_intel_metrics': threat_intel_metrics,
            'correlation_count': len(self.results['findings']['correlations'])
        }

    def generate_strategic_recommendations(self):
        """Generate strategic security recommendations"""
        recommendations = []
        metrics = self.results['metrics']
        
        # Overall risk assessment
        overall_risk = metrics['overall_risk_score']
        if overall_risk > 70:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Risk Management',
                'recommendation': 'Immediate security review required - multiple high-risk findings detected',
                'justification': f'Overall risk score of {overall_risk:.1f}/100 requires immediate attention'
            })
        elif overall_risk > 50:
            recommendations.append({
                'priority': 'HIGH', 
                'category': 'Risk Management',
                'recommendation': 'Comprehensive security improvement program recommended',
                'justification': f'Risk score of {overall_risk:.1f}/100 indicates significant security gaps'
            })
        
        # Critical findings
        critical_count = metrics['risk_distribution']['CRITICAL']
        if critical_count > 0:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Immediate Action',
                'recommendation': f'Address {critical_count} critical security findings immediately',
                'justification': 'Critical findings pose immediate risk to organizational security'
            })
        
        # Correlation-based recommendations
        correlation_count = metrics['correlation_count']
        if correlation_count > 0:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Cross-Domain Security',
                'recommendation': f'Investigate {correlation_count} cross-domain security correlations',
                'justification': 'Cross-domain correlations indicate potential systemic security issues'
            })
        
        # Domain-specific recommendations
        domain_metrics = metrics.get('domain_metrics', {})
        
        if 'github' in domain_metrics:
            github_metrics = domain_metrics['github']
            if github_metrics['avg_risk_score'] > 60:
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Code Security',
                    'recommendation': 'Implement comprehensive secure coding practices and CI/CD security scanning',
                    'justification': f"GitHub repositories show high risk score ({github_metrics['avg_risk_score']:.1f}/100)"
                })
        
        if 'aws' in domain_metrics:
            aws_metrics = domain_metrics['aws']
            if aws_metrics['avg_risk_score'] > 60:
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Infrastructure Security',
                    'recommendation': 'Review and harden AWS infrastructure security configurations',
                    'justification': f"AWS infrastructure shows high risk score ({aws_metrics['avg_risk_score']:.1f}/100)"
                })
        
        # Threat intelligence recommendations
        threat_intel_metrics = metrics.get('threat_intel_metrics', {})
        if threat_intel_metrics.get('high_risk_indicators', 0) > 0:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Threat Intelligence',
                'recommendation': 'Implement threat intelligence-driven security controls',
                'justification': f"{threat_intel_metrics['high_risk_indicators']} high-risk threat indicators detected"
            })
        
        # Strategic recommendations
        recommendations.extend([
            {
                'priority': 'MEDIUM',
                'category': 'Security Program',
                'recommendation': 'Implement automated security monitoring and alerting',
                'justification': 'Proactive monitoring essential for comprehensive security posture'
            },
            {
                'priority': 'MEDIUM',
                'category': 'Compliance',
                'recommendation': 'Regular security assessments and compliance audits',
                'justification': 'Continuous assessment needed to maintain security standards'
            },
            {
                'priority': 'LOW',
                'category': 'Security Awareness',
                'recommendation': 'Security training program for development and operations teams',
                'justification': 'Human factor remains critical component of security posture'
            }
        ])
        
        # Sort recommendations by priority
        priority_order = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4}
        recommendations.sort(key=lambda x: priority_order.get(x['priority'], 5))
        
        self.results['recommendations'] = recommendations

    async def save_analysis_results(self):
        """Save analysis results to files"""
        # Main results JSON
        results_file = self.output_dir / f"security-analysis-{self.results['analysis_id']}.json"
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        # Summary report
        summary_file = self.output_dir / f"summary-{self.results['analysis_id']}.md"
        await self.generate_markdown_report(summary_file)
        
        # CSV export for findings
        csv_file = self.output_dir / f"findings-{self.results['analysis_id']}.csv"
        await self.export_findings_csv(csv_file)
        
        print(f"📄 Results saved:")
        print(f"  • JSON: {results_file}")
        print(f"  • Summary: {summary_file}")
        print(f"  • CSV: {csv_file}")

    async def generate_markdown_report(self, file_path: Path):
        """Generate markdown summary report"""
        metrics = self.results['metrics']
        
        report = f"""# Security Analysis Report
        
**Analysis ID:** {self.results['analysis_id']}  
**Timestamp:** {self.results['timestamp']}  
**Duration:** {self.results['analysis_duration_seconds']:.1f} seconds  
**Scope:** {', '.join(self.results['scope'])}

## Executive Summary

- **Overall Risk Score:** {metrics['overall_risk_score']:.1f}/100
- **Total Findings:** {metrics['total_findings']}
- **Critical Issues:** {metrics['risk_distribution']['CRITICAL']}
- **High Risk Issues:** {metrics['risk_distribution']['HIGH']}
- **Cross-Domain Correlations:** {metrics['correlation_count']}

## Risk Distribution

| Severity | Count |
|----------|-------|
| Critical | {metrics['risk_distribution']['CRITICAL']} |
| High | {metrics['risk_distribution']['HIGH']} |
| Medium | {metrics['risk_distribution']['MEDIUM']} |
| Low | {metrics['risk_distribution']['LOW']} |
| Info | {metrics['risk_distribution']['INFO']} |

## Key Recommendations

"""
        
        for i, rec in enumerate(self.results['recommendations'][:5], 1):
            report += f"{i}. **{rec['priority']}** - {rec['recommendation']}\n"
            report += f"   *{rec['justification']}*\n\n"
        
        if self.results['findings']['correlations']:
            report += "## Top Cross-Domain Correlations\n\n"
            for corr in self.results['findings']['correlations'][:3]:
                report += f"- **{corr['title']}** (Risk: {corr['risk_score']:.1f}/100)\n"
                report += f"  {corr['description']}\n\n"
        
        report += f"""
## Analysis Coverage

{self._generate_coverage_summary()}

## Next Steps

1. Address critical findings immediately
2. Review and validate cross-domain correlations  
3. Implement recommended security controls
4. Schedule follow-up assessment

*Generated by Enhanced Security Analyzer v2.0*
"""
        
        with open(file_path, 'w') as f:
            f.write(report)

    def _generate_coverage_summary(self) -> str:
        """Generate analysis coverage summary"""
        summary = ""
        domain_metrics = self.results['metrics'].get('domain_metrics', {})
        
        for domain, metrics in domain_metrics.items():
            summary += f"- **{domain.title()}:** {metrics['finding_count']} findings (avg risk: {metrics['avg_risk_score']:.1f}/100)\n"
        
        if self.results['findings']['threat_intel']:
            ti_metrics = self.results['metrics']['threat_intel_metrics']
            summary += f"- **Threat Intelligence:** {ti_metrics['total_indicators_analyzed']} indicators analyzed\n"
        
        return summary

    async def export_findings_csv(self, file_path: Path):
        """Export findings to CSV format"""
        import csv
        
        all_findings = []
        
        # Collect all findings with domain tags
        for domain, findings in self.results['findings'].items():
            if domain == 'correlations':
                continue  # Skip correlations for CSV
            for finding in findings:
                finding_row = {
                    'domain': domain,
                    'finding_id': finding.get('finding_id', ''),
                    'severity': finding.get('severity', ''),
                    'category': finding.get('category', ''),
                    'title': finding.get('title', ''),
                    'description': finding.get('description', ''),
                    'risk_score': finding.get('risk_score', 0),
                    'remediation': finding.get('remediation', '')
                }
                all_findings.append(finding_row)
        
        if all_findings:
            with open(file_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=all_findings[0].keys())
                writer.writeheader()
                writer.writerows(all_findings)

# CLI Interface
async def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description='Enhanced Security Analyzer - Multi-Domain Security Intelligence')
    parser.add_argument('--github-org', help='GitHub organization to analyze')
    parser.add_argument('--aws-profile', help='AWS profile to use for infrastructure analysis')
    parser.add_argument('--threat-intel', nargs='*', help='Additional indicators to analyze')
    parser.add_argument('--output-dir', default='./security-analysis-results', help='Output directory for results')
    parser.add_argument('--config', help='Configuration file path')
    
    args = parser.parse_args()
    
    # Load configuration
    config = {'output_dir': args.output_dir}
    if args.config and Path(args.config).exists():
        with open(args.config) as f:
            config.update(json.load(f))
    
    # Initialize analyzer
    analyzer = EnhancedSecurityAnalyzer(config)
    
    # Run analysis
    try:
        results = await analyzer.analyze_organization(
            github_org=args.github_org,
            aws_profile=args.aws_profile,
            threat_intel_scope=args.threat_intel
        )
        
        print("\n🎯 Analysis Summary:")
        print(f"Risk Score: {results['metrics']['overall_risk_score']:.1f}/100")
        print(f"Total Findings: {results['metrics']['total_findings']}")
        print(f"Correlations: {results['metrics']['correlation_count']}")
        print(f"\n📊 Next Steps: Review {args.output_dir} for detailed results")
        
    except KeyboardInterrupt:
        print("\n⚠️ Analysis interrupted by user")
    except Exception as e:
        print(f"\n❌ Analysis failed: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())