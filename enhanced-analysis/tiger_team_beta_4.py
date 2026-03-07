#!/usr/bin/env python3
"""
Tiger Team Beta-4: DevSecOps Security Automation Specialist
Advanced secure development lifecycle automation and governance
"""

import os
import ast
import json
import asyncio
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import subprocess
import re

@dataclass
class SecurityVulnerability:
    """Comprehensive vulnerability representation"""
    vuln_id: str
    cwe_id: Optional[str]
    cvss_score: float
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str  # SAST, DAST, SCA, SECRET, CONFIG
    title: str
    description: str
    file_path: str
    line_number: Optional[int]
    code_context: Optional[str]
    proof_of_concept: Optional[str]
    remediation: str
    business_impact: str
    confidence: float  # 0-100
    false_positive_likelihood: float

@dataclass
class ArchitectureAssessment:
    """Secure architecture analysis results"""
    assessment_id: str
    architecture_type: str  # microservices, monolith, serverless, etc.
    threat_model: Dict[str, Any]
    security_controls: List[Dict]
    compliance_gaps: List[Dict]
    risk_score: float
    recommendations: List[str]
    attack_surface_analysis: Dict[str, Any]

@dataclass
class SupplyChainRisk:
    """Supply chain security risk analysis"""
    component_name: str
    component_version: str
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    vulnerability_count: int
    license_risk: str
    maintenance_status: str  # ACTIVE, DEPRECATED, ABANDONED
    alternatives: List[str]
    mitigation_steps: List[str]
    sbom_entry: Dict[str, Any]

class AdvancedDevSecOpsEngine:
    """Comprehensive DevSecOps security automation platform"""
    
    def __init__(self, workspace_path: str = "."):
        self.workspace_path = Path(workspace_path)
        self.security_rules = self.load_security_rules()
        self.vulnerability_database = {}
        self.architecture_analyzer = ArchitectureSecurityAnalyzer()
        self.supply_chain_analyzer = SupplyChainSecurityAnalyzer()
        
        print("🛡️ Tiger Team Beta-4: Advanced DevSecOps Security Platform")

    def load_security_rules(self) -> Dict[str, List[Dict]]:
        """Load comprehensive security rules and patterns"""
        return {
            'injection_patterns': [
                {
                    'pattern': r'(?i)(select|insert|update|delete|drop|create|alter)\s+.*\+.*[\'"`]',
                    'cwe': 'CWE-89',
                    'severity': 'HIGH',
                    'title': 'SQL Injection via String Concatenation',
                    'description': 'Direct string concatenation in SQL queries can lead to SQL injection'
                },
                {
                    'pattern': r'eval\s*\(\s*[\'"`].*[\'"`]\s*\)',
                    'cwe': 'CWE-95',
                    'severity': 'CRITICAL',
                    'title': 'Code Injection via eval()',
                    'description': 'Use of eval() with user input can lead to arbitrary code execution'
                }
            ],
            'authentication_patterns': [
                {
                    'pattern': r'password\s*=\s*[\'"`][\'"`]',
                    'cwe': 'CWE-798',
                    'severity': 'HIGH',
                    'title': 'Empty or Default Password',
                    'description': 'Empty or default passwords provide no authentication security'
                },
                {
                    'pattern': r'(?i)md5\s*\(\s*.*password.*\)',
                    'cwe': 'CWE-327',
                    'severity': 'MEDIUM',
                    'title': 'Weak Password Hashing',
                    'description': 'MD5 is cryptographically broken and should not be used for passwords'
                }
            ],
            'cryptography_patterns': [
                {
                    'pattern': r'(?i)des|rc4|md5|sha1(?!.*hmac)',
                    'cwe': 'CWE-327',
                    'severity': 'MEDIUM',
                    'title': 'Weak Cryptographic Algorithm',
                    'description': 'Use of cryptographically weak algorithms'
                },
                {
                    'pattern': r'random\.random\(\)|Math\.random\(\)',
                    'cwe': 'CWE-338',
                    'severity': 'MEDIUM',
                    'title': 'Weak Random Number Generation',
                    'description': 'Pseudorandom number generators are not cryptographically secure'
                }
            ],
            'input_validation_patterns': [
                {
                    'pattern': r'innerHTML\s*=\s*.*\+.*',
                    'cwe': 'CWE-79',
                    'severity': 'HIGH',
                    'title': 'XSS via innerHTML',
                    'description': 'Direct assignment to innerHTML with concatenation can lead to XSS'
                },
                {
                    'pattern': r'(?i)exec\s*\(\s*.*input.*\)',
                    'cwe': 'CWE-78',
                    'severity': 'CRITICAL',
                    'title': 'Command Injection',
                    'description': 'Execution of system commands with user input'
                }
            ]
        }

    async def comprehensive_security_analysis(self, 
                                            target_path: str = None,
                                            include_architecture: bool = True,
                                            include_supply_chain: bool = True) -> Dict[str, Any]:
        """Perform comprehensive DevSecOps security analysis"""
        
        target = Path(target_path) if target_path else self.workspace_path
        print(f"🔍 Starting comprehensive DevSecOps analysis of {target}")
        
        analysis_results = {
            'analysis_id': f"DEVSEC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'timestamp': datetime.now().isoformat(),
            'target_path': str(target),
            'vulnerabilities': [],
            'architecture_assessment': None,
            'supply_chain_risks': [],
            'metrics': {}
        }
        
        # Phase 1: Static Application Security Testing (SAST)
        print("📋 Phase 1: Advanced Static Application Security Testing")
        sast_vulns = await self.perform_advanced_sast(target)
        analysis_results['vulnerabilities'].extend(sast_vulns)
        
        # Phase 2: Architecture Security Analysis
        if include_architecture:
            print("🏗️ Phase 2: Architecture Security Assessment")
            arch_assessment = await self.architecture_analyzer.analyze_architecture(target)
            analysis_results['architecture_assessment'] = asdict(arch_assessment) if arch_assessment else None
        
        # Phase 3: Supply Chain Security Analysis
        if include_supply_chain:
            print("📦 Phase 3: Supply Chain Security Analysis")
            supply_risks = await self.supply_chain_analyzer.analyze_dependencies(target)
            analysis_results['supply_chain_risks'] = [asdict(risk) for risk in supply_risks]
        
        # Phase 4: Container Security Analysis
        print("🐳 Phase 4: Container Security Analysis")
        container_vulns = await self.analyze_container_security(target)
        analysis_results['vulnerabilities'].extend(container_vulns)
        
        # Phase 5: Infrastructure as Code Analysis
        print("☁️ Phase 5: Infrastructure as Code Security")
        iac_vulns = await self.analyze_infrastructure_as_code(target)
        analysis_results['vulnerabilities'].extend(iac_vulns)
        
        # Phase 6: CI/CD Pipeline Security
        print("🔄 Phase 6: CI/CD Pipeline Security Assessment")
        cicd_vulns = await self.analyze_cicd_security(target)
        analysis_results['vulnerabilities'].extend(cicd_vulns)
        
        # Calculate comprehensive metrics
        analysis_results['metrics'] = self.calculate_security_metrics(analysis_results)
        
        print(f"✅ DevSecOps analysis complete: {len(analysis_results['vulnerabilities'])} vulnerabilities found")
        return analysis_results

    async def perform_advanced_sast(self, target_path: Path) -> List[SecurityVulnerability]:
        """Advanced static application security testing"""
        vulnerabilities = []
        
        # Analyze different file types
        file_analyzers = {
            '.py': self.analyze_python_security,
            '.js': self.analyze_javascript_security,
            '.ts': self.analyze_typescript_security,
            '.java': self.analyze_java_security,
            '.go': self.analyze_go_security,
            '.yaml': self.analyze_yaml_security,
            '.yml': self.analyze_yaml_security,
            '.json': self.analyze_json_security,
            '.tf': self.analyze_terraform_security
        }
        
        for file_path in target_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in file_analyzers:
                try:
                    analyzer = file_analyzers[file_path.suffix]
                    file_vulns = await analyzer(file_path)
                    vulnerabilities.extend(file_vulns)
                except Exception as e:
                    print(f"    ⚠️ Failed to analyze {file_path}: {str(e)}")
        
        # Deduplicate and prioritize vulnerabilities
        vulnerabilities = self.deduplicate_vulnerabilities(vulnerabilities)
        vulnerabilities = self.calculate_risk_scores(vulnerabilities)
        
        return vulnerabilities

    async def analyze_python_security(self, file_path: Path) -> List[SecurityVulnerability]:
        """Advanced Python security analysis"""
        vulnerabilities = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Parse AST for advanced analysis
            try:
                tree = ast.parse(content)
                ast_vulnerabilities = self.analyze_python_ast(tree, file_path, content)
                vulnerabilities.extend(ast_vulnerabilities)
            except SyntaxError:
                pass  # Skip files with syntax errors
            
            # Pattern-based analysis
            pattern_vulnerabilities = self.analyze_security_patterns(content, file_path, 'python')
            vulnerabilities.extend(pattern_vulnerabilities)
            
            # Python-specific security checks
            python_specific_vulns = self.analyze_python_specific_issues(content, file_path)
            vulnerabilities.extend(python_specific_vulns)
            
        except Exception as e:
            print(f"      ⚠️ Python analysis failed for {file_path}: {str(e)}")
        
        return vulnerabilities

    def analyze_python_ast(self, tree: ast.AST, file_path: Path, content: str) -> List[SecurityVulnerability]:
        """Analyze Python AST for security vulnerabilities"""
        vulnerabilities = []
        lines = content.split('\n')
        
        class SecurityVisitor(ast.NodeVisitor):
            def __init__(self):
                self.vulns = []
            
            def visit_Call(self, node):
                # Check for dangerous function calls
                if isinstance(node.func, ast.Name):
                    if node.func.id in ['eval', 'exec', 'compile']:
                        # Check if argument comes from user input
                        if self.is_potentially_user_controlled(node.args[0]):
                            vuln = SecurityVulnerability(
                                vuln_id=f"PY-AST-{len(self.vulns)+1}",
                                cwe_id='CWE-95',
                                cvss_score=9.0,
                                severity='CRITICAL',
                                category='SAST',
                                title=f'Code Injection via {node.func.id}()',
                                description=f'Use of {node.func.id}() with potentially user-controlled input',
                                file_path=str(file_path),
                                line_number=node.lineno,
                                code_context=lines[node.lineno-1] if node.lineno <= len(lines) else '',
                                proof_of_concept=f'# Attacker could inject: {node.func.id}("__import__(\'os\').system(\'rm -rf /\')")',
                                remediation=f'Avoid using {node.func.id}() with user input. Use safer alternatives.',
                                business_impact='Complete system compromise possible',
                                confidence=85.0,
                                false_positive_likelihood=15.0
                            )
                            self.vulns.append(vuln)
                    
                    elif node.func.id == 'subprocess.call' or (isinstance(node.func, ast.Attribute) and node.func.attr in ['call', 'run', 'Popen']):
                        # Check for shell injection
                        if len(node.args) > 0 and self.is_potentially_user_controlled(node.args[0]):
                            vuln = SecurityVulnerability(
                                vuln_id=f"PY-AST-{len(self.vulns)+1}",
                                cwe_id='CWE-78',
                                cvss_score=8.5,
                                severity='HIGH',
                                category='SAST',
                                title='Command Injection via subprocess',
                                description='Subprocess call with potentially user-controlled input',
                                file_path=str(file_path),
                                line_number=node.lineno,
                                code_context=lines[node.lineno-1] if node.lineno <= len(lines) else '',
                                proof_of_concept='# Attacker could inject: subprocess.call("rm -rf / ; echo", shell=True)',
                                remediation='Use parameterized subprocess calls or input validation',
                                business_impact='System command execution by attacker',
                                confidence=80.0,
                                false_positive_likelihood=20.0
                            )
                            self.vulns.append(vuln)
                
                self.generic_visit(node)
            
            def visit_Assign(self, node):
                # Check for hardcoded secrets
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    value = node.value.value
                    if len(value) > 20 and any(target in str(node.targets).lower() for target in ['password', 'secret', 'key', 'token']):
                        vuln = SecurityVulnerability(
                            vuln_id=f"PY-AST-{len(self.vulns)+1}",
                            cwe_id='CWE-798',
                            cvss_score=7.5,
                            severity='HIGH',
                            category='SAST',
                            title='Hardcoded Secret',
                            description='Potential hardcoded secret or password in source code',
                            file_path=str(file_path),
                            line_number=node.lineno,
                            code_context=lines[node.lineno-1] if node.lineno <= len(lines) else '',
                            proof_of_concept='# Secret exposed in source code repository',
                            remediation='Use environment variables or secret management systems',
                            business_impact='Credential exposure and unauthorized access',
                            confidence=70.0,
                            false_positive_likelihood=30.0
                        )
                        self.vulns.append(vuln)
                
                self.generic_visit(node)
            
            def is_potentially_user_controlled(self, node):
                """Heuristic to determine if a node represents user-controlled input"""
                if isinstance(node, ast.Name):
                    suspicious_names = ['input', 'request', 'args', 'argv', 'params', 'data', 'json', 'form']
                    return any(name in node.id.lower() for name in suspicious_names)
                elif isinstance(node, ast.Subscript):
                    return self.is_potentially_user_controlled(node.value)
                elif isinstance(node, ast.Attribute):
                    return self.is_potentially_user_controlled(node.value)
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    if node.func.id in ['input', 'raw_input']:
                        return True
                return False
        
        visitor = SecurityVisitor()
        visitor.visit(tree)
        vulnerabilities.extend(visitor.vulns)
        
        return vulnerabilities

    async def analyze_javascript_security(self, file_path: Path) -> List[SecurityVulnerability]:
        """Advanced JavaScript/Node.js security analysis"""
        vulnerabilities = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')
            
            # JavaScript-specific vulnerability patterns
            js_patterns = [
                {
                    'pattern': r'innerHTML\s*=\s*.*\+',
                    'cwe': 'CWE-79',
                    'severity': 'HIGH',
                    'title': 'XSS via innerHTML',
                    'description': 'Direct assignment to innerHTML with concatenation can lead to XSS'
                },
                {
                    'pattern': r'document\.write\s*\(',
                    'cwe': 'CWE-79',
                    'severity': 'MEDIUM',
                    'title': 'XSS via document.write',
                    'description': 'document.write() can introduce XSS vulnerabilities'
                },
                {
                    'pattern': r'eval\s*\(',
                    'cwe': 'CWE-95',
                    'severity': 'CRITICAL',
                    'title': 'Code Injection via eval()',
                    'description': 'eval() can execute arbitrary JavaScript code'
                },
                {
                    'pattern': r'setTimeout\s*\(\s*[\'"`].*[\'"`]',
                    'cwe': 'CWE-95',
                    'severity': 'HIGH',
                    'title': 'Code Injection via setTimeout string',
                    'description': 'setTimeout with string argument can execute arbitrary code'
                }
            ]
            
            for i, line in enumerate(lines, 1):
                for pattern_def in js_patterns:
                    if re.search(pattern_def['pattern'], line, re.IGNORECASE):
                        vuln = SecurityVulnerability(
                            vuln_id=f"JS-{hashlib.md5(f'{file_path}:{i}:{pattern_def["title"]}'.encode()).hexdigest()[:8]}",
                            cwe_id=pattern_def['cwe'],
                            cvss_score=self.get_cvss_for_severity(pattern_def['severity']),
                            severity=pattern_def['severity'],
                            category='SAST',
                            title=pattern_def['title'],
                            description=pattern_def['description'],
                            file_path=str(file_path),
                            line_number=i,
                            code_context=line.strip(),
                            proof_of_concept=self.generate_js_poc(pattern_def['cwe']),
                            remediation=self.get_js_remediation(pattern_def['cwe']),
                            business_impact=self.get_business_impact(pattern_def['severity']),
                            confidence=75.0,
                            false_positive_likelihood=25.0
                        )
                        vulnerabilities.append(vuln)
            
            # Check for insecure dependencies
            if 'package.json' in file_path.name:
                dep_vulns = await self.analyze_npm_dependencies(content, file_path)
                vulnerabilities.extend(dep_vulns)
                
        except Exception as e:
            print(f"      ⚠️ JavaScript analysis failed for {file_path}: {str(e)}")
        
        return vulnerabilities

    async def analyze_container_security(self, target_path: Path) -> List[SecurityVulnerability]:
        """Analyze Docker and container security"""
        vulnerabilities = []
        
        # Find Dockerfiles
        dockerfiles = list(target_path.rglob('Dockerfile*'))
        
        for dockerfile in dockerfiles:
            try:
                content = dockerfile.read_text()
                lines = content.split('\n')
                
                container_issues = [
                    {
                        'pattern': r'^FROM\s+.*:latest',
                        'severity': 'MEDIUM',
                        'title': 'Base Image Using Latest Tag',
                        'description': 'Using latest tag can introduce unpredictable dependencies'
                    },
                    {
                        'pattern': r'^USER\s+root',
                        'severity': 'HIGH',
                        'title': 'Container Running as Root',
                        'description': 'Containers should not run as root user for security'
                    },
                    {
                        'pattern': r'^RUN\s+.*sudo',
                        'severity': 'MEDIUM',
                        'title': 'Sudo Usage in Container',
                        'description': 'Avoid sudo in container builds'
                    },
                    {
                        'pattern': r'^COPY\s+\*\s+/',
                        'severity': 'MEDIUM',
                        'title': 'Overly Broad File Copy',
                        'description': 'Copying all files can include sensitive information'
                    }
                ]
                
                for i, line in enumerate(lines, 1):
                    for issue in container_issues:
                        if re.search(issue['pattern'], line, re.IGNORECASE):
                            vuln = SecurityVulnerability(
                                vuln_id=f"DOCKER-{len(vulnerabilities)+1}",
                                cwe_id='CWE-732',  # Incorrect Permission Assignment
                                cvss_score=self.get_cvss_for_severity(issue['severity']),
                                severity=issue['severity'],
                                category='CONTAINER',
                                title=issue['title'],
                                description=issue['description'],
                                file_path=str(dockerfile),
                                line_number=i,
                                code_context=line.strip(),
                                proof_of_concept='Container security misconfiguration',
                                remediation=self.get_container_remediation(issue['title']),
                                business_impact='Container escape or privilege escalation',
                                confidence=80.0,
                                false_positive_likelihood=20.0
                            )
                            vulnerabilities.append(vuln)
                            
            except Exception as e:
                print(f"      ⚠️ Docker analysis failed for {dockerfile}: {str(e)}")
        
        return vulnerabilities

    async def analyze_infrastructure_as_code(self, target_path: Path) -> List[SecurityVulnerability]:
        """Analyze Infrastructure as Code (Terraform, CloudFormation) security"""
        vulnerabilities = []
        
        # Terraform files
        tf_files = list(target_path.rglob('*.tf'))
        
        for tf_file in tf_files:
            try:
                content = tf_file.read_text()
                lines = content.split('\n')
                
                terraform_issues = [
                    {
                        'pattern': r'source_security_group_id\s*=\s*["\']0\.0\.0\.0/0["\']',
                        'severity': 'CRITICAL',
                        'title': 'Security Group Allows All Traffic',
                        'description': 'Security group allows unrestricted access from anywhere'
                    },
                    {
                        'pattern': r'publicly_accessible\s*=\s*true',
                        'severity': 'HIGH',
                        'title': 'Database Publicly Accessible',
                        'description': 'Database configured to be publicly accessible'
                    },
                    {
                        'pattern': r'versioning\s*{\s*enabled\s*=\s*false',
                        'severity': 'MEDIUM',
                        'title': 'S3 Versioning Disabled',
                        'description': 'S3 bucket versioning is disabled'
                    },
                    {
                        'pattern': r'force_destroy\s*=\s*true',
                        'severity': 'MEDIUM',
                        'title': 'Force Destroy Enabled',
                        'description': 'Resource configured to allow force destruction'
                    }
                ]
                
                for i, line in enumerate(lines, 1):
                    for issue in terraform_issues:
                        if re.search(issue['pattern'], line):
                            vuln = SecurityVulnerability(
                                vuln_id=f"IAC-{len(vulnerabilities)+1}",
                                cwe_id='CWE-665',  # Improper Initialization
                                cvss_score=self.get_cvss_for_severity(issue['severity']),
                                severity=issue['severity'],
                                category='INFRASTRUCTURE',
                                title=issue['title'],
                                description=issue['description'],
                                file_path=str(tf_file),
                                line_number=i,
                                code_context=line.strip(),
                                proof_of_concept='Infrastructure misconfiguration',
                                remediation=self.get_iac_remediation(issue['title']),
                                business_impact='Infrastructure security compromise',
                                confidence=90.0,
                                false_positive_likelihood=10.0
                            )
                            vulnerabilities.append(vuln)
                            
            except Exception as e:
                print(f"      ⚠️ Terraform analysis failed for {tf_file}: {str(e)}")
        
        return vulnerabilities

    async def analyze_cicd_security(self, target_path: Path) -> List[SecurityVulnerability]:
        """Analyze CI/CD pipeline security"""
        vulnerabilities = []
        
        # CI/CD configuration files
        cicd_patterns = {
            '.github/workflows/*.yml': 'GitHub Actions',
            '.github/workflows/*.yaml': 'GitHub Actions', 
            '.gitlab-ci.yml': 'GitLab CI',
            'Jenkinsfile': 'Jenkins',
            '.circleci/config.yml': 'CircleCI',
            'azure-pipelines.yml': 'Azure Pipelines'
        }
        
        for pattern, platform in cicd_patterns.items():
            cicd_files = list(target_path.rglob(pattern))
            
            for cicd_file in cicd_files:
                try:
                    content = cicd_file.read_text()
                    lines = content.split('\n')
                    
                    pipeline_issues = [
                        {
                            'pattern': r'run:\s*.*\$\{.*\}.*',
                            'severity': 'HIGH',
                            'title': 'Script Injection in CI/CD',
                            'description': 'Unescaped variable substitution in pipeline commands'
                        },
                        {
                            'pattern': r'with:\s*.*token:\s*\$\{\{\s*secrets\.',
                            'severity': 'MEDIUM',
                            'title': 'Secret Exposed in Logs',
                            'description': 'Secrets may be exposed in pipeline logs'
                        },
                        {
                            'pattern': r'permissions:\s*.*write-all',
                            'severity': 'HIGH',
                            'title': 'Overly Broad Permissions',
                            'description': 'Pipeline has excessive permissions'
                        }
                    ]
                    
                    for i, line in enumerate(lines, 1):
                        for issue in pipeline_issues:
                            if re.search(issue['pattern'], line):
                                vuln = SecurityVulnerability(
                                    vuln_id=f"CICD-{len(vulnerabilities)+1}",
                                    cwe_id='CWE-94',  # Code Injection
                                    cvss_score=self.get_cvss_for_severity(issue['severity']),
                                    severity=issue['severity'],
                                    category='CICD',
                                    title=f'{issue["title"]} ({platform})',
                                    description=issue['description'],
                                    file_path=str(cicd_file),
                                    line_number=i,
                                    code_context=line.strip(),
                                    proof_of_concept='CI/CD pipeline security misconfiguration',
                                    remediation=self.get_cicd_remediation(issue['title']),
                                    business_impact='Build system compromise',
                                    confidence=75.0,
                                    false_positive_likelihood=25.0
                                )
                                vulnerabilities.append(vuln)
                                
                except Exception as e:
                    print(f"      ⚠️ CI/CD analysis failed for {cicd_file}: {str(e)}")
        
        return vulnerabilities

    def analyze_security_patterns(self, content: str, file_path: Path, file_type: str) -> List[SecurityVulnerability]:
        """Analyze content for security anti-patterns"""
        vulnerabilities = []
        lines = content.split('\n')
        
        # Apply relevant patterns based on file type
        relevant_patterns = []
        for category, patterns in self.security_rules.items():
            if self.is_pattern_relevant(category, file_type):
                relevant_patterns.extend(patterns)
        
        for i, line in enumerate(lines, 1):
            for pattern_def in relevant_patterns:
                if re.search(pattern_def['pattern'], line, re.IGNORECASE):
                    vuln = SecurityVulnerability(
                        vuln_id=f"{file_type.upper()}-PATTERN-{len(vulnerabilities)+1}",
                        cwe_id=pattern_def['cwe'],
                        cvss_score=self.get_cvss_for_severity(pattern_def['severity']),
                        severity=pattern_def['severity'],
                        category='SAST',
                        title=pattern_def['title'],
                        description=pattern_def['description'],
                        file_path=str(file_path),
                        line_number=i,
                        code_context=line.strip(),
                        proof_of_concept=self.generate_poc(pattern_def['cwe']),
                        remediation=self.get_remediation(pattern_def['cwe']),
                        business_impact=self.get_business_impact(pattern_def['severity']),
                        confidence=70.0,
                        false_positive_likelihood=30.0
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities

    def is_pattern_relevant(self, pattern_category: str, file_type: str) -> bool:
        """Determine if a pattern category is relevant for a file type"""
        relevance_map = {
            'injection_patterns': ['python', 'javascript', 'typescript', 'java', 'go'],
            'authentication_patterns': ['python', 'javascript', 'typescript', 'java', 'go'],
            'cryptography_patterns': ['python', 'javascript', 'typescript', 'java', 'go'],
            'input_validation_patterns': ['python', 'javascript', 'typescript', 'java']
        }
        
        return file_type in relevance_map.get(pattern_category, [])

    def get_cvss_for_severity(self, severity: str) -> float:
        """Get CVSS score for severity level"""
        severity_scores = {
            'CRITICAL': 9.0,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.5
        }
        return severity_scores.get(severity, 5.0)

    def get_business_impact(self, severity: str) -> str:
        """Get business impact description for severity"""
        impact_map = {
            'CRITICAL': 'Severe business disruption, complete system compromise possible',
            'HIGH': 'Significant business impact, data breach or service disruption likely',
            'MEDIUM': 'Moderate business impact, potential data exposure or service degradation',
            'LOW': 'Minor business impact, limited security implications'
        }
        return impact_map.get(severity, 'Unknown business impact')

    def generate_poc(self, cwe_id: str) -> str:
        """Generate proof of concept for CWE"""
        poc_map = {
            'CWE-89': 'SELECT * FROM users WHERE id = 1; DROP TABLE users; --',
            'CWE-78': 'system("rm -rf / && echo pwned")',
            'CWE-79': '<script>alert("XSS")</script>',
            'CWE-95': 'eval("__import__(\'os\').system(\'rm -rf /\')")',
            'CWE-327': 'Using MD5: vulnerable to collision attacks',
            'CWE-798': 'Hardcoded credentials exposed in source code'
        }
        return poc_map.get(cwe_id, 'Security vulnerability exploitation possible')

    def get_remediation(self, cwe_id: str) -> str:
        """Get remediation guidance for CWE"""
        remediation_map = {
            'CWE-89': 'Use parameterized queries or prepared statements',
            'CWE-78': 'Use input validation and avoid shell=True in subprocess calls',
            'CWE-79': 'Use proper output encoding and Content Security Policy',
            'CWE-95': 'Avoid eval() and exec(), use safer alternatives like ast.literal_eval',
            'CWE-327': 'Use strong cryptographic algorithms like AES-256, SHA-256, or bcrypt',
            'CWE-798': 'Use environment variables or secure credential management systems'
        }
        return remediation_map.get(cwe_id, 'Follow secure coding practices')

    def generate_js_poc(self, cwe_id: str) -> str:
        """Generate JavaScript-specific proof of concept"""
        js_poc_map = {
            'CWE-79': 'element.innerHTML = "<img src=x onerror=alert(document.cookie)>";',
            'CWE-95': 'eval("fetch(\'/admin\').then(r => r.text()).then(console.log)");'
        }
        return js_poc_map.get(cwe_id, self.generate_poc(cwe_id))

    def get_js_remediation(self, cwe_id: str) -> str:
        """Get JavaScript-specific remediation"""
        js_remediation_map = {
            'CWE-79': 'Use textContent instead of innerHTML, or properly escape output',
            'CWE-95': 'Use JSON.parse() for data, avoid eval() entirely'
        }
        return js_remediation_map.get(cwe_id, self.get_remediation(cwe_id))

    def get_container_remediation(self, title: str) -> str:
        """Get container-specific remediation"""
        container_remediation_map = {
            'Base Image Using Latest Tag': 'Pin to specific image versions using digest or tagged version',
            'Container Running as Root': 'Create and use a non-root user in Dockerfile',
            'Sudo Usage in Container': 'Build containers without sudo, use multi-stage builds if needed',
            'Overly Broad File Copy': 'Use .dockerignore and specific file paths in COPY commands'
        }
        return container_remediation_map.get(title, 'Follow container security best practices')

    def get_iac_remediation(self, title: str) -> str:
        """Get Infrastructure as Code remediation"""
        iac_remediation_map = {
            'Security Group Allows All Traffic': 'Restrict security groups to specific IP ranges and ports',
            'Database Publicly Accessible': 'Place databases in private subnets with no public access',
            'S3 Versioning Disabled': 'Enable S3 versioning for data protection and recovery',
            'Force Destroy Enabled': 'Remove force_destroy or protect critical resources'
        }
        return iac_remediation_map.get(title, 'Follow infrastructure security best practices')

    def get_cicd_remediation(self, title: str) -> str:
        """Get CI/CD specific remediation"""
        cicd_remediation_map = {
            'Script Injection in CI/CD': 'Escape variables properly and validate inputs',
            'Secret Exposed in Logs': 'Use masked secrets and avoid logging sensitive information',
            'Overly Broad Permissions': 'Use principle of least privilege for pipeline permissions'
        }
        return cicd_remediation_map.get(title, 'Follow CI/CD security best practices')

    def deduplicate_vulnerabilities(self, vulnerabilities: List[SecurityVulnerability]) -> List[SecurityVulnerability]:
        """Remove duplicate vulnerabilities"""
        seen = set()
        deduplicated = []
        
        for vuln in vulnerabilities:
            # Create a key for deduplication
            key = f"{vuln.file_path}:{vuln.line_number}:{vuln.cwe_id}"
            if key not in seen:
                seen.add(key)
                deduplicated.append(vuln)
        
        return deduplicated

    def calculate_risk_scores(self, vulnerabilities: List[SecurityVulnerability]) -> List[SecurityVulnerability]:
        """Calculate and update risk scores for vulnerabilities"""
        for vuln in vulnerabilities:
            # Risk score factors
            cvss_factor = vuln.cvss_score / 10.0  # Normalize to 0-1
            confidence_factor = vuln.confidence / 100.0
            false_positive_penalty = vuln.false_positive_likelihood / 100.0
            
            # Business context factors
            business_factor = self.get_business_context_factor(vuln.file_path)
            
            # Calculate composite risk score
            risk_score = (cvss_factor * confidence_factor * (1 - false_positive_penalty) * business_factor) * 100
            vuln.cvss_score = min(max(risk_score, 0.0), 10.0)
        
        return vulnerabilities

    def get_business_context_factor(self, file_path: str) -> float:
        """Get business context multiplier for file path"""
        if any(path in file_path for path in ['/admin', '/auth', '/payment', '/api']):
            return 1.2  # Higher risk for critical paths
        elif any(path in file_path for path in ['/test', '/docs', '/examples']):
            return 0.8  # Lower risk for non-production paths
        else:
            return 1.0  # Standard risk

    def calculate_security_metrics(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive security metrics"""
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return {
                'total_vulnerabilities': 0,
                'risk_score': 0.0,
                'severity_distribution': {},
                'category_distribution': {},
                'confidence_score': 100.0
            }
        
        # Severity distribution
        severity_counts = {}
        for vuln in vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
        
        # Category distribution
        category_counts = {}
        for vuln in vulnerabilities:
            category_counts[vuln.category] = category_counts.get(vuln.category, 0) + 1
        
        # Overall risk score
        total_cvss = sum(vuln.cvss_score for vuln in vulnerabilities)
        avg_risk_score = total_cvss / len(vulnerabilities) if vulnerabilities else 0
        
        # Confidence score (inverse of average false positive likelihood)
        avg_confidence = sum(vuln.confidence for vuln in vulnerabilities) / len(vulnerabilities)
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'risk_score': avg_risk_score,
            'severity_distribution': severity_counts,
            'category_distribution': category_counts,
            'confidence_score': avg_confidence,
            'critical_count': severity_counts.get('CRITICAL', 0),
            'high_count': severity_counts.get('HIGH', 0),
            'medium_count': severity_counts.get('MEDIUM', 0),
            'low_count': severity_counts.get('LOW', 0)
        }

    # Placeholder methods for additional analyzers
    async def analyze_typescript_security(self, file_path: Path) -> List[SecurityVulnerability]:
        """TypeScript security analysis (similar to JavaScript)"""
        return await self.analyze_javascript_security(file_path)

    async def analyze_java_security(self, file_path: Path) -> List[SecurityVulnerability]:
        """Java security analysis"""
        # Implement Java-specific security analysis
        return []

    async def analyze_go_security(self, file_path: Path) -> List[SecurityVulnerability]:
        """Go security analysis"""
        # Implement Go-specific security analysis
        return []

    async def analyze_yaml_security(self, file_path: Path) -> List[SecurityVulnerability]:
        """YAML configuration security analysis"""
        # Implement YAML security analysis
        return []

    async def analyze_json_security(self, file_path: Path) -> List[SecurityVulnerability]:
        """JSON configuration security analysis"""
        # Implement JSON security analysis
        return []

    async def analyze_terraform_security(self, file_path: Path) -> List[SecurityVulnerability]:
        """Terraform-specific security analysis"""
        return await self.analyze_infrastructure_as_code(file_path.parent)

    async def analyze_python_specific_issues(self, content: str, file_path: Path) -> List[SecurityVulnerability]:
        """Python-specific security issues"""
        vulnerabilities = []
        lines = content.split('\n')
        
        # Check for dangerous imports
        dangerous_imports = ['pickle', 'cPickle', 'marshal', 'shelve']
        for i, line in enumerate(lines, 1):
            for dangerous in dangerous_imports:
                if re.search(rf'import\s+{dangerous}|from\s+{dangerous}', line):
                    vuln = SecurityVulnerability(
                        vuln_id=f"PY-IMPORT-{len(vulnerabilities)+1}",
                        cwe_id='CWE-502',  # Deserialization of Untrusted Data
                        cvss_score=7.0,
                        severity='HIGH',
                        category='SAST',
                        title=f'Dangerous Import: {dangerous}',
                        description=f'Import of {dangerous} module which can lead to code execution',
                        file_path=str(file_path),
                        line_number=i,
                        code_context=line.strip(),
                        proof_of_concept=f'# Attacker can execute code via {dangerous} deserialization',
                        remediation=f'Avoid {dangerous} module or use safe alternatives like json',
                        business_impact='Code execution via deserialization attack',
                        confidence=85.0,
                        false_positive_likelihood=15.0
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities

    async def analyze_npm_dependencies(self, content: str, file_path: Path) -> List[SecurityVulnerability]:
        """Analyze NPM dependencies for vulnerabilities"""
        vulnerabilities = []
        
        try:
            package_data = json.loads(content)
            dependencies = {**package_data.get('dependencies', {}), **package_data.get('devDependencies', {})}
            
            # Known vulnerable packages (simplified for demo)
            known_vulns = {
                'lodash': {
                    'versions': ['<4.17.19'],
                    'cve': 'CVE-2020-8203',
                    'severity': 'HIGH',
                    'description': 'Prototype pollution vulnerability'
                },
                'handlebars': {
                    'versions': ['<4.7.7'],
                    'cve': 'CVE-2021-23383',
                    'severity': 'CRITICAL',
                    'description': 'Remote code execution vulnerability'
                }
            }
            
            for package_name, version in dependencies.items():
                if package_name in known_vulns:
                    vuln_info = known_vulns[package_name]
                    # Simplified version checking
                    vuln = SecurityVulnerability(
                        vuln_id=f"NPM-{package_name.upper()}",
                        cwe_id='CWE-937',  # Using Components with Known Vulnerabilities
                        cvss_score=self.get_cvss_for_severity(vuln_info['severity']),
                        severity=vuln_info['severity'],
                        category='SCA',
                        title=f'Vulnerable NPM Package: {package_name}',
                        description=vuln_info['description'],
                        file_path=str(file_path),
                        line_number=None,
                        code_context=f'"{package_name}": "{version}"',
                        proof_of_concept=f'Package {package_name} has known vulnerability {vuln_info["cve"]}',
                        remediation=f'Update {package_name} to latest secure version',
                        business_impact='Application compromise via vulnerable dependency',
                        confidence=95.0,
                        false_positive_likelihood=5.0
                    )
                    vulnerabilities.append(vuln)
                    
        except json.JSONDecodeError:
            pass  # Skip invalid JSON files
        
        return vulnerabilities

class ArchitectureSecurityAnalyzer:
    """Architecture-level security analysis"""
    
    async def analyze_architecture(self, target_path: Path) -> Optional[ArchitectureAssessment]:
        """Analyze architecture for security issues"""
        
        # Detect architecture type
        arch_type = self.detect_architecture_type(target_path)
        
        # Generate threat model
        threat_model = await self.generate_threat_model(target_path, arch_type)
        
        # Analyze security controls
        security_controls = await self.analyze_security_controls(target_path)
        
        # Check compliance
        compliance_gaps = await self.check_compliance_gaps(target_path)
        
        # Calculate risk score
        risk_score = self.calculate_architecture_risk(security_controls, compliance_gaps)
        
        assessment = ArchitectureAssessment(
            assessment_id=f"ARCH-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            architecture_type=arch_type,
            threat_model=threat_model,
            security_controls=security_controls,
            compliance_gaps=compliance_gaps,
            risk_score=risk_score,
            recommendations=self.generate_architecture_recommendations(arch_type, security_controls),
            attack_surface_analysis=await self.analyze_attack_surface(target_path)
        )
        
        return assessment

    def detect_architecture_type(self, target_path: Path) -> str:
        """Detect application architecture type"""
        # Check for various architecture indicators
        if (target_path / 'docker-compose.yml').exists():
            return 'microservices'
        elif (target_path / 'serverless.yml').exists():
            return 'serverless'
        elif (target_path / 'Dockerfile').exists():
            return 'containerized_monolith'
        else:
            return 'traditional_application'

    async def generate_threat_model(self, target_path: Path, arch_type: str) -> Dict[str, Any]:
        """Generate STRIDE threat model"""
        # Simplified threat model generation
        return {
            'spoofing': self.analyze_identity_threats(target_path),
            'tampering': self.analyze_data_integrity_threats(target_path),
            'repudiation': self.analyze_audit_threats(target_path),
            'information_disclosure': self.analyze_confidentiality_threats(target_path),
            'denial_of_service': self.analyze_availability_threats(target_path),
            'elevation_of_privilege': self.analyze_authorization_threats(target_path)
        }

    def analyze_identity_threats(self, target_path: Path) -> List[Dict]:
        """Analyze identity spoofing threats"""
        # Implement identity threat analysis
        return []

    def analyze_data_integrity_threats(self, target_path: Path) -> List[Dict]:
        """Analyze data tampering threats"""
        # Implement data integrity threat analysis
        return []

    def analyze_audit_threats(self, target_path: Path) -> List[Dict]:
        """Analyze repudiation threats"""
        # Implement audit threat analysis
        return []

    def analyze_confidentiality_threats(self, target_path: Path) -> List[Dict]:
        """Analyze information disclosure threats"""
        # Implement confidentiality threat analysis
        return []

    def analyze_availability_threats(self, target_path: Path) -> List[Dict]:
        """Analyze denial of service threats"""
        # Implement availability threat analysis
        return []

    def analyze_authorization_threats(self, target_path: Path) -> List[Dict]:
        """Analyze privilege escalation threats"""
        # Implement authorization threat analysis
        return []

    async def analyze_security_controls(self, target_path: Path) -> List[Dict]:
        """Analyze existing security controls"""
        # Implement security control analysis
        return []

    async def check_compliance_gaps(self, target_path: Path) -> List[Dict]:
        """Check for compliance gaps"""
        # Implement compliance gap analysis
        return []

    def calculate_architecture_risk(self, security_controls: List[Dict], compliance_gaps: List[Dict]) -> float:
        """Calculate overall architecture risk score"""
        # Simplified risk calculation
        base_risk = 50.0
        control_factor = len(security_controls) * -5  # More controls = lower risk
        gap_factor = len(compliance_gaps) * 10  # More gaps = higher risk
        
        return max(min(base_risk + control_factor + gap_factor, 100.0), 0.0)

    def generate_architecture_recommendations(self, arch_type: str, security_controls: List[Dict]) -> List[str]:
        """Generate architecture-specific recommendations"""
        recommendations = [
            'Implement defense in depth strategy',
            'Use principle of least privilege',
            'Enable comprehensive logging and monitoring'
        ]
        
        if arch_type == 'microservices':
            recommendations.extend([
                'Implement service mesh for security',
                'Use mutual TLS between services',
                'Implement API rate limiting and authentication'
            ])
        elif arch_type == 'serverless':
            recommendations.extend([
                'Implement function-level access controls',
                'Use managed identity services',
                'Monitor function invocation patterns'
            ])
        
        return recommendations

    async def analyze_attack_surface(self, target_path: Path) -> Dict[str, Any]:
        """Analyze application attack surface"""
        # Implement attack surface analysis
        return {
            'external_endpoints': [],
            'authentication_points': [],
            'data_inputs': [],
            'third_party_integrations': [],
            'administrative_interfaces': []
        }

class SupplyChainSecurityAnalyzer:
    """Supply chain security analysis"""
    
    async def analyze_dependencies(self, target_path: Path) -> List[SupplyChainRisk]:
        """Analyze dependencies for supply chain risks"""
        risks = []
        
        # Analyze different package managers
        package_files = {
            'package.json': self.analyze_npm_supply_chain,
            'requirements.txt': self.analyze_pip_supply_chain,
            'go.mod': self.analyze_go_supply_chain,
            'pom.xml': self.analyze_maven_supply_chain
        }
        
        for file_name, analyzer in package_files.items():
            package_file = target_path / file_name
            if package_file.exists():
                file_risks = await analyzer(package_file)
                risks.extend(file_risks)
        
        return risks

    async def analyze_npm_supply_chain(self, package_file: Path) -> List[SupplyChainRisk]:
        """Analyze NPM supply chain risks"""
        risks = []
        
        try:
            content = package_file.read_text()
            package_data = json.loads(content)
            dependencies = {**package_data.get('dependencies', {}), **package_data.get('devDependencies', {})}
            
            for package_name, version in dependencies.items():
                risk = await self.assess_package_risk(package_name, version, 'npm')
                if risk:
                    risks.append(risk)
                    
        except (json.JSONDecodeError, FileNotFoundError):
            pass
        
        return risks

    async def assess_package_risk(self, package_name: str, version: str, ecosystem: str) -> Optional[SupplyChainRisk]:
        """Assess individual package risk"""
        # Simplified risk assessment (would integrate with vulnerability databases)
        
        # High-risk packages (simplified)
        high_risk_packages = {
            'lodash': {'risk': 'HIGH', 'reason': 'Frequent security issues'},
            'request': {'risk': 'HIGH', 'reason': 'Deprecated package'},
            'handlebars': {'risk': 'MEDIUM', 'reason': 'Template injection risks'}
        }
        
        if package_name in high_risk_packages:
            risk_info = high_risk_packages[package_name]
            return SupplyChainRisk(
                component_name=package_name,
                component_version=version,
                risk_level=risk_info['risk'],
                vulnerability_count=1,  # Simplified
                license_risk='UNKNOWN',
                maintenance_status='ACTIVE',
                alternatives=[],  # Would be populated from real data
                mitigation_steps=[
                    f'Review usage of {package_name}',
                    'Consider alternative packages',
                    'Update to latest secure version'
                ],
                sbom_entry={
                    'name': package_name,
                    'version': version,
                    'ecosystem': ecosystem,
                    'risk_assessment_date': datetime.now().isoformat()
                }
            )
        
        return None

    # Placeholder methods for other package managers
    async def analyze_pip_supply_chain(self, requirements_file: Path) -> List[SupplyChainRisk]:
        """Analyze Python pip supply chain risks"""
        return []

    async def analyze_go_supply_chain(self, go_mod_file: Path) -> List[SupplyChainRisk]:
        """Analyze Go module supply chain risks"""
        return []

    async def analyze_maven_supply_chain(self, pom_file: Path) -> List[SupplyChainRisk]:
        """Analyze Maven supply chain risks"""
        return []

# Example usage and testing
async def demo_devsecops_analysis():
    """Demonstrate advanced DevSecOps capabilities"""
    
    print("🚀 Tiger Team Beta-4 Demo: Advanced DevSecOps Security Analysis")
    
    # Initialize DevSecOps engine
    devsecops = AdvancedDevSecOpsEngine()
    
    # Run comprehensive analysis
    results = await devsecops.comprehensive_security_analysis(
        target_path=".",  # Analyze current directory
        include_architecture=True,
        include_supply_chain=True
    )
    
    print(f"\n📊 DevSecOps Analysis Results:")
    print(f"Analysis ID: {results['analysis_id']}")
    print(f"Target: {results['target_path']}")
    
    metrics = results['metrics']
    print(f"\nVulnerability Summary:")
    print(f"  Total Vulnerabilities: {metrics['total_vulnerabilities']}")
    print(f"  Risk Score: {metrics['risk_score']:.1f}/10")
    print(f"  Critical: {metrics.get('critical_count', 0)}")
    print(f"  High: {metrics.get('high_count', 0)}")
    print(f"  Medium: {metrics.get('medium_count', 0)}")
    print(f"  Low: {metrics.get('low_count', 0)}")
    
    # Show top vulnerabilities
    if results['vulnerabilities']:
        print(f"\nTop 3 Vulnerabilities:")
        sorted_vulns = sorted(results['vulnerabilities'], key=lambda x: x.cvss_score, reverse=True)
        for i, vuln in enumerate(sorted_vulns[:3], 1):
            print(f"  {i}. {vuln.title} ({vuln.severity})")
            print(f"     File: {vuln.file_path}:{vuln.line_number}")
            print(f"     CVSS: {vuln.cvss_score:.1f}")
    
    # Architecture assessment
    if results['architecture_assessment']:
        arch = results['architecture_assessment']
        print(f"\nArchitecture Assessment:")
        print(f"  Type: {arch['architecture_type']}")
        print(f"  Risk Score: {arch['risk_score']:.1f}/100")
        print(f"  Security Controls: {len(arch['security_controls'])}")
    
    # Supply chain risks
    supply_risks = results['supply_chain_risks']
    if supply_risks:
        print(f"\nSupply Chain Risks:")
        high_risk_components = [r for r in supply_risks if r['risk_level'] == 'HIGH']
        print(f"  High Risk Components: {len(high_risk_components)}")
        for risk in high_risk_components[:3]:
            print(f"    • {risk['component_name']} v{risk['component_version']}")

if __name__ == "__main__":
    asyncio.run(demo_devsecops_analysis())