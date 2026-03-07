#!/usr/bin/env python3
"""
Enhanced Security Analyzer - Setup and Test Script
Demonstrates the multi-domain security analysis capabilities
"""

import os
import sys
import json
import asyncio
from pathlib import Path

# Add the security-assessment directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from enhanced_security_analyzer import EnhancedSecurityAnalyzer

async def demo_analysis():
    """Demonstrate the enhanced security analysis capabilities"""
    
    print("🚀 Enhanced Security Analyzer Demo")
    print("=" * 50)
    
    # Check prerequisites
    print("\n📋 Checking Prerequisites...")
    
    # Check GitHub CLI
    try:
        import subprocess
        result = subprocess.run(['gh', 'auth', 'status'], capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ GitHub CLI authenticated")
        else:
            print("⚠️ GitHub CLI not authenticated - GitHub analysis will be limited")
    except FileNotFoundError:
        print("⚠️ GitHub CLI not found - install with 'brew install gh' or similar")
    
    # Check AWS CLI
    try:
        import boto3
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        print(f"✅ AWS authenticated as {identity.get('Arn', 'unknown')}")
    except Exception as e:
        print(f"⚠️ AWS not configured - {str(e)}")
    
    # Check API keys
    vt_key = os.getenv('VIRUSTOTAL_API_KEY')
    shodan_key = os.getenv('SHODAN_API_KEY')
    
    if vt_key:
        print("✅ VirusTotal API key configured")
    else:
        print("⚠️ VirusTotal API key not found in VIRUSTOTAL_API_KEY env var")
    
    if shodan_key:
        print("✅ Shodan API key configured")
    else:
        print("⚠️ Shodan API key not found in SHODAN_API_KEY env var")
    
    # Configuration
    config = {
        'output_dir': './demo-results',
        'github_enabled': True,
        'aws_enabled': True
    }
    
    print(f"\n🔧 Configuration:")
    print(f"  • Output Directory: {config['output_dir']}")
    print(f"  • GitHub Analysis: {'Enabled' if config['github_enabled'] else 'Disabled'}")
    print(f"  • AWS Analysis: {'Enabled' if config['aws_enabled'] else 'Disabled'}")
    
    # Initialize analyzer
    analyzer = EnhancedSecurityAnalyzer(config)
    
    # Demo indicators for threat intelligence testing
    demo_threat_indicators = [
        '8.8.8.8',  # Google DNS (should be clean)
        'google.com',  # Should be clean
        'malware-domain.com',  # Hypothetical malicious domain
        'suspicious-ip.com'  # Another test indicator
    ]
    
    print(f"\n🔍 Starting Enhanced Analysis Demo...")
    print(f"  • Threat Intel Test Indicators: {len(demo_threat_indicators)}")
    
    try:
        # Run the analysis
        results = await analyzer.analyze_organization(
            github_org=None,  # Will analyze personal repos
            aws_profile=None,  # Will use default profile
            threat_intel_scope=demo_threat_indicators
        )
        
        print("\n📊 Demo Analysis Results:")
        print("=" * 30)
        
        metrics = results['metrics']
        print(f"Overall Risk Score: {metrics['overall_risk_score']:.1f}/100")
        print(f"Total Findings: {metrics['total_findings']}")
        print(f"Analysis Scope: {', '.join(results['scope'])}")
        
        # Risk distribution
        print(f"\nRisk Distribution:")
        for severity, count in metrics['risk_distribution'].items():
            if count > 0:
                print(f"  • {severity}: {count}")
        
        # Domain-specific results
        if 'domain_metrics' in metrics:
            print(f"\nDomain Analysis:")
            for domain, domain_metrics in metrics['domain_metrics'].items():
                print(f"  • {domain.title()}: {domain_metrics['finding_count']} findings "
                      f"(avg risk: {domain_metrics['avg_risk_score']:.1f}/100)")
        
        # Threat intelligence results
        if 'threat_intel_metrics' in metrics:
            ti_metrics = metrics['threat_intel_metrics']
            print(f"\nThreat Intelligence:")
            print(f"  • Indicators Analyzed: {ti_metrics['total_indicators_analyzed']}")
            print(f"  • High Risk Indicators: {ti_metrics['high_risk_indicators']}")
            print(f"  • Avg Reputation Score: {ti_metrics['avg_reputation_score']:.1f}/100")
        
        # Cross-domain correlations
        correlations = results['findings']['correlations']
        if correlations:
            print(f"\nCross-Domain Correlations:")
            for i, corr in enumerate(correlations[:3], 1):
                print(f"  {i}. {corr['title']} (Risk: {corr['risk_score']:.1f}/100)")
                print(f"     Domains: {', '.join(corr['domains'])}")
        
        # Top recommendations
        print(f"\nTop Recommendations:")
        for i, rec in enumerate(results['recommendations'][:5], 1):
            print(f"  {i}. [{rec['priority']}] {rec['recommendation']}")
        
        print(f"\n✅ Demo complete! Check {config['output_dir']} for detailed results.")
        
        # Show file outputs
        output_dir = Path(config['output_dir'])
        if output_dir.exists():
            print(f"\n📁 Generated Files:")
            for file in output_dir.glob('*'):
                print(f"  • {file.name}")
    
    except Exception as e:
        print(f"\n❌ Demo failed: {str(e)}")
        import traceback
        traceback.print_exc()

def setup_environment():
    """Setup environment for enhanced security analyzer"""
    
    print("🔧 Enhanced Security Analyzer Setup")
    print("=" * 40)
    
    # Install required packages
    required_packages = [
        'virustotal-python',
        'shodan', 
        'boto3',
        'dnspython',
        'python-whois',
        'requests'
    ]
    
    print("\n📦 Installing required packages...")
    import subprocess
    
    for package in required_packages:
        try:
            result = subprocess.run([
                sys.executable, '-m', 'pip', 'install', package
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"✅ {package}")
            else:
                print(f"⚠️ {package} - {result.stderr.strip()}")
        except Exception as e:
            print(f"❌ {package} - {str(e)}")
    
    # Setup instructions
    print("\n🔑 API Key Setup Instructions:")
    print("=" * 30)
    print("1. VirusTotal API Key:")
    print("   • Sign up at https://www.virustotal.com/gui/join-us")
    print("   • Get API key from https://www.virustotal.com/gui/my-apikey")
    print("   • Set environment variable: export VIRUSTOTAL_API_KEY='your-key'")
    
    print("\n2. Shodan API Key:")
    print("   • Sign up at https://account.shodan.io/register")
    print("   • Get API key from https://account.shodan.io/")
    print("   • Set environment variable: export SHODAN_API_KEY='your-key'")
    
    print("\n3. GitHub CLI Setup:")
    print("   • Install: brew install gh")
    print("   • Authenticate: gh auth login")
    
    print("\n4. AWS CLI Setup:")
    print("   • Install: brew install awscli")
    print("   • Configure: aws configure")
    
    # Create demo configuration
    demo_config = {
        "output_dir": "./security-analysis-results",
        "github_enabled": True,
        "aws_enabled": True,
        "threat_intel_enabled": True,
        "correlation_enabled": True
    }
    
    config_file = Path("demo-config.json")
    with open(config_file, 'w') as f:
        json.dump(demo_config, f, indent=2)
    
    print(f"\n📄 Demo configuration created: {config_file}")
    
    # Create sample .env file
    env_sample = """# Enhanced Security Analyzer Environment Variables
# Copy to .env and fill in your API keys

# VirusTotal API Key (free tier: 500 requests/day)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Shodan API Key (free tier: 100 queries/month)
SHODAN_API_KEY=your_shodan_api_key_here

# AWS Profile (optional, defaults to default profile)
AWS_PROFILE=default

# GitHub Organization (optional, defaults to personal repos)
GITHUB_ORG=your-org-name
"""
    
    env_file = Path(".env.sample")
    with open(env_file, 'w') as f:
        f.write(env_sample)
    
    print(f"📄 Sample environment file created: {env_file}")
    print("\n✅ Setup complete! Run 'python setup_and_test.py demo' to test")

def print_usage():
    """Print usage information"""
    print("Enhanced Security Analyzer - Setup and Test")
    print("=" * 40)
    print("\nUsage:")
    print("  python setup_and_test.py setup    - Setup environment and dependencies")
    print("  python setup_and_test.py demo     - Run analysis demo")
    print("  python setup_and_test.py analyze  - Run full analysis")
    print("\nExample full analysis:")
    print("  python enhanced_security_analyzer.py --github-org myorg --aws-profile prod")
    print("\nFor more options:")
    print("  python enhanced_security_analyzer.py --help")

async def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print_usage()
        return
    
    command = sys.argv[1]
    
    if command == "setup":
        setup_environment()
    elif command == "demo":
        await demo_analysis()
    elif command == "analyze":
        # Import and run the main analyzer
        from enhanced_security_analyzer import main as analyzer_main
        await analyzer_main()
    else:
        print_usage()

if __name__ == "__main__":
    asyncio.run(main())