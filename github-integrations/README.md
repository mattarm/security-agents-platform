# GitHub Security Tools Integration

This directory contains integration frameworks for 10 verified GitHub security tools.

## Integrated Tools

1. **MITRE CALDERA** - Adversary emulation framework
2. **TheHive** - Security incident response platform
3. **BloodHound** - Active Directory attack path analysis
4. **Atomic Red Team** - Small and highly portable detection tests
5. **Sigma** - Generic signature format for SIEM systems
6. **Velociraptor** - Digital forensics and incident response
7. **Empire** - PowerShell and Python post-exploitation framework
8. **CrackMapExec** - Network penetration testing toolkit
9. **MISP** - Malware information sharing platform
10. **Wazuh** - Security monitoring platform

## Usage

All tools are integrated through the main GitHub security tools manager:

```python
from github_security_tools import GitHubSecurityToolsManager

# Initialize manager
manager = GitHubSecurityToolsManager()

# Execute tool
result = await manager.execute_tool("caldera", "list_adversaries")
```

See [github_security_tools.py](./github_security_tools.py) for complete implementation.