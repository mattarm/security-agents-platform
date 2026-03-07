#!/usr/bin/env python3
"""
Documentation Link Validator
Validates that all links in documentation are navigable
"""

import re
from pathlib import Path

def validate_documentation_links():
    """Validate all links in documentation files"""
    
    repo_root = Path(__file__).parent.parent
    
    # Files to check for links
    doc_files = [
        "README.md",
        "DOCUMENTATION-INDEX.md",
        "PLATFORM-SUMMARY-ACCURATE.md",
        "ARCHITECTURE.md"
    ]
    
    print("🔍 Validating Documentation Links")
    print("=" * 50)
    
    all_valid = True
    
    for doc_file in doc_files:
        file_path = repo_root / doc_file
        if not file_path.exists():
            print(f"❌ Documentation file missing: {doc_file}")
            all_valid = False
            continue
        
        print(f"\n📄 Checking: {doc_file}")
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Find all markdown links [text](path)
        links = re.findall(r'\[([^\]]+)\]\(([^)]+)\)', content)
        
        for link_text, link_path in links:
            # Skip external links (http/https)
            if link_path.startswith(('http://', 'https://', '#')):
                continue
            
            # Resolve relative path
            if link_path.startswith('./'):
                target_path = repo_root / link_path[2:]
            else:
                target_path = repo_root / link_path
            
            # Check if target exists
            if target_path.exists():
                print(f"  ✅ {link_text}: {link_path}")
            else:
                print(f"  ❌ {link_text}: {link_path} (NOT FOUND)")
                all_valid = False
    
    print(f"\n{'='*50}")
    if all_valid:
        print("🎉 All documentation links are valid!")
        return True
    else:
        print("⚠️ Some documentation links are broken!")
        return False

if __name__ == "__main__":
    validate_documentation_links()