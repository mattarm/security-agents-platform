#!/usr/bin/env python3
"""
Health check script for Slack War Room Bot
"""

import sys
import os
import sqlite3
import requests
from pathlib import Path

def check_database():
    """Check database connectivity"""
    try:
        db_path = os.environ.get("DB_PATH", "/app/data/war_rooms.db")
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM war_rooms")
            conn.close()
            return True
        return False
    except Exception as e:
        print(f"Database check failed: {e}")
        return False

def check_slack_connectivity():
    """Check Slack API connectivity"""
    try:
        bot_token = os.environ.get("SLACK_BOT_TOKEN")
        if not bot_token:
            return False
        
        headers = {"Authorization": f"Bearer {bot_token}"}
        response = requests.get("https://slack.com/api/api.test", headers=headers, timeout=10)
        return response.status_code == 200
    except Exception as e:
        print(f"Slack connectivity check failed: {e}")
        return False

def check_crowdstrike_config():
    """Check CrowdStrike configuration"""
    client_id = os.environ.get("CROWDSTRIKE_CLIENT_ID")
    client_secret = os.environ.get("CROWDSTRIKE_CLIENT_SECRET")
    return bool(client_id and client_secret)

def main():
    """Main health check function"""
    checks = [
        ("Database", check_database),
        ("Slack", check_slack_connectivity),
        ("CrowdStrike Config", check_crowdstrike_config)
    ]
    
    all_passed = True
    for check_name, check_func in checks:
        try:
            if check_func():
                print(f"✅ {check_name}: OK")
            else:
                print(f"❌ {check_name}: FAILED")
                all_passed = False
        except Exception as e:
            print(f"❌ {check_name}: ERROR - {e}")
            all_passed = False
    
    if all_passed:
        print("🎉 All health checks passed")
        sys.exit(0)
    else:
        print("⚠️ Some health checks failed")
        sys.exit(1)

if __name__ == "__main__":
    main()