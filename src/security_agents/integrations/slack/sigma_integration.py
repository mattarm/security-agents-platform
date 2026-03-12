#!/usr/bin/env python3
"""
Sigma Agent Slack Integration
Security Program Metrics & Reporting commands for Slack War Rooms
"""

import asyncio
import logging
import json
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

from agents.sigma_metrics_agent import SigmaMetricsAgent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SigmaSlackIntegration:
    """Sigma agent integration for Slack War Rooms"""
    
    def __init__(self):
        self.sigma_agent = SigmaMetricsAgent()
        self.commands = {
            "dashboard": self.handle_dashboard_command,
            "report": self.handle_report_command,
            "metric": self.handle_metric_command,
            "update": self.handle_update_command,
            "trend": self.handle_trend_command
        }
    
    async def execute_sigma_command(self, command: str, parameters: str) -> dict:
        """Execute Sigma agent command from Slack"""
        
        try:
            if command not in self.commands:
                return {
                    "error": f"Unknown Sigma command: {command}",
                    "available_commands": list(self.commands.keys())
                }
            
            handler = self.commands[command]
            result = await handler(parameters)
            
            return {
                "command": f"sigma {command} {parameters}",
                "result": result,
                "execution_time": 2.5,  # Simulated
                "source": "Sigma Security Program Metrics Agent"
            }
            
        except Exception as e:
            logger.error(f"Sigma command error: {e}")
            return {
                "error": f"Sigma command failed: {str(e)}",
                "command": f"sigma {command} {parameters}"
            }
    
    async def handle_dashboard_command(self, parameters: str) -> dict:
        """Handle dashboard command"""
        
        # Generate executive dashboard
        dashboard = await self.sigma_agent.generate_executive_dashboard()
        
        return {
            "command_type": "dashboard",
            "dashboard_data": dashboard,
            "summary": f"Security program: {dashboard.get('achievement_rate', 0):.1f}% target achievement",
            "critical_items": dashboard.get('critical_attention', 0),
            "trend_summary": dashboard.get('trend_summary', {}),
            "last_updated": dashboard.get('last_updated', 'unknown')
        }
    
    async def handle_report_command(self, parameters: str) -> dict:
        """Handle report generation command"""
        
        # Parse report type from parameters
        if "strategic" in parameters.lower():
            report_type = "strategic"
            time_period = "monthly"
        elif "tactical" in parameters.lower():
            report_type = "tactical"
            time_period = "weekly"
        else:
            # Generate both reports
            reports = await self.sigma_agent.run_scheduled_reporting()
            
            return {
                "command_type": "report_generation",
                "reports_generated": {
                    "strategic": reports["strategic_report"],
                    "tactical": reports["tactical_report"]
                },
                "generated_at": reports["generated_at"],
                "summary": "Both strategic and tactical reports generated successfully"
            }
        
        # Generate specific report type
        if report_type == "strategic":
            report = await self.sigma_agent.reporter.generate_strategic_report(time_period)
        else:
            report = await self.sigma_agent.reporter.generate_tactical_report(time_period)
        
        return {
            "command_type": f"{report_type}_report",
            "report_file": report.pdf_path,
            "report_id": report.report_id,
            "time_period": report.time_period,
            "metrics_included": len(report.metrics_included),
            "key_findings_count": len(report.key_findings),
            "recommendations_count": len(report.recommendations)
        }
    
    async def handle_metric_command(self, parameters: str) -> dict:
        """Handle individual metric query"""
        
        # Parse metric category or specific metric
        if not parameters.strip():
            return {"error": "Please specify metric category or name"}
        
        category = parameters.strip().lower()
        
        # Get metrics by category
        metrics = self.sigma_agent.db.get_metrics_by_category(category)
        
        if not metrics:
            # Try to get all metrics if category doesn't exist
            all_metrics = await self.sigma_agent.reporter._get_all_metrics()
            matching_metrics = [m for m in all_metrics if parameters.lower() in m.name.lower()]
            
            if not matching_metrics:
                return {
                    "error": f"No metrics found for '{parameters}'",
                    "available_categories": ["detection", "incident_response", "vulnerability_management", "compliance", "soc_operations"]
                }
            
            metrics = matching_metrics
        
        # Format metrics response
        metrics_data = []
        for metric in metrics:
            variance = ((metric.current_value - metric.target_value) / metric.target_value * 100) if metric.target_value > 0 else 0
            
            metrics_data.append({
                "name": metric.name,
                "current_value": metric.current_value,
                "target_value": metric.target_value,
                "unit": metric.unit,
                "variance_percent": variance,
                "trend": metric.trend_direction.value,
                "last_updated": metric.last_updated.strftime('%Y-%m-%d %H:%M'),
                "data_source": metric.data_source
            })
        
        return {
            "command_type": "metrics_query",
            "category": category,
            "metrics_count": len(metrics_data),
            "metrics": metrics_data[:5],  # Limit for Slack display
            "summary": f"Found {len(metrics_data)} metrics in {category} category"
        }
    
    async def handle_update_command(self, parameters: str) -> dict:
        """Handle metrics update command"""
        
        # Update metrics from all sources
        updates_count = await self.sigma_agent.update_metrics_from_sources()
        
        # Get updated dashboard for summary
        dashboard = await self.sigma_agent.generate_executive_dashboard()
        
        return {
            "command_type": "metrics_update",
            "updates_processed": updates_count,
            "last_updated": datetime.now().isoformat(),
            "updated_achievement_rate": dashboard.get('achievement_rate', 0),
            "critical_metrics": dashboard.get('critical_attention', 0),
            "summary": f"Updated {updates_count} metrics from data sources"
        }
    
    async def handle_trend_command(self, parameters: str) -> dict:
        """Handle trend analysis command"""
        
        # Get all metrics for trend analysis
        all_metrics = await self.sigma_agent.reporter._get_all_metrics()
        
        # Analyze trends by category
        categories = ["detection", "incident_response", "vulnerability_management", "compliance"]
        trend_analysis = {}
        
        for category in categories:
            category_metrics = [m for m in all_metrics if m.category == category]
            
            if category_metrics:
                improving = sum(1 for m in category_metrics if m.trend_direction.value == "improving")
                declining = sum(1 for m in category_metrics if m.trend_direction.value == "declining")
                stable = sum(1 for m in category_metrics if m.trend_direction.value == "stable")
                
                trend_analysis[category] = {
                    "total_metrics": len(category_metrics),
                    "improving": improving,
                    "declining": declining,
                    "stable": stable,
                    "health_score": ((improving * 2 + stable) / (len(category_metrics) * 2)) * 100
                }
        
        # Overall trend summary
        total_improving = sum(data["improving"] for data in trend_analysis.values())
        total_declining = sum(data["declining"] for data in trend_analysis.values())
        total_metrics = sum(data["total_metrics"] for data in trend_analysis.values())
        
        overall_trend = "improving" if total_improving > total_declining else "declining" if total_declining > total_improving else "stable"
        
        return {
            "command_type": "trend_analysis",
            "overall_trend": overall_trend,
            "total_metrics_analyzed": total_metrics,
            "improving_metrics": total_improving,
            "declining_metrics": total_declining,
            "category_trends": trend_analysis,
            "summary": f"Program trend: {overall_trend} ({total_improving} improving, {total_declining} declining)"
        }

# Slack command formatting helpers
def format_sigma_response(result: dict) -> dict:
    """Format Sigma agent response for Slack display"""
    
    if "error" in result:
        return {
            "text": f"❌ {result['error']}",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Sigma Agent Error*\n{result['error']}"
                    }
                }
            ]
        }
    
    command_type = result.get("result", {}).get("command_type", "unknown")
    
    if command_type == "dashboard":
        return format_dashboard_response(result["result"])
    elif command_type in ["strategic_report", "tactical_report", "report_generation"]:
        return format_report_response(result["result"])
    elif command_type == "metrics_query":
        return format_metrics_response(result["result"])
    elif command_type == "metrics_update":
        return format_update_response(result["result"])
    elif command_type == "trend_analysis":
        return format_trend_response(result["result"])
    else:
        return format_generic_response(result)

def format_dashboard_response(result: dict) -> dict:
    """Format dashboard response for Slack"""
    
    dashboard = result.get("dashboard_data", {})
    
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"📊 *Security Program Dashboard*\n\n*Overall Score:* {dashboard.get('achievement_rate', 0):.1f}%\n*Targets Achieved:* {dashboard.get('targets_achieved', 0)}/{dashboard.get('total_metrics', 0)}\n*Critical Attention:* {dashboard.get('critical_attention', 0)} metrics"
            }
        }
    ]
    
    # Add trend summary
    trends = dashboard.get('trend_summary', {})
    if trends:
        trend_text = f"📈 *Trends:* {trends.get('improving', 0)} ↗ | {trends.get('stable', 0)} → | {trends.get('declining', 0)} ↘"
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": trend_text
            }
        })
    
    # Add critical metrics if any
    risk_indicators = dashboard.get('risk_indicators', [])
    if risk_indicators:
        critical_text = "*Critical Metrics:*\n"
        for indicator in risk_indicators[:3]:
            critical_text += f"• {indicator['metric']}: {indicator['gap']:.1f}% below target\n"
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn", 
                "text": critical_text
            }
        })
    
    return {
        "text": f"Security Program Dashboard - {dashboard.get('achievement_rate', 0):.1f}% achievement",
        "blocks": blocks
    }

def format_report_response(result: dict) -> dict:
    """Format report generation response for Slack"""
    
    if "reports_generated" in result:
        # Both reports generated
        return {
            "text": "Security program reports generated",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"📋 *Security Program Reports Generated*\n\n*Strategic Report:* {result['reports_generated']['strategic']}\n*Tactical Report:* {result['reports_generated']['tactical']}\n*Generated:* {result['generated_at'][:19]}"
                    }
                }
            ]
        }
    else:
        # Single report generated
        report_type = result.get("command_type", "report").replace("_", " ").title()
        
        return {
            "text": f"{report_type} generated successfully",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"📋 *{report_type} Generated*\n\n*File:* {result.get('report_file', 'N/A')}\n*Metrics:* {result.get('metrics_included', 0)}\n*Key Findings:* {result.get('key_findings_count', 0)}\n*Recommendations:* {result.get('recommendations_count', 0)}"
                    }
                }
            ]
        }

def format_metrics_response(result: dict) -> dict:
    """Format metrics query response for Slack"""
    
    category = result.get("category", "unknown").replace("_", " ").title()
    metrics = result.get("metrics", [])
    
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"📊 *{category} Metrics*\n\nFound {result.get('metrics_count', 0)} metrics"
            }
        }
    ]
    
    # Add metrics table
    if metrics:
        metrics_text = "*Metric Details:*\n"
        for metric in metrics[:3]:  # Show top 3 for Slack
            variance_emoji = "✅" if metric["variance_percent"] >= 0 else "⚠️"
            trend_emoji = {"improving": "↗", "declining": "↘", "stable": "→"}.get(metric["trend"], "?")
            
            metrics_text += f"{variance_emoji} *{metric['name']}*: {metric['current_value']} {metric['unit']} "
            metrics_text += f"(Target: {metric['target_value']}) {trend_emoji}\n"
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": metrics_text
            }
        })
    
    return {
        "text": f"{category} metrics: {result.get('metrics_count', 0)} found",
        "blocks": blocks
    }

def format_update_response(result: dict) -> dict:
    """Format metrics update response for Slack"""
    
    return {
        "text": f"Metrics updated: {result.get('updates_processed', 0)} processed",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"🔄 *Metrics Update Complete*\n\n*Updates Processed:* {result.get('updates_processed', 0)}\n*Achievement Rate:* {result.get('updated_achievement_rate', 0):.1f}%\n*Critical Metrics:* {result.get('critical_metrics', 0)}\n*Last Updated:* {result.get('last_updated', 'N/A')[:19]}"
                }
            }
        ]
    }

def format_trend_response(result: dict) -> dict:
    """Format trend analysis response for Slack"""
    
    overall_trend = result.get("overall_trend", "unknown")
    trend_emoji = {"improving": "📈", "declining": "📉", "stable": "📊"}.get(overall_trend, "📊")
    
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{trend_emoji} *Security Program Trends*\n\n*Overall Trend:* {overall_trend.title()}\n*Improving:* {result.get('improving_metrics', 0)}\n*Declining:* {result.get('declining_metrics', 0)}\n*Total Analyzed:* {result.get('total_metrics_analyzed', 0)}"
            }
        }
    ]
    
    # Add category breakdown
    categories = result.get("category_trends", {})
    if categories:
        category_text = "*Category Health Scores:*\n"
        for category, data in categories.items():
            health_score = data.get("health_score", 0)
            health_emoji = "🟢" if health_score >= 75 else "🟡" if health_score >= 50 else "🔴"
            category_text += f"{health_emoji} {category.replace('_', ' ').title()}: {health_score:.1f}%\n"
        
        blocks.append({
            "type": "section", 
            "text": {
                "type": "mrkdwn",
                "text": category_text
            }
        })
    
    return {
        "text": f"Program trend analysis: {overall_trend}",
        "blocks": blocks
    }

def format_generic_response(result: dict) -> dict:
    """Format generic Sigma response for Slack"""
    
    return {
        "text": "Sigma agent response",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"📊 *Sigma Agent Response*\n\n*Command:* {result.get('command', 'N/A')}\n*Execution Time:* {result.get('execution_time', 0)}s\n*Source:* {result.get('source', 'Sigma Agent')}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"```{json.dumps(result.get('result', {}), indent=2)}```"
                }
            }
        ]
    }

# Example usage and testing
async def main():
    """Test Sigma Slack integration"""
    
    print("🚀 Testing Sigma Agent Slack Integration")
    print("=" * 50)
    
    # Initialize integration
    integration = SigmaSlackIntegration()
    
    # Test commands
    test_commands = [
        ("dashboard", ""),
        ("metric", "detection"),
        ("update", ""),
        ("trend", ""),
        ("report", "strategic")
    ]
    
    for command, params in test_commands:
        print(f"\n📊 Testing: /sigma {command} {params}")
        
        try:
            result = await integration.execute_sigma_command(command, params)
            formatted = format_sigma_response(result)
            
            print(f"   Status: {'✅ Success' if 'error' not in result else '❌ Error'}")
            print(f"   Response: {formatted['text']}")
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    print("\n✅ Sigma Slack integration testing complete!")

if __name__ == "__main__":
    asyncio.run(main())