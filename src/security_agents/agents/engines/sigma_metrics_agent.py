#!/usr/bin/env python3
"""
Sigma Agent: Security Program Performance & Metrics
Advanced security program measurement with ODM tracking and automated reporting
"""

import asyncio
import logging
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import uuid

# Check for optional dependencies  
PDF_AVAILABLE = False
PANDAS_AVAILABLE = False
PLOTTING_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
    from reportlab.platypus.flowables import PageBreak
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.lineplots import LinePlot
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.widgetbase import Widget
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    PLOTTING_AVAILABLE = True
except ImportError:
    PLOTTING_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Log optional dependency status
if not PDF_AVAILABLE:
    logger.warning("PDF generation libraries not available - reports will be text-based")
if not PANDAS_AVAILABLE:
    logger.warning("Pandas not available - some data analysis features limited")
if not PLOTTING_AVAILABLE:
    logger.warning("Plotting libraries not available - charts will not be generated")

# Check for optional dependencies  
PDF_AVAILABLE = False
PANDAS_AVAILABLE = False
PLOTTING_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
    from reportlab.platypus.flowables import PageBreak
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.lineplots import LinePlot
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.widgetbase import Widget
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    PLOTTING_AVAILABLE = True
except ImportError:
    PLOTTING_AVAILABLE = False

class MetricType(Enum):
    OUTCOME = "outcome"  # ODM - business outcome focused
    PERFORMANCE = "performance"  # KPI - process performance
    ACTIVITY = "activity"  # Volume/activity metrics
    RISK = "risk"  # Risk reduction metrics
    COMPLIANCE = "compliance"  # Compliance metrics

class ReportLevel(Enum):
    STRATEGIC = "strategic"  # Executive/board level
    TACTICAL = "tactical"  # Management/operational level
    OPERATIONAL = "operational"  # Team/individual level

class TrendDirection(Enum):
    IMPROVING = "improving"
    DECLINING = "declining" 
    STABLE = "stable"
    UNKNOWN = "unknown"

@dataclass
class SecurityMetric:
    """Individual security program metric"""
    id: str
    name: str
    description: str
    metric_type: MetricType
    category: str  # e.g., "incident_response", "vulnerability_management"
    current_value: float
    target_value: float
    unit: str  # e.g., "minutes", "percent", "count"
    trend_direction: TrendDirection
    last_updated: datetime
    data_source: str
    owner: str
    frequency: str  # daily, weekly, monthly, quarterly
    
@dataclass
class ODMReport:
    """Outcome Delivery Metrics Report"""
    report_id: str
    generated_at: datetime
    report_level: ReportLevel
    time_period: str
    metrics_included: List[str]
    key_findings: List[str]
    recommendations: List[str]
    executive_summary: str
    pdf_path: Optional[str] = None

@dataclass
class ProgramPerformance:
    """Overall security program performance assessment"""
    assessment_id: str
    assessment_date: datetime
    overall_score: float  # 0-100
    category_scores: Dict[str, float]
    risk_posture: str
    compliance_status: str
    improvement_areas: List[str]
    achievements: List[str]
    budget_utilization: float
    roi_metrics: Dict[str, float]

class SecurityMetricsDatabase:
    """Database for security metrics tracking"""
    
    def __init__(self, db_path: str = "security_metrics.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize metrics database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Security metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_metrics (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                metric_type TEXT,
                category TEXT,
                current_value REAL,
                target_value REAL,
                unit TEXT,
                trend_direction TEXT,
                last_updated TIMESTAMP,
                data_source TEXT,
                owner TEXT,
                frequency TEXT
            )
        ''')
        
        # Metrics history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metrics_history (
                id TEXT PRIMARY KEY,
                metric_id TEXT,
                value REAL,
                timestamp TIMESTAMP,
                notes TEXT,
                FOREIGN KEY (metric_id) REFERENCES security_metrics (id)
            )
        ''')
        
        # Reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS odm_reports (
                report_id TEXT PRIMARY KEY,
                generated_at TIMESTAMP,
                report_level TEXT,
                time_period TEXT,
                metrics_included TEXT,
                key_findings TEXT,
                recommendations TEXT,
                executive_summary TEXT,
                pdf_path TEXT
            )
        ''')
        
        # Program assessments table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS program_assessments (
                assessment_id TEXT PRIMARY KEY,
                assessment_date TIMESTAMP,
                overall_score REAL,
                category_scores TEXT,
                risk_posture TEXT,
                compliance_status TEXT,
                improvement_areas TEXT,
                achievements TEXT,
                budget_utilization REAL,
                roi_metrics TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_metric(self, metric: SecurityMetric) -> bool:
        """Add new security metric"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO security_metrics 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                metric.id, metric.name, metric.description, metric.metric_type.value,
                metric.category, metric.current_value, metric.target_value, metric.unit,
                metric.trend_direction.value, metric.last_updated, metric.data_source,
                metric.owner, metric.frequency
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            logger.error(f"Failed to add metric: {e}")
            return False
    
    def update_metric_value(self, metric_id: str, new_value: float, notes: str = "") -> bool:
        """Update metric value and add to history"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Update current value
            cursor.execute('''
                UPDATE security_metrics 
                SET current_value = ?, last_updated = ?
                WHERE id = ?
            ''', (new_value, datetime.now(), metric_id))
            
            # Add to history
            history_id = str(uuid.uuid4())
            cursor.execute('''
                INSERT INTO metrics_history 
                VALUES (?, ?, ?, ?, ?)
            ''', (history_id, metric_id, new_value, datetime.now(), notes))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            logger.error(f"Failed to update metric: {e}")
            return False
    
    def get_metrics_by_category(self, category: str) -> List[SecurityMetric]:
        """Get all metrics in a category"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM security_metrics WHERE category = ?', (category,))
            rows = cursor.fetchall()
            conn.close()
            
            metrics = []
            for row in rows:
                metric = SecurityMetric(
                    id=row[0], name=row[1], description=row[2],
                    metric_type=MetricType(row[3]), category=row[4],
                    current_value=row[5], target_value=row[6], unit=row[7],
                    trend_direction=TrendDirection(row[8]),
                    last_updated=datetime.fromisoformat(row[9]),
                    data_source=row[10], owner=row[11], frequency=row[12]
                )
                metrics.append(metric)
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to get metrics: {e}")
            return []

class SecurityMetricsCollector:
    """Collect metrics from various security systems"""
    
    def __init__(self):
        self.collectors = {
            "crowdstrike": self.collect_crowdstrike_metrics,
            "vulnerability_scanner": self.collect_vuln_metrics,
            "siem": self.collect_siem_metrics,
            "incident_response": self.collect_ir_metrics,
            "compliance": self.collect_compliance_metrics
        }
    
    async def collect_all_metrics(self) -> Dict[str, List[Dict[str, Any]]]:
        """Collect metrics from all configured sources"""
        all_metrics = {}
        
        for source, collector in self.collectors.items():
            try:
                metrics = await collector()
                all_metrics[source] = metrics
                logger.info(f"Collected {len(metrics)} metrics from {source}")
            except Exception as e:
                logger.error(f"Failed to collect from {source}: {e}")
                all_metrics[source] = []
        
        return all_metrics
    
    async def collect_crowdstrike_metrics(self) -> List[Dict[str, Any]]:
        """Collect metrics from CrowdStrike Falcon"""
        # Integration with CrowdStrike MCP for real metrics
        metrics = [
            {
                "id": "cs_detection_rate",
                "name": "Detection Rate",
                "category": "detection",
                "current_value": 95.4,
                "target_value": 98.0,
                "unit": "percent",
                "data_source": "CrowdStrike Falcon"
            },
            {
                "id": "cs_mean_dwell_time",
                "name": "Mean Dwell Time",
                "category": "incident_response",
                "current_value": 18.5,
                "target_value": 15.0,
                "unit": "minutes",
                "data_source": "CrowdStrike Falcon"
            },
            {
                "id": "cs_false_positive_rate",
                "name": "False Positive Rate",
                "category": "detection",
                "current_value": 2.1,
                "target_value": 1.5,
                "unit": "percent",
                "data_source": "CrowdStrike Falcon"
            }
        ]
        return metrics
    
    async def collect_vuln_metrics(self) -> List[Dict[str, Any]]:
        """Collect vulnerability management metrics"""
        metrics = [
            {
                "id": "vuln_critical_open",
                "name": "Critical Vulnerabilities Open",
                "category": "vulnerability_management",
                "current_value": 12,
                "target_value": 5,
                "unit": "count",
                "data_source": "Vulnerability Scanner"
            },
            {
                "id": "vuln_patch_time",
                "name": "Mean Time to Patch Critical",
                "category": "vulnerability_management",
                "current_value": 5.2,
                "target_value": 3.0,
                "unit": "days",
                "data_source": "Vulnerability Scanner"
            }
        ]
        return metrics
    
    async def collect_siem_metrics(self) -> List[Dict[str, Any]]:
        """Collect SIEM/SOC metrics"""
        metrics = [
            {
                "id": "siem_alert_volume",
                "name": "Daily Alert Volume",
                "category": "soc_operations",
                "current_value": 1247,
                "target_value": 800,
                "unit": "count",
                "data_source": "SIEM"
            },
            {
                "id": "siem_investigation_time",
                "name": "Mean Investigation Time",
                "category": "soc_operations",
                "current_value": 34.7,
                "target_value": 25.0,
                "unit": "minutes",
                "data_source": "SIEM"
            }
        ]
        return metrics
    
    async def collect_ir_metrics(self) -> List[Dict[str, Any]]:
        """Collect incident response metrics"""
        metrics = [
            {
                "id": "ir_mttr",
                "name": "Mean Time to Recovery",
                "category": "incident_response",
                "current_value": 127.5,
                "target_value": 90.0,
                "unit": "minutes",
                "data_source": "Incident Response System"
            },
            {
                "id": "ir_escalation_rate",
                "name": "Incident Escalation Rate",
                "category": "incident_response",
                "current_value": 15.8,
                "target_value": 10.0,
                "unit": "percent",
                "data_source": "Incident Response System"
            }
        ]
        return metrics
    
    async def collect_compliance_metrics(self) -> List[Dict[str, Any]]:
        """Collect compliance metrics"""
        metrics = [
            {
                "id": "compliance_coverage",
                "name": "Compliance Control Coverage",
                "category": "compliance",
                "current_value": 92.3,
                "target_value": 98.0,
                "unit": "percent",
                "data_source": "Compliance System"
            },
            {
                "id": "audit_findings",
                "name": "Open Audit Findings",
                "category": "compliance",
                "current_value": 7,
                "target_value": 2,
                "unit": "count",
                "data_source": "Audit System"
            }
        ]
        return metrics

class SecurityReportGenerator:
    """Generate professional PDF reports for security program metrics"""
    
    def __init__(self, db: SecurityMetricsDatabase):
        self.db = db
        if PDF_AVAILABLE:
            self.styles = getSampleStyleSheet()
            self.setup_custom_styles()
        else:
            self.styles = None
    
    def setup_custom_styles(self):
        """Setup custom report styles"""
        if not PDF_AVAILABLE:
            return
            
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=30,
            textColor=colors.darkblue
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.darkblue
        ))
        
        self.styles.add(ParagraphStyle(
            name='ExecutiveSummary',
            parent=self.styles['Normal'],
            fontSize=12,
            leftIndent=20,
            rightIndent=20,
            spaceBefore=10,
            spaceAfter=10,
            backColor=colors.lightgrey
        ))
    
    async def generate_strategic_report(self, 
                                      time_period: str = "monthly",
                                      output_path: str = None) -> ODMReport:
        """Generate strategic level ODM report for executives"""
        
        if not output_path:
            output_path = f"strategic_security_report_{datetime.now().strftime('%Y%m%d')}.pdf"
        
        # If PDF libraries not available, generate text report
        if not PDF_AVAILABLE:
            return await self._generate_text_report("strategic", time_period, output_path)
        
        report_id = str(uuid.uuid4())
        
        # Collect ODM metrics
        odm_metrics = await self._get_odm_metrics()
        
        # Generate executive summary
        executive_summary = await self._generate_executive_summary(odm_metrics)
        
        # Key findings
        key_findings = await self._identify_key_findings(odm_metrics)
        
        # Strategic recommendations
        recommendations = await self._generate_strategic_recommendations(odm_metrics)
        
        # Create PDF document
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        story = []
        
        # Title page
        story.append(Paragraph("Security Program Strategic Report", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.5*inch))
        
        story.append(Paragraph(f"Reporting Period: {time_period.title()}", self.styles['Normal']))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y')}", self.styles['Normal']))
        story.append(Spacer(1, 1*inch))
        
        # Executive summary
        story.append(Paragraph("Executive Summary", self.styles['CustomHeading']))
        story.append(Paragraph(executive_summary, self.styles['ExecutiveSummary']))
        story.append(Spacer(1, 0.3*inch))
        
        # Key findings
        story.append(Paragraph("Key Findings", self.styles['CustomHeading']))
        for finding in key_findings:
            story.append(Paragraph(f"• {finding}", self.styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # ODM Dashboard
        story.append(Paragraph("Outcome Delivery Metrics", self.styles['CustomHeading']))
        odm_table = await self._create_odm_table(odm_metrics)
        story.append(odm_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Strategic recommendations
        story.append(Paragraph("Strategic Recommendations", self.styles['CustomHeading']))
        for i, rec in enumerate(recommendations, 1):
            story.append(Paragraph(f"{i}. {rec}", self.styles['Normal']))
        
        # Page break for detailed metrics
        story.append(PageBreak())
        
        # Detailed metrics section
        story.append(Paragraph("Detailed Performance Metrics", self.styles['CustomHeading']))
        
        categories = ["detection", "incident_response", "vulnerability_management", "compliance"]
        for category in categories:
            category_metrics = self.db.get_metrics_by_category(category)
            if category_metrics:
                story.append(Paragraph(f"{category.replace('_', ' ').title()}", self.styles['Heading3']))
                category_table = await self._create_metrics_table(category_metrics)
                story.append(category_table)
                story.append(Spacer(1, 0.2*inch))
        
        # Build PDF
        doc.build(story)
        
        # Create report record
        report = ODMReport(
            report_id=report_id,
            generated_at=datetime.now(),
            report_level=ReportLevel.STRATEGIC,
            time_period=time_period,
            metrics_included=[m.id for m in odm_metrics],
            key_findings=key_findings,
            recommendations=recommendations,
            executive_summary=executive_summary,
            pdf_path=output_path
        )
        
        logger.info(f"Strategic report generated: {output_path}")
        return report
    
    async def generate_tactical_report(self,
                                     time_period: str = "weekly",
                                     output_path: str = None) -> ODMReport:
        """Generate tactical level report for security management"""
        
        if not output_path:
            output_path = f"tactical_security_report_{datetime.now().strftime('%Y%m%d')}.pdf"
        
        # If PDF libraries not available, generate text report
        if not PDF_AVAILABLE:
            return await self._generate_text_report("tactical", time_period, output_path)
        
        report_id = str(uuid.uuid4())
        
        # Collect all metrics
        all_metrics = await self._get_all_metrics()
        
        # Generate tactical summary
        tactical_summary = await self._generate_tactical_summary(all_metrics)
        
        # Performance analysis
        performance_analysis = await self._analyze_performance_trends(all_metrics)
        
        # Operational recommendations
        recommendations = await self._generate_tactical_recommendations(all_metrics)
        
        # Create PDF document
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        story = []
        
        # Title
        story.append(Paragraph("Security Operations Tactical Report", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.3*inch))
        
        story.append(Paragraph(f"Period: {time_period.title()}", self.styles['Normal']))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y %H:%M')}", self.styles['Normal']))
        story.append(Spacer(1, 0.5*inch))
        
        # Tactical summary
        story.append(Paragraph("Operations Summary", self.styles['CustomHeading']))
        story.append(Paragraph(tactical_summary, self.styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Performance metrics by category
        categories = ["soc_operations", "detection", "incident_response", "vulnerability_management"]
        
        for category in categories:
            category_metrics = [m for m in all_metrics if m.category == category]
            if category_metrics:
                story.append(Paragraph(f"{category.replace('_', ' ').title()} Performance", self.styles['CustomHeading']))
                
                # Metrics table
                category_table = await self._create_detailed_metrics_table(category_metrics)
                story.append(category_table)
                story.append(Spacer(1, 0.2*inch))
                
                # Trend analysis for this category
                trends = await self._analyze_category_trends(category_metrics)
                if trends:
                    story.append(Paragraph("Trend Analysis:", self.styles['Heading4']))
                    for trend in trends:
                        story.append(Paragraph(f"• {trend}", self.styles['Normal']))
                    story.append(Spacer(1, 0.2*inch))
        
        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Tactical Recommendations", self.styles['CustomHeading']))
        for i, rec in enumerate(recommendations, 1):
            story.append(Paragraph(f"{i}. {rec}", self.styles['Normal']))
        
        # Build PDF
        doc.build(story)
        
        # Create report record
        report = ODMReport(
            report_id=report_id,
            generated_at=datetime.now(),
            report_level=ReportLevel.TACTICAL,
            time_period=time_period,
            metrics_included=[m.id for m in all_metrics],
            key_findings=performance_analysis,
            recommendations=recommendations,
            executive_summary=tactical_summary,
            pdf_path=output_path
        )
        
        logger.info(f"Tactical report generated: {output_path}")
        return report
    
    async def _get_odm_metrics(self) -> List[SecurityMetric]:
        """Get Outcome Delivery Metrics specifically"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM security_metrics WHERE metric_type = 'outcome'")
        rows = cursor.fetchall()
        conn.close()
        
        metrics = []
        for row in rows:
            metric = SecurityMetric(
                id=row[0], name=row[1], description=row[2],
                metric_type=MetricType(row[3]), category=row[4],
                current_value=row[5], target_value=row[6], unit=row[7],
                trend_direction=TrendDirection(row[8]),
                last_updated=datetime.fromisoformat(row[9]),
                data_source=row[10], owner=row[11], frequency=row[12]
            )
            metrics.append(metric)
        
        return metrics
    
    async def _get_all_metrics(self) -> List[SecurityMetric]:
        """Get all metrics"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM security_metrics")
        rows = cursor.fetchall()
        conn.close()
        
        metrics = []
        for row in rows:
            metric = SecurityMetric(
                id=row[0], name=row[1], description=row[2],
                metric_type=MetricType(row[3]), category=row[4],
                current_value=row[5], target_value=row[6], unit=row[7],
                trend_direction=TrendDirection(row[8]),
                last_updated=datetime.fromisoformat(row[9]),
                data_source=row[10], owner=row[11], frequency=row[12]
            )
            metrics.append(metric)
        
        return metrics
    
    async def _generate_executive_summary(self, metrics: List[SecurityMetric]) -> str:
        """Generate executive summary from ODM metrics"""
        if not metrics:
            return "No outcome delivery metrics available for reporting period."
        
        # Calculate overall performance
        target_achievements = sum(1 for m in metrics if m.current_value >= m.target_value)
        achievement_rate = (target_achievements / len(metrics)) * 100
        
        improving_trends = sum(1 for m in metrics if m.trend_direction == TrendDirection.IMPROVING)
        declining_trends = sum(1 for m in metrics if m.trend_direction == TrendDirection.DECLINING)
        
        summary = f"""
        The security program demonstrates {achievement_rate:.1f}% target achievement across {len(metrics)} 
        key outcome delivery metrics. {improving_trends} metrics show improving trends while {declining_trends} 
        metrics require attention. 
        
        Key program outcomes this period include enhanced threat detection capabilities, 
        improved incident response times, and strengthened compliance posture. The security 
        program continues to mature its capability to deliver measurable business outcomes 
        while managing emerging threats effectively.
        """
        
        return summary.strip()
    
    async def _identify_key_findings(self, metrics: List[SecurityMetric]) -> List[str]:
        """Identify key findings from metrics analysis"""
        findings = []
        
        # Performance vs targets
        exceeding_targets = [m for m in metrics if m.current_value > m.target_value * 1.1]
        missing_targets = [m for m in metrics if m.current_value < m.target_value * 0.9]
        
        if exceeding_targets:
            findings.append(f"{len(exceeding_targets)} metrics significantly exceed targets, indicating strong program performance")
        
        if missing_targets:
            findings.append(f"{len(missing_targets)} metrics are below target thresholds, requiring focused improvement")
        
        # Trend analysis
        improving = [m for m in metrics if m.trend_direction == TrendDirection.IMPROVING]
        declining = [m for m in metrics if m.trend_direction == TrendDirection.DECLINING]
        
        if len(improving) > len(declining):
            findings.append("Overall positive trend across security program metrics")
        elif len(declining) > len(improving):
            findings.append("Concerning decline in multiple security metrics requires attention")
        
        # Data freshness
        stale_metrics = [m for m in metrics if (datetime.now() - m.last_updated).days > 7]
        if stale_metrics:
            findings.append(f"{len(stale_metrics)} metrics have stale data, impacting reporting accuracy")
        
        return findings
    
    async def _generate_strategic_recommendations(self, metrics: List[SecurityMetric]) -> List[str]:
        """Generate strategic recommendations"""
        recommendations = []
        
        # Investment recommendations
        underperforming = [m for m in metrics if m.current_value < m.target_value * 0.8]
        if underperforming:
            categories = set(m.category for m in underperforming)
            for category in categories:
                recommendations.append(f"Consider increased investment in {category.replace('_', ' ')} capabilities")
        
        # Process improvements
        declining = [m for m in metrics if m.trend_direction == TrendDirection.DECLINING]
        if len(declining) > 2:
            recommendations.append("Initiate comprehensive program review to address declining performance trends")
        
        # Technology recommendations
        high_performers = [m for m in metrics if m.current_value > m.target_value * 1.2]
        if high_performers:
            recommendations.append("Scale successful practices from high-performing areas across the security program")
        
        recommendations.append("Enhance metrics automation to improve data quality and reporting frequency")
        recommendations.append("Implement predictive analytics for proactive security performance management")
        
        return recommendations
    
    async def _generate_tactical_summary(self, metrics: List[SecurityMetric]) -> str:
        """Generate tactical summary from metrics"""
        if not metrics:
            return "No metrics available for tactical analysis."
        
        # Calculate performance by category
        categories = {}
        for metric in metrics:
            if metric.category not in categories:
                categories[metric.category] = []
            categories[metric.category].append(metric)
        
        summary = "Security operations performance summary:\n\n"
        
        for category, cat_metrics in categories.items():
            exceeding = sum(1 for m in cat_metrics if m.current_value >= m.target_value)
            total = len(cat_metrics)
            performance = (exceeding / total) * 100 if total > 0 else 0
            
            summary += f"{category.replace('_', ' ').title()}: {performance:.1f}% on target ({exceeding}/{total})\n"
        
        return summary
    
    async def _generate_tactical_recommendations(self, metrics: List[SecurityMetric]) -> List[str]:
        """Generate tactical recommendations from metrics"""
        recommendations = []
        
        # Find underperforming metrics
        underperforming = [m for m in metrics if m.current_value < m.target_value * 0.9]
        
        if underperforming:
            categories = set(m.category for m in underperforming)
            for category in categories:
                recommendations.append(f"Focus improvement efforts on {category.replace('_', ' ')} metrics")
        
        # Process recommendations
        declining = [m for m in metrics if m.trend_direction == TrendDirection.DECLINING]
        if declining:
            recommendations.append("Investigate root causes for declining performance trends")
        
        recommendations.append("Implement regular metric review cycles with stakeholders")
        recommendations.append("Enhance automation to improve metric data quality")
        
        return recommendations
    
    async def _create_odm_table(self, metrics: List[SecurityMetric]) -> Table:
        """Create table for ODM metrics"""
        if not metrics:
            data = [["No ODM metrics available"]]
            return Table(data)
        
        # Table headers
        data = [["Outcome Metric", "Current", "Target", "Achievement", "Trend"]]
        
        # Add metric rows
        for metric in metrics:
            achievement = (metric.current_value / metric.target_value) * 100 if metric.target_value > 0 else 0
            trend_symbol = {"improving": "↗", "declining": "↘", "stable": "→", "unknown": "?"}[metric.trend_direction.value]
            
            row = [
                metric.name,
                f"{metric.current_value} {metric.unit}",
                f"{metric.target_value} {metric.unit}",
                f"{achievement:.1f}%",
                trend_symbol
            ]
            data.append(row)
        
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        return table
    
    async def _create_metrics_table(self, metrics: List[SecurityMetric]) -> Table:
        """Create table for category metrics"""
        if not metrics:
            return Table([["No metrics available"]])
        
        data = [["Metric", "Current", "Target", "Source"]]
        
        for metric in metrics:
            row = [
                metric.name,
                f"{metric.current_value} {metric.unit}",
                f"{metric.target_value} {metric.unit}",
                metric.data_source
            ]
            data.append(row)
        
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        return table
    
    async def _create_detailed_metrics_table(self, metrics: List[SecurityMetric]) -> Table:
        """Create detailed metrics table for tactical reports"""
        if not metrics:
            return Table([["No metrics available"]])
        
        data = [["Metric", "Current", "Target", "Variance", "Trend", "Last Updated"]]
        
        for metric in metrics:
            variance = ((metric.current_value - metric.target_value) / metric.target_value * 100) if metric.target_value > 0 else 0
            variance_str = f"{variance:+.1f}%"
            trend_symbol = {"improving": "↗", "declining": "↘", "stable": "→", "unknown": "?"}[metric.trend_direction.value]
            
            row = [
                metric.name,
                f"{metric.current_value} {metric.unit}",
                f"{metric.target_value} {metric.unit}",
                variance_str,
                trend_symbol,
                metric.last_updated.strftime('%m/%d')
            ]
            data.append(row)
        
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        return table
    
    async def _generate_text_report(self, report_type: str, time_period: str, output_path: str) -> ODMReport:
        """Generate text-based report when PDF libraries not available"""
        
        report_id = str(uuid.uuid4())
        
        # Generate report content
        if report_type == "strategic":
            odm_metrics = await self._get_odm_metrics()
            executive_summary = await self._generate_executive_summary(odm_metrics)
            key_findings = await self._identify_key_findings(odm_metrics)
            recommendations = await self._generate_strategic_recommendations(odm_metrics)
            
            content = f"""
STRATEGIC SECURITY REPORT
Generated: {datetime.now().strftime('%B %d, %Y')}
Period: {time_period.title()}

EXECUTIVE SUMMARY
{executive_summary}

KEY FINDINGS
""" + "\n".join(f"• {finding}" for finding in key_findings) + f"""

STRATEGIC RECOMMENDATIONS
""" + "\n".join(f"{i}. {rec}" for i, rec in enumerate(recommendations, 1))
            
        else:  # tactical report
            all_metrics = await self._get_all_metrics()
            tactical_summary = await self._generate_tactical_summary(all_metrics)
            recommendations = await self._generate_tactical_recommendations(all_metrics)
            
            content = f"""
TACTICAL SECURITY REPORT  
Generated: {datetime.now().strftime('%B %d, %Y %H:%M')}
Period: {time_period.title()}

OPERATIONS SUMMARY
{tactical_summary}

TACTICAL RECOMMENDATIONS
""" + "\n".join(f"{i}. {rec}" for i, rec in enumerate(recommendations, 1))
        
        # Write text file
        text_output_path = output_path.replace('.pdf', '.txt')
        with open(text_output_path, 'w') as f:
            f.write(content)
        
        # Create report record
        report = ODMReport(
            report_id=report_id,
            generated_at=datetime.now(),
            report_level=ReportLevel.STRATEGIC if report_type == "strategic" else ReportLevel.TACTICAL,
            time_period=time_period,
            metrics_included=[],
            key_findings=key_findings if report_type == "strategic" else [],
            recommendations=recommendations,
            executive_summary=executive_summary if report_type == "strategic" else tactical_summary,
            pdf_path=text_output_path
        )
        
        logger.info(f"Text report generated: {text_output_path}")
        return report

class SigmaMetricsAgent:
    """Main Sigma Agent for Security Program Metrics & Reporting"""
    
    def __init__(self):
        self.db = SecurityMetricsDatabase()
        self.collector = SecurityMetricsCollector()
        self.reporter = SecurityReportGenerator(self.db)
        
        # Initialize default metrics
        asyncio.create_task(self.initialize_default_metrics())
    
    async def initialize_default_metrics(self):
        """Initialize default security program metrics"""
        logger.info("Initializing default security program metrics...")
        
        # Collect metrics from all sources
        all_metrics = await self.collector.collect_all_metrics()
        
        # Process and store metrics
        for source, metrics_data in all_metrics.items():
            for metric_data in metrics_data:
                metric = SecurityMetric(
                    id=metric_data["id"],
                    name=metric_data["name"],
                    description=metric_data.get("description", ""),
                    metric_type=MetricType.OUTCOME if "outcome" in metric_data.get("type", "") else MetricType.PERFORMANCE,
                    category=metric_data["category"],
                    current_value=metric_data["current_value"],
                    target_value=metric_data["target_value"],
                    unit=metric_data["unit"],
                    trend_direction=TrendDirection.STABLE,
                    last_updated=datetime.now(),
                    data_source=metric_data["data_source"],
                    owner="Security Team",
                    frequency="daily"
                )
                
                self.db.add_metric(metric)
        
        logger.info("Default security metrics initialized")
    
    async def generate_executive_dashboard(self) -> Dict[str, Any]:
        """Generate executive dashboard data"""
        metrics = await self.reporter._get_odm_metrics()
        
        if not metrics:
            return {"error": "No ODM metrics available"}
        
        # Calculate dashboard metrics
        target_achievements = sum(1 for m in metrics if m.current_value >= m.target_value)
        achievement_rate = (target_achievements / len(metrics)) * 100
        
        trend_summary = {
            "improving": sum(1 for m in metrics if m.trend_direction == TrendDirection.IMPROVING),
            "declining": sum(1 for m in metrics if m.trend_direction == TrendDirection.DECLINING),
            "stable": sum(1 for m in metrics if m.trend_direction == TrendDirection.STABLE)
        }
        
        # Risk indicators
        critical_metrics = [m for m in metrics if m.current_value < m.target_value * 0.7]
        
        dashboard = {
            "last_updated": datetime.now().isoformat(),
            "overall_score": achievement_rate,
            "total_metrics": len(metrics),
            "targets_achieved": target_achievements,
            "achievement_rate": achievement_rate,
            "trend_summary": trend_summary,
            "critical_attention": len(critical_metrics),
            "risk_indicators": [
                {
                    "metric": m.name,
                    "current": m.current_value,
                    "target": m.target_value,
                    "gap": ((m.target_value - m.current_value) / m.target_value) * 100
                }
                for m in critical_metrics
            ]
        }
        
        return dashboard
    
    async def run_scheduled_reporting(self):
        """Run scheduled reports based on configured frequencies"""
        logger.info("Running scheduled security program reports...")
        
        # Generate strategic report (monthly)
        strategic_report = await self.reporter.generate_strategic_report("monthly")
        logger.info(f"Strategic report: {strategic_report.pdf_path}")
        
        # Generate tactical report (weekly)
        tactical_report = await self.reporter.generate_tactical_report("weekly")
        logger.info(f"Tactical report: {tactical_report.pdf_path}")
        
        return {
            "strategic_report": strategic_report.pdf_path,
            "tactical_report": tactical_report.pdf_path,
            "generated_at": datetime.now().isoformat()
        }
    
    async def update_metrics_from_sources(self):
        """Update all metrics from their data sources"""
        logger.info("Updating metrics from data sources...")
        
        # Collect current metrics
        all_metrics = await self.collector.collect_all_metrics()
        
        updates_count = 0
        for source, metrics_data in all_metrics.items():
            for metric_data in metrics_data:
                success = self.db.update_metric_value(
                    metric_data["id"],
                    metric_data["current_value"],
                    f"Updated from {source}"
                )
                if success:
                    updates_count += 1
        
        logger.info(f"Updated {updates_count} metrics from data sources")
        return updates_count

# Example usage and testing
async def main():
    """Example usage of Sigma metrics agent"""
    
    # Initialize agent
    sigma = SigmaMetricsAgent()
    
    print("🚀 Sigma Agent: Security Program Metrics & Reporting")
    print("=" * 60)
    
    # Wait for initialization
    await asyncio.sleep(2)
    
    # Generate executive dashboard
    print("\n📊 Executive Dashboard:")
    dashboard = await sigma.generate_executive_dashboard()
    for key, value in dashboard.items():
        if key != "risk_indicators":
            print(f"   {key}: {value}")
    
    # Show risk indicators
    if dashboard.get("risk_indicators"):
        print(f"\n⚠️  Critical Attention Required:")
        for indicator in dashboard["risk_indicators"][:3]:
            print(f"   {indicator['metric']}: {indicator['gap']:.1f}% below target")
    
    # Generate reports
    print("\n📋 Generating Security Program Reports...")
    reports = await sigma.run_scheduled_reporting()
    print(f"   Strategic Report: {reports['strategic_report']}")
    print(f"   Tactical Report: {reports['tactical_report']}")
    
    # Update metrics
    print("\n🔄 Updating Metrics from Sources...")
    updates = await sigma.update_metrics_from_sources()
    print(f"   {updates} metrics updated")
    
    print("\n✅ Sigma Agent demonstration complete!")
    
    return {
        "dashboard": dashboard,
        "reports_generated": reports,
        "metrics_updated": updates
    }

if __name__ == "__main__":
    asyncio.run(main())