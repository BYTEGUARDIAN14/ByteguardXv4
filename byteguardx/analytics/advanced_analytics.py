"""
Advanced analytics and predictive insights for ByteGuardX
Provides trend analysis, risk scoring, and predictive vulnerability detection
"""

import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
from pathlib import Path
import threading
from collections import defaultdict
import pickle

from ..database.connection_pool import db_manager
from ..database.models import ScanResult, Finding, User, Organization

logger = logging.getLogger(__name__)

class TrendDirection(Enum):
    """Trend direction indicators"""
    IMPROVING = "improving"
    STABLE = "stable"
    DEGRADING = "degrading"
    UNKNOWN = "unknown"

class RiskLevel(Enum):
    """Risk level classifications"""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class TrendAnalysis:
    """Trend analysis results"""
    metric_name: str
    current_value: float
    previous_value: float
    change_percent: float
    direction: TrendDirection
    confidence: float
    time_period: str
    data_points: List[Tuple[datetime, float]] = field(default_factory=list)

@dataclass
class RiskScore:
    """Risk scoring results"""
    overall_score: float
    risk_level: RiskLevel
    contributing_factors: Dict[str, float]
    recommendations: List[str]
    confidence: float
    calculated_at: datetime

@dataclass
class PredictiveInsight:
    """Predictive analytics insight"""
    insight_type: str
    title: str
    description: str
    probability: float
    impact_score: float
    time_horizon: str  # "1_week", "1_month", "3_months"
    recommended_actions: List[str]
    supporting_data: Dict[str, Any] = field(default_factory=dict)

class AdvancedAnalytics:
    """
    Advanced analytics engine for ByteGuardX
    Provides trend analysis, risk scoring, and predictive insights
    """
    
    def __init__(self, analytics_dir: str = "data/analytics"):
        self.analytics_dir = Path(analytics_dir)
        self.analytics_dir.mkdir(parents=True, exist_ok=True)
        
        # Cache for computed analytics
        self._cache = {}
        self._cache_ttl = {}
        self._cache_lock = threading.RLock()
        
        # Analytics models
        self.models = {}
        self._load_models()
        
        # Configuration
        self.config = {
            'cache_ttl_minutes': 30,
            'min_data_points': 5,
            'trend_analysis_days': 30,
            'risk_score_weights': {
                'critical_findings': 0.4,
                'high_findings': 0.3,
                'scan_frequency': 0.1,
                'fix_rate': 0.2
            }
        }
    
    def analyze_security_trends(self, organization_id: str = None, 
                               days: int = 30) -> Dict[str, TrendAnalysis]:
        """Analyze security trends over time"""
        try:
            cache_key = f"trends_{organization_id}_{days}"
            
            # Check cache
            if self._is_cached(cache_key):
                return self._get_cached(cache_key)
            
            with db_manager.get_session() as session:
                # Build query
                query = session.query(ScanResult)
                
                if organization_id:
                    query = query.join(User).filter(User.organization_id == organization_id)
                
                # Get scans from the specified period
                start_date = datetime.now() - timedelta(days=days)
                scans = query.filter(
                    ScanResult.completed_at >= start_date,
                    ScanResult.status == 'completed'
                ).order_by(ScanResult.completed_at).all()
                
                if len(scans) < self.config['min_data_points']:
                    logger.warning(f"Insufficient data for trend analysis: {len(scans)} scans")
                    return {}
                
                # Analyze trends
                trends = {}
                
                # Total findings trend
                trends['total_findings'] = self._analyze_metric_trend(
                    scans, 'total_findings', days
                )
                
                # Critical findings trend
                trends['critical_findings'] = self._analyze_metric_trend(
                    scans, 'critical_findings', days
                )
                
                # High findings trend
                trends['high_findings'] = self._analyze_metric_trend(
                    scans, 'high_findings', days
                )
                
                # Scan frequency trend
                trends['scan_frequency'] = self._analyze_scan_frequency_trend(scans, days)
                
                # Files per scan trend
                trends['files_per_scan'] = self._analyze_metric_trend(
                    scans, 'total_files', days
                )
                
                # Scan duration trend
                trends['scan_duration'] = self._analyze_metric_trend(
                    scans, 'scan_duration_seconds', days
                )
                
                # Cache results
                self._cache_result(cache_key, trends)
                
                return trends
                
        except Exception as e:
            logger.error(f"Failed to analyze security trends: {e}")
            return {}
    
    def calculate_risk_score(self, organization_id: str = None) -> RiskScore:
        """Calculate comprehensive risk score"""
        try:
            cache_key = f"risk_score_{organization_id}"
            
            # Check cache
            if self._is_cached(cache_key):
                return self._get_cached(cache_key)
            
            with db_manager.get_session() as session:
                # Get recent scan data (last 30 days)
                start_date = datetime.now() - timedelta(days=30)
                
                query = session.query(ScanResult)
                if organization_id:
                    query = query.join(User).filter(User.organization_id == organization_id)
                
                recent_scans = query.filter(
                    ScanResult.completed_at >= start_date,
                    ScanResult.status == 'completed'
                ).all()
                
                if not recent_scans:
                    return RiskScore(
                        overall_score=0.0,
                        risk_level=RiskLevel.UNKNOWN,
                        contributing_factors={},
                        recommendations=["No recent scan data available"],
                        confidence=0.0,
                        calculated_at=datetime.now()
                    )
                
                # Calculate risk factors
                factors = {}
                
                # Critical findings factor
                total_critical = sum(scan.critical_findings or 0 for scan in recent_scans)
                total_scans = len(recent_scans)
                avg_critical = total_critical / total_scans if total_scans > 0 else 0
                factors['critical_findings'] = min(avg_critical / 10.0, 1.0)  # Normalize to 0-1
                
                # High findings factor
                total_high = sum(scan.high_findings or 0 for scan in recent_scans)
                avg_high = total_high / total_scans if total_scans > 0 else 0
                factors['high_findings'] = min(avg_high / 20.0, 1.0)  # Normalize to 0-1
                
                # Scan frequency factor (lower frequency = higher risk)
                days_since_last_scan = (datetime.now() - max(scan.completed_at for scan in recent_scans)).days
                factors['scan_frequency'] = min(days_since_last_scan / 7.0, 1.0)  # Weekly scans expected
                
                # Fix rate factor (placeholder - would need fix tracking)
                factors['fix_rate'] = 0.3  # Assume 70% fix rate for now
                
                # Calculate weighted score
                weights = self.config['risk_score_weights']
                overall_score = sum(
                    factors.get(factor, 0) * weight 
                    for factor, weight in weights.items()
                )
                
                # Determine risk level
                if overall_score >= 0.8:
                    risk_level = RiskLevel.CRITICAL
                elif overall_score >= 0.6:
                    risk_level = RiskLevel.HIGH
                elif overall_score >= 0.4:
                    risk_level = RiskLevel.MEDIUM
                elif overall_score >= 0.2:
                    risk_level = RiskLevel.LOW
                else:
                    risk_level = RiskLevel.VERY_LOW
                
                # Generate recommendations
                recommendations = self._generate_risk_recommendations(factors, overall_score)
                
                # Calculate confidence based on data quality
                confidence = min(len(recent_scans) / 10.0, 1.0)  # More scans = higher confidence
                
                risk_score = RiskScore(
                    overall_score=overall_score,
                    risk_level=risk_level,
                    contributing_factors=factors,
                    recommendations=recommendations,
                    confidence=confidence,
                    calculated_at=datetime.now()
                )
                
                # Cache result
                self._cache_result(cache_key, risk_score)
                
                return risk_score
                
        except Exception as e:
            logger.error(f"Failed to calculate risk score: {e}")
            return RiskScore(
                overall_score=0.0,
                risk_level=RiskLevel.UNKNOWN,
                contributing_factors={},
                recommendations=["Error calculating risk score"],
                confidence=0.0,
                calculated_at=datetime.now()
            )
    
    def generate_predictive_insights(self, organization_id: str = None) -> List[PredictiveInsight]:
        """Generate predictive insights based on historical data"""
        try:
            cache_key = f"insights_{organization_id}"
            
            # Check cache
            if self._is_cached(cache_key):
                return self._get_cached(cache_key)
            
            insights = []
            
            # Get trend analysis
            trends = self.analyze_security_trends(organization_id, days=90)
            
            # Vulnerability trend prediction
            if 'critical_findings' in trends:
                trend = trends['critical_findings']
                if trend.direction == TrendDirection.DEGRADING and trend.change_percent > 20:
                    insights.append(PredictiveInsight(
                        insight_type="vulnerability_trend",
                        title="Critical Vulnerability Increase Predicted",
                        description=f"Critical findings have increased by {trend.change_percent:.1f}% and are likely to continue rising",
                        probability=0.75,
                        impact_score=0.9,
                        time_horizon="1_month",
                        recommended_actions=[
                            "Increase scan frequency",
                            "Review security policies",
                            "Implement additional security controls",
                            "Schedule security training"
                        ],
                        supporting_data={'trend_data': trend}
                    ))
            
            # Scan frequency prediction
            if 'scan_frequency' in trends:
                trend = trends['scan_frequency']
                if trend.direction == TrendDirection.DEGRADING:
                    insights.append(PredictiveInsight(
                        insight_type="scan_frequency",
                        title="Decreased Scanning Activity Detected",
                        description="Scan frequency is declining, which may lead to undetected vulnerabilities",
                        probability=0.8,
                        impact_score=0.6,
                        time_horizon="2_weeks",
                        recommended_actions=[
                            "Set up automated scanning schedules",
                            "Send scan reminders to teams",
                            "Review scanning policies"
                        ],
                        supporting_data={'trend_data': trend}
                    ))
            
            # Performance degradation prediction
            if 'scan_duration' in trends:
                trend = trends['scan_duration']
                if trend.direction == TrendDirection.DEGRADING and trend.change_percent > 50:
                    insights.append(PredictiveInsight(
                        insight_type="performance",
                        title="Scan Performance Degradation",
                        description=f"Scan duration has increased by {trend.change_percent:.1f}%, indicating potential performance issues",
                        probability=0.7,
                        impact_score=0.4,
                        time_horizon="1_week",
                        recommended_actions=[
                            "Optimize scan configurations",
                            "Review system resources",
                            "Consider incremental scanning",
                            "Update scanning infrastructure"
                        ],
                        supporting_data={'trend_data': trend}
                    ))
            
            # Risk score prediction
            risk_score = self.calculate_risk_score(organization_id)
            if risk_score.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                insights.append(PredictiveInsight(
                    insight_type="risk_escalation",
                    title="High Risk Level Detected",
                    description=f"Current risk level is {risk_score.risk_level.value} with score {risk_score.overall_score:.2f}",
                    probability=0.9,
                    impact_score=0.8,
                    time_horizon="immediate",
                    recommended_actions=risk_score.recommendations,
                    supporting_data={'risk_score': risk_score}
                ))
            
            # Cache results
            self._cache_result(cache_key, insights)
            
            return insights
            
        except Exception as e:
            logger.error(f"Failed to generate predictive insights: {e}")
            return []
    
    def get_vulnerability_patterns(self, organization_id: str = None) -> Dict[str, Any]:
        """Analyze vulnerability patterns and hotspots"""
        try:
            with db_manager.get_session() as session:
                # Get findings from last 90 days
                start_date = datetime.now() - timedelta(days=90)
                
                query = session.query(Finding).join(ScanResult)
                if organization_id:
                    query = query.join(User).filter(User.organization_id == organization_id)
                
                findings = query.filter(
                    ScanResult.completed_at >= start_date
                ).all()
                
                if not findings:
                    return {}
                
                patterns = {
                    'vulnerability_types': defaultdict(int),
                    'severity_distribution': defaultdict(int),
                    'file_hotspots': defaultdict(int),
                    'scanner_effectiveness': defaultdict(int),
                    'temporal_patterns': defaultdict(list)
                }
                
                for finding in findings:
                    # Vulnerability types
                    patterns['vulnerability_types'][finding.vulnerability_type] += 1
                    
                    # Severity distribution
                    patterns['severity_distribution'][finding.severity] += 1
                    
                    # File hotspots
                    if finding.file_path:
                        patterns['file_hotspots'][finding.file_path] += 1
                    
                    # Scanner effectiveness
                    patterns['scanner_effectiveness'][finding.scanner_type] += 1
                    
                    # Temporal patterns
                    week = finding.created_at.strftime('%Y-W%U')
                    patterns['temporal_patterns'][week].append(finding.severity)
                
                # Convert to regular dicts and sort
                result = {
                    'vulnerability_types': dict(sorted(
                        patterns['vulnerability_types'].items(),
                        key=lambda x: x[1], reverse=True
                    )[:10]),
                    'severity_distribution': dict(patterns['severity_distribution']),
                    'file_hotspots': dict(sorted(
                        patterns['file_hotspots'].items(),
                        key=lambda x: x[1], reverse=True
                    )[:20]),
                    'scanner_effectiveness': dict(patterns['scanner_effectiveness']),
                    'temporal_patterns': dict(patterns['temporal_patterns'])
                }
                
                return result
                
        except Exception as e:
            logger.error(f"Failed to analyze vulnerability patterns: {e}")
            return {}
    
    def _analyze_metric_trend(self, scans: List, metric_field: str, days: int) -> TrendAnalysis:
        """Analyze trend for a specific metric"""
        try:
            # Extract metric values with timestamps
            data_points = []
            for scan in scans:
                value = getattr(scan, metric_field, 0) or 0
                data_points.append((scan.completed_at, float(value)))
            
            if len(data_points) < 2:
                return TrendAnalysis(
                    metric_name=metric_field,
                    current_value=0.0,
                    previous_value=0.0,
                    change_percent=0.0,
                    direction=TrendDirection.UNKNOWN,
                    confidence=0.0,
                    time_period=f"{days}_days",
                    data_points=data_points
                )
            
            # Sort by timestamp
            data_points.sort(key=lambda x: x[0])
            
            # Calculate trend using linear regression
            timestamps = np.array([dp[0].timestamp() for dp in data_points])
            values = np.array([dp[1] for dp in data_points])
            
            # Normalize timestamps
            timestamps = timestamps - timestamps[0]
            
            # Linear regression
            if len(timestamps) > 1:
                slope, intercept = np.polyfit(timestamps, values, 1)
                
                # Calculate current and previous values
                current_value = values[-1]
                previous_value = values[0] if len(values) > 1 else current_value
                
                # Calculate change percentage
                if previous_value != 0:
                    change_percent = ((current_value - previous_value) / previous_value) * 100
                else:
                    change_percent = 0.0
                
                # Determine direction
                if abs(change_percent) < 5:  # Less than 5% change
                    direction = TrendDirection.STABLE
                elif change_percent > 0:
                    direction = TrendDirection.DEGRADING  # More findings = worse
                else:
                    direction = TrendDirection.IMPROVING  # Fewer findings = better
                
                # Calculate confidence based on data quality
                confidence = min(len(data_points) / 10.0, 1.0)
                
                return TrendAnalysis(
                    metric_name=metric_field,
                    current_value=current_value,
                    previous_value=previous_value,
                    change_percent=change_percent,
                    direction=direction,
                    confidence=confidence,
                    time_period=f"{days}_days",
                    data_points=data_points
                )
            
        except Exception as e:
            logger.error(f"Failed to analyze trend for {metric_field}: {e}")
        
        return TrendAnalysis(
            metric_name=metric_field,
            current_value=0.0,
            previous_value=0.0,
            change_percent=0.0,
            direction=TrendDirection.UNKNOWN,
            confidence=0.0,
            time_period=f"{days}_days",
            data_points=[]
        )
    
    def _analyze_scan_frequency_trend(self, scans: List, days: int) -> TrendAnalysis:
        """Analyze scan frequency trend"""
        try:
            if not scans:
                return TrendAnalysis(
                    metric_name="scan_frequency",
                    current_value=0.0,
                    previous_value=0.0,
                    change_percent=0.0,
                    direction=TrendDirection.UNKNOWN,
                    confidence=0.0,
                    time_period=f"{days}_days"
                )
            
            # Group scans by week
            weekly_counts = defaultdict(int)
            for scan in scans:
                week = scan.completed_at.strftime('%Y-W%U')
                weekly_counts[week] += 1
            
            # Calculate average scans per week
            weeks = sorted(weekly_counts.keys())
            if len(weeks) < 2:
                return TrendAnalysis(
                    metric_name="scan_frequency",
                    current_value=len(scans),
                    previous_value=len(scans),
                    change_percent=0.0,
                    direction=TrendDirection.STABLE,
                    confidence=0.5,
                    time_period=f"{days}_days"
                )
            
            # Compare first half vs second half
            mid_point = len(weeks) // 2
            first_half_avg = np.mean([weekly_counts[week] for week in weeks[:mid_point]])
            second_half_avg = np.mean([weekly_counts[week] for week in weeks[mid_point:]])
            
            # Calculate change
            if first_half_avg != 0:
                change_percent = ((second_half_avg - first_half_avg) / first_half_avg) * 100
            else:
                change_percent = 0.0
            
            # Determine direction (more scans = better)
            if abs(change_percent) < 10:
                direction = TrendDirection.STABLE
            elif change_percent > 0:
                direction = TrendDirection.IMPROVING
            else:
                direction = TrendDirection.DEGRADING
            
            return TrendAnalysis(
                metric_name="scan_frequency",
                current_value=second_half_avg,
                previous_value=first_half_avg,
                change_percent=change_percent,
                direction=direction,
                confidence=min(len(weeks) / 8.0, 1.0),  # 8 weeks for full confidence
                time_period=f"{days}_days"
            )
            
        except Exception as e:
            logger.error(f"Failed to analyze scan frequency trend: {e}")
            return TrendAnalysis(
                metric_name="scan_frequency",
                current_value=0.0,
                previous_value=0.0,
                change_percent=0.0,
                direction=TrendDirection.UNKNOWN,
                confidence=0.0,
                time_period=f"{days}_days"
            )
    
    def _generate_risk_recommendations(self, factors: Dict[str, float], 
                                     overall_score: float) -> List[str]:
        """Generate risk mitigation recommendations"""
        recommendations = []
        
        if factors.get('critical_findings', 0) > 0.5:
            recommendations.append("Address critical vulnerabilities immediately")
            recommendations.append("Implement emergency security patches")
        
        if factors.get('high_findings', 0) > 0.5:
            recommendations.append("Prioritize high-severity vulnerability remediation")
            recommendations.append("Review and update security policies")
        
        if factors.get('scan_frequency', 0) > 0.5:
            recommendations.append("Increase scanning frequency")
            recommendations.append("Implement automated scanning schedules")
        
        if factors.get('fix_rate', 0) > 0.5:
            recommendations.append("Improve vulnerability remediation processes")
            recommendations.append("Provide security training to development teams")
        
        if overall_score > 0.7:
            recommendations.append("Consider engaging external security consultants")
            recommendations.append("Implement additional security monitoring")
        
        return recommendations
    
    def _is_cached(self, key: str) -> bool:
        """Check if result is cached and not expired"""
        with self._cache_lock:
            if key not in self._cache:
                return False
            
            ttl = self._cache_ttl.get(key, 0)
            return datetime.now().timestamp() < ttl
    
    def _get_cached(self, key: str):
        """Get cached result"""
        with self._cache_lock:
            return self._cache.get(key)
    
    def _cache_result(self, key: str, result):
        """Cache result with TTL"""
        with self._cache_lock:
            self._cache[key] = result
            ttl = datetime.now() + timedelta(minutes=self.config['cache_ttl_minutes'])
            self._cache_ttl[key] = ttl.timestamp()
    
    def _load_models(self):
        """Load pre-trained analytics models"""
        # Placeholder for loading ML models for predictions
        pass

# Global analytics instance
advanced_analytics = AdvancedAnalytics()
