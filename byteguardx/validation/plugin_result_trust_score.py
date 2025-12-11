"""
Plugin Result Trust Scoring System for ByteGuardX
Evaluates plugin reliability and result trustworthiness
"""

import os
import time
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import json
from pathlib import Path

logger = logging.getLogger(__name__)

class TrustLevel(Enum):
    """Trust levels for plugins"""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"

class PluginRiskCategory(Enum):
    """Risk categories for plugins"""
    SAFE = "safe"
    LOW_RISK = "low_risk"
    MEDIUM_RISK = "medium_risk"
    HIGH_RISK = "high_risk"
    CRITICAL_RISK = "critical_risk"

@dataclass
class PluginMetrics:
    """Plugin performance and reliability metrics"""
    plugin_name: str
    total_executions: int
    successful_executions: int
    failed_executions: int
    average_execution_time: float
    false_positive_rate: float
    false_negative_rate: float
    user_feedback_score: float
    last_updated: datetime
    version: str
    author_verified: bool
    
@dataclass
class TrustScore:
    """Trust score for a plugin"""
    plugin_name: str
    overall_score: float
    trust_level: TrustLevel
    risk_category: PluginRiskCategory
    component_scores: Dict[str, float]
    confidence_interval: Tuple[float, float]
    last_calculated: datetime
    factors: List[str]
    recommendations: List[str]

class PluginTrustScorer:
    """
    Advanced plugin trust scoring system
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.plugin_metrics = {}
        self.trust_scores = {}
        self.feedback_history = {}
        
        # Trust scoring weights
        self.scoring_weights = {
            'reliability': 0.25,      # Success rate, stability
            'performance': 0.20,      # Execution time, efficiency
            'accuracy': 0.25,         # False positive/negative rates
            'reputation': 0.15,       # User feedback, community rating
            'security': 0.10,         # Security analysis, code review
            'maintenance': 0.05       # Update frequency, support
        }
        
        # Load existing metrics
        self._load_plugin_metrics()
        
    def calculate_trust_score(self, plugin_name: str, plugin_metadata: Dict[str, Any] = None) -> TrustScore:
        """
        Calculate comprehensive trust score for a plugin
        """
        try:
            # Get or initialize plugin metrics
            metrics = self.plugin_metrics.get(plugin_name, self._initialize_plugin_metrics(plugin_name))
            
            # Calculate component scores
            component_scores = {}
            
            # 1. Reliability Score
            component_scores['reliability'] = self._calculate_reliability_score(metrics)
            
            # 2. Performance Score
            component_scores['performance'] = self._calculate_performance_score(metrics)
            
            # 3. Accuracy Score
            component_scores['accuracy'] = self._calculate_accuracy_score(metrics)
            
            # 4. Reputation Score
            component_scores['reputation'] = self._calculate_reputation_score(metrics, plugin_metadata)
            
            # 5. Security Score
            component_scores['security'] = self._calculate_security_score(plugin_name, plugin_metadata)
            
            # 6. Maintenance Score
            component_scores['maintenance'] = self._calculate_maintenance_score(metrics, plugin_metadata)
            
            # Calculate weighted overall score
            overall_score = sum(
                component_scores[component] * self.scoring_weights[component]
                for component in component_scores
            )
            
            # Determine trust level and risk category
            trust_level = self._determine_trust_level(overall_score)
            risk_category = self._determine_risk_category(overall_score, component_scores)
            
            # Calculate confidence interval
            confidence_interval = self._calculate_confidence_interval(overall_score, metrics)
            
            # Generate factors and recommendations
            factors = self._generate_trust_factors(component_scores, metrics)
            recommendations = self._generate_recommendations(component_scores, trust_level)
            
            trust_score = TrustScore(
                plugin_name=plugin_name,
                overall_score=overall_score,
                trust_level=trust_level,
                risk_category=risk_category,
                component_scores=component_scores,
                confidence_interval=confidence_interval,
                last_calculated=datetime.now(),
                factors=factors,
                recommendations=recommendations
            )
            
            # Cache the trust score
            self.trust_scores[plugin_name] = trust_score
            
            return trust_score
            
        except Exception as e:
            logger.error(f"Trust score calculation failed for plugin {plugin_name}: {e}")
            return self._create_default_trust_score(plugin_name)
    
    def update_plugin_metrics(self, plugin_name: str, execution_result: Dict[str, Any]):
        """
        Update plugin metrics based on execution result
        """
        try:
            if plugin_name not in self.plugin_metrics:
                self.plugin_metrics[plugin_name] = self._initialize_plugin_metrics(plugin_name)
            
            metrics = self.plugin_metrics[plugin_name]
            
            # Update execution counts
            metrics.total_executions += 1
            
            if execution_result.get('success', False):
                metrics.successful_executions += 1
            else:
                metrics.failed_executions += 1
            
            # Update execution time
            execution_time = execution_result.get('execution_time', 0.0)
            if execution_time > 0:
                # Calculate running average
                total_time = metrics.average_execution_time * (metrics.total_executions - 1)
                metrics.average_execution_time = (total_time + execution_time) / metrics.total_executions
            
            # Update false positive/negative rates if feedback is available
            if 'user_feedback' in execution_result:
                self._update_accuracy_metrics(metrics, execution_result['user_feedback'])
            
            # Save updated metrics
            self._save_plugin_metrics()
            
        except Exception as e:
            logger.error(f"Failed to update metrics for plugin {plugin_name}: {e}")
    
    def add_user_feedback(self, plugin_name: str, feedback: Dict[str, Any]):
        """
        Add user feedback for a plugin
        """
        try:
            if plugin_name not in self.feedback_history:
                self.feedback_history[plugin_name] = []
            
            feedback['timestamp'] = datetime.now().isoformat()
            self.feedback_history[plugin_name].append(feedback)
            
            # Update plugin metrics
            if plugin_name in self.plugin_metrics:
                self._update_user_feedback_score(plugin_name)
            
            # Recalculate trust score
            self.calculate_trust_score(plugin_name)
            
        except Exception as e:
            logger.error(f"Failed to add user feedback for plugin {plugin_name}: {e}")
    
    def get_plugin_trust_level(self, plugin_name: str) -> TrustLevel:
        """
        Get current trust level for a plugin
        """
        if plugin_name in self.trust_scores:
            return self.trust_scores[plugin_name].trust_level
        else:
            # Calculate trust score if not cached
            trust_score = self.calculate_trust_score(plugin_name)
            return trust_score.trust_level
    
    def get_trusted_plugins(self, min_trust_level: TrustLevel = TrustLevel.MEDIUM) -> List[str]:
        """
        Get list of plugins meeting minimum trust level
        """
        trusted_plugins = []
        trust_level_values = {
            TrustLevel.VERY_LOW: 1,
            TrustLevel.LOW: 2,
            TrustLevel.MEDIUM: 3,
            TrustLevel.HIGH: 4,
            TrustLevel.VERY_HIGH: 5
        }
        
        min_value = trust_level_values[min_trust_level]
        
        for plugin_name in self.plugin_metrics:
            trust_score = self.calculate_trust_score(plugin_name)
            if trust_level_values[trust_score.trust_level] >= min_value:
                trusted_plugins.append(plugin_name)
        
        return trusted_plugins
    
    def _calculate_reliability_score(self, metrics: PluginMetrics) -> float:
        """
        Calculate reliability score based on success rate and stability
        """
        if metrics.total_executions == 0:
            return 0.5  # Neutral score for new plugins
        
        success_rate = metrics.successful_executions / metrics.total_executions
        
        # Penalize plugins with very few executions
        execution_confidence = min(metrics.total_executions / 100, 1.0)
        
        reliability_score = success_rate * execution_confidence
        
        # Bonus for consistent performance
        if metrics.total_executions > 50 and success_rate > 0.95:
            reliability_score = min(reliability_score + 0.1, 1.0)
        
        return reliability_score
    
    def _calculate_performance_score(self, metrics: PluginMetrics) -> float:
        """
        Calculate performance score based on execution time
        """
        if metrics.average_execution_time <= 0:
            return 0.5  # Neutral score if no timing data
        
        # Performance thresholds (in seconds)
        excellent_threshold = 1.0
        good_threshold = 5.0
        acceptable_threshold = 15.0
        
        if metrics.average_execution_time <= excellent_threshold:
            return 1.0
        elif metrics.average_execution_time <= good_threshold:
            return 0.8
        elif metrics.average_execution_time <= acceptable_threshold:
            return 0.6
        else:
            # Exponential decay for very slow plugins
            return max(0.1, 0.6 * (acceptable_threshold / metrics.average_execution_time))
    
    def _calculate_accuracy_score(self, metrics: PluginMetrics) -> float:
        """
        Calculate accuracy score based on false positive/negative rates
        """
        # Start with neutral score
        accuracy_score = 0.5
        
        # Penalize high false positive rate
        if metrics.false_positive_rate > 0:
            fp_penalty = min(metrics.false_positive_rate * 0.5, 0.4)
            accuracy_score -= fp_penalty
        
        # Penalize high false negative rate (more severely)
        if metrics.false_negative_rate > 0:
            fn_penalty = min(metrics.false_negative_rate * 0.7, 0.5)
            accuracy_score -= fn_penalty
        
        # Bonus for low error rates
        if metrics.false_positive_rate < 0.1 and metrics.false_negative_rate < 0.05:
            accuracy_score += 0.3
        
        return max(min(accuracy_score, 1.0), 0.0)
    
    def _calculate_reputation_score(self, metrics: PluginMetrics, plugin_metadata: Dict[str, Any] = None) -> float:
        """
        Calculate reputation score based on user feedback and community rating
        """
        reputation_score = metrics.user_feedback_score
        
        # Factor in author verification
        if plugin_metadata and plugin_metadata.get('author_verified', False):
            reputation_score += 0.2
        
        # Factor in community adoption
        if plugin_metadata and 'download_count' in plugin_metadata:
            download_count = plugin_metadata['download_count']
            adoption_bonus = min(download_count / 10000, 0.2)  # Max 0.2 bonus
            reputation_score += adoption_bonus
        
        return min(reputation_score, 1.0)
    
    def _calculate_security_score(self, plugin_name: str, plugin_metadata: Dict[str, Any] = None) -> float:
        """
        Calculate security score based on code analysis and security review
        """
        security_score = 0.5  # Base score
        
        # Check for security review
        if plugin_metadata and plugin_metadata.get('security_reviewed', False):
            security_score += 0.3
        
        # Check for code signing
        if plugin_metadata and plugin_metadata.get('code_signed', False):
            security_score += 0.2
        
        # Check for known vulnerabilities
        if plugin_metadata and plugin_metadata.get('known_vulnerabilities', 0) > 0:
            vuln_penalty = min(plugin_metadata['known_vulnerabilities'] * 0.1, 0.4)
            security_score -= vuln_penalty
        
        return max(min(security_score, 1.0), 0.0)

    def _calculate_maintenance_score(self, metrics: PluginMetrics, plugin_metadata: Dict[str, Any] = None) -> float:
        """
        Calculate maintenance score based on update frequency and support
        """
        maintenance_score = 0.5  # Base score

        # Check last update time
        if metrics.last_updated:
            days_since_update = (datetime.now() - metrics.last_updated).days

            if days_since_update <= 30:
                maintenance_score += 0.3
            elif days_since_update <= 90:
                maintenance_score += 0.2
            elif days_since_update <= 180:
                maintenance_score += 0.1
            else:
                # Penalize very old plugins
                maintenance_score -= min((days_since_update - 180) / 365 * 0.3, 0.3)

        # Check version information
        if plugin_metadata and 'version' in plugin_metadata:
            version = plugin_metadata['version']
            if self._is_semantic_version(version):
                maintenance_score += 0.1

        # Check for documentation
        if plugin_metadata and plugin_metadata.get('has_documentation', False):
            maintenance_score += 0.1

        return max(min(maintenance_score, 1.0), 0.0)

    def _determine_trust_level(self, overall_score: float) -> TrustLevel:
        """
        Determine trust level based on overall score
        """
        if overall_score >= 0.9:
            return TrustLevel.VERY_HIGH
        elif overall_score >= 0.75:
            return TrustLevel.HIGH
        elif overall_score >= 0.6:
            return TrustLevel.MEDIUM
        elif overall_score >= 0.4:
            return TrustLevel.LOW
        else:
            return TrustLevel.VERY_LOW

    def _determine_risk_category(self, overall_score: float, component_scores: Dict[str, float]) -> PluginRiskCategory:
        """
        Determine risk category based on scores
        """
        # Check for critical security issues
        if component_scores.get('security', 0.5) < 0.3:
            return PluginRiskCategory.CRITICAL_RISK

        # Check for high reliability issues
        if component_scores.get('reliability', 0.5) < 0.4:
            return PluginRiskCategory.HIGH_RISK

        # Overall score-based categorization
        if overall_score >= 0.8:
            return PluginRiskCategory.SAFE
        elif overall_score >= 0.6:
            return PluginRiskCategory.LOW_RISK
        elif overall_score >= 0.4:
            return PluginRiskCategory.MEDIUM_RISK
        else:
            return PluginRiskCategory.HIGH_RISK

    def _calculate_confidence_interval(self, overall_score: float, metrics: PluginMetrics) -> Tuple[float, float]:
        """
        Calculate confidence interval for the trust score
        """
        # Base confidence interval width
        base_width = 0.1

        # Adjust based on sample size
        if metrics.total_executions < 10:
            width = base_width * 2
        elif metrics.total_executions < 50:
            width = base_width * 1.5
        else:
            width = base_width

        # Ensure bounds are within [0, 1]
        lower_bound = max(overall_score - width, 0.0)
        upper_bound = min(overall_score + width, 1.0)

        return (lower_bound, upper_bound)

    def _generate_trust_factors(self, component_scores: Dict[str, float], metrics: PluginMetrics) -> List[str]:
        """
        Generate list of factors affecting trust score
        """
        factors = []

        # Positive factors
        if component_scores.get('reliability', 0) > 0.8:
            factors.append(f"High reliability ({metrics.successful_executions}/{metrics.total_executions} success rate)")

        if component_scores.get('performance', 0) > 0.8:
            factors.append(f"Excellent performance ({metrics.average_execution_time:.2f}s avg execution time)")

        if component_scores.get('accuracy', 0) > 0.8:
            factors.append(f"High accuracy (FP: {metrics.false_positive_rate:.1%}, FN: {metrics.false_negative_rate:.1%})")

        if component_scores.get('reputation', 0) > 0.8:
            factors.append(f"Strong reputation (user score: {metrics.user_feedback_score:.2f})")

        # Negative factors
        if component_scores.get('reliability', 0) < 0.5:
            factors.append(f"Reliability concerns ({metrics.failed_executions} failures)")

        if component_scores.get('performance', 0) < 0.5:
            factors.append(f"Performance issues (slow execution: {metrics.average_execution_time:.2f}s)")

        if component_scores.get('accuracy', 0) < 0.5:
            factors.append("Accuracy concerns (high false positive/negative rates)")

        if component_scores.get('security', 0) < 0.5:
            factors.append("Security concerns identified")

        return factors

    def _generate_recommendations(self, component_scores: Dict[str, float], trust_level: TrustLevel) -> List[str]:
        """
        Generate recommendations based on trust score
        """
        recommendations = []

        if trust_level in [TrustLevel.VERY_LOW, TrustLevel.LOW]:
            recommendations.append("Consider disabling this plugin until issues are resolved")
            recommendations.append("Manual review of plugin results recommended")

        if component_scores.get('reliability', 0) < 0.6:
            recommendations.append("Monitor plugin execution for failures")

        if component_scores.get('performance', 0) < 0.6:
            recommendations.append("Consider timeout limits for this plugin")

        if component_scores.get('accuracy', 0) < 0.6:
            recommendations.append("Apply additional validation to plugin results")

        if component_scores.get('security', 0) < 0.6:
            recommendations.append("Run plugin in sandboxed environment")

        if component_scores.get('maintenance', 0) < 0.5:
            recommendations.append("Check for plugin updates or alternatives")

        if trust_level == TrustLevel.VERY_HIGH:
            recommendations.append("Plugin can be trusted for automated processing")

        return recommendations

    def _initialize_plugin_metrics(self, plugin_name: str) -> PluginMetrics:
        """
        Initialize metrics for a new plugin
        """
        return PluginMetrics(
            plugin_name=plugin_name,
            total_executions=0,
            successful_executions=0,
            failed_executions=0,
            average_execution_time=0.0,
            false_positive_rate=0.0,
            false_negative_rate=0.0,
            user_feedback_score=0.5,
            last_updated=datetime.now(),
            version="unknown",
            author_verified=False
        )

    def _create_default_trust_score(self, plugin_name: str) -> TrustScore:
        """
        Create default trust score for error cases
        """
        return TrustScore(
            plugin_name=plugin_name,
            overall_score=0.3,
            trust_level=TrustLevel.LOW,
            risk_category=PluginRiskCategory.MEDIUM_RISK,
            component_scores={},
            confidence_interval=(0.1, 0.5),
            last_calculated=datetime.now(),
            factors=["Insufficient data for accurate scoring"],
            recommendations=["Manual review recommended", "Monitor plugin behavior"]
        )

    def _update_accuracy_metrics(self, metrics: PluginMetrics, feedback: Dict[str, Any]):
        """
        Update accuracy metrics based on user feedback
        """
        feedback_type = feedback.get('type', '')

        if feedback_type == 'false_positive':
            # Update false positive rate
            total_positives = metrics.total_executions
            if total_positives > 0:
                current_fps = metrics.false_positive_rate * total_positives
                metrics.false_positive_rate = (current_fps + 1) / (total_positives + 1)

        elif feedback_type == 'false_negative':
            # Update false negative rate
            total_executions = metrics.total_executions
            if total_executions > 0:
                current_fns = metrics.false_negative_rate * total_executions
                metrics.false_negative_rate = (current_fns + 1) / (total_executions + 1)

    def _update_user_feedback_score(self, plugin_name: str):
        """
        Update user feedback score based on feedback history
        """
        if plugin_name not in self.feedback_history:
            return

        feedback_list = self.feedback_history[plugin_name]
        if not feedback_list:
            return

        # Calculate average rating from recent feedback
        recent_feedback = [
            f for f in feedback_list
            if datetime.fromisoformat(f['timestamp']) > datetime.now() - timedelta(days=90)
        ]

        if recent_feedback:
            ratings = [f.get('rating', 3) for f in recent_feedback]  # Default rating: 3/5
            avg_rating = sum(ratings) / len(ratings)
            normalized_score = (avg_rating - 1) / 4  # Convert 1-5 scale to 0-1

            self.plugin_metrics[plugin_name].user_feedback_score = normalized_score

    def _is_semantic_version(self, version: str) -> bool:
        """
        Check if version follows semantic versioning
        """
        import re
        semver_pattern = r'^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$'
        return bool(re.match(semver_pattern, version))

    def _load_plugin_metrics(self):
        """
        Load plugin metrics from storage
        """
        try:
            metrics_file = Path("data/plugin_metrics.json")
            if metrics_file.exists():
                with open(metrics_file, 'r') as f:
                    data = json.load(f)

                for plugin_name, metrics_data in data.items():
                    # Convert datetime strings back to datetime objects
                    if 'last_updated' in metrics_data:
                        metrics_data['last_updated'] = datetime.fromisoformat(metrics_data['last_updated'])

                    self.plugin_metrics[plugin_name] = PluginMetrics(**metrics_data)

        except Exception as e:
            logger.error(f"Failed to load plugin metrics: {e}")

    def _save_plugin_metrics(self):
        """
        Save plugin metrics to storage
        """
        try:
            metrics_file = Path("data/plugin_metrics.json")
            metrics_file.parent.mkdir(exist_ok=True)

            # Convert to serializable format
            data = {}
            for plugin_name, metrics in self.plugin_metrics.items():
                metrics_dict = asdict(metrics)
                # Convert datetime to string
                if 'last_updated' in metrics_dict:
                    metrics_dict['last_updated'] = metrics_dict['last_updated'].isoformat()
                data[plugin_name] = metrics_dict

            with open(metrics_file, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            logger.error(f"Failed to save plugin metrics: {e}")

    def get_trust_statistics(self) -> Dict[str, Any]:
        """
        Get trust scoring statistics
        """
        if not self.trust_scores:
            return {'total_plugins': 0}

        trust_levels = [score.trust_level for score in self.trust_scores.values()]
        risk_categories = [score.risk_category for score in self.trust_scores.values()]
        overall_scores = [score.overall_score for score in self.trust_scores.values()]

        return {
            'total_plugins': len(self.trust_scores),
            'average_trust_score': sum(overall_scores) / len(overall_scores),
            'trust_level_distribution': {
                level.value: sum(1 for tl in trust_levels if tl == level)
                for level in TrustLevel
            },
            'risk_category_distribution': {
                category.value: sum(1 for rc in risk_categories if rc == category)
                for category in PluginRiskCategory
            },
            'high_trust_plugins': len([s for s in self.trust_scores.values() if s.trust_level in [TrustLevel.HIGH, TrustLevel.VERY_HIGH]]),
            'risky_plugins': len([s for s in self.trust_scores.values() if s.risk_category in [PluginRiskCategory.HIGH_RISK, PluginRiskCategory.CRITICAL_RISK]])
        }

# Global plugin trust scorer instance
plugin_trust_scorer = PluginTrustScorer()
