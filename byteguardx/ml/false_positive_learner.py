"""
False Positive Learning System
Learns from user feedback to reduce false positives over time
"""

import json
import logging
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import hashlib
import re
from enum import Enum

logger = logging.getLogger(__name__)

class FeedbackType(Enum):
    """Types of user feedback"""
    FALSE_POSITIVE = "false_positive"
    TRUE_POSITIVE = "true_positive"
    SEVERITY_ADJUSTMENT = "severity_adjustment"
    CONTEXT_CLARIFICATION = "context_clarification"

@dataclass
class UserFeedback:
    """User feedback on a finding"""
    finding_id: str
    feedback_type: FeedbackType
    original_severity: str
    user_severity: Optional[str] = None
    reason: str = ""
    context: str = ""
    user_id: str = ""
    timestamp: str = ""
    confidence: float = 1.0

@dataclass
class LearningPattern:
    """Learned pattern from user feedback"""
    pattern_id: str
    pattern_type: str
    code_pattern: str
    context_patterns: List[str]
    false_positive_indicators: List[str]
    confidence_adjustment: float
    severity_adjustment: str
    usage_count: int = 0
    accuracy_score: float = 0.0
    last_updated: str = ""

class FalsePositiveLearner:
    """
    Machine learning system to reduce false positives
    """
    
    def __init__(self, data_dir: str = "data/ml"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.feedback_file = self.data_dir / "user_feedback.json"
        self.patterns_file = self.data_dir / "learned_patterns.json"
        self.stats_file = self.data_dir / "learning_stats.json"
        
        # Learning data
        self.feedback_history: List[UserFeedback] = []
        self.learned_patterns: Dict[str, LearningPattern] = {}
        self.pattern_effectiveness: Dict[str, float] = {}
        
        # Load existing data
        self._load_data()
        
        # False positive indicators
        self.fp_indicators = {
            'test_files': [r'test_.*\.py$', r'.*_test\.py$', r'.*\.test\.js$'],
            'example_code': [r'example', r'demo', r'sample', r'tutorial'],
            'comments': [r'#.*example', r'//.*demo', r'/\*.*sample.*\*/'],
            'placeholder_values': [r'placeholder', r'dummy', r'fake', r'mock'],
            'documentation': [r'README', r'docs/', r'\.md$', r'\.rst$']
        }

        # Rate limiting for feedback
        self.user_feedback_count = defaultdict(list)
        self.max_feedback_per_hour = 50
        self.max_feedback_per_day = 200
    
    def process_feedback(self, finding: Dict[str, Any], feedback: UserFeedback) -> bool:
        """Process user feedback and learn from it"""
        try:
            # Validate feedback before processing
            if not self._validate_feedback(finding, feedback):
                logger.warning(f"Invalid feedback rejected for finding {feedback.finding_id}")
                return False

            # Check rate limiting
            if not self._check_rate_limit(feedback.user_id):
                logger.warning(f"Rate limit exceeded for user {feedback.user_id}")
                return False

            # Store feedback
            feedback.timestamp = datetime.now().isoformat()
            self.feedback_history.append(feedback)
            
            # Learn patterns based on feedback type
            if feedback.feedback_type == FeedbackType.FALSE_POSITIVE:
                self._learn_false_positive_pattern(finding, feedback)
            elif feedback.feedback_type == FeedbackType.SEVERITY_ADJUSTMENT:
                self._learn_severity_adjustment(finding, feedback)
            elif feedback.feedback_type == FeedbackType.CONTEXT_CLARIFICATION:
                self._learn_context_pattern(finding, feedback)
            
            # Update pattern effectiveness
            self._update_pattern_effectiveness()
            
            # Save data
            self._save_data()
            
            logger.info(f"Processed feedback for finding {feedback.finding_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to process feedback: {e}")
            return False
    
    def adjust_finding_confidence(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Adjust finding confidence based on learned patterns"""
        try:
            original_confidence = finding.get('confidence', 1.0)
            adjusted_confidence = original_confidence
            adjustments = []
            
            # Check against learned false positive patterns
            for pattern_id, pattern in self.learned_patterns.items():
                if self._matches_pattern(finding, pattern):
                    adjustment = pattern.confidence_adjustment
                    adjusted_confidence *= (1 + adjustment)
                    adjustments.append({
                        'pattern_id': pattern_id,
                        'adjustment': adjustment,
                        'reason': f"Learned pattern: {pattern.pattern_type}"
                    })
            
            # Check built-in false positive indicators
            fp_score = self._calculate_fp_score(finding)
            if fp_score > 0.3:
                fp_adjustment = -0.2 * fp_score
                adjusted_confidence *= (1 + fp_adjustment)
                adjustments.append({
                    'pattern_id': 'builtin_fp_indicators',
                    'adjustment': fp_adjustment,
                    'reason': f"False positive indicators detected (score: {fp_score:.2f})"
                })
            
            # Ensure confidence stays within bounds
            adjusted_confidence = max(0.0, min(1.0, adjusted_confidence))
            
            # Update finding
            finding['confidence'] = adjusted_confidence
            finding['confidence_adjustments'] = adjustments
            finding['original_confidence'] = original_confidence
            
            return finding
            
        except Exception as e:
            logger.error(f"Failed to adjust finding confidence: {e}")
            return finding
    
    def suggest_severity_adjustment(self, finding: Dict[str, Any]) -> Optional[str]:
        """Suggest severity adjustment based on learned patterns"""
        try:
            current_severity = finding.get('severity', 'medium')
            
            # Check learned severity adjustment patterns
            for pattern in self.learned_patterns.values():
                if (pattern.pattern_type == 'severity_adjustment' and 
                    self._matches_pattern(finding, pattern)):
                    
                    if pattern.accuracy_score > 0.7:  # High confidence pattern
                        return pattern.severity_adjustment
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to suggest severity adjustment: {e}")
            return None
    
    def _learn_false_positive_pattern(self, finding: Dict[str, Any], feedback: UserFeedback):
        """Learn patterns that indicate false positives"""
        try:
            # Extract pattern from the finding
            code_pattern = self._extract_code_pattern(finding)
            context_patterns = self._extract_context_patterns(finding)
            fp_indicators = self._extract_fp_indicators(finding)
            
            # Create or update pattern
            pattern_id = self._generate_pattern_id(code_pattern, "false_positive")
            
            if pattern_id in self.learned_patterns:
                # Update existing pattern
                pattern = self.learned_patterns[pattern_id]
                pattern.usage_count += 1
                pattern.last_updated = datetime.now().isoformat()
                
                # Merge context patterns
                for ctx in context_patterns:
                    if ctx not in pattern.context_patterns:
                        pattern.context_patterns.append(ctx)
                
                # Merge FP indicators
                for indicator in fp_indicators:
                    if indicator not in pattern.false_positive_indicators:
                        pattern.false_positive_indicators.append(indicator)
            else:
                # Create new pattern
                pattern = LearningPattern(
                    pattern_id=pattern_id,
                    pattern_type="false_positive",
                    code_pattern=code_pattern,
                    context_patterns=context_patterns,
                    false_positive_indicators=fp_indicators,
                    confidence_adjustment=-0.3,  # Reduce confidence for similar findings
                    severity_adjustment="",
                    usage_count=1,
                    accuracy_score=0.5,  # Start with neutral score
                    last_updated=datetime.now().isoformat()
                )
                
                self.learned_patterns[pattern_id] = pattern
            
            logger.info(f"Learned false positive pattern: {pattern_id}")
            
        except Exception as e:
            logger.error(f"Failed to learn false positive pattern: {e}")
    
    def _learn_severity_adjustment(self, finding: Dict[str, Any], feedback: UserFeedback):
        """Learn patterns for severity adjustments"""
        try:
            if not feedback.user_severity:
                return
            
            code_pattern = self._extract_code_pattern(finding)
            context_patterns = self._extract_context_patterns(finding)
            
            pattern_id = self._generate_pattern_id(code_pattern, "severity_adjustment")
            
            if pattern_id in self.learned_patterns:
                pattern = self.learned_patterns[pattern_id]
                pattern.usage_count += 1
                pattern.last_updated = datetime.now().isoformat()
            else:
                pattern = LearningPattern(
                    pattern_id=pattern_id,
                    pattern_type="severity_adjustment",
                    code_pattern=code_pattern,
                    context_patterns=context_patterns,
                    false_positive_indicators=[],
                    confidence_adjustment=0.0,
                    severity_adjustment=feedback.user_severity,
                    usage_count=1,
                    accuracy_score=0.5,
                    last_updated=datetime.now().isoformat()
                )
                
                self.learned_patterns[pattern_id] = pattern
            
            logger.info(f"Learned severity adjustment pattern: {pattern_id}")
            
        except Exception as e:
            logger.error(f"Failed to learn severity adjustment: {e}")
    
    def _learn_context_pattern(self, finding: Dict[str, Any], feedback: UserFeedback):
        """Learn context-specific patterns"""
        try:
            code_pattern = self._extract_code_pattern(finding)
            context_patterns = self._extract_context_patterns(finding)
            
            # Add user-provided context
            if feedback.context:
                context_patterns.append(feedback.context)
            
            pattern_id = self._generate_pattern_id(code_pattern, "context")
            
            if pattern_id in self.learned_patterns:
                pattern = self.learned_patterns[pattern_id]
                pattern.usage_count += 1
                pattern.context_patterns.extend(context_patterns)
                pattern.last_updated = datetime.now().isoformat()
            else:
                pattern = LearningPattern(
                    pattern_id=pattern_id,
                    pattern_type="context",
                    code_pattern=code_pattern,
                    context_patterns=context_patterns,
                    false_positive_indicators=[],
                    confidence_adjustment=0.1,  # Slight confidence boost for context clarity
                    severity_adjustment="",
                    usage_count=1,
                    accuracy_score=0.5,
                    last_updated=datetime.now().isoformat()
                )
                
                self.learned_patterns[pattern_id] = pattern
            
            logger.info(f"Learned context pattern: {pattern_id}")
            
        except Exception as e:
            logger.error(f"Failed to learn context pattern: {e}")
    
    def _extract_code_pattern(self, finding: Dict[str, Any]) -> str:
        """Extract code pattern from finding"""
        # Normalize the code context for pattern matching
        context = finding.get('context', '')
        
        # Remove variable names and values to create a pattern
        pattern = re.sub(r'\b\w+\s*=\s*["\'][^"\']*["\']', 'VAR="VALUE"', context)
        pattern = re.sub(r'\b\w+\s*=\s*\d+', 'VAR=NUM', pattern)
        pattern = re.sub(r'\b[a-zA-Z_]\w*', 'IDENTIFIER', pattern)
        
        return pattern.strip()
    
    def _extract_context_patterns(self, finding: Dict[str, Any]) -> List[str]:
        """Extract context patterns from finding"""
        patterns = []
        
        file_path = finding.get('file_path', '')
        
        # File type patterns
        if file_path.endswith('.test.py') or 'test' in file_path:
            patterns.append('test_file')
        
        if any(keyword in file_path.lower() for keyword in ['example', 'demo', 'sample']):
            patterns.append('example_code')
        
        if any(keyword in file_path.lower() for keyword in ['doc', 'readme']):
            patterns.append('documentation')
        
        # Code context patterns
        context = finding.get('context', '').lower()
        
        if any(keyword in context for keyword in ['test', 'mock', 'fake']):
            patterns.append('test_context')
        
        if any(keyword in context for keyword in ['example', 'demo', 'sample']):
            patterns.append('example_context')
        
        return patterns
    
    def _extract_fp_indicators(self, finding: Dict[str, Any]) -> List[str]:
        """Extract false positive indicators"""
        indicators = []
        
        file_path = finding.get('file_path', '')
        context = finding.get('context', '')
        description = finding.get('description', '')
        
        # Check file path indicators
        for category, patterns in self.fp_indicators.items():
            for pattern in patterns:
                if re.search(pattern, file_path, re.IGNORECASE):
                    indicators.append(f"file_{category}")
        
        # Check context indicators
        if any(keyword in context.lower() for keyword in ['placeholder', 'dummy', 'fake', 'mock', 'test']):
            indicators.append('placeholder_content')
        
        if re.search(r'#.*example|//.*demo|/\*.*sample.*\*/', context):
            indicators.append('comment_example')
        
        return indicators
    
    def _matches_pattern(self, finding: Dict[str, Any], pattern: LearningPattern) -> bool:
        """Check if finding matches a learned pattern"""
        try:
            # Check code pattern match
            finding_pattern = self._extract_code_pattern(finding)
            if pattern.code_pattern not in finding_pattern and finding_pattern not in pattern.code_pattern:
                return False
            
            # Check context patterns
            finding_contexts = self._extract_context_patterns(finding)
            context_match = any(ctx in pattern.context_patterns for ctx in finding_contexts)
            
            # Check false positive indicators
            finding_indicators = self._extract_fp_indicators(finding)
            fp_match = any(indicator in pattern.false_positive_indicators for indicator in finding_indicators)
            
            # Pattern matches if code pattern matches and either context or FP indicators match
            return context_match or fp_match or len(pattern.context_patterns) == 0
            
        except Exception as e:
            logger.error(f"Pattern matching failed: {e}")
            return False
    
    def _calculate_fp_score(self, finding: Dict[str, Any]) -> float:
        """Calculate false positive score based on built-in indicators"""
        score = 0.0
        
        file_path = finding.get('file_path', '')
        context = finding.get('context', '')
        
        # File-based indicators
        if any(pattern in file_path.lower() for pattern in ['test', 'example', 'demo', 'sample']):
            score += 0.3
        
        if any(pattern in file_path.lower() for pattern in ['doc', 'readme', '.md']):
            score += 0.2
        
        # Context-based indicators
        if any(keyword in context.lower() for keyword in ['placeholder', 'dummy', 'fake', 'mock']):
            score += 0.4
        
        if re.search(r'(example|demo|sample|test)', context, re.IGNORECASE):
            score += 0.2
        
        # Comment indicators
        if re.search(r'#.*example|//.*demo|/\*.*sample.*\*/', context):
            score += 0.3
        
        return min(score, 1.0)
    
    def _update_pattern_effectiveness(self):
        """Update effectiveness scores for learned patterns"""
        try:
            # Calculate accuracy for each pattern based on feedback
            pattern_feedback = defaultdict(list)
            
            for feedback in self.feedback_history:
                # Find patterns that would have matched this feedback
                for pattern_id, pattern in self.learned_patterns.items():
                    # This is simplified - in practice would need to track which patterns were applied
                    pattern_feedback[pattern_id].append(feedback.feedback_type == FeedbackType.TRUE_POSITIVE)
            
            # Update accuracy scores
            for pattern_id, feedback_list in pattern_feedback.items():
                if len(feedback_list) > 0:
                    accuracy = sum(feedback_list) / len(feedback_list)
                    self.learned_patterns[pattern_id].accuracy_score = accuracy
                    self.pattern_effectiveness[pattern_id] = accuracy
            
        except Exception as e:
            logger.error(f"Failed to update pattern effectiveness: {e}")
    
    def _generate_pattern_id(self, code_pattern: str, pattern_type: str) -> str:
        """Generate unique pattern ID"""
        pattern_hash = hashlib.md5(f"{pattern_type}:{code_pattern}".encode()).hexdigest()[:8]
        return f"{pattern_type}_{pattern_hash}"
    
    def get_learning_stats(self) -> Dict[str, Any]:
        """Get learning system statistics"""
        try:
            total_feedback = len(self.feedback_history)
            feedback_by_type = Counter(f.feedback_type.value for f in self.feedback_history)
            
            # Calculate average pattern accuracy
            avg_accuracy = 0.0
            if self.learned_patterns:
                avg_accuracy = sum(p.accuracy_score for p in self.learned_patterns.values()) / len(self.learned_patterns)
            
            # Recent feedback (last 30 days)
            recent_cutoff = datetime.now() - timedelta(days=30)
            recent_feedback = [
                f for f in self.feedback_history 
                if datetime.fromisoformat(f.timestamp) > recent_cutoff
            ]
            
            return {
                'total_feedback': total_feedback,
                'feedback_by_type': dict(feedback_by_type),
                'learned_patterns': len(self.learned_patterns),
                'average_pattern_accuracy': round(avg_accuracy, 3),
                'recent_feedback_count': len(recent_feedback),
                'most_effective_patterns': [
                    {'pattern_id': pid, 'accuracy': acc}
                    for pid, acc in sorted(self.pattern_effectiveness.items(), 
                                         key=lambda x: x[1], reverse=True)[:5]
                ]
            }
            
        except Exception as e:
            logger.error(f"Failed to get learning stats: {e}")
            return {}
    
    def _load_data(self):
        """Load learning data from files"""
        try:
            # Load feedback history
            if self.feedback_file.exists():
                with open(self.feedback_file, 'r') as f:
                    feedback_data = json.load(f)
                    self.feedback_history = [
                        UserFeedback(**item) for item in feedback_data
                    ]
            
            # Load learned patterns
            if self.patterns_file.exists():
                with open(self.patterns_file, 'r') as f:
                    patterns_data = json.load(f)
                    self.learned_patterns = {
                        pid: LearningPattern(**pattern_data)
                        for pid, pattern_data in patterns_data.items()
                    }
            
            logger.info(f"Loaded {len(self.feedback_history)} feedback entries and {len(self.learned_patterns)} patterns")
            
        except Exception as e:
            logger.error(f"Failed to load learning data: {e}")
    
    def _save_data(self):
        """Save learning data to files"""
        try:
            # Save feedback history
            with open(self.feedback_file, 'w') as f:
                feedback_data = [asdict(feedback) for feedback in self.feedback_history]
                json.dump(feedback_data, f, indent=2)
            
            # Save learned patterns
            with open(self.patterns_file, 'w') as f:
                patterns_data = {
                    pid: asdict(pattern) 
                    for pid, pattern in self.learned_patterns.items()
                }
                json.dump(patterns_data, f, indent=2)
            
            # Save stats
            with open(self.stats_file, 'w') as f:
                stats = self.get_learning_stats()
                json.dump(stats, f, indent=2)
            
            logger.info("Learning data saved successfully")
            
        except Exception as e:
            logger.error(f"Failed to save learning data: {e}")

    def _validate_feedback(self, finding: Dict[str, Any], feedback: UserFeedback) -> bool:
        """Validate feedback to prevent model poisoning"""
        try:
            # Validate finding_id
            if not feedback.finding_id or len(feedback.finding_id) > 100:
                return False

            # Validate feedback type
            if feedback.feedback_type not in FeedbackType:
                return False

            # Validate user_id
            if not feedback.user_id or len(feedback.user_id) > 100:
                return False

            # Validate reason length
            if len(feedback.reason) > 1000:
                return False

            # Validate context length
            if len(feedback.context) > 5000:
                return False

            # Check for malicious patterns in text fields
            dangerous_patterns = [
                r'<script',
                r'javascript:',
                r'eval\(',
                r'exec\(',
                r'__import__',
                r'subprocess',
                r'os\.system',
                r'\.\./',
                r'\\\\',
                r'[<>"\']'
            ]

            text_fields = [feedback.reason, feedback.context]
            for field in text_fields:
                if field:
                    for pattern in dangerous_patterns:
                        if re.search(pattern, field, re.IGNORECASE):
                            logger.warning(f"Dangerous pattern detected in feedback: {pattern}")
                            return False

            # Validate confidence range
            if not (0.0 <= feedback.confidence <= 1.0):
                return False

            # Validate severity values
            valid_severities = ['low', 'medium', 'high', 'critical']
            if feedback.original_severity and feedback.original_severity not in valid_severities:
                return False
            if feedback.user_severity and feedback.user_severity not in valid_severities:
                return False

            return True

        except Exception as e:
            logger.error(f"Feedback validation error: {e}")
            return False

    def _check_rate_limit(self, user_id: str) -> bool:
        """Check if user has exceeded feedback rate limits"""
        try:
            now = datetime.now()
            hour_ago = now - timedelta(hours=1)
            day_ago = now - timedelta(days=1)

            # Clean old entries
            self.user_feedback_count[user_id] = [
                timestamp for timestamp in self.user_feedback_count[user_id]
                if timestamp > day_ago
            ]

            # Count recent feedback
            hour_count = sum(1 for timestamp in self.user_feedback_count[user_id] if timestamp > hour_ago)
            day_count = len(self.user_feedback_count[user_id])

            # Check limits
            if hour_count >= self.max_feedback_per_hour:
                return False
            if day_count >= self.max_feedback_per_day:
                return False

            # Add current timestamp
            self.user_feedback_count[user_id].append(now)

            return True

        except Exception as e:
            logger.error(f"Rate limit check error: {e}")
            return False
