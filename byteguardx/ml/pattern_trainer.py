"""
Custom Pattern Training System
Allows users to train custom security patterns and rules
"""

import json
import logging
import re
import ast
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter
import hashlib
from enum import Enum

logger = logging.getLogger(__name__)

class PatternType(Enum):
    """Types of security patterns"""
    REGEX = "regex"
    AST = "ast"
    SEMANTIC = "semantic"
    BEHAVIORAL = "behavioral"

class PatternCategory(Enum):
    """Categories of security patterns"""
    SECRET = "secret"
    VULNERABILITY = "vulnerability"
    CODE_SMELL = "code_smell"
    COMPLIANCE = "compliance"
    CUSTOM = "custom"

@dataclass
class TrainingExample:
    """Training example for pattern learning"""
    code_snippet: str
    is_positive: bool  # True if this is a positive example (contains the pattern)
    language: str
    file_path: str = ""
    line_number: int = 0
    context: str = ""
    metadata: Dict[str, Any] = None

@dataclass
class CustomPattern:
    """Custom security pattern definition"""
    pattern_id: str
    name: str
    description: str
    pattern_type: PatternType
    category: PatternCategory
    language: str
    severity: str
    confidence: float
    pattern_definition: Dict[str, Any]
    training_examples: List[TrainingExample]
    validation_score: float = 0.0
    usage_count: int = 0
    created_by: str = ""
    created_at: str = ""
    last_updated: str = ""

class PatternTrainer:
    """
    System for training custom security patterns
    """
    
    def __init__(self, data_dir: str = "data/patterns"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.patterns_file = self.data_dir / "custom_patterns.json"
        self.training_file = self.data_dir / "training_data.json"
        self.validation_file = self.data_dir / "validation_results.json"
        
        # Pattern storage
        self.custom_patterns: Dict[str, CustomPattern] = {}
        self.training_data: Dict[str, List[TrainingExample]] = defaultdict(list)
        self.validation_results: Dict[str, Dict] = {}
        
        # Load existing data
        self._load_data()
        
        # Built-in pattern templates
        self.pattern_templates = {
            PatternType.REGEX: {
                'secret_detection': {
                    'description': 'Detect hardcoded secrets using regex patterns',
                    'template': r'(password|secret|key|token)\s*[:=]\s*["\'][^"\']{8,}["\']',
                    'flags': ['IGNORECASE']
                },
                'sql_injection': {
                    'description': 'Detect potential SQL injection patterns',
                    'template': r'(SELECT|INSERT|UPDATE|DELETE)\s+.*\+.*',
                    'flags': ['IGNORECASE']
                }
            },
            PatternType.AST: {
                'unsafe_eval': {
                    'description': 'Detect unsafe eval() usage',
                    'template': {
                        'node_type': 'Call',
                        'func_name': 'eval',
                        'check_args': True
                    }
                }
            }
        }
    
    def create_pattern(self, name: str, description: str, pattern_type: PatternType,
                      category: PatternCategory, language: str, severity: str,
                      pattern_definition: Dict[str, Any], created_by: str = "") -> str:
        """Create a new custom pattern"""
        try:
            pattern_id = self._generate_pattern_id(name, pattern_type, language)
            
            pattern = CustomPattern(
                pattern_id=pattern_id,
                name=name,
                description=description,
                pattern_type=pattern_type,
                category=category,
                language=language,
                severity=severity,
                confidence=0.5,  # Initial confidence
                pattern_definition=pattern_definition,
                training_examples=[],
                created_by=created_by,
                created_at=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            )
            
            self.custom_patterns[pattern_id] = pattern
            self._save_data()
            
            logger.info(f"Created custom pattern: {pattern_id}")
            return pattern_id
            
        except Exception as e:
            logger.error(f"Failed to create pattern: {e}")
            raise
    
    def add_training_example(self, pattern_id: str, example: TrainingExample) -> bool:
        """Add training example to a pattern"""
        try:
            if pattern_id not in self.custom_patterns:
                raise ValueError(f"Pattern {pattern_id} not found")
            
            pattern = self.custom_patterns[pattern_id]
            pattern.training_examples.append(example)
            pattern.last_updated = datetime.now().isoformat()
            
            # Store in training data
            self.training_data[pattern_id].append(example)
            
            # Retrain pattern if enough examples
            if len(pattern.training_examples) >= 10:
                self._retrain_pattern(pattern_id)
            
            self._save_data()
            return True
            
        except Exception as e:
            logger.error(f"Failed to add training example: {e}")
            return False
    
    def train_pattern_from_examples(self, pattern_id: str, 
                                  positive_examples: List[str],
                                  negative_examples: List[str],
                                  language: str = "python") -> bool:
        """Train pattern from positive and negative examples"""
        try:
            if pattern_id not in self.custom_patterns:
                raise ValueError(f"Pattern {pattern_id} not found")
            
            pattern = self.custom_patterns[pattern_id]
            
            # Add positive examples
            for code in positive_examples:
                example = TrainingExample(
                    code_snippet=code,
                    is_positive=True,
                    language=language
                )
                pattern.training_examples.append(example)
            
            # Add negative examples
            for code in negative_examples:
                example = TrainingExample(
                    code_snippet=code,
                    is_positive=False,
                    language=language
                )
                pattern.training_examples.append(example)
            
            # Train the pattern
            success = self._retrain_pattern(pattern_id)
            
            if success:
                pattern.last_updated = datetime.now().isoformat()
                self._save_data()
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to train pattern: {e}")
            return False
    
    def validate_pattern(self, pattern_id: str, test_examples: List[TrainingExample]) -> Dict[str, Any]:
        """Validate pattern against test examples"""
        try:
            if pattern_id not in self.custom_patterns:
                raise ValueError(f"Pattern {pattern_id} not found")
            
            pattern = self.custom_patterns[pattern_id]
            
            true_positives = 0
            false_positives = 0
            true_negatives = 0
            false_negatives = 0
            
            for example in test_examples:
                matches = self._apply_pattern(pattern, example.code_snippet)
                predicted_positive = len(matches) > 0
                
                if example.is_positive and predicted_positive:
                    true_positives += 1
                elif example.is_positive and not predicted_positive:
                    false_negatives += 1
                elif not example.is_positive and predicted_positive:
                    false_positives += 1
                else:
                    true_negatives += 1
            
            # Calculate metrics
            precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
            recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            accuracy = (true_positives + true_negatives) / len(test_examples) if test_examples else 0
            
            validation_result = {
                'pattern_id': pattern_id,
                'test_examples': len(test_examples),
                'true_positives': true_positives,
                'false_positives': false_positives,
                'true_negatives': true_negatives,
                'false_negatives': false_negatives,
                'precision': precision,
                'recall': recall,
                'f1_score': f1_score,
                'accuracy': accuracy,
                'timestamp': datetime.now().isoformat()
            }
            
            # Update pattern confidence based on validation
            pattern.validation_score = f1_score
            pattern.confidence = min(0.95, max(0.1, f1_score))
            
            # Store validation results
            self.validation_results[pattern_id] = validation_result
            self._save_data()
            
            logger.info(f"Validated pattern {pattern_id}: F1={f1_score:.3f}, Accuracy={accuracy:.3f}")
            return validation_result
            
        except Exception as e:
            logger.error(f"Pattern validation failed: {e}")
            return {}
    
    def apply_custom_patterns(self, code: str, language: str, file_path: str = "") -> List[Dict[str, Any]]:
        """Apply all custom patterns to code"""
        findings = []
        
        try:
            # Filter patterns by language
            applicable_patterns = [
                pattern for pattern in self.custom_patterns.values()
                if pattern.language == language or pattern.language == "all"
            ]
            
            for pattern in applicable_patterns:
                matches = self._apply_pattern(pattern, code)
                
                for match in matches:
                    finding = {
                        'type': 'custom_pattern',
                        'subtype': pattern.category.value,
                        'pattern_id': pattern.pattern_id,
                        'pattern_name': pattern.name,
                        'severity': pattern.severity,
                        'confidence': pattern.confidence,
                        'description': pattern.description,
                        'file_path': file_path,
                        'line_number': match.get('line_number', 0),
                        'context': match.get('context', ''),
                        'match_text': match.get('match_text', ''),
                        'recommendation': f"Review code for {pattern.name.lower()}"
                    }
                    findings.append(finding)
                
                # Update usage count
                if matches:
                    pattern.usage_count += len(matches)
            
            return findings
            
        except Exception as e:
            logger.error(f"Failed to apply custom patterns: {e}")
            return []
    
    def _apply_pattern(self, pattern: CustomPattern, code: str) -> List[Dict[str, Any]]:
        """Apply a single pattern to code"""
        matches = []
        
        try:
            if pattern.pattern_type == PatternType.REGEX:
                matches = self._apply_regex_pattern(pattern, code)
            elif pattern.pattern_type == PatternType.AST:
                matches = self._apply_ast_pattern(pattern, code)
            elif pattern.pattern_type == PatternType.SEMANTIC:
                matches = self._apply_semantic_pattern(pattern, code)
            elif pattern.pattern_type == PatternType.BEHAVIORAL:
                matches = self._apply_behavioral_pattern(pattern, code)
            
        except Exception as e:
            logger.warning(f"Pattern application failed for {pattern.pattern_id}: {e}")
        
        return matches
    
    def _apply_regex_pattern(self, pattern: CustomPattern, code: str) -> List[Dict[str, Any]]:
        """Apply regex pattern to code"""
        matches = []
        pattern_def = pattern.pattern_definition
        
        regex_pattern = pattern_def.get('pattern', '')
        flags = pattern_def.get('flags', [])
        
        # Convert flags
        regex_flags = 0
        if 'IGNORECASE' in flags:
            regex_flags |= re.IGNORECASE
        if 'MULTILINE' in flags:
            regex_flags |= re.MULTILINE
        if 'DOTALL' in flags:
            regex_flags |= re.DOTALL
        
        try:
            compiled_pattern = re.compile(regex_pattern, regex_flags)
            
            for match in compiled_pattern.finditer(code):
                # Find line number
                line_number = code[:match.start()].count('\n') + 1
                
                # Extract context (line containing the match)
                lines = code.split('\n')
                context = lines[line_number - 1] if line_number <= len(lines) else ""
                
                matches.append({
                    'line_number': line_number,
                    'context': context.strip(),
                    'match_text': match.group(0),
                    'start': match.start(),
                    'end': match.end()
                })
                
        except re.error as e:
            logger.warning(f"Invalid regex pattern: {e}")
        
        return matches
    
    def _apply_ast_pattern(self, pattern: CustomPattern, code: str) -> List[Dict[str, Any]]:
        """Apply AST-based pattern to code"""
        matches = []
        pattern_def = pattern.pattern_definition
        
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                if self._matches_ast_pattern(node, pattern_def):
                    line_number = getattr(node, 'lineno', 0)
                    
                    # Extract context
                    lines = code.split('\n')
                    context = lines[line_number - 1] if line_number <= len(lines) else ""
                    
                    matches.append({
                        'line_number': line_number,
                        'context': context.strip(),
                        'match_text': context.strip(),
                        'node_type': type(node).__name__
                    })
                    
        except SyntaxError:
            # Code might not be valid Python
            pass
        except Exception as e:
            logger.warning(f"AST pattern matching failed: {e}")
        
        return matches
    
    def _matches_ast_pattern(self, node: ast.AST, pattern_def: Dict[str, Any]) -> bool:
        """Check if AST node matches pattern definition"""
        node_type = pattern_def.get('node_type')
        if node_type and type(node).__name__ != node_type:
            return False
        
        # Check function name for Call nodes
        if isinstance(node, ast.Call) and 'func_name' in pattern_def:
            func_name = pattern_def['func_name']
            if hasattr(node.func, 'id') and node.func.id == func_name:
                return True
            elif hasattr(node.func, 'attr') and node.func.attr == func_name:
                return True
        
        # Check attribute access
        if isinstance(node, ast.Attribute) and 'attr_name' in pattern_def:
            return node.attr == pattern_def['attr_name']
        
        # Check variable names
        if isinstance(node, ast.Name) and 'var_name' in pattern_def:
            return node.id == pattern_def['var_name']
        
        return False
    
    def _apply_semantic_pattern(self, pattern: CustomPattern, code: str) -> List[Dict[str, Any]]:
        """Apply semantic pattern (simplified implementation)"""
        # This would require more sophisticated NLP/semantic analysis
        # For now, implement as enhanced regex with context awareness
        return self._apply_regex_pattern(pattern, code)
    
    def _apply_behavioral_pattern(self, pattern: CustomPattern, code: str) -> List[Dict[str, Any]]:
        """Apply behavioral pattern (simplified implementation)"""
        # This would require dynamic analysis or execution tracing
        # For now, implement as pattern matching on common behavioral indicators
        return self._apply_regex_pattern(pattern, code)
    
    def _retrain_pattern(self, pattern_id: str) -> bool:
        """Retrain pattern based on training examples"""
        try:
            pattern = self.custom_patterns[pattern_id]
            
            if pattern.pattern_type == PatternType.REGEX:
                return self._retrain_regex_pattern(pattern)
            elif pattern.pattern_type == PatternType.AST:
                return self._retrain_ast_pattern(pattern)
            
            return True
            
        except Exception as e:
            logger.error(f"Pattern retraining failed: {e}")
            return False
    
    def _retrain_regex_pattern(self, pattern: CustomPattern) -> bool:
        """Retrain regex pattern from examples"""
        try:
            positive_examples = [ex.code_snippet for ex in pattern.training_examples if ex.is_positive]
            negative_examples = [ex.code_snippet for ex in pattern.training_examples if not ex.is_positive]
            
            if len(positive_examples) < 3:
                logger.warning(f"Not enough positive examples for pattern {pattern.pattern_id}")
                return False
            
            # Extract common patterns from positive examples
            # This is a simplified approach - in production would use more sophisticated methods
            common_tokens = self._extract_common_tokens(positive_examples)
            
            if common_tokens:
                # Generate new regex pattern
                escaped_tokens = [re.escape(token) for token in common_tokens[:3]]
                new_pattern = '|'.join(escaped_tokens)
                
                pattern.pattern_definition['pattern'] = new_pattern
                pattern.confidence = min(0.9, pattern.confidence + 0.1)
                
                logger.info(f"Retrained regex pattern {pattern.pattern_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Regex pattern retraining failed: {e}")
            return False
    
    def _retrain_ast_pattern(self, pattern: CustomPattern) -> bool:
        """Retrain AST pattern from examples"""
        # Simplified AST pattern retraining
        # In production would analyze AST structures of positive examples
        return True
    
    def _extract_common_tokens(self, examples: List[str]) -> List[str]:
        """Extract common tokens from code examples"""
        all_tokens = []
        
        for example in examples:
            # Simple tokenization
            tokens = re.findall(r'\b\w+\b', example.lower())
            all_tokens.extend(tokens)
        
        # Find most common tokens
        token_counts = Counter(all_tokens)
        common_tokens = [token for token, count in token_counts.most_common(10) if count > 1]
        
        return common_tokens
    
    def get_pattern_stats(self) -> Dict[str, Any]:
        """Get statistics about custom patterns"""
        try:
            total_patterns = len(self.custom_patterns)
            patterns_by_category = Counter(p.category.value for p in self.custom_patterns.values())
            patterns_by_language = Counter(p.language for p in self.custom_patterns.values())
            
            avg_confidence = sum(p.confidence for p in self.custom_patterns.values()) / total_patterns if total_patterns > 0 else 0
            total_usage = sum(p.usage_count for p in self.custom_patterns.values())
            
            return {
                'total_patterns': total_patterns,
                'patterns_by_category': dict(patterns_by_category),
                'patterns_by_language': dict(patterns_by_language),
                'average_confidence': round(avg_confidence, 3),
                'total_usage': total_usage,
                'validated_patterns': len([p for p in self.custom_patterns.values() if p.validation_score > 0])
            }
            
        except Exception as e:
            logger.error(f"Failed to get pattern stats: {e}")
            return {}
    
    def export_patterns(self, pattern_ids: List[str] = None) -> Dict[str, Any]:
        """Export patterns for sharing"""
        try:
            patterns_to_export = {}
            
            if pattern_ids:
                patterns_to_export = {
                    pid: self.custom_patterns[pid] 
                    for pid in pattern_ids 
                    if pid in self.custom_patterns
                }
            else:
                patterns_to_export = self.custom_patterns
            
            export_data = {
                'export_timestamp': datetime.now().isoformat(),
                'patterns': {
                    pid: asdict(pattern) 
                    for pid, pattern in patterns_to_export.items()
                },
                'validation_results': {
                    pid: self.validation_results.get(pid, {})
                    for pid in patterns_to_export.keys()
                }
            }
            
            return export_data
            
        except Exception as e:
            logger.error(f"Pattern export failed: {e}")
            return {}
    
    def import_patterns(self, import_data: Dict[str, Any]) -> bool:
        """Import patterns from export data"""
        try:
            imported_patterns = import_data.get('patterns', {})
            imported_validations = import_data.get('validation_results', {})
            
            for pattern_id, pattern_data in imported_patterns.items():
                # Convert back to CustomPattern object
                pattern = CustomPattern(**pattern_data)
                
                # Generate new ID if pattern already exists
                if pattern_id in self.custom_patterns:
                    pattern.pattern_id = self._generate_pattern_id(
                        pattern.name + "_imported", 
                        pattern.pattern_type, 
                        pattern.language
                    )
                
                self.custom_patterns[pattern.pattern_id] = pattern
                
                # Import validation results
                if pattern_id in imported_validations:
                    self.validation_results[pattern.pattern_id] = imported_validations[pattern_id]
            
            self._save_data()
            logger.info(f"Imported {len(imported_patterns)} patterns")
            return True
            
        except Exception as e:
            logger.error(f"Pattern import failed: {e}")
            return False
    
    def _generate_pattern_id(self, name: str, pattern_type: PatternType, language: str) -> str:
        """Generate unique pattern ID"""
        base_string = f"{name}_{pattern_type.value}_{language}_{datetime.now().isoformat()}"
        pattern_hash = hashlib.md5(base_string.encode()).hexdigest()[:8]
        return f"custom_{pattern_hash}"
    
    def _load_data(self):
        """Load pattern data from files"""
        try:
            # Load custom patterns
            if self.patterns_file.exists():
                with open(self.patterns_file, 'r') as f:
                    patterns_data = json.load(f)
                    for pattern_id, pattern_dict in patterns_data.items():
                        # Convert enum strings back to enums
                        pattern_dict['pattern_type'] = PatternType(pattern_dict['pattern_type'])
                        pattern_dict['category'] = PatternCategory(pattern_dict['category'])
                        
                        # Convert training examples
                        training_examples = []
                        for ex_data in pattern_dict.get('training_examples', []):
                            training_examples.append(TrainingExample(**ex_data))
                        pattern_dict['training_examples'] = training_examples
                        
                        self.custom_patterns[pattern_id] = CustomPattern(**pattern_dict)
            
            # Load validation results
            if self.validation_file.exists():
                with open(self.validation_file, 'r') as f:
                    self.validation_results = json.load(f)
            
            logger.info(f"Loaded {len(self.custom_patterns)} custom patterns")
            
        except Exception as e:
            logger.error(f"Failed to load pattern data: {e}")
    
    def _save_data(self):
        """Save pattern data to files"""
        try:
            # Save custom patterns
            patterns_data = {}
            for pattern_id, pattern in self.custom_patterns.items():
                pattern_dict = asdict(pattern)
                # Convert enums to strings for JSON serialization
                pattern_dict['pattern_type'] = pattern.pattern_type.value
                pattern_dict['category'] = pattern.category.value
                patterns_data[pattern_id] = pattern_dict
            
            with open(self.patterns_file, 'w') as f:
                json.dump(patterns_data, f, indent=2)
            
            # Save validation results
            with open(self.validation_file, 'w') as f:
                json.dump(self.validation_results, f, indent=2)
            
            logger.info("Pattern data saved successfully")
            
        except Exception as e:
            logger.error(f"Failed to save pattern data: {e}")
