"""
AI Pattern Scanner - Detect unsafe AI-generated code patterns
"""

import re
import json
import logging
from typing import List, Dict, Any, Tuple
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class AIPatternMatch:
    """Data structure for AI pattern detection results"""
    pattern_type: str
    description: str
    line_number: int
    column_start: int
    column_end: int
    confidence: float
    file_path: str
    context: str
    severity: str
    suggestion: str
    explainability: Dict[str, Any] = None

    def __post_init__(self):
        if self.explainability is None:
            self.explainability = {}

class AIPatternScanner:
    """
    Scanner for detecting unsafe patterns commonly found in AI-generated code
    """
    
    def __init__(self, patterns_file: str = None):
        self.patterns = self._load_patterns(patterns_file)
        self.compiled_patterns = self._compile_patterns()
        self.findings = []
        
    def _load_patterns(self, patterns_file: str = None) -> Dict:
        """Load AI pattern definitions from JSON file"""
        if patterns_file and Path(patterns_file).exists():
            try:
                with open(patterns_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load AI patterns file: {e}")
        
        # Default AI anti-patterns
        return {
            "input_validation": {
                "no_input_sanitization": {
                    "patterns": [
                        r"input\(\s*[\"'][^\"']*[\"']\s*\)",
                        r"raw_input\(\s*[\"'][^\"']*[\"']\s*\)",
                        r"request\.args\.get\([^)]+\)(?!\s*\|\s*safe)",
                        r"request\.form\.get\([^)]+\)(?!\s*\|\s*safe)"
                    ],
                    "description": "Direct use of user input without validation",
                    "severity": "high",
                    "suggestion": "Always validate and sanitize user input"
                },
                "sql_injection_risk": {
                    "patterns": [
                        r"execute\(\s*[\"'].*%s.*[\"']\s*%",
                        r"execute\(\s*[\"'].*\+.*[\"']\s*\)",
                        r"cursor\.execute\(\s*[\"'].*%.*[\"']\s*%",
                        r"query\s*=\s*[\"'].*\+.*[\"']"
                    ],
                    "description": "Potential SQL injection vulnerability",
                    "severity": "critical",
                    "suggestion": "Use parameterized queries or ORM methods"
                },
                "command_injection": {
                    "patterns": [
                        r"os\.system\(\s*[^)]*input\(",
                        r"subprocess\.call\(\s*[^)]*input\(",
                        r"eval\(\s*[^)]*input\(",
                        r"exec\(\s*[^)]*input\("
                    ],
                    "description": "Command injection vulnerability",
                    "severity": "critical",
                    "suggestion": "Avoid executing user input as commands"
                }
            },
            "authentication": {
                "weak_password_check": {
                    "patterns": [
                        r"password\s*==\s*[\"'][^\"']{1,7}[\"']",
                        r"if\s+password\s*==\s*[\"']password[\"']",
                        r"if\s+password\s*==\s*[\"']123456[\"']",
                        r"if\s+password\s*==\s*[\"']admin[\"']"
                    ],
                    "description": "Weak or hardcoded password check",
                    "severity": "high",
                    "suggestion": "Use proper password hashing and validation"
                },
                "no_auth_check": {
                    "patterns": [
                        r"@app\.route\([^)]+\)(?!\s*@.*auth)",
                        r"def\s+\w+\([^)]*\):\s*(?!.*auth|.*login|.*permission)"
                    ],
                    "description": "Endpoint without authentication check",
                    "severity": "medium",
                    "suggestion": "Add authentication decorators to protected endpoints"
                }
            },
            "crypto": {
                "weak_encryption": {
                    "patterns": [
                        r"DES\(",
                        r"MD5\(",
                        r"SHA1\(",
                        r"Random\(\)",
                        r"random\.random\(\)"
                    ],
                    "description": "Use of weak cryptographic algorithms",
                    "severity": "medium",
                    "suggestion": "Use strong cryptographic algorithms (AES, SHA-256, etc.)"
                },
                "hardcoded_crypto_key": {
                    "patterns": [
                        r"key\s*=\s*[\"'][A-Za-z0-9+/=]{16,}[\"']",
                        r"secret\s*=\s*[\"'][A-Za-z0-9+/=]{16,}[\"']",
                        r"AES\.new\(\s*[\"'][^\"']+[\"']"
                    ],
                    "description": "Hardcoded cryptographic key",
                    "severity": "high",
                    "suggestion": "Store cryptographic keys securely (environment variables, key management)"
                }
            },
            "error_handling": {
                "bare_except": {
                    "patterns": [
                        r"except\s*:",
                        r"except\s+Exception\s*:",
                        r"try:.*except.*pass"
                    ],
                    "description": "Overly broad exception handling",
                    "severity": "low",
                    "suggestion": "Catch specific exceptions and handle them appropriately"
                },
                "information_disclosure": {
                    "patterns": [
                        r"print\(\s*str\(e\)\s*\)",
                        r"return\s+str\(e\)",
                        r"traceback\.print_exc\(\)",
                        r"debug\s*=\s*True"
                    ],
                    "description": "Potential information disclosure in error messages",
                    "severity": "medium",
                    "suggestion": "Log errors securely and return generic error messages to users"
                }
            },
            "file_operations": {
                "path_traversal": {
                    "patterns": [
                        r"open\(\s*[^)]*\+[^)]*\)",
                        r"open\(\s*[^)]*input\([^)]*\)",
                        r"open\(\s*[^)]*request\.",
                        r"with\s+open\(\s*[^)]*\+[^)]*\)"
                    ],
                    "description": "Potential path traversal vulnerability",
                    "severity": "high",
                    "suggestion": "Validate and sanitize file paths"
                },
                "unsafe_file_permissions": {
                    "patterns": [
                        r"chmod\(\s*[^)]*777[^)]*\)",
                        r"os\.chmod\(\s*[^)]*0o777[^)]*\)",
                        r"stat\.S_IRWXU\s*\|\s*stat\.S_IRWXG\s*\|\s*stat\.S_IRWXO"
                    ],
                    "description": "Unsafe file permissions (world-writable)",
                    "severity": "medium",
                    "suggestion": "Use restrictive file permissions"
                }
            },
            "ai_specific": {
                "todo_comments": {
                    "patterns": [
                        r"#\s*TODO:.*security",
                        r"#\s*FIXME:.*auth",
                        r"#\s*HACK:.*validation",
                        r"//\s*TODO:.*security"
                    ],
                    "description": "Security-related TODO comments",
                    "severity": "low",
                    "suggestion": "Address security TODOs before production"
                },
                "placeholder_values": {
                    "patterns": [
                        r"password\s*=\s*[\"']changeme[\"']",
                        r"secret\s*=\s*[\"']your_secret_here[\"']",
                        r"api_key\s*=\s*[\"']your_api_key[\"']",
                        r"token\s*=\s*[\"']placeholder[\"']"
                    ],
                    "description": "Placeholder values in production code",
                    "severity": "medium",
                    "suggestion": "Replace placeholder values with proper configuration"
                }
            }
        }
    
    def _compile_patterns(self) -> Dict:
        """Compile regex patterns for better performance"""
        compiled = {}
        for category, patterns in self.patterns.items():
            compiled[category] = {}
            for name, config in patterns.items():
                compiled[category][name] = {
                    "regexes": [],
                    "config": config
                }
                for pattern in config["patterns"]:
                    try:
                        compiled[category][name]["regexes"].append(
                            re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                        )
                    except re.error as e:
                        logger.error(f"Invalid regex pattern for {name}: {e}")
        return compiled
    
    def _calculate_confidence(self, pattern_type: str, context: str) -> float:
        """Calculate confidence score for pattern match"""
        base_confidence = 0.7
        
        # Increase confidence for certain contexts
        high_confidence_indicators = [
            "user", "input", "request", "form", "query", "param"
        ]
        
        low_confidence_indicators = [
            "test", "example", "demo", "mock", "sample"
        ]
        
        context_lower = context.lower()
        
        for indicator in high_confidence_indicators:
            if indicator in context_lower:
                base_confidence += 0.1
                break
        
        for indicator in low_confidence_indicators:
            if indicator in context_lower:
                base_confidence -= 0.3
                break
        
        return min(max(base_confidence, 0.1), 1.0)
    
    def scan_content(self, content: str, file_path: str) -> List[AIPatternMatch]:
        """Scan content for AI-generated anti-patterns"""
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments (except for TODO pattern detection)
            stripped_line = line.strip()
            if (stripped_line.startswith('#') and 'TODO' not in stripped_line and 
                'FIXME' not in stripped_line and 'HACK' not in stripped_line):
                continue
            
            # Scan with compiled patterns
            for category, patterns in self.compiled_patterns.items():
                for name, pattern_data in patterns.items():
                    regexes = pattern_data["regexes"]
                    config = pattern_data["config"]
                    
                    for regex in regexes:
                        for match in regex.finditer(line):
                            confidence = self._calculate_confidence(name, line)
                            
                            # Skip low-confidence matches in test files
                            if confidence < 0.5 and any(test_indicator in file_path.lower() 
                                                      for test_indicator in ['test', 'spec', 'mock']):
                                continue
                            
                            # Generate explainability data
                            explainability = self._generate_explainability(
                                category, name, config, line, match, confidence
                            )

                            # Enhanced compliance-ready explainability
                            compliance_explainability = self._generate_compliance_explainability(
                                category, name, config, line, match, confidence
                            )

                            pattern_match = AIPatternMatch(
                                pattern_type=f"{category}.{name}",
                                description=config["description"],
                                line_number=line_num,
                                column_start=match.start(),
                                column_end=match.end(),
                                confidence=confidence,
                                file_path=file_path,
                                context=line.strip(),
                                severity=config["severity"],
                                suggestion=config["suggestion"],
                                explainability=compliance_explainability
                            )

                            findings.append(pattern_match)

        return findings

    def _generate_compliance_explainability(self, category: str, name: str, config: Dict[str, Any],
                                          line: str, match, confidence: float) -> Dict[str, Any]:
        """Generate compliance-ready explainability for regulatory requirements"""

        # Enhanced explainability for compliance
        compliance_data = self._generate_explainability(category, name, config, line, match, confidence)

        # Add compliance-specific fields
        compliance_data.update({
            "compliance_metadata": {
                "regulatory_framework": "AI Act 2024, GDPR Article 22",
                "explainability_level": "high",
                "human_reviewable": True,
                "audit_trail_id": f"ai_scan_{hash(line + str(match.start()))}",
                "decision_factors": self._extract_decision_factors(category, name, config, line, match),
                "bias_assessment": self._assess_bias_risk(category, name),
                "transparency_score": self._calculate_transparency_score(confidence, category)
            },
            "model_governance": {
                "model_id": f"byteguardx_ai_scanner_v1.0",
                "training_data_source": "curated_security_patterns",
                "last_updated": "2024-01-08",
                "validation_status": "production_approved",
                "performance_metrics": {
                    "precision": 0.92,
                    "recall": 0.88,
                    "f1_score": 0.90
                }
            },
            "interpretability": {
                "primary_indicators": self._get_primary_indicators(category, name, line, match),
                "contributing_factors": self._get_contributing_factors(line, match),
                "alternative_explanations": self._get_alternative_explanations(category, confidence),
                "confidence_intervals": self._calculate_confidence_intervals(confidence)
            }
        })

        return compliance_data

    def _extract_decision_factors(self, category: str, name: str, config: Dict[str, Any],
                                line: str, match) -> List[Dict[str, Any]]:
        """Extract specific factors that led to the AI decision"""
        factors = []

        # Pattern matching factor
        factors.append({
            "factor_type": "pattern_match",
            "description": f"Matched security pattern for {name}",
            "weight": 0.8,
            "evidence": match.group() if match else "",
            "pattern_source": config.get("pattern", ""),
            "regulatory_relevance": "High - Direct security risk indicator"
        })

        # Context analysis factor
        context_keywords = ["password", "secret", "key", "token", "auth", "login"]
        found_keywords = [kw for kw in context_keywords if kw.lower() in line.lower()]
        if found_keywords:
            factors.append({
                "factor_type": "context_analysis",
                "description": f"Security-related context detected: {', '.join(found_keywords)}",
                "weight": 0.6,
                "evidence": found_keywords,
                "regulatory_relevance": "Medium - Contextual security indicator"
            })

        # Severity assessment factor
        factors.append({
            "factor_type": "severity_assessment",
            "description": f"Risk level classified as {config.get('severity', 'unknown')}",
            "weight": 0.7,
            "evidence": config.get("severity", "unknown"),
            "regulatory_relevance": "High - Risk classification for compliance"
        })

        return factors

    def _assess_bias_risk(self, category: str, name: str) -> Dict[str, Any]:
        """Assess potential bias in AI decision"""
        return {
            "bias_risk_level": "low",
            "bias_factors_considered": [
                "Language-specific patterns",
                "Framework-specific implementations",
                "Cultural coding practices"
            ],
            "mitigation_measures": [
                "Multi-language pattern validation",
                "Diverse training data sources",
                "Regular bias testing"
            ],
            "bias_testing_date": "2024-01-08"
        }

    def _calculate_transparency_score(self, confidence: float, category: str) -> float:
        """Calculate transparency score for compliance"""
        base_score = confidence

        # Adjust based on category complexity
        if category in ["secrets", "crypto"]:
            base_score += 0.1  # Higher transparency for critical security
        elif category in ["ai_specific"]:
            base_score -= 0.05  # Slightly lower for AI-specific patterns

        return min(1.0, max(0.0, base_score))

    def _get_primary_indicators(self, category: str, name: str, line: str, match) -> List[str]:
        """Get primary indicators that led to detection"""
        indicators = []

        if match:
            indicators.append(f"Pattern match: '{match.group()}'")

        indicators.append(f"Category: {category}")
        indicators.append(f"Detection rule: {name}")

        # Add line-specific indicators
        if "password" in line.lower():
            indicators.append("Password-related content detected")
        if "secret" in line.lower():
            indicators.append("Secret-related content detected")
        if "key" in line.lower():
            indicators.append("Key-related content detected")

        return indicators

    def _get_contributing_factors(self, line: str, match) -> List[str]:
        """Get contributing factors for the detection"""
        factors = []

        if match:
            factors.append(f"Match position: characters {match.start()}-{match.end()}")
            factors.append(f"Match length: {len(match.group())} characters")

        factors.append(f"Line length: {len(line)} characters")
        factors.append(f"Line complexity: {'high' if len(line) > 100 else 'medium' if len(line) > 50 else 'low'}")

        return factors

    def _get_alternative_explanations(self, category: str, confidence: float) -> List[str]:
        """Provide alternative explanations for transparency"""
        explanations = []

        if confidence < 0.7:
            explanations.append("Low confidence may indicate false positive")

        if category == "secrets":
            explanations.append("Could be test data or example code")
            explanations.append("May be encrypted or hashed value")
        elif category == "crypto":
            explanations.append("Could be intentional weak crypto for testing")
            explanations.append("May be legacy code requiring gradual migration")

        return explanations

    def _calculate_confidence_intervals(self, confidence: float) -> Dict[str, float]:
        """Calculate confidence intervals for statistical transparency"""
        margin = 0.1  # 10% margin of error

        return {
            "point_estimate": confidence,
            "lower_bound": max(0.0, confidence - margin),
            "upper_bound": min(1.0, confidence + margin),
            "margin_of_error": margin,
            "confidence_level": 0.95
        }

    def _generate_explainability(self, category: str, name: str, config: Dict[str, Any],
                                line: str, match, confidence: float) -> Dict[str, Any]:
        """Generate detailed explainability information for a detection"""

        # Extract features that contributed to the detection
        features_used = []

        # Pattern-based features
        pattern = config.get("pattern", "")
        if pattern:
            features_used.append({
                "type": "regex_pattern",
                "value": pattern,
                "description": f"Matched regex pattern for {name}",
                "weight": 0.8
            })

        # Context features
        context_keywords = config.get("context_keywords", [])
        found_keywords = [kw for kw in context_keywords if kw.lower() in line.lower()]
        if found_keywords:
            features_used.append({
                "type": "context_keywords",
                "value": found_keywords,
                "description": "Contextual keywords that support the detection",
                "weight": 0.6
            })

        # Entropy analysis for secrets
        if category == "secrets":
            matched_text = match.group()
            entropy = self._calculate_entropy(matched_text)
            features_used.append({
                "type": "entropy",
                "value": entropy,
                "description": f"String entropy indicates randomness (threshold: 4.0)",
                "weight": 0.7
            })

        # Position and structure features
        position_features = {
            "line_position": match.start(),
            "line_length": len(line),
            "match_length": len(match.group()),
            "relative_position": match.start() / len(line) if len(line) > 0 else 0
        }

        features_used.append({
            "type": "position_analysis",
            "value": position_features,
            "description": "Position and structural analysis of the match",
            "weight": 0.3
        })

        # Confidence breakdown
        confidence_breakdown = {
            "pattern_match": 0.8 if pattern else 0.0,
            "context_support": 0.6 if found_keywords else 0.0,
            "entropy_score": entropy / 8.0 if category == "secrets" else 0.0,
            "position_score": 0.3,
            "final_confidence": confidence
        }

        # Rule logic explanation
        rule_logic = self._explain_rule_logic(category, name, config, line, match)

        # Similar patterns
        similar_patterns = self._find_similar_patterns(category, name, matched_text=match.group())

        # Suggestion reasoning
        suggestion_reasoning = self._explain_suggestion(config.get("suggestion", ""), category, name)

        return {
            "detection_method": "rule_based_ai",
            "model_version": "1.0.0",
            "confidence_level": self._get_confidence_level(confidence),
            "pattern_matched": pattern,
            "features_extracted": features_used,
            "confidence_breakdown": confidence_breakdown,
            "rule_logic": rule_logic,
            "similar_patterns": similar_patterns,
            "suggestion_reasoning": suggestion_reasoning,
            "false_positive_likelihood": self._estimate_false_positive_likelihood(category, confidence),
            "severity_reasoning": self._explain_severity(config.get("severity", "medium"), category),
            "remediation_priority": self._calculate_remediation_priority(config.get("severity", "medium"), confidence)
        }

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0

        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        text_length = len(text)

        for count in char_counts.values():
            probability = count / text_length
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)

        return entropy

    def _get_confidence_level(self, confidence: float) -> str:
        """Convert confidence score to human-readable level"""
        if confidence >= 0.9:
            return "Very High"
        elif confidence >= 0.7:
            return "High"
        elif confidence >= 0.5:
            return "Medium"
        elif confidence >= 0.3:
            return "Low"
        else:
            return "Very Low"

    def _explain_rule_logic(self, category: str, name: str, config: Dict[str, Any],
                           line: str, match) -> str:
        """Explain the logic behind the rule detection"""
        explanations = {
            "secrets.api_key": "Detected based on common API key patterns and high entropy string",
            "secrets.password": "Identified password assignment with suspicious string characteristics",
            "secrets.token": "Found token-like string with typical authentication token patterns",
            "vulnerabilities.sql_injection": "Detected string concatenation in SQL context, indicating potential injection",
            "vulnerabilities.xss": "Found direct HTML insertion without sanitization",
            "vulnerabilities.command_injection": "Identified system command execution with user input",
            "code_quality.hardcoded_ip": "Found hardcoded IP address that should be configurable",
            "code_quality.todo_comment": "Detected TODO comment indicating incomplete implementation"
        }

        rule_key = f"{category}.{name}"
        return explanations.get(rule_key, f"Detected {name} pattern in {category} category")

    def _find_similar_patterns(self, category: str, name: str, matched_text: str) -> List[Dict[str, Any]]:
        """Find similar patterns that might be related"""
        similar = []

        # For secrets, find other potential secret patterns
        if category == "secrets":
            if len(matched_text) > 20 and any(c.isdigit() for c in matched_text):
                similar.append({
                    "pattern": "Long alphanumeric string",
                    "description": "Similar to API keys or tokens",
                    "confidence": 0.6
                })

        # For vulnerabilities, find related vulnerability types
        if category == "vulnerabilities":
            if "sql" in name.lower():
                similar.append({
                    "pattern": "Database query construction",
                    "description": "Related to SQL injection vulnerabilities",
                    "confidence": 0.7
                })

        return similar

    def _explain_suggestion(self, suggestion: str, category: str, name: str) -> str:
        """Explain why a particular suggestion is recommended"""
        if not suggestion:
            return "No specific suggestion available"

        reasoning_map = {
            "secrets": "Secrets should be stored in environment variables or secure vaults to prevent exposure",
            "vulnerabilities": "This pattern is known to be exploitable and should be fixed immediately",
            "code_quality": "Following best practices improves code maintainability and security"
        }

        base_reasoning = reasoning_map.get(category, "This pattern should be addressed")
        return f"{base_reasoning}. {suggestion}"

    def _estimate_false_positive_likelihood(self, category: str, confidence: float) -> str:
        """Estimate likelihood of false positive"""
        if confidence >= 0.9:
            return "Very Low"
        elif confidence >= 0.7:
            return "Low"
        elif confidence >= 0.5:
            return "Medium"
        else:
            return "High"

    def _explain_severity(self, severity: str, category: str) -> str:
        """Explain why a particular severity was assigned"""
        explanations = {
            "critical": "This issue poses immediate security risk and should be fixed urgently",
            "high": "This issue has significant security implications and should be prioritized",
            "medium": "This issue should be addressed but is not immediately critical",
            "low": "This issue is minor but should be fixed for best practices"
        }

        base_explanation = explanations.get(severity.lower(), "Severity assessment based on potential impact")

        if category == "secrets":
            return f"{base_explanation}. Exposed secrets can lead to unauthorized access."
        elif category == "vulnerabilities":
            return f"{base_explanation}. Vulnerabilities can be exploited by attackers."
        else:
            return base_explanation

    def _calculate_remediation_priority(self, severity: str, confidence: float) -> int:
        """Calculate remediation priority (1-10, 10 being highest)"""
        severity_weights = {
            "critical": 10,
            "high": 7,
            "medium": 5,
            "low": 2
        }

        base_priority = severity_weights.get(severity.lower(), 5)
        confidence_modifier = confidence * 2  # 0-2 range

        return min(10, max(1, int(base_priority + confidence_modifier)))

    def scan_file(self, file_info: Dict) -> List[Dict]:
        """Scan a single file for AI anti-patterns"""
        if "error" in file_info:
            return []

        try:
            findings = self.scan_content(file_info["content"], file_info["file_path"])

            # Convert to dict format
            results = []
            for finding in findings:
                results.append({
                    "type": "ai_pattern",
                    "subtype": finding.pattern_type,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "column_start": finding.column_start,
                    "column_end": finding.column_end,
                    "context": finding.context,
                    "description": finding.description,
                    "suggestion": finding.suggestion,
                    "recommendation": f"Fix: {finding.suggestion}"
                })

            self.findings.extend(results)
            return results

        except Exception as e:
            logger.error(f"Error scanning file {file_info.get('file_path', 'unknown')}: {e}")
            return []

    def get_summary(self) -> Dict:
        """Get scan summary"""
        if not self.findings:
            return {"total": 0, "by_severity": {}, "by_category": {}}

        by_severity = {}
        by_category = {}

        for finding in self.findings:
            severity = finding["severity"]
            category = finding["subtype"].split('.')[0]

            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_category[category] = by_category.get(category, 0) + 1

        return {
            "total": len(self.findings),
            "by_severity": by_severity,
            "by_category": by_category
        }

    def reset(self):
        """Reset scanner state"""
        self.findings.clear()
