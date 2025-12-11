"""
Password Policy and Validation for ByteGuardX
Implements strong password requirements and validation
"""

import re
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import os

logger = logging.getLogger(__name__)

class PasswordStrength(Enum):
    """Password strength levels"""
    WEAK = "weak"
    FAIR = "fair"
    GOOD = "good"
    STRONG = "strong"
    VERY_STRONG = "very_strong"

@dataclass
class PasswordPolicy:
    """Password policy configuration"""
    min_length: int = 8
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special_chars: bool = True
    min_special_chars: int = 1
    min_digits: int = 1
    min_uppercase: int = 1
    min_lowercase: int = 1
    
    # Advanced requirements
    max_consecutive_chars: int = 3
    max_repeated_chars: int = 2
    prevent_common_passwords: bool = True
    prevent_personal_info: bool = True
    prevent_keyboard_patterns: bool = True
    
    # History and expiration
    password_history_count: int = 5
    password_expiry_days: int = 90
    
    # Special character set
    special_chars: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"

@dataclass
class PasswordValidationResult:
    """Result of password validation"""
    is_valid: bool
    strength: PasswordStrength
    score: int  # 0-100
    errors: List[str]
    warnings: List[str]
    suggestions: List[str]

class PasswordValidator:
    """Advanced password validator with comprehensive checks"""
    
    def __init__(self, policy: Optional[PasswordPolicy] = None):
        self.policy = policy or PasswordPolicy()
        self._load_common_passwords()
        self._load_keyboard_patterns()
    
    def _load_common_passwords(self):
        """Load common passwords list"""
        # Common passwords (subset for demo - in production, load from file)
        self.common_passwords = {
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'shadow', 'superman', 'michael',
            'football', 'baseball', 'liverpool', 'jordan', 'harley',
            'robert', 'thomas', 'daniel', 'matthew', 'anthony'
        }
    
    def _load_keyboard_patterns(self):
        """Load keyboard patterns to detect"""
        self.keyboard_patterns = [
            'qwerty', 'asdf', 'zxcv', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
            '1234567890', '0987654321', 'abcdefg', 'zyxwvut'
        ]
    
    def validate_password(self, password: str, user_info: Optional[Dict[str, str]] = None) -> PasswordValidationResult:
        """Comprehensive password validation"""
        errors = []
        warnings = []
        suggestions = []
        score = 0
        
        # Basic length check
        if len(password) < self.policy.min_length:
            errors.append(f"Password must be at least {self.policy.min_length} characters long")
        elif len(password) >= self.policy.min_length:
            score += 10
        
        if len(password) > self.policy.max_length:
            errors.append(f"Password must not exceed {self.policy.max_length} characters")
        
        # Character type requirements
        uppercase_count = sum(1 for c in password if c.isupper())
        lowercase_count = sum(1 for c in password if c.islower())
        digit_count = sum(1 for c in password if c.isdigit())
        special_count = sum(1 for c in password if c in self.policy.special_chars)
        
        if self.policy.require_uppercase and uppercase_count < self.policy.min_uppercase:
            errors.append(f"Password must contain at least {self.policy.min_uppercase} uppercase letter(s)")
        elif uppercase_count >= self.policy.min_uppercase:
            score += 15
        
        if self.policy.require_lowercase and lowercase_count < self.policy.min_lowercase:
            errors.append(f"Password must contain at least {self.policy.min_lowercase} lowercase letter(s)")
        elif lowercase_count >= self.policy.min_lowercase:
            score += 15
        
        if self.policy.require_digits and digit_count < self.policy.min_digits:
            errors.append(f"Password must contain at least {self.policy.min_digits} digit(s)")
        elif digit_count >= self.policy.min_digits:
            score += 15
        
        if self.policy.require_special_chars and special_count < self.policy.min_special_chars:
            errors.append(f"Password must contain at least {self.policy.min_special_chars} special character(s): {self.policy.special_chars}")
        elif special_count >= self.policy.min_special_chars:
            score += 15
        
        # Advanced pattern checks
        if self.policy.max_consecutive_chars > 0:
            consecutive_count = self._check_consecutive_chars(password)
            if consecutive_count > self.policy.max_consecutive_chars:
                errors.append(f"Password contains too many consecutive characters (max: {self.policy.max_consecutive_chars})")
            else:
                score += 10
        
        if self.policy.max_repeated_chars > 0:
            repeated_count = self._check_repeated_chars(password)
            if repeated_count > self.policy.max_repeated_chars:
                errors.append(f"Password contains too many repeated characters (max: {self.policy.max_repeated_chars})")
            else:
                score += 10
        
        # Common password check
        if self.policy.prevent_common_passwords:
            if password.lower() in self.common_passwords:
                errors.append("Password is too common and easily guessable")
            else:
                score += 10
        
        # Keyboard pattern check
        if self.policy.prevent_keyboard_patterns:
            if self._contains_keyboard_pattern(password.lower()):
                warnings.append("Password contains keyboard patterns which are less secure")
            else:
                score += 5
        
        # Personal information check
        if self.policy.prevent_personal_info and user_info:
            personal_info_found = self._check_personal_info(password, user_info)
            if personal_info_found:
                errors.append("Password should not contain personal information")
            else:
                score += 10
        
        # Bonus points for length
        if len(password) >= 16:
            score += 10
        if len(password) >= 20:
            score += 5
        
        # Determine strength
        strength = self._calculate_strength(score, len(errors))
        
        # Generate suggestions
        if errors:
            suggestions = self._generate_suggestions(password, errors)
        
        return PasswordValidationResult(
            is_valid=len(errors) == 0,
            strength=strength,
            score=min(score, 100),
            errors=errors,
            warnings=warnings,
            suggestions=suggestions
        )
    
    def _check_consecutive_chars(self, password: str) -> int:
        """Check for consecutive characters (abc, 123, etc.)"""
        max_consecutive = 0
        current_consecutive = 1
        
        for i in range(1, len(password)):
            if ord(password[i]) == ord(password[i-1]) + 1:
                current_consecutive += 1
                max_consecutive = max(max_consecutive, current_consecutive)
            else:
                current_consecutive = 1
        
        return max_consecutive
    
    def _check_repeated_chars(self, password: str) -> int:
        """Check for repeated characters (aaa, 111, etc.)"""
        max_repeated = 0
        current_repeated = 1
        
        for i in range(1, len(password)):
            if password[i] == password[i-1]:
                current_repeated += 1
                max_repeated = max(max_repeated, current_repeated)
            else:
                current_repeated = 1
        
        return max_repeated
    
    def _contains_keyboard_pattern(self, password: str) -> bool:
        """Check if password contains keyboard patterns"""
        for pattern in self.keyboard_patterns:
            if pattern in password or pattern[::-1] in password:
                return True
        return False
    
    def _check_personal_info(self, password: str, user_info: Dict[str, str]) -> bool:
        """Check if password contains personal information"""
        password_lower = password.lower()
        
        # Check common personal info fields
        personal_fields = ['email', 'username', 'first_name', 'last_name', 'name']
        
        for field in personal_fields:
            if field in user_info and user_info[field]:
                value = user_info[field].lower()
                # Check if personal info is contained in password
                if len(value) >= 3 and value in password_lower:
                    return True
                # Check if password is contained in personal info
                if len(password_lower) >= 3 and password_lower in value:
                    return True
        
        return False
    
    def _calculate_strength(self, score: int, error_count: int) -> PasswordStrength:
        """Calculate password strength based on score and errors"""
        if error_count > 0:
            return PasswordStrength.WEAK
        
        if score >= 90:
            return PasswordStrength.VERY_STRONG
        elif score >= 75:
            return PasswordStrength.STRONG
        elif score >= 60:
            return PasswordStrength.GOOD
        elif score >= 40:
            return PasswordStrength.FAIR
        else:
            return PasswordStrength.WEAK
    
    def _generate_suggestions(self, password: str, errors: List[str]) -> List[str]:
        """Generate helpful suggestions for password improvement"""
        suggestions = []
        
        if any("length" in error.lower() for error in errors):
            suggestions.append(f"Make your password at least {self.policy.min_length} characters long")
        
        if any("uppercase" in error.lower() for error in errors):
            suggestions.append("Add uppercase letters (A-Z)")
        
        if any("lowercase" in error.lower() for error in errors):
            suggestions.append("Add lowercase letters (a-z)")
        
        if any("digit" in error.lower() for error in errors):
            suggestions.append("Add numbers (0-9)")
        
        if any("special" in error.lower() for error in errors):
            suggestions.append(f"Add special characters: {self.policy.special_chars}")
        
        if any("common" in error.lower() for error in errors):
            suggestions.append("Avoid common passwords - use a unique combination")
        
        if any("personal" in error.lower() for error in errors):
            suggestions.append("Don't use personal information like your name or email")
        
        # General suggestions
        suggestions.extend([
            "Consider using a passphrase with random words",
            "Use a password manager to generate and store strong passwords",
            "Make it memorable but unpredictable"
        ])
        
        return suggestions[:5]  # Limit to 5 suggestions
    
    def generate_password(self, length: int = None) -> str:
        """Generate a strong password that meets policy requirements"""
        import secrets
        import string
        
        if length is None:
            length = max(self.policy.min_length, 16)
        
        # Character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = self.policy.special_chars
        
        # Ensure minimum requirements
        password = []
        
        if self.policy.require_lowercase:
            password.extend(secrets.choice(lowercase) for _ in range(self.policy.min_lowercase))
        
        if self.policy.require_uppercase:
            password.extend(secrets.choice(uppercase) for _ in range(self.policy.min_uppercase))
        
        if self.policy.require_digits:
            password.extend(secrets.choice(digits) for _ in range(self.policy.min_digits))
        
        if self.policy.require_special_chars:
            password.extend(secrets.choice(special) for _ in range(self.policy.min_special_chars))
        
        # Fill remaining length with random characters
        all_chars = lowercase + uppercase + digits + special
        remaining_length = length - len(password)
        
        password.extend(secrets.choice(all_chars) for _ in range(remaining_length))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)

# Global instance with default policy
password_validator = PasswordValidator()
