"""
CVSS (Common Vulnerability Scoring System) Calculator
Implements CVSS v3.1 scoring for vulnerability assessment
"""

import math
from typing import Dict, Tuple, Optional
from enum import Enum
from dataclasses import dataclass


class CVSSMetric(Enum):
    """CVSS v3.1 Base Metrics"""
    # Attack Vector (AV)
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"
    
    # Attack Complexity (AC)
    LOW = "L"
    HIGH = "H"
    
    # Privileges Required (PR)
    NONE = "N"
    LOW_PRIV = "L"
    HIGH_PRIV = "H"
    
    # User Interaction (UI)
    NONE_UI = "N"
    REQUIRED = "R"
    
    # Scope (S)
    UNCHANGED = "U"
    CHANGED = "C"
    
    # Impact Metrics (C, I, A)
    NONE_IMPACT = "N"
    LOW_IMPACT = "L"
    HIGH_IMPACT = "H"


@dataclass
class CVSSVector:
    """CVSS v3.1 Vector representation"""
    attack_vector: str = "N"  # Network
    attack_complexity: str = "L"  # Low
    privileges_required: str = "N"  # None
    user_interaction: str = "N"  # None
    scope: str = "U"  # Unchanged
    confidentiality: str = "N"  # None
    integrity: str = "N"  # None
    availability: str = "N"  # None
    
    def to_string(self) -> str:
        """Convert to CVSS vector string"""
        return (f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
                f"PR:{self.privileges_required}/UI:{self.user_interaction}/"
                f"S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}/"
                f"A:{self.availability}")
    
    @classmethod
    def from_string(cls, vector_string: str) -> 'CVSSVector':
        """Parse CVSS vector string"""
        vector = cls()
        
        if not vector_string.startswith("CVSS:3.1/"):
            raise ValueError("Invalid CVSS vector format")
        
        parts = vector_string.replace("CVSS:3.1/", "").split("/")
        
        for part in parts:
            if ":" not in part:
                continue
            
            metric, value = part.split(":", 1)
            
            if metric == "AV":
                vector.attack_vector = value
            elif metric == "AC":
                vector.attack_complexity = value
            elif metric == "PR":
                vector.privileges_required = value
            elif metric == "UI":
                vector.user_interaction = value
            elif metric == "S":
                vector.scope = value
            elif metric == "C":
                vector.confidentiality = value
            elif metric == "I":
                vector.integrity = value
            elif metric == "A":
                vector.availability = value
        
        return vector


class CVSSCalculator:
    """CVSS v3.1 Score Calculator"""
    
    # Base metric values according to CVSS v3.1 specification
    ATTACK_VECTOR_VALUES = {
        "N": 0.85,  # Network
        "A": 0.62,  # Adjacent
        "L": 0.55,  # Local
        "P": 0.2    # Physical
    }
    
    ATTACK_COMPLEXITY_VALUES = {
        "L": 0.77,  # Low
        "H": 0.44   # High
    }
    
    PRIVILEGES_REQUIRED_VALUES = {
        "N": 0.85,  # None
        "L": 0.62,  # Low (unchanged scope)
        "H": 0.27   # High (unchanged scope)
    }
    
    PRIVILEGES_REQUIRED_CHANGED_VALUES = {
        "N": 0.85,  # None
        "L": 0.68,  # Low (changed scope)
        "H": 0.50   # High (changed scope)
    }
    
    USER_INTERACTION_VALUES = {
        "N": 0.85,  # None
        "R": 0.62   # Required
    }
    
    IMPACT_VALUES = {
        "H": 0.56,  # High
        "L": 0.22,  # Low
        "N": 0.0    # None
    }
    
    @classmethod
    def calculate_base_score(cls, vector: CVSSVector) -> Tuple[float, str]:
        """Calculate CVSS base score and severity label"""
        
        # Get metric values
        av = cls.ATTACK_VECTOR_VALUES[vector.attack_vector]
        ac = cls.ATTACK_COMPLEXITY_VALUES[vector.attack_complexity]
        ui = cls.USER_INTERACTION_VALUES[vector.user_interaction]
        
        # Privileges Required depends on scope
        if vector.scope == "C":  # Changed
            pr = cls.PRIVILEGES_REQUIRED_CHANGED_VALUES[vector.privileges_required]
        else:  # Unchanged
            pr = cls.PRIVILEGES_REQUIRED_VALUES[vector.privileges_required]
        
        # Impact metrics
        conf_impact = cls.IMPACT_VALUES[vector.confidentiality]
        integ_impact = cls.IMPACT_VALUES[vector.integrity]
        avail_impact = cls.IMPACT_VALUES[vector.availability]
        
        # Calculate Impact Sub-Score (ISS)
        iss = 1 - ((1 - conf_impact) * (1 - integ_impact) * (1 - avail_impact))
        
        # Calculate Impact Score
        if vector.scope == "U":  # Unchanged
            impact = 6.42 * iss
        else:  # Changed
            impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
        
        # Calculate Exploitability Score
        exploitability = 8.22 * av * ac * pr * ui
        
        # Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        elif vector.scope == "U":  # Unchanged
            base_score = min(impact + exploitability, 10.0)
        else:  # Changed
            base_score = min(1.08 * (impact + exploitability), 10.0)
        
        # Round up to one decimal place
        base_score = math.ceil(base_score * 10) / 10
        
        # Determine severity label
        severity_label = cls.get_severity_label(base_score)
        
        return base_score, severity_label
    
    @staticmethod
    def get_severity_label(score: float) -> str:
        """Get severity label from CVSS score"""
        if score == 0.0:
            return "None"
        elif 0.1 <= score <= 3.9:
            return "Low"
        elif 4.0 <= score <= 6.9:
            return "Medium"
        elif 7.0 <= score <= 8.9:
            return "High"
        elif 9.0 <= score <= 10.0:
            return "Critical"
        else:
            return "Unknown"
    
    @classmethod
    def auto_calculate_from_finding(cls, finding_data: Dict) -> Tuple[CVSSVector, float, str]:
        """Auto-calculate CVSS from finding characteristics"""
        vector = CVSSVector()
        
        # Determine attack vector based on finding type
        scanner_type = finding_data.get('scanner_type', '').lower()
        file_path = finding_data.get('file_path', '').lower()
        
        if 'api' in file_path or 'web' in file_path or 'http' in file_path:
            vector.attack_vector = "N"  # Network
        elif 'config' in file_path or 'env' in file_path:
            vector.attack_vector = "L"  # Local
        else:
            vector.attack_vector = "A"  # Adjacent (default)
        
        # Determine complexity based on finding type
        if scanner_type == 'secret':
            vector.attack_complexity = "L"  # Secrets are usually easy to exploit
        elif scanner_type == 'dependency':
            vector.attack_complexity = "H"  # Dependencies may require specific conditions
        else:
            vector.attack_complexity = "L"  # Default to low
        
        # Determine privileges required
        if 'admin' in file_path or 'root' in file_path:
            vector.privileges_required = "H"  # High privileges
        elif 'user' in file_path or 'auth' in file_path:
            vector.privileges_required = "L"  # Low privileges
        else:
            vector.privileges_required = "N"  # None required
        
        # User interaction (most security issues don't require interaction)
        vector.user_interaction = "N"
        
        # Scope (assume unchanged unless specific indicators)
        vector.scope = "U"
        
        # Impact based on severity
        severity = finding_data.get('severity', 'medium').lower()
        
        if severity in ['critical', 'high']:
            vector.confidentiality = "H"
            vector.integrity = "H"
            vector.availability = "L"
        elif severity == 'medium':
            vector.confidentiality = "L"
            vector.integrity = "L"
            vector.availability = "N"
        else:  # low
            vector.confidentiality = "L"
            vector.integrity = "N"
            vector.availability = "N"
        
        # Calculate score
        score, label = cls.calculate_base_score(vector)
        
        return vector, score, label


def calculate_cvss_for_finding(finding_data: Dict) -> Dict[str, any]:
    """
    Calculate CVSS metrics for a finding
    
    Args:
        finding_data: Dictionary containing finding information
        
    Returns:
        Dictionary with CVSS vector, scores, and severity label
    """
    try:
        vector, score, label = CVSSCalculator.auto_calculate_from_finding(finding_data)
        
        return {
            'cvss_vector': vector.to_string(),
            'cvss_base_score': score,
            'cvss_severity_label': label,
            'cvss_temporal_score': 0.0,  # Not implemented yet
            'cvss_environmental_score': 0.0  # Not implemented yet
        }
    except Exception as e:
        # Return default values if calculation fails
        return {
            'cvss_vector': None,
            'cvss_base_score': 0.0,
            'cvss_severity_label': 'None',
            'cvss_temporal_score': 0.0,
            'cvss_environmental_score': 0.0
        }
