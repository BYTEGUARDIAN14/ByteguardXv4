"""
Timezone-Sensitive Scheduling System
Provides intelligent scheduling based on user timezone and regional preferences
"""

import logging
import pytz
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import requests
from croniter import croniter

logger = logging.getLogger(__name__)

class ScheduleFrequency(Enum):
    """Scan frequency options"""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM = "custom"

class RegionProfile(Enum):
    """Regional profiles for scheduling preferences"""
    NORTH_AMERICA = "north_america"
    EUROPE = "europe"
    ASIA_PACIFIC = "asia_pacific"
    MIDDLE_EAST = "middle_east"
    LATIN_AMERICA = "latin_america"
    AFRICA = "africa"

@dataclass
class TimezoneInfo:
    """Timezone information"""
    timezone: str
    offset_hours: float
    dst_active: bool
    region: RegionProfile
    business_hours_start: int = 9  # 24-hour format
    business_hours_end: int = 17   # 24-hour format
    weekend_days: List[int] = field(default_factory=lambda: [5, 6])  # Saturday, Sunday

@dataclass
class ScheduleRecommendation:
    """Schedule recommendation based on timezone and usage patterns"""
    frequency: ScheduleFrequency
    cron_expression: str
    next_run: datetime
    description: str
    reasoning: str
    optimal_for_timezone: bool
    estimated_duration: Optional[int] = None  # minutes

class TimezoneScheduler:
    """
    Intelligent scheduling system with timezone awareness
    """
    
    def __init__(self):
        self.timezone_cache: Dict[str, TimezoneInfo] = {}
        self.regional_preferences = self._load_regional_preferences()
        self.schedule_templates = self._load_schedule_templates()
        
    def _load_regional_preferences(self) -> Dict[RegionProfile, Dict[str, Any]]:
        """Load regional scheduling preferences"""
        return {
            RegionProfile.NORTH_AMERICA: {
                'preferred_scan_times': [2, 3, 4],  # 2-4 AM
                'avoid_times': [9, 10, 11, 12, 13, 14, 15, 16, 17],  # Business hours
                'weekend_scanning': True,
                'holiday_awareness': True,
                'peak_development_hours': [9, 10, 11, 14, 15, 16, 17]
            },
            RegionProfile.EUROPE: {
                'preferred_scan_times': [1, 2, 3],  # 1-3 AM
                'avoid_times': [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
                'weekend_scanning': False,  # More conservative
                'holiday_awareness': True,
                'peak_development_hours': [8, 9, 10, 11, 14, 15, 16, 17]
            },
            RegionProfile.ASIA_PACIFIC: {
                'preferred_scan_times': [0, 1, 2, 23],  # Midnight to 2 AM, 11 PM
                'avoid_times': [9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
                'weekend_scanning': True,
                'holiday_awareness': True,
                'peak_development_hours': [9, 10, 11, 13, 14, 15, 16, 17, 18]
            },
            RegionProfile.MIDDLE_EAST: {
                'preferred_scan_times': [2, 3, 4, 5],  # 2-5 AM
                'avoid_times': [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                'weekend_scanning': True,
                'holiday_awareness': True,
                'peak_development_hours': [8, 9, 10, 11, 13, 14, 15, 16]
            },
            RegionProfile.LATIN_AMERICA: {
                'preferred_scan_times': [1, 2, 3, 4],  # 1-4 AM
                'avoid_times': [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
                'weekend_scanning': True,
                'holiday_awareness': False,  # Less holiday data available
                'peak_development_hours': [8, 9, 10, 11, 14, 15, 16, 17]
            },
            RegionProfile.AFRICA: {
                'preferred_scan_times': [2, 3, 4, 5],  # 2-5 AM
                'avoid_times': [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                'weekend_scanning': True,
                'holiday_awareness': False,
                'peak_development_hours': [8, 9, 10, 11, 14, 15, 16, 17]
            }
        }
    
    def _load_schedule_templates(self) -> Dict[ScheduleFrequency, List[str]]:
        """Load cron expression templates for different frequencies"""
        return {
            ScheduleFrequency.HOURLY: [
                "0 * * * *",  # Every hour
                "30 * * * *",  # Every hour at 30 minutes
                "0 */2 * * *",  # Every 2 hours
                "0 */4 * * *",  # Every 4 hours
                "0 */6 * * *",  # Every 6 hours
            ],
            ScheduleFrequency.DAILY: [
                "0 2 * * *",   # Daily at 2 AM
                "0 3 * * *",   # Daily at 3 AM
                "0 1 * * *",   # Daily at 1 AM
                "0 4 * * *",   # Daily at 4 AM
                "30 2 * * *",  # Daily at 2:30 AM
            ],
            ScheduleFrequency.WEEKLY: [
                "0 2 * * 0",   # Weekly on Sunday at 2 AM
                "0 3 * * 1",   # Weekly on Monday at 3 AM
                "0 1 * * 6",   # Weekly on Saturday at 1 AM
                "0 2 * * 6",   # Weekly on Saturday at 2 AM
            ],
            ScheduleFrequency.MONTHLY: [
                "0 2 1 * *",   # Monthly on 1st at 2 AM
                "0 3 15 * *",  # Monthly on 15th at 3 AM
                "0 1 * * 0",   # First Sunday of month at 1 AM
            ]
        }
    
    def detect_timezone_from_ip(self, ip_address: str) -> Optional[TimezoneInfo]:
        """Detect timezone from IP address"""
        try:
            # Use a geolocation service (this is a simplified example)
            # In production, you'd use a proper geolocation API
            response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                timezone_str = data.get('timezone')
                if timezone_str:
                    return self._get_timezone_info(timezone_str)
        except Exception as e:
            logger.warning(f"Failed to detect timezone from IP {ip_address}: {e}")
        
        return None
    
    def _get_timezone_info(self, timezone_str: str) -> TimezoneInfo:
        """Get comprehensive timezone information"""
        if timezone_str in self.timezone_cache:
            return self.timezone_cache[timezone_str]
        
        try:
            tz = pytz.timezone(timezone_str)
            now = datetime.now(tz)
            
            # Determine region based on timezone
            region = self._determine_region(timezone_str)
            
            # Get UTC offset
            offset_hours = now.utcoffset().total_seconds() / 3600
            
            # Check if DST is active
            dst_active = bool(now.dst())
            
            timezone_info = TimezoneInfo(
                timezone=timezone_str,
                offset_hours=offset_hours,
                dst_active=dst_active,
                region=region
            )
            
            self.timezone_cache[timezone_str] = timezone_info
            return timezone_info
            
        except Exception as e:
            logger.error(f"Error getting timezone info for {timezone_str}: {e}")
            # Return default timezone info
            return TimezoneInfo(
                timezone="UTC",
                offset_hours=0,
                dst_active=False,
                region=RegionProfile.NORTH_AMERICA
            )
    
    def _determine_region(self, timezone_str: str) -> RegionProfile:
        """Determine region from timezone string"""
        timezone_lower = timezone_str.lower()
        
        if any(region in timezone_lower for region in ['america', 'new_york', 'chicago', 'denver', 'los_angeles']):
            return RegionProfile.NORTH_AMERICA
        elif any(region in timezone_lower for region in ['europe', 'london', 'paris', 'berlin', 'rome']):
            return RegionProfile.EUROPE
        elif any(region in timezone_lower for region in ['asia', 'tokyo', 'shanghai', 'mumbai', 'singapore']):
            return RegionProfile.ASIA_PACIFIC
        elif any(region in timezone_lower for region in ['dubai', 'riyadh', 'tehran', 'baghdad']):
            return RegionProfile.MIDDLE_EAST
        elif any(region in timezone_lower for region in ['sao_paulo', 'mexico', 'bogota', 'lima']):
            return RegionProfile.LATIN_AMERICA
        elif any(region in timezone_lower for region in ['cairo', 'johannesburg', 'nairobi', 'lagos']):
            return RegionProfile.AFRICA
        else:
            return RegionProfile.NORTH_AMERICA  # Default
    
    def get_schedule_recommendations(self, 
                                   timezone_str: str,
                                   project_size: str = "medium",
                                   team_size: int = 5,
                                   current_usage: Dict[str, Any] = None) -> List[ScheduleRecommendation]:
        """Get intelligent schedule recommendations"""
        timezone_info = self._get_timezone_info(timezone_str)
        regional_prefs = self.regional_preferences[timezone_info.region]
        current_usage = current_usage or {}
        
        recommendations = []
        
        # Daily recommendations
        for hour in regional_prefs['preferred_scan_times']:
            cron_expr = f"0 {hour} * * *"
            next_run = self._calculate_next_run(cron_expr, timezone_str)
            
            recommendations.append(ScheduleRecommendation(
                frequency=ScheduleFrequency.DAILY,
                cron_expression=cron_expr,
                next_run=next_run,
                description=f"Daily at {hour}:00 {timezone_info.timezone}",
                reasoning=f"Optimal for {timezone_info.region.value} region during low-activity hours",
                optimal_for_timezone=True,
                estimated_duration=self._estimate_scan_duration(project_size, team_size)
            ))
        
        # Weekly recommendations
        if regional_prefs['weekend_scanning']:
            weekend_hour = regional_prefs['preferred_scan_times'][0]
            cron_expr = f"0 {weekend_hour} * * 0"  # Sunday
            next_run = self._calculate_next_run(cron_expr, timezone_str)
            
            recommendations.append(ScheduleRecommendation(
                frequency=ScheduleFrequency.WEEKLY,
                cron_expression=cron_expr,
                next_run=next_run,
                description=f"Weekly on Sunday at {weekend_hour}:00 {timezone_info.timezone}",
                reasoning="Weekend scanning for comprehensive weekly review",
                optimal_for_timezone=True,
                estimated_duration=self._estimate_scan_duration(project_size, team_size, comprehensive=True)
            ))
        
        # Hourly recommendations for active projects
        if current_usage.get('daily_commits', 0) > 10:
            avoid_hours = regional_prefs['avoid_times']
            good_hours = [h for h in range(24) if h not in avoid_hours]
            
            if good_hours:
                hour = good_hours[0]
                cron_expr = f"0 */4 * * *"  # Every 4 hours, but adjust start time
                next_run = self._calculate_next_run(cron_expr, timezone_str)
                
                recommendations.append(ScheduleRecommendation(
                    frequency=ScheduleFrequency.HOURLY,
                    cron_expression=cron_expr,
                    next_run=next_run,
                    description="Every 4 hours during off-peak times",
                    reasoning="High activity project requires frequent scanning",
                    optimal_for_timezone=True,
                    estimated_duration=self._estimate_scan_duration(project_size, team_size, quick=True)
                ))
        
        # Sort by optimization for timezone
        recommendations.sort(key=lambda x: (not x.optimal_for_timezone, x.next_run))
        
        return recommendations[:5]  # Return top 5 recommendations
    
    def _calculate_next_run(self, cron_expression: str, timezone_str: str) -> datetime:
        """Calculate next run time for cron expression in given timezone"""
        try:
            tz = pytz.timezone(timezone_str)
            now = datetime.now(tz)
            cron = croniter(cron_expression, now)
            return cron.get_next(datetime)
        except Exception as e:
            logger.error(f"Error calculating next run: {e}")
            return datetime.now() + timedelta(hours=1)
    
    def _estimate_scan_duration(self, project_size: str, team_size: int, 
                              comprehensive: bool = False, quick: bool = False) -> int:
        """Estimate scan duration in minutes"""
        base_duration = {
            "small": 5,
            "medium": 15,
            "large": 30,
            "enterprise": 60
        }.get(project_size, 15)
        
        # Adjust for team size
        team_multiplier = min(1 + (team_size / 10), 2.0)
        duration = int(base_duration * team_multiplier)
        
        if comprehensive:
            duration *= 2
        elif quick:
            duration = max(duration // 2, 2)
        
        return duration

# Global instance
timezone_scheduler = TimezoneScheduler()
