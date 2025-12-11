#!/usr/bin/env python3
"""
Advanced Behavioral Biometrics for ByteGuardX
Implements continuous authentication through behavioral patterns
"""

import logging
import numpy as np
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from collections import deque, defaultdict
import statistics
import math

logger = logging.getLogger(__name__)

@dataclass
class KeystrokePattern:
    """Keystroke dynamics pattern"""
    user_id: str
    dwell_times: List[float]  # Key press duration
    flight_times: List[float]  # Time between key releases
    typing_rhythm: List[float]  # Inter-keystroke intervals
    pressure_patterns: List[float]  # Key press pressure (if available)
    recorded_at: datetime
    text_length: int
    typing_speed: float  # WPM

@dataclass
class MousePattern:
    """Mouse movement and click patterns"""
    user_id: str
    movement_velocity: List[float]
    movement_acceleration: List[float]
    click_patterns: List[Dict[str, float]]  # Click duration, pressure
    scroll_patterns: List[Dict[str, float]]  # Scroll speed, direction
    movement_trajectory: List[Tuple[float, float]]  # X, Y coordinates
    recorded_at: datetime
    session_duration: float

@dataclass
class TouchPattern:
    """Touch/swipe patterns for mobile devices"""
    user_id: str
    touch_pressure: List[float]
    touch_area: List[float]
    swipe_velocity: List[float]
    swipe_direction: List[float]
    multi_touch_patterns: List[Dict[str, Any]]
    recorded_at: datetime
    device_type: str

@dataclass
class BiometricProfile:
    """User's behavioral biometric profile"""
    user_id: str
    keystroke_profile: Dict[str, Any]
    mouse_profile: Dict[str, Any]
    touch_profile: Dict[str, Any]
    confidence_score: float
    last_updated: datetime
    sample_count: int
    is_stable: bool

@dataclass
class BiometricAnomaly:
    """Detected behavioral anomaly"""
    anomaly_id: str
    user_id: str
    anomaly_type: str
    confidence: float
    deviation_score: float
    detected_patterns: Dict[str, Any]
    baseline_patterns: Dict[str, Any]
    detected_at: datetime
    risk_level: str

class BehavioralBiometricsEngine:
    """
    Advanced behavioral biometrics engine for continuous authentication
    """
    
    def __init__(self):
        # User profiles and patterns
        self.user_profiles: Dict[str, BiometricProfile] = {}
        self.keystroke_samples: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.mouse_samples: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.touch_samples: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # Anomaly detection
        self.detected_anomalies: List[BiometricAnomaly] = []
        
        # Configuration
        self.min_samples_for_profile = 20
        self.anomaly_threshold = 0.7
        self.profile_update_interval = timedelta(hours=24)
        
        # Statistical thresholds
        self.keystroke_thresholds = {
            'dwell_time_std': 0.05,  # Standard deviation threshold
            'flight_time_std': 0.08,
            'rhythm_variance': 0.1,
            'speed_deviation': 0.2
        }
        
        self.mouse_thresholds = {
            'velocity_std': 0.15,
            'acceleration_std': 0.2,
            'click_duration_std': 0.1,
            'trajectory_deviation': 0.25
        }
    
    def record_keystroke_pattern(self, user_id: str, keystroke_data: Dict[str, Any]) -> bool:
        """Record keystroke dynamics for a user"""
        try:
            # Extract keystroke metrics
            dwell_times = keystroke_data.get('dwell_times', [])
            flight_times = keystroke_data.get('flight_times', [])
            text_content = keystroke_data.get('text', '')
            timestamp = datetime.now()
            
            if len(dwell_times) < 5 or len(flight_times) < 5:
                return False  # Insufficient data
            
            # Calculate typing rhythm and speed
            typing_rhythm = self._calculate_typing_rhythm(dwell_times, flight_times)
            typing_speed = self._calculate_typing_speed(text_content, sum(dwell_times) + sum(flight_times))
            
            # Create keystroke pattern
            pattern = KeystrokePattern(
                user_id=user_id,
                dwell_times=dwell_times,
                flight_times=flight_times,
                typing_rhythm=typing_rhythm,
                pressure_patterns=keystroke_data.get('pressure_patterns', []),
                recorded_at=timestamp,
                text_length=len(text_content),
                typing_speed=typing_speed
            )
            
            # Store sample
            self.keystroke_samples[user_id].append(pattern)
            
            # Update profile if enough samples
            if len(self.keystroke_samples[user_id]) >= self.min_samples_for_profile:
                self._update_keystroke_profile(user_id)
            
            logger.debug(f"Recorded keystroke pattern for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to record keystroke pattern: {e}")
            return False
    
    def record_mouse_pattern(self, user_id: str, mouse_data: Dict[str, Any]) -> bool:
        """Record mouse movement and click patterns"""
        try:
            # Extract mouse metrics
            movements = mouse_data.get('movements', [])
            clicks = mouse_data.get('clicks', [])
            scrolls = mouse_data.get('scrolls', [])
            timestamp = datetime.now()
            
            if len(movements) < 10:
                return False  # Insufficient data
            
            # Calculate movement metrics
            velocity = self._calculate_movement_velocity(movements)
            acceleration = self._calculate_movement_acceleration(velocity)
            trajectory = [(m['x'], m['y']) for m in movements]
            
            # Process click patterns
            click_patterns = []
            for click in clicks:
                click_patterns.append({
                    'duration': click.get('duration', 0),
                    'pressure': click.get('pressure', 0),
                    'button': click.get('button', 'left')
                })
            
            # Process scroll patterns
            scroll_patterns = []
            for scroll in scrolls:
                scroll_patterns.append({
                    'speed': scroll.get('speed', 0),
                    'direction': scroll.get('direction', 0),
                    'acceleration': scroll.get('acceleration', 0)
                })
            
            # Create mouse pattern
            pattern = MousePattern(
                user_id=user_id,
                movement_velocity=velocity,
                movement_acceleration=acceleration,
                click_patterns=click_patterns,
                scroll_patterns=scroll_patterns,
                movement_trajectory=trajectory,
                recorded_at=timestamp,
                session_duration=mouse_data.get('session_duration', 0)
            )
            
            # Store sample
            self.mouse_samples[user_id].append(pattern)
            
            # Update profile if enough samples
            if len(self.mouse_samples[user_id]) >= self.min_samples_for_profile:
                self._update_mouse_profile(user_id)
            
            logger.debug(f"Recorded mouse pattern for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to record mouse pattern: {e}")
            return False
    
    def authenticate_user(self, user_id: str, current_patterns: Dict[str, Any]) -> Tuple[bool, float, List[str]]:
        """
        Authenticate user based on behavioral biometrics
        Returns: (is_authentic, confidence_score, anomalies)
        """
        try:
            if user_id not in self.user_profiles:
                return False, 0.0, ["No biometric profile available"]
            
            profile = self.user_profiles[user_id]
            anomalies = []
            confidence_scores = []
            
            # Analyze keystroke patterns
            if 'keystroke' in current_patterns and profile.keystroke_profile:
                keystroke_confidence, keystroke_anomalies = self._analyze_keystroke_authentication(
                    user_id, current_patterns['keystroke'], profile.keystroke_profile
                )
                confidence_scores.append(keystroke_confidence)
                anomalies.extend(keystroke_anomalies)
            
            # Analyze mouse patterns
            if 'mouse' in current_patterns and profile.mouse_profile:
                mouse_confidence, mouse_anomalies = self._analyze_mouse_authentication(
                    user_id, current_patterns['mouse'], profile.mouse_profile
                )
                confidence_scores.append(mouse_confidence)
                anomalies.extend(mouse_anomalies)
            
            # Analyze touch patterns (for mobile)
            if 'touch' in current_patterns and profile.touch_profile:
                touch_confidence, touch_anomalies = self._analyze_touch_authentication(
                    user_id, current_patterns['touch'], profile.touch_profile
                )
                confidence_scores.append(touch_confidence)
                anomalies.extend(touch_anomalies)
            
            # Calculate overall confidence
            if not confidence_scores:
                return False, 0.0, ["No patterns to analyze"]
            
            overall_confidence = statistics.mean(confidence_scores)
            is_authentic = overall_confidence >= self.anomaly_threshold and len(anomalies) == 0
            
            # Log authentication attempt
            logger.info(f"Biometric authentication for {user_id}: confidence={overall_confidence:.3f}, authentic={is_authentic}")
            
            return is_authentic, overall_confidence, anomalies
            
        except Exception as e:
            logger.error(f"Biometric authentication error: {e}")
            return False, 0.0, ["Authentication system error"]
    
    def _calculate_typing_rhythm(self, dwell_times: List[float], flight_times: List[float]) -> List[float]:
        """Calculate typing rhythm patterns"""
        rhythm = []
        for i in range(min(len(dwell_times), len(flight_times))):
            if i > 0:
                interval = dwell_times[i] + flight_times[i-1]
                rhythm.append(interval)
        return rhythm
    
    def _calculate_typing_speed(self, text: str, total_time: float) -> float:
        """Calculate typing speed in WPM"""
        if total_time == 0:
            return 0.0
        
        # Approximate words (5 characters = 1 word)
        words = len(text) / 5
        minutes = total_time / 60
        return words / minutes if minutes > 0 else 0.0
    
    def _calculate_movement_velocity(self, movements: List[Dict[str, Any]]) -> List[float]:
        """Calculate mouse movement velocity"""
        velocities = []
        for i in range(1, len(movements)):
            prev = movements[i-1]
            curr = movements[i]
            
            dx = curr['x'] - prev['x']
            dy = curr['y'] - prev['y']
            dt = curr['timestamp'] - prev['timestamp']
            
            if dt > 0:
                distance = math.sqrt(dx*dx + dy*dy)
                velocity = distance / dt
                velocities.append(velocity)
        
        return velocities
    
    def _calculate_movement_acceleration(self, velocities: List[float]) -> List[float]:
        """Calculate mouse movement acceleration"""
        accelerations = []
        for i in range(1, len(velocities)):
            dv = velocities[i] - velocities[i-1]
            accelerations.append(dv)  # Assuming unit time intervals
        
        return accelerations
    
    def _update_keystroke_profile(self, user_id: str):
        """Update user's keystroke biometric profile"""
        try:
            samples = list(self.keystroke_samples[user_id])
            
            # Calculate statistical features
            all_dwell_times = [t for sample in samples for t in sample.dwell_times]
            all_flight_times = [t for sample in samples for t in sample.flight_times]
            all_rhythms = [r for sample in samples for r in sample.typing_rhythm]
            all_speeds = [sample.typing_speed for sample in samples]
            
            keystroke_profile = {
                'dwell_time_mean': statistics.mean(all_dwell_times) if all_dwell_times else 0,
                'dwell_time_std': statistics.stdev(all_dwell_times) if len(all_dwell_times) > 1 else 0,
                'flight_time_mean': statistics.mean(all_flight_times) if all_flight_times else 0,
                'flight_time_std': statistics.stdev(all_flight_times) if len(all_flight_times) > 1 else 0,
                'rhythm_mean': statistics.mean(all_rhythms) if all_rhythms else 0,
                'rhythm_std': statistics.stdev(all_rhythms) if len(all_rhythms) > 1 else 0,
                'speed_mean': statistics.mean(all_speeds) if all_speeds else 0,
                'speed_std': statistics.stdev(all_speeds) if len(all_speeds) > 1 else 0,
                'sample_count': len(samples)
            }
            
            # Update or create profile
            if user_id in self.user_profiles:
                self.user_profiles[user_id].keystroke_profile = keystroke_profile
                self.user_profiles[user_id].last_updated = datetime.now()
                self.user_profiles[user_id].sample_count = len(samples)
            else:
                self.user_profiles[user_id] = BiometricProfile(
                    user_id=user_id,
                    keystroke_profile=keystroke_profile,
                    mouse_profile={},
                    touch_profile={},
                    confidence_score=0.8,
                    last_updated=datetime.now(),
                    sample_count=len(samples),
                    is_stable=len(samples) >= 50
                )
            
            logger.info(f"Updated keystroke profile for user {user_id}")
            
        except Exception as e:
            logger.error(f"Failed to update keystroke profile: {e}")
    
    def _update_mouse_profile(self, user_id: str):
        """Update user's mouse biometric profile"""
        try:
            samples = list(self.mouse_samples[user_id])
            
            # Calculate statistical features
            all_velocities = [v for sample in samples for v in sample.movement_velocity]
            all_accelerations = [a for sample in samples for a in sample.movement_acceleration]
            all_click_durations = [c['duration'] for sample in samples for c in sample.click_patterns]
            
            mouse_profile = {
                'velocity_mean': statistics.mean(all_velocities) if all_velocities else 0,
                'velocity_std': statistics.stdev(all_velocities) if len(all_velocities) > 1 else 0,
                'acceleration_mean': statistics.mean(all_accelerations) if all_accelerations else 0,
                'acceleration_std': statistics.stdev(all_accelerations) if len(all_accelerations) > 1 else 0,
                'click_duration_mean': statistics.mean(all_click_durations) if all_click_durations else 0,
                'click_duration_std': statistics.stdev(all_click_durations) if len(all_click_durations) > 1 else 0,
                'sample_count': len(samples)
            }
            
            # Update or create profile
            if user_id in self.user_profiles:
                self.user_profiles[user_id].mouse_profile = mouse_profile
                self.user_profiles[user_id].last_updated = datetime.now()
            else:
                self.user_profiles[user_id] = BiometricProfile(
                    user_id=user_id,
                    keystroke_profile={},
                    mouse_profile=mouse_profile,
                    touch_profile={},
                    confidence_score=0.8,
                    last_updated=datetime.now(),
                    sample_count=len(samples),
                    is_stable=len(samples) >= 50
                )
            
            logger.info(f"Updated mouse profile for user {user_id}")
            
        except Exception as e:
            logger.error(f"Failed to update mouse profile: {e}")
    
    def _analyze_keystroke_authentication(self, user_id: str, current_pattern: Dict[str, Any], 
                                        profile: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Analyze keystroke pattern for authentication"""
        anomalies = []
        confidence = 1.0
        
        try:
            # Analyze dwell times
            current_dwell_mean = statistics.mean(current_pattern.get('dwell_times', []))
            profile_dwell_mean = profile.get('dwell_time_mean', 0)
            profile_dwell_std = profile.get('dwell_time_std', 0)
            
            if profile_dwell_std > 0:
                dwell_deviation = abs(current_dwell_mean - profile_dwell_mean) / profile_dwell_std
                if dwell_deviation > 2.0:  # 2 standard deviations
                    anomalies.append(f"Dwell time deviation: {dwell_deviation:.2f}")
                    confidence *= 0.7
            
            # Analyze flight times
            current_flight_mean = statistics.mean(current_pattern.get('flight_times', []))
            profile_flight_mean = profile.get('flight_time_mean', 0)
            profile_flight_std = profile.get('flight_time_std', 0)
            
            if profile_flight_std > 0:
                flight_deviation = abs(current_flight_mean - profile_flight_mean) / profile_flight_std
                if flight_deviation > 2.0:
                    anomalies.append(f"Flight time deviation: {flight_deviation:.2f}")
                    confidence *= 0.7
            
            # Analyze typing speed
            current_speed = current_pattern.get('typing_speed', 0)
            profile_speed_mean = profile.get('speed_mean', 0)
            profile_speed_std = profile.get('speed_std', 0)
            
            if profile_speed_std > 0 and profile_speed_mean > 0:
                speed_deviation = abs(current_speed - profile_speed_mean) / profile_speed_mean
                if speed_deviation > 0.3:  # 30% deviation
                    anomalies.append(f"Typing speed deviation: {speed_deviation:.2f}")
                    confidence *= 0.8
            
            return confidence, anomalies
            
        except Exception as e:
            logger.error(f"Keystroke analysis error: {e}")
            return 0.0, ["Analysis error"]
    
    def _analyze_mouse_authentication(self, user_id: str, current_pattern: Dict[str, Any], 
                                    profile: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Analyze mouse pattern for authentication"""
        anomalies = []
        confidence = 1.0
        
        try:
            # Analyze movement velocity
            current_velocities = current_pattern.get('movement_velocity', [])
            if current_velocities:
                current_velocity_mean = statistics.mean(current_velocities)
                profile_velocity_mean = profile.get('velocity_mean', 0)
                profile_velocity_std = profile.get('velocity_std', 0)
                
                if profile_velocity_std > 0:
                    velocity_deviation = abs(current_velocity_mean - profile_velocity_mean) / profile_velocity_std
                    if velocity_deviation > 2.0:
                        anomalies.append(f"Mouse velocity deviation: {velocity_deviation:.2f}")
                        confidence *= 0.8
            
            # Analyze click patterns
            current_clicks = current_pattern.get('click_patterns', [])
            if current_clicks:
                current_click_durations = [c.get('duration', 0) for c in current_clicks]
                current_click_mean = statistics.mean(current_click_durations)
                profile_click_mean = profile.get('click_duration_mean', 0)
                profile_click_std = profile.get('click_duration_std', 0)
                
                if profile_click_std > 0:
                    click_deviation = abs(current_click_mean - profile_click_mean) / profile_click_std
                    if click_deviation > 2.0:
                        anomalies.append(f"Click duration deviation: {click_deviation:.2f}")
                        confidence *= 0.8
            
            return confidence, anomalies
            
        except Exception as e:
            logger.error(f"Mouse analysis error: {e}")
            return 0.0, ["Analysis error"]
    
    def _analyze_touch_authentication(self, user_id: str, current_pattern: Dict[str, Any], 
                                    profile: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Analyze touch pattern for authentication (mobile devices)"""
        # Placeholder for touch pattern analysis
        # Would implement similar statistical analysis for touch patterns
        return 0.8, []
    
    def get_biometric_status(self, user_id: str) -> Dict[str, Any]:
        """Get biometric profile status for a user"""
        if user_id not in self.user_profiles:
            return {
                'profile_exists': False,
                'sample_count': 0,
                'is_stable': False,
                'last_updated': None
            }
        
        profile = self.user_profiles[user_id]
        return {
            'profile_exists': True,
            'sample_count': profile.sample_count,
            'is_stable': profile.is_stable,
            'confidence_score': profile.confidence_score,
            'last_updated': profile.last_updated.isoformat(),
            'keystroke_samples': len(self.keystroke_samples[user_id]),
            'mouse_samples': len(self.mouse_samples[user_id]),
            'touch_samples': len(self.touch_samples[user_id])
        }
    
    def detect_anomalies(self) -> List[BiometricAnomaly]:
        """Detect behavioral anomalies across all users"""
        current_anomalies = []
        
        # This would implement more sophisticated anomaly detection
        # For now, return recent anomalies
        cutoff_time = datetime.now() - timedelta(hours=1)
        current_anomalies = [
            anomaly for anomaly in self.detected_anomalies
            if anomaly.detected_at > cutoff_time
        ]
        
        return current_anomalies

# Global behavioral biometrics engine
behavioral_biometrics = BehavioralBiometricsEngine()
