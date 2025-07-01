"""
Event Bus - Pub/Sub system for communication between scanners
"""

import logging
from typing import Dict, List, Callable, Any
from dataclasses import dataclass
from datetime import datetime
import threading

logger = logging.getLogger(__name__)

@dataclass
class Event:
    """Event data structure"""
    type: str
    data: Dict[str, Any]
    timestamp: datetime
    source: str
    
class EventBus:
    """
    Thread-safe event bus for scanner communication
    """
    
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._lock = threading.Lock()
        self._event_history: List[Event] = []
        self._max_history = 1000
    
    def subscribe(self, event_type: str, callback: Callable[[Event], None]):
        """
        Subscribe to an event type
        """
        with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []
            self._subscribers[event_type].append(callback)
            logger.debug(f"Subscribed to event type: {event_type}")
    
    def unsubscribe(self, event_type: str, callback: Callable[[Event], None]):
        """
        Unsubscribe from an event type
        """
        with self._lock:
            if event_type in self._subscribers:
                try:
                    self._subscribers[event_type].remove(callback)
                    logger.debug(f"Unsubscribed from event type: {event_type}")
                except ValueError:
                    logger.warning(f"Callback not found for event type: {event_type}")
    
    def publish(self, event_type: str, data: Dict[str, Any], source: str = "unknown"):
        """
        Publish an event to all subscribers
        """
        event = Event(
            type=event_type,
            data=data,
            timestamp=datetime.now(),
            source=source
        )
        
        # Store in history
        with self._lock:
            self._event_history.append(event)
            if len(self._event_history) > self._max_history:
                self._event_history.pop(0)
        
        # Notify subscribers
        subscribers = self._subscribers.get(event_type, [])
        for callback in subscribers:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in event callback for {event_type}: {e}")
        
        logger.debug(f"Published event: {event_type} from {source}")
    
    def get_event_history(self, event_type: str = None) -> List[Event]:
        """
        Get event history, optionally filtered by type
        """
        with self._lock:
            if event_type:
                return [e for e in self._event_history if e.type == event_type]
            return self._event_history.copy()
    
    def clear_history(self):
        """
        Clear event history
        """
        with self._lock:
            self._event_history.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get event bus statistics
        """
        with self._lock:
            event_counts = {}
            for event in self._event_history:
                event_counts[event.type] = event_counts.get(event.type, 0) + 1
            
            return {
                "total_events": len(self._event_history),
                "event_types": len(self._subscribers),
                "event_counts": event_counts,
                "subscribers": {
                    event_type: len(callbacks) 
                    for event_type, callbacks in self._subscribers.items()
                }
            }

# Global event bus instance
event_bus = EventBus()

# Common event types
class EventTypes:
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_ERROR = "scan_error"
    FILE_PROCESSED = "file_processed"
    VULNERABILITY_FOUND = "vulnerability_found"
    FIX_SUGGESTED = "fix_suggested"
    REPORT_GENERATED = "report_generated"
