"""
Circuit Breaker Pattern Implementation

Provides fault tolerance and resilience for the identity threat response system.
Prevents cascading failures and provides graceful degradation.
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from enum import Enum
from dataclasses import dataclass


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, requests blocked
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration"""
    failure_threshold: int = 5  # Number of failures before opening
    timeout_seconds: int = 300  # Time to wait before testing (5 minutes)
    recovery_time_seconds: int = 600  # Time to wait before closing (10 minutes)
    success_threshold: int = 3  # Successes needed to close from half-open
    monitoring_window_seconds: int = 60  # Time window for failure counting


class CircuitBreaker:
    """
    Circuit breaker implementation for identity threat response operations
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize circuit breaker"""
        self.config = CircuitBreakerConfig(
            failure_threshold=config.get('failure_threshold', 5),
            timeout_seconds=config.get('timeout_seconds', 300),
            recovery_time_seconds=config.get('recovery_time_seconds', 600),
            success_threshold=config.get('success_threshold', 3),
            monitoring_window_seconds=config.get('monitoring_window_seconds', 60)
        )
        
        # Current state
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[float] = None
        self.last_success_time: Optional[float] = None
        self.state_change_time = time.time()
        
        # Failure tracking within monitoring window
        self.failure_timestamps = []
        
        # Statistics
        self.total_requests = 0
        self.total_failures = 0
        self.total_successes = 0
        self.state_transitions = []
        
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Circuit breaker initialized in {self.state.value} state")

    async def can_execute(self) -> bool:
        """
        Check if circuit breaker allows execution
        
        Returns:
            True if execution is allowed, False otherwise
        """
        current_time = time.time()
        
        # Clean old failure timestamps
        self._clean_old_failures(current_time)
        
        if self.state == CircuitState.CLOSED:
            # Normal operation - check if we've exceeded failure threshold
            if len(self.failure_timestamps) >= self.config.failure_threshold:
                await self._transition_to_open()
                return False
            return True
        
        elif self.state == CircuitState.OPEN:
            # Check if timeout period has passed
            if (current_time - self.state_change_time) >= self.config.timeout_seconds:
                await self._transition_to_half_open()
                return True
            return False
        
        elif self.state == CircuitState.HALF_OPEN:
            # Allow limited requests to test if service recovered
            return True
        
        return False

    async def record_success(self) -> None:
        """Record a successful operation"""
        current_time = time.time()
        
        self.total_requests += 1
        self.total_successes += 1
        self.last_success_time = current_time
        
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            
            # Check if we have enough successes to close circuit
            if self.success_count >= self.config.success_threshold:
                await self._transition_to_closed()
        
        elif self.state == CircuitState.OPEN:
            # Shouldn't happen, but handle gracefully
            self.logger.warning("Recorded success while circuit is open")
        
        self.logger.debug(f"Recorded success. State: {self.state.value}, Success count: {self.success_count}")

    async def record_failure(self) -> None:
        """Record a failed operation"""
        current_time = time.time()
        
        self.total_requests += 1
        self.total_failures += 1
        self.last_failure_time = current_time
        self.failure_timestamps.append(current_time)
        
        # Clean old failures
        self._clean_old_failures(current_time)
        
        if self.state == CircuitState.CLOSED:
            # Check if we should open the circuit
            if len(self.failure_timestamps) >= self.config.failure_threshold:
                await self._transition_to_open()
        
        elif self.state == CircuitState.HALF_OPEN:
            # Failure during half-open means service still not recovered
            await self._transition_to_open()
        
        self.logger.debug(f"Recorded failure. State: {self.state.value}, Recent failures: {len(self.failure_timestamps)}")

    def _clean_old_failures(self, current_time: float) -> None:
        """Remove failure timestamps outside monitoring window"""
        cutoff_time = current_time - self.config.monitoring_window_seconds
        self.failure_timestamps = [
            timestamp for timestamp in self.failure_timestamps 
            if timestamp > cutoff_time
        ]

    async def _transition_to_open(self) -> None:
        """Transition circuit to OPEN state"""
        if self.state != CircuitState.OPEN:
            old_state = self.state
            self.state = CircuitState.OPEN
            self.state_change_time = time.time()
            self.success_count = 0
            
            self._record_state_transition(old_state, CircuitState.OPEN)
            
            self.logger.warning(
                f"Circuit breaker opened due to {len(self.failure_timestamps)} failures "
                f"in {self.config.monitoring_window_seconds} seconds"
            )
            
            # Optionally trigger alerts
            await self._send_circuit_alert("opened")

    async def _transition_to_half_open(self) -> None:
        """Transition circuit to HALF_OPEN state"""
        if self.state != CircuitState.HALF_OPEN:
            old_state = self.state
            self.state = CircuitState.HALF_OPEN
            self.state_change_time = time.time()
            self.success_count = 0
            
            self._record_state_transition(old_state, CircuitState.HALF_OPEN)
            
            self.logger.info("Circuit breaker moved to half-open state for testing")

    async def _transition_to_closed(self) -> None:
        """Transition circuit to CLOSED state"""
        if self.state != CircuitState.CLOSED:
            old_state = self.state
            self.state = CircuitState.CLOSED
            self.state_change_time = time.time()
            self.failure_count = 0
            self.success_count = 0
            self.failure_timestamps.clear()
            
            self._record_state_transition(old_state, CircuitState.CLOSED)
            
            self.logger.info("Circuit breaker closed - service appears to have recovered")
            
            # Optionally trigger alerts
            await self._send_circuit_alert("closed")

    def _record_state_transition(self, from_state: CircuitState, to_state: CircuitState) -> None:
        """Record state transition for analytics"""
        transition = {
            'timestamp': datetime.now(),
            'from_state': from_state.value,
            'to_state': to_state.value,
            'failure_count': len(self.failure_timestamps),
            'total_failures': self.total_failures,
            'total_successes': self.total_successes
        }
        
        self.state_transitions.append(transition)
        
        # Keep only last 100 transitions
        if len(self.state_transitions) > 100:
            self.state_transitions = self.state_transitions[-100:]

    async def _send_circuit_alert(self, action: str) -> None:
        """Send alert about circuit breaker state change"""
        # This would integrate with the notification system
        # For now, just log it
        self.logger.info(f"Circuit breaker {action} - consider investigating service health")

    async def get_state(self) -> Dict[str, Any]:
        """Get current circuit breaker state and statistics"""
        current_time = time.time()
        self._clean_old_failures(current_time)
        
        return {
            'state': self.state.value,
            'failure_count_recent': len(self.failure_timestamps),
            'success_count_current': self.success_count,
            'total_requests': self.total_requests,
            'total_failures': self.total_failures,
            'total_successes': self.total_successes,
            'failure_rate': self.total_failures / max(1, self.total_requests),
            'last_failure_time': datetime.fromtimestamp(self.last_failure_time).isoformat() if self.last_failure_time else None,
            'last_success_time': datetime.fromtimestamp(self.last_success_time).isoformat() if self.last_success_time else None,
            'state_change_time': datetime.fromtimestamp(self.state_change_time).isoformat(),
            'time_since_state_change': current_time - self.state_change_time,
            'config': {
                'failure_threshold': self.config.failure_threshold,
                'timeout_seconds': self.config.timeout_seconds,
                'recovery_time_seconds': self.config.recovery_time_seconds,
                'success_threshold': self.config.success_threshold,
                'monitoring_window_seconds': self.config.monitoring_window_seconds
            }
        }

    async def get_health_metrics(self) -> Dict[str, Any]:
        """Get detailed health metrics"""
        state = await self.get_state()
        
        # Calculate additional metrics
        recent_failure_rate = len(self.failure_timestamps) / max(1, self.config.monitoring_window_seconds / 60)  # failures per minute
        
        # Service health assessment
        health_score = 100
        if self.state == CircuitState.OPEN:
            health_score = 0
        elif self.state == CircuitState.HALF_OPEN:
            health_score = 25
        elif recent_failure_rate > self.config.failure_threshold / 2:
            health_score = 50
        
        return {
            **state,
            'health_metrics': {
                'health_score': health_score,
                'recent_failure_rate_per_minute': recent_failure_rate,
                'uptime_percentage': (self.total_successes / max(1, self.total_requests)) * 100,
                'mean_time_between_failures': self._calculate_mtbf(),
                'recent_state_transitions': self.state_transitions[-10:] if self.state_transitions else []
            }
        }

    def _calculate_mtbf(self) -> Optional[float]:
        """Calculate Mean Time Between Failures in seconds"""
        if len(self.state_transitions) < 2:
            return None
        
        failure_transitions = [
            t for t in self.state_transitions 
            if t['to_state'] == CircuitState.OPEN.value
        ]
        
        if len(failure_transitions) < 2:
            return None
        
        time_diffs = []
        for i in range(1, len(failure_transitions)):
            time_diff = (failure_transitions[i]['timestamp'] - failure_transitions[i-1]['timestamp']).total_seconds()
            time_diffs.append(time_diff)
        
        return sum(time_diffs) / len(time_diffs) if time_diffs else None

    async def reset(self) -> None:
        """Reset circuit breaker to initial state"""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.last_success_time = None
        self.state_change_time = time.time()
        self.failure_timestamps.clear()
        
        self.logger.info("Circuit breaker manually reset to closed state")

    async def force_open(self) -> None:
        """Manually force circuit breaker to open state"""
        await self._transition_to_open()
        self.logger.warning("Circuit breaker manually forced to open state")

    async def is_healthy(self) -> bool:
        """Simple health check"""
        return self.state in [CircuitState.CLOSED, CircuitState.HALF_OPEN]

    def __str__(self) -> str:
        return f"CircuitBreaker(state={self.state.value}, failures={len(self.failure_timestamps)})"

    def __repr__(self) -> str:
        return (f"CircuitBreaker(state={self.state.value}, "
                f"recent_failures={len(self.failure_timestamps)}, "
                f"total_requests={self.total_requests}, "
                f"total_failures={self.total_failures})")


class CircuitBreakerDecorator:
    """
    Decorator for applying circuit breaker pattern to functions
    """
    
    def __init__(self, circuit_breaker: CircuitBreaker):
        self.circuit_breaker = circuit_breaker

    def __call__(self, func):
        async def wrapper(*args, **kwargs):
            # Check if circuit breaker allows execution
            if not await self.circuit_breaker.can_execute():
                raise CircuitBreakerOpenError("Circuit breaker is open - request blocked")
            
            try:
                # Execute the function
                result = await func(*args, **kwargs)
                
                # Record success
                await self.circuit_breaker.record_success()
                
                return result
                
            except Exception as e:
                # Record failure
                await self.circuit_breaker.record_failure()
                
                # Re-raise the exception
                raise e
        
        return wrapper


class CircuitBreakerOpenError(Exception):
    """Exception raised when circuit breaker blocks a request"""
    pass


class CircuitBreakerManager:
    """
    Manages multiple circuit breakers for different services/operations
    """
    
    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.logger = logging.getLogger(__name__)

    def add_circuit_breaker(self, name: str, config: Dict[str, Any]) -> CircuitBreaker:
        """Add a named circuit breaker"""
        circuit_breaker = CircuitBreaker(config)
        self.circuit_breakers[name] = circuit_breaker
        self.logger.info(f"Added circuit breaker: {name}")
        return circuit_breaker

    def get_circuit_breaker(self, name: str) -> Optional[CircuitBreaker]:
        """Get circuit breaker by name"""
        return self.circuit_breakers.get(name)

    async def get_all_states(self) -> Dict[str, Dict[str, Any]]:
        """Get states of all circuit breakers"""
        states = {}
        for name, circuit_breaker in self.circuit_breakers.items():
            states[name] = await circuit_breaker.get_state()
        return states

    async def reset_all(self) -> None:
        """Reset all circuit breakers"""
        for circuit_breaker in self.circuit_breakers.values():
            await circuit_breaker.reset()
        self.logger.info("Reset all circuit breakers")

    async def health_check(self) -> Dict[str, bool]:
        """Check health of all circuit breakers"""
        health = {}
        for name, circuit_breaker in self.circuit_breakers.items():
            health[name] = await circuit_breaker.is_healthy()
        return health