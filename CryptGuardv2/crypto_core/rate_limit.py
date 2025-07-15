"""
Rate limiting module for CryptGuard v2
"""
import time
from typing import Dict, Optional

# Simple rate limiting state
_failure_counts: Dict[str, int] = {}
_last_attempt: Dict[str, float] = {}

def check_allowed(identifier: str = "default", max_failures: int = 5, lockout_time: float = 300.0) -> bool:
    """
    Check if an operation is allowed based on failure count and time.
    
    Args:
        identifier: Unique identifier for the operation
        max_failures: Maximum number of failures before lockout
        lockout_time: Time in seconds to wait after max failures
    
    Returns:
        True if operation is allowed, False if rate limited
    """
    current_time = time.time()
    
    # Check if we're in lockout period
    if identifier in _last_attempt:
        time_since_last = current_time - _last_attempt[identifier]
        failures = _failure_counts.get(identifier, 0)
        
        if failures >= max_failures and time_since_last < lockout_time:
            return False
        
        # Reset if lockout period has passed
        if time_since_last >= lockout_time:
            _failure_counts[identifier] = 0
    
    return True

def register_failure(identifier: str = "default") -> None:
    """
    Register a failure for the given identifier.
    
    Args:
        identifier: Unique identifier for the operation
    """
    current_time = time.time()
    _failure_counts[identifier] = _failure_counts.get(identifier, 0) + 1
    _last_attempt[identifier] = current_time

def reset(identifier: str = "default") -> None:
    """
    Reset the failure count for the given identifier.
    
    Args:
        identifier: Unique identifier for the operation
    """
    _failure_counts.pop(identifier, None)
    _last_attempt.pop(identifier, None)

def get_failure_count(identifier: str = "default") -> int:
    """
    Get the current failure count for an identifier.
    
    Args:
        identifier: Unique identifier for the operation
    
    Returns:
        Current failure count
    """
    return _failure_counts.get(identifier, 0)
