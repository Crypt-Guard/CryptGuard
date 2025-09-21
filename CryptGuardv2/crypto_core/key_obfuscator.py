# key_obfuscator.py
"""Key obfuscation using XOR masking with automatic rotation."""
from __future__ import annotations

import contextlib
import secrets
import threading
import time
import warnings
from typing import Optional, Final

from .secure_bytes import SecureBytes, secure_memzero

# Constants
DEFAULT_ROTATION_INTERVAL: Final[float] = 60.0  # seconds
MIN_KEY_SIZE: Final[int] = 16  # minimum key size in bytes
MAX_KEY_SIZE: Final[int] = 65536  # maximum key size (64KB)


class KeyObfuscator:
    """
    Obfuscate sensitive keys using XOR masking with periodic rotation.
    
    This provides a basic level of protection against casual memory inspection
    but is NOT cryptographically secure. It's designed to:
    - Prevent keys from appearing as plain strings in memory dumps
    - Make static analysis more difficult
    - Reduce the window of exposure for plaintext keys
    
    Threat model:
    - PROTECTS against: casual memory dumps, string searches, basic debugging
    - DOES NOT protect against: dedicated attackers, kernel access, cold boot attacks
    
    Features:
    - XOR masking with random mask
    - Automatic mask rotation (configurable interval)
    - Thread-safe operations
    - Controlled exposure through context managers
    
    Usage:
        # Create obfuscator from SecureBytes
        key_bytes = SecureBytes(b"my_secret_key_32_bytes_long_here")
        obf = KeyObfuscator(key_bytes)
        
        # Use with controlled exposure
        with obf.expose() as exposed_key:
            # exposed_key is a SecureBytes containing the plaintext
            use_key(exposed_key.view())
        # Key is automatically re-obfuscated after use
        
        # Manual deobfuscation (remember to clear!)
        plaintext = obf.deobfuscate()
        try:
            use_key(plaintext.view())
        finally:
            plaintext.clear()
    """
    
    __slots__ = (
        "_masked", "_mask", "_cleared", "_lock",
        "_rotation_timer", "_rotation_interval",
        "_last_rotation", "_auto_rotate", "__weakref__"
    )
    
    def __init__(
        self,
        key_sb: SecureBytes,
        *,
        auto_rotate: bool = True,
        rotation_interval: float = DEFAULT_ROTATION_INTERVAL
    ) -> None:
        """
        Initialize key obfuscator with a SecureBytes key.
        
        AVISO DE SEGURANÇA: KeyObfuscator fornece apenas OFUSCAÇÃO, não proteção 
        criptográfica. Reduz varredura casual de memória, mas não resiste a atacante dedicado.
        
        Args:
            key_sb: SecureBytes containing the key to obfuscate.
                   Will be cleared after extraction.
            auto_rotate: Whether to automatically rotate the mask periodically
            rotation_interval: Seconds between automatic rotations
            
        Raises:
            ValueError: If key is empty or less than MIN_KEY_SIZE bytes
            RuntimeError: If key_sb is already cleared
        """
        # Aviso de segurança: isto é ofuscação, não proteção criptográfica.
        # Reduz varredura casual de memória, mas não resiste a atacante dedicado.
        warnings.warn(
            "KeyObfuscator fornece apenas ofuscação; não é um cofre criptográfico.",
            RuntimeWarning, stacklevel=2
        )
        # Extract key bytes using callback pattern
        plain: Optional[bytearray] = None
        
        def extract_key(b: bytes) -> None:
            nonlocal plain
            plain = bytearray(b)
        
        try:
            key_sb.with_bytes(extract_key)
        except ValueError as e:
            if "already cleared" in str(e):
                raise RuntimeError("Cannot create obfuscator from cleared SecureBytes") from e
            raise
        
        if plain is None or len(plain) == 0:
            if plain is not None:
                secure_memzero(plain)
            key_sb.clear()
            raise ValueError("Key cannot be empty")
        
        if len(plain) < MIN_KEY_SIZE:
            secure_memzero(plain)
            key_sb.clear()
            raise ValueError(f"Key must be at least {MIN_KEY_SIZE} bytes, got {len(plain)}")
        
        if len(plain) > MAX_KEY_SIZE:
            secure_memzero(plain)
            key_sb.clear()
            raise ValueError(f"Key must be at most {MAX_KEY_SIZE} bytes, got {len(plain)}")
        
        # Initialize state
        self._lock = threading.RLock()
        self._cleared = False
        self._auto_rotate = auto_rotate
        self._rotation_interval = max(1.0, rotation_interval)  # Minimum 1 second
        self._last_rotation = time.monotonic()
        self._rotation_timer: Optional[threading.Timer] = None
        
        # Generate initial mask and apply XOR
        key_len = len(plain)
        self._mask = bytearray(secrets.token_bytes(key_len))
        self._masked = bytearray(key_len)
        
        for i in range(key_len):
            self._masked[i] = plain[i] ^ self._mask[i]
        
        # Clear the source
        secure_memzero(plain)
        key_sb.clear()
        
        # Start auto-rotation if enabled
        if self._auto_rotate:
            self._start_rotation_timer()
    
    def _start_rotation_timer(self) -> None:
        """Start the automatic rotation timer."""
        with self._lock:
            if self._cleared or self._rotation_timer is not None:
                return
            
            self._rotation_timer = threading.Timer(
                self._rotation_interval,
                self._rotate_and_reschedule
            )
            self._rotation_timer.daemon = True
            self._rotation_timer.start()
    
    def _stop_rotation_timer(self) -> None:
        """Stop the automatic rotation timer."""
        with self._lock:
            if self._rotation_timer is not None:
                self._rotation_timer.cancel()
                self._rotation_timer = None
    
    def _rotate_and_reschedule(self) -> None:
        """Timer callback to rotate mask and reschedule."""
        with self._lock:
            if not self._cleared:
                self.obfuscate()
                # Reset timer for next rotation
                self._rotation_timer = None
                if self._auto_rotate:
                    self._start_rotation_timer()
    
    @property
    def cleared(self) -> bool:
        """Check if the obfuscator has been cleared."""
        with self._lock:
            return self._cleared
    
    @property
    def time_since_rotation(self) -> float:
        """Get seconds since last mask rotation."""
        with self._lock:
            return time.monotonic() - self._last_rotation
    
    def deobfuscate(self) -> SecureBytes:
        """
        Reconstruct the original key into a new SecureBytes.
        
        Returns:
            New SecureBytes containing the plaintext key.
            Caller is responsible for clearing it after use.
            
        Raises:
            RuntimeError: If already cleared
        """
        with self._lock:
            if self._cleared:
                raise RuntimeError("KeyObfuscator has been cleared")
            
            # XOR to recover plaintext
            key_len = len(self._masked)
            plaintext = bytearray(key_len)
            
            for i in range(key_len):
                plaintext[i] = self._masked[i] ^ self._mask[i]
            
            # Create SecureBytes and clear temporary
            result = SecureBytes(plaintext)
            secure_memzero(plaintext)
            
            return result
    
    def obfuscate(self) -> None:
        """
        Re-obfuscate with a new random mask without exposing plaintext.
        
        This performs: masked' = (masked ^ old_mask) ^ new_mask
        Which equals: plaintext ^ new_mask
        """
        with self._lock:
            if self._cleared:
                return
            
            key_len = len(self._mask)
            new_mask = bytearray(secrets.token_bytes(key_len))
            
            # Update masked data: XOR out old mask, XOR in new mask
            for i in range(key_len):
                # This computes: (plaintext ^ old_mask) ^ old_mask ^ new_mask
                # Which simplifies to: plaintext ^ new_mask
                self._masked[i] = self._masked[i] ^ self._mask[i] ^ new_mask[i]
            
            # Replace old mask with new mask
            secure_memzero(self._mask)
            self._mask = new_mask
            self._last_rotation = time.monotonic()
    
    def clear(self) -> None:
        """
        Permanently clear all key material.
        
        This method is idempotent - multiple calls are safe.
        Stops any active rotation timer.
        """
        with self._lock:
            if self._cleared:
                return
            
            # Stop rotation timer
            self._stop_rotation_timer()
            
            # Zero all buffers
            secure_memzero(self._masked)
            secure_memzero(self._mask)
            
            # Clear buffers
            self._masked.clear()
            self._mask.clear()
            
            # Mark as cleared
            self._cleared = True
    
    def expose(self) -> TimedExposure:
        """
        Get a context manager for controlled key exposure.
        
        Returns:
            TimedExposure context manager that provides temporary access
            to the plaintext key and ensures cleanup.
            
        Example:
            with obf.expose() as key:
                # key is a SecureBytes containing plaintext
                use_key(key.view())
            # key is automatically cleared and mask is rotated
        """
        return TimedExposure(self)
    
    def __del__(self) -> None:
        """Ensure cleanup on destruction."""
        try:
            self.clear()
        except Exception:
            pass  # Best effort in destructor
    
    def __repr__(self) -> str:
        """Safe representation that doesn't leak key size."""
        return "<KeyObfuscator ***>"
    
    def __str__(self) -> str:
        """Safe string representation."""
        return "<KeyObfuscator ***>"


class TimedExposure(contextlib.AbstractContextManager):
    """
    Context manager for controlled exposure of obfuscated keys.
    
    Ensures that:
    - Key is only exposed within the context
    - Key is cleared after use
    - Mask is rotated after exposure
    - Thread-safe against concurrent access
    """
    
    __slots__ = ("_obfuscator", "_plaintext", "_lock", "_active")
    
    def __init__(self, obfuscator: KeyObfuscator) -> None:
        """
        Initialize exposure context.
        
        Args:
            obfuscator: KeyObfuscator instance to expose
        """
        self._obfuscator = obfuscator
        self._plaintext: Optional[SecureBytes] = None
        self._lock = threading.Lock()
        self._active = False
    
    def __enter__(self) -> SecureBytes:
        """
        Enter context and deobfuscate key.
        
        Returns:
            SecureBytes containing plaintext key
            
        Raises:
            RuntimeError: If already in use or obfuscator is cleared
        """
        with self._lock:
            if self._active:
                raise RuntimeError("TimedExposure is already active")
            if self._obfuscator.cleared:
                raise RuntimeError("Cannot expose a cleared KeyObfuscator")
            
            self._active = True
            self._plaintext = self._obfuscator.deobfuscate()
            return self._plaintext
    
    def __exit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[Exception],
        exc_tb: Optional[object]
    ) -> None:
        """
        Exit context, clear plaintext and rotate mask.
        
        Args:
            exc_type: Exception type if raised
            exc_val: Exception value if raised
            exc_tb: Exception traceback if raised
        """
        with self._lock:
            try:
                # Clear the exposed plaintext
                if self._plaintext is not None:
                    self._plaintext.clear()
                    self._plaintext = None
            finally:
                # Always rotate mask after exposure
                if not self._obfuscator.cleared:
                    self._obfuscator.obfuscate()
                
                self._active = False


# Export public API
__all__ = ["KeyObfuscator", "TimedExposure"]