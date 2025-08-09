"""Legacy operations for .enc+.meta format backward compatibility."""
from __future__ import annotations
from pathlib import Path

def decrypt_legacy(in_path: str|Path, out_path: str|Path, password: str|bytes) -> Path:
    """Decrypt legacy .enc+.meta format."""
    if isinstance(password, str):
        password = password.encode()
    
    # This is a placeholder - you should implement this based on your existing
    # decrypt logic for .enc+.meta files
    raise NotImplementedError(
        "Legacy decrypt needs to be implemented based on your existing .enc+.meta logic. "
        "Move your current decrypt implementation here."
    )
