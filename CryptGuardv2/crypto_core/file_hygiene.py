"""
File hygiene utilities for CryptGuard.

Provides secure file deletion and temporary file management with proper
disclaimers about limitations on SSDs and NVMe drives.
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
import time
from pathlib import Path
from typing import Callable

from .log_utils import log_best_effort
from .paths import BASE_DIR

logger = logging.getLogger("crypto_core")

# Temporary folder for CryptGuard operations
HYGIENE_TEMP_DIR = BASE_DIR / "temp"

# SSD detection cache
_SSD_CACHE: dict[str, bool] = {}


class SecureFileShredder:
    """
    Secure file deletion with overwrite + rename + delete pattern.
    
    WARNING: On SSDs and NVMe drives, overwrite-based secure deletion is NOT
    fully effective due to:
    - Wear leveling: Controller redistributes writes across physical cells
    - Over-provisioning: Hidden spare cells may retain old data
    - TRIM: OS may discard data before overwrite completes
    
    For maximum security on SSDs:
    - Use full-disk encryption (BitLocker, LUKS, FileVault)
    - Physically destroy drives when decommissioning
    - Rely on encryption at rest rather than secure deletion
    
    This implementation provides best-effort deletion suitable for:
    - Quick cleanup of temporary files
    - Reducing forensic recovery on HDDs
    - Defense-in-depth alongside encryption
    """

    def __init__(self, passes: int = 3, chunk_size: int = 1024 * 1024):
        """
        Initialize shredder.
        
        Args:
            passes: Number of overwrite passes (1-7 recommended)
            chunk_size: Size of chunks for overwriting large files
        """
        self.passes = max(1, min(passes, 7))  # Clamp to 1-7
        self.chunk_size = chunk_size

    def shred_file(
        self,
        path: str | Path,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> bool:
        """
        Securely delete a file using overwrite + rename + delete.
        
        Args:
            path: Path to file to delete
            progress_callback: Optional callback(current_pass, total_passes)
        
        Returns:
            True if deletion succeeded, False otherwise
        """
        p = Path(path)
        
        if not p.exists():
            logger.debug("File does not exist: %s", p)
            return True
        
        if p.is_dir():
            logger.warning("Cannot shred directory: %s", p)
            return False
        
        # Check if on SSD and warn
        if is_ssd(p):
            logger.warning(
                "File %s is on SSD/NVMe - secure deletion not fully effective. "
                "Consider using full-disk encryption for data protection.",
                p.name
            )
        
        try:
            size = p.stat().st_size
        except Exception as exc:
            logger.error("Cannot stat file %s: %s", p, exc)
            return False
        
        # Overwrite passes
        try:
            with open(p, "r+b", buffering=0) as f:
                for pass_num in range(self.passes):
                    if progress_callback:
                        progress_callback(pass_num + 1, self.passes)
                    
                    f.seek(0)
                    remaining = size
                    while remaining > 0:
                        n = min(self.chunk_size, remaining)
                        f.write(os.urandom(n))
                        remaining -= n
                    
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except Exception as exc:
                        log_best_effort(__name__, exc)
                
                # Truncate
                try:
                    f.seek(0)
                    f.truncate(0)
                except Exception as exc:
                    log_best_effort(__name__, exc)
        
        except Exception as exc:
            logger.warning("Failed to overwrite %s: %s", p, exc)
            # Continue to rename/delete even if overwrite failed
        
        # Rename to break file system links
        try:
            new_name = p.with_name(f".deleted_{int(time.time())}_{p.name}")
            p.rename(new_name)
            p = new_name
        except Exception as exc:
            log_best_effort(__name__, exc)
        
        # Final deletion
        try:
            p.unlink(missing_ok=True)
            logger.info("Securely deleted file: %s", path)
            return True
        except Exception as exc:
            logger.error("Failed to delete %s: %s", p, exc)
            return False

    def shred_directory(self, path: str | Path) -> bool:
        """
        Recursively delete a directory (best-effort, no overwrite for dirs).
        
        Args:
            path: Directory path to delete
        
        Returns:
            True if deletion succeeded, False otherwise
        """
        p = Path(path)
        
        if not p.exists():
            return True
        
        if not p.is_dir():
            return self.shred_file(p)
        
        try:
            # Shred all files first
            for item in p.rglob("*"):
                if item.is_file():
                    self.shred_file(item)
            
            # Remove empty directories
            shutil.rmtree(p, ignore_errors=True)
            logger.info("Deleted directory: %s", path)
            return True
        except Exception as exc:
            logger.error("Failed to delete directory %s: %s", p, exc)
            return False


class TempFolderManager:
    """
    Manages CryptGuard's temporary folder for intermediate files.
    
    Structure:
        <BASE_DIR>/temp/
            archives/       - Temporary ZIP archives
            decrypt/        - Temporary decrypted files
            .cleanup_log    - Last cleanup timestamp
    """

    def __init__(self, temp_dir: Path | None = None):
        """
        Initialize temp folder manager.
        
        Args:
            temp_dir: Custom temp directory (defaults to HYGIENE_TEMP_DIR)
        """
        self.temp_dir = Path(temp_dir) if temp_dir else HYGIENE_TEMP_DIR
        self.archives_dir = self.temp_dir / "archives"
        self.decrypt_dir = self.temp_dir / "decrypt"
        self.cleanup_log = self.temp_dir / ".cleanup_log"

    def ensure_dirs(self) -> None:
        """Create temp directory structure if it doesn't exist."""
        try:
            self.temp_dir.mkdir(parents=True, exist_ok=True)
            self.archives_dir.mkdir(exist_ok=True)
            self.decrypt_dir.mkdir(exist_ok=True)
            
            # Set restrictive permissions on POSIX
            if os.name != "nt":
                try:
                    self.temp_dir.chmod(0o700)
                    self.archives_dir.chmod(0o700)
                    self.decrypt_dir.chmod(0o700)
                except Exception as exc:
                    log_best_effort(__name__, exc)
        except Exception as exc:
            logger.error("Failed to create temp directories: %s", exc)

    def cleanup(
        self,
        max_age_hours: int = 24,
        dry_run: bool = False,
    ) -> tuple[int, int]:
        """
        Clean up old files from temp directory.
        
        Args:
            max_age_hours: Delete files older than this many hours
            dry_run: If True, only report what would be deleted
        
        Returns:
            Tuple of (files_removed, bytes_freed)
        """
        if not self.temp_dir.exists():
            return 0, 0
        
        cutoff_time = time.time() - (max_age_hours * 3600)
        files_removed = 0
        bytes_freed = 0
        
        try:
            for item in self.temp_dir.rglob("*"):
                if not item.is_file():
                    continue
                
                # Skip cleanup log
                if item.name == ".cleanup_log":
                    continue
                
                try:
                    # Check if file is old enough
                    mtime = item.stat().st_mtime
                    if mtime > cutoff_time:
                        continue
                    
                    # Check if file is locked (in use)
                    if self._is_file_locked(item):
                        logger.debug("Skipping locked file: %s", item)
                        continue
                    
                    file_size = item.stat().st_size
                    
                    if not dry_run:
                        item.unlink()
                        logger.debug("Cleaned temp file: %s", item)
                    
                    files_removed += 1
                    bytes_freed += file_size
                
                except Exception as exc:
                    log_best_effort(__name__, exc)
            
            # Update cleanup log
            if not dry_run and files_removed > 0:
                try:
                    self.cleanup_log.write_text(
                        f"{time.time()}\n{files_removed}\n{bytes_freed}\n",
                        encoding="utf-8"
                    )
                except Exception as exc:
                    log_best_effort(__name__, exc)
        
        except Exception as exc:
            logger.error("Temp cleanup failed: %s", exc)
        
        return files_removed, bytes_freed

    def get_temp_stats(self) -> dict[str, int]:
        """
        Get statistics about temp folder.
        
        Returns:
            Dict with 'file_count' and 'total_bytes'
        """
        if not self.temp_dir.exists():
            return {"file_count": 0, "total_bytes": 0}
        
        file_count = 0
        total_bytes = 0
        
        try:
            for item in self.temp_dir.rglob("*"):
                if item.is_file() and item.name != ".cleanup_log":
                    file_count += 1
                    try:
                        total_bytes += item.stat().st_size
                    except Exception:
                        pass
        except Exception as exc:
            logger.error("Failed to get temp stats: %s", exc)
        
        return {"file_count": file_count, "total_bytes": total_bytes}

    @staticmethod
    def _is_file_locked(path: Path) -> bool:
        """
        Check if a file is locked (in use).
        
        Args:
            path: File path to check
        
        Returns:
            True if file is locked, False otherwise
        """
        try:
            # Try to open for exclusive write
            with open(path, "r+b") as f:
                pass
            return False
        except (PermissionError, OSError):
            return True


def is_ssd(path: str | Path) -> bool:
    """
    Detect if a path is on an SSD or NVMe drive.
    
    Note: Detection is best-effort and may not be 100% accurate.
    
    Args:
        path: File or directory path to check
    
    Returns:
        True if likely on SSD, False if likely on HDD or unknown
    """
    p = Path(path).resolve()
    
    # Use cache to avoid repeated checks
    cache_key = str(p.drive if hasattr(p, 'drive') else p.anchor)
    if cache_key in _SSD_CACHE:
        return _SSD_CACHE[cache_key]
    
    is_solid_state = False
    
    try:
        system = platform.system()
        
        if system == "Windows":
            is_solid_state = _detect_ssd_windows(p)
        elif system == "Linux":
            is_solid_state = _detect_ssd_linux(p)
        elif system == "Darwin":
            is_solid_state = _detect_ssd_macos(p)
        else:
            # Unknown system, assume SSD for safety (show warnings)
            is_solid_state = True
    
    except Exception as exc:
        log_best_effort(__name__, exc)
        # On error, assume SSD for safety
        is_solid_state = True
    
    _SSD_CACHE[cache_key] = is_solid_state
    return is_solid_state


def _detect_ssd_windows(path: Path) -> bool:
    """Windows SSD detection using WMI or disk properties."""
    try:
        import subprocess
        
        # Get the drive letter
        drive = path.drive if hasattr(path, 'drive') and path.drive else "C:"
        
        # Use PowerShell to check disk media type
        cmd = f'Get-PhysicalDisk | Where-Object {{$_.DeviceID -eq (Get-Partition -DriveLetter "{drive[0]}").DiskNumber}} | Select-Object -ExpandProperty MediaType'
        result = subprocess.run(
            ["powershell", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        
        if result.returncode == 0:
            media_type = result.stdout.strip().lower()
            return "ssd" in media_type or "nvme" in media_type
    
    except Exception as exc:
        log_best_effort(__name__, exc)
    
    return False


def _detect_ssd_linux(path: Path) -> bool:
    """Linux SSD detection using /sys/block."""
    try:
        import subprocess
        
        # Get the device for this path
        result = subprocess.run(
            ["df", str(path)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        
        if result.returncode != 0:
            return False
        
        # Parse device name (e.g., /dev/sda1 -> sda)
        lines = result.stdout.strip().split("\n")
        if len(lines) < 2:
            return False
        
        device = lines[1].split()[0]  # e.g., /dev/sda1
        device_name = device.replace("/dev/", "").rstrip("0123456789")
        
        # Check rotational flag
        rotational_file = Path(f"/sys/block/{device_name}/queue/rotational")
        if rotational_file.exists():
            rotational = rotational_file.read_text().strip()
            return rotational == "0"  # 0 = SSD, 1 = HDD
    
    except Exception as exc:
        log_best_effort(__name__, exc)
    
    return False


def _detect_ssd_macos(path: Path) -> bool:
    """macOS SSD detection using diskutil."""
    try:
        import subprocess
        
        result = subprocess.run(
            ["diskutil", "info", str(path)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        
        if result.returncode == 0:
            output = result.stdout.lower()
            return "solid state" in output or "ssd" in output
    
    except Exception as exc:
        log_best_effort(__name__, exc)
    
    return False


def get_temp_dir() -> Path:
    """
    Get CryptGuard's temporary directory path.
    
    Returns:
        Path to temp directory
    """
    return HYGIENE_TEMP_DIR


def cleanup_temp_folder(max_age_hours: int = 24, dry_run: bool = False) -> tuple[int, int]:
    """
    Clean up CryptGuard's temporary folder.
    
    Args:
        max_age_hours: Delete files older than this many hours
        dry_run: If True, only report what would be deleted
    
    Returns:
        Tuple of (files_removed, bytes_freed)
    """
    manager = TempFolderManager()
    manager.ensure_dirs()
    return manager.cleanup(max_age_hours, dry_run)


def secure_delete_file(
    path: str | Path,
    passes: int = 3,
    progress_callback: Callable[[int, int], None] | None = None,
) -> bool:
    """
    Securely delete a file with overwrite + rename + delete.
    
    WARNING: Not fully effective on SSDs/NVMe drives due to wear leveling.
    Use full-disk encryption for data protection on SSDs.
    
    Args:
        path: Path to file to delete
        passes: Number of overwrite passes (1-7)
        progress_callback: Optional callback(current_pass, total_passes)
    
    Returns:
        True if deletion succeeded, False otherwise
    """
    shredder = SecureFileShredder(passes=passes)
    return shredder.shred_file(path, progress_callback)


__all__ = [
    "SecureFileShredder",
    "TempFolderManager",
    "is_ssd",
    "get_temp_dir",
    "cleanup_temp_folder",
    "secure_delete_file",
    "HYGIENE_TEMP_DIR",
]
