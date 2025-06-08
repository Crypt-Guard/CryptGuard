"""File permission utilities for CryptGuard."""

import os
import platform
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def secure_permissions(path: Path) -> None:
    try:
        if platform.system() == "Windows":
            _secure_permissions_windows(path)
        else:
            _secure_permissions_unix(path)
    except Exception as e:
        logger.warning("Failed to set permissions on %s: %s", path, e)


def _secure_permissions_windows(path: Path) -> None:
    try:
        import win32security
        import win32api
        import ntsecuritycon as nsec

        user_name = win32api.GetUserName()
        user_sid, _, _ = win32security.LookupAccountName(None, user_name)
        dacl = win32security.ACL()
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            nsec.FILE_GENERIC_READ | nsec.FILE_GENERIC_WRITE | nsec.DELETE,
            user_sid,
        )
        sd = win32security.SECURITY_DESCRIPTOR()
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(
            str(path), win32security.DACL_SECURITY_INFORMATION, sd
        )
        logger.debug("Applied Windows ACL on %s", path)
    except ImportError:
        os.chmod(path, 0o600)
        logger.info("pywin32 unavailable, used chmod on %s", path)
    except Exception as e:
        os.chmod(path, 0o600)
        logger.warning("ACL error on %s: %s", path, e)


def _secure_permissions_unix(path: Path) -> None:
    os.chmod(path, 0o600)
    logger.debug("POSIX permissions set to 600 on %s", path)


def verify_permissions(path: Path) -> bool:
    try:
        stat = path.stat()
        if platform.system() != "Windows":
            if stat.st_mode & 0o077:
                logger.warning("Permissions too open: %o", stat.st_mode & 0o777)
                return False
        return True
    except Exception as e:
        logger.error("Permission check failed on %s: %s", path, e)
        return False
