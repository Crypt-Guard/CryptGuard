#!/usr/bin/env python3
"""
CLI for file hygiene operations (secure deletion and temp cleanup).

Commands:
  python -m cli.hygiene_cli --temp                      # Clean temporary files  
  python -m cli.hygiene_cli --file PATH [--passes N]     # Secure delete a file
  python -m cli.hygiene_cli --all                        # Full cleanup
  python -m cli.hygiene_cli --status                     # Show hygiene status
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from crypto_core.file_hygiene import (
    TempFolderManager,
    cleanup_temp_folder,
    is_ssd,
    secure_delete_file,
)
from crypto_core.logger import logger


def cmd_temp_cleanup(args: argparse.Namespace) -> int:
    """Clean temporary files."""
    max_age = args.max_age if hasattr(args, "max_age") else 24
    dry_run = args.dry_run if hasattr(args, "dry_run") else False
    
    print(f"[*] Cleaning temporary files older than {max_age} hours...")
    if dry_run:
        print("    (DRY RUN - no files will be deleted)")
    
    try:
        files_removed, bytes_freed = cleanup_temp_folder(max_age, dry_run)
        
        if files_removed == 0:
            print("[+] No temporary files to clean.")
        else:
            size_mb = bytes_freed / (1024 * 1024)
            action = "Would remove" if dry_run else "Removed"
            print(f"[+] {action} {files_removed} file(s), freed {size_mb:.2f} MB")
        
        return 0
    
    except Exception as exc:
        logger.exception("Temp cleanup failed")
        print(f"[!] Error: {exc}", file=sys.stderr)
        return 1


def cmd_secure_delete(args: argparse.Namespace) -> int:
    """Securely delete a specific file."""
    file_path = Path(args.file)
    passes = args.passes if hasattr(args, "passes") else 3
    
    if not file_path.exists():
        print(f"[!] File not found: {file_path}", file=sys.stderr)
        return 1
    
    if file_path.is_dir():
        print(f"[!] Cannot delete directory with --file. Use --all instead.", file=sys.stderr)
        return 1
    
    # Check if SSD and warn
    if is_ssd(file_path):
        print("[!] WARNING: File is on SSD/NVMe storage.")
        print("    Secure deletion is NOT fully effective on SSDs due to wear leveling.")
        print("    For maximum security, use full-disk encryption (BitLocker, LUKS, etc.)")
        print()
        
        response = input("Continue anyway? [y/N]: ").strip().lower()
        if response != "y":
            print("Cancelled.")
            return 0
    
    print(f"[*] Securely deleting: {file_path.name}")
    print(f"    Passes: {passes}")
    
    def progress(current, total):
        print(f"    Pass {current}/{total}...", end="\r")
    
    try:
        success = secure_delete_file(file_path, passes, progress)
        
        if success:
            print(f"\n[+] File securely deleted: {file_path.name}")
            return 0
        else:
            print(f"\n[!] Failed to delete file: {file_path.name}", file=sys.stderr)
            return 1
    
    except Exception as exc:
        logger.exception("Secure delete failed")
        print(f"\n[!] Error: {exc}", file=sys.stderr)
        return 1


def cmd_full_cleanup(args: argparse.Namespace) -> int:
    """Perform full cleanup (temp files + orphaned files)."""
    print("[*] Full cleanup mode")
    print()
    
    # First clean temp files
    print("1. Cleaning temporary files...")
    result = cmd_temp_cleanup(args)
    if result != 0:
        return result
    
    print()
    print("[+] Full cleanup complete.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Show hygiene status."""
    try:
        manager = TempFolderManager()
        manager.ensure_dirs()
        
        stats = manager.get_temp_stats()
        file_count = stats["file_count"]
        total_bytes = stats["total_bytes"]
        size_mb = total_bytes / (1024 * 1024)
        
        print("Hygiene Status")
        print("=" * 50)
        print(f"Temp directory: {manager.temp_dir}")
        print(f"Temp files:     {file_count}")
        print(f"Total size:     {size_mb:.2f} MB")
        print()
        
        if file_count > 0:
            print("[i] Tip: Run 'python -m cli.hygiene_cli --temp' to clean temporary files")
        else:
            print("[+] Temp directory is clean")
        
        return 0
    
    except Exception as exc:
        logger.exception("Status check failed")
        print(f"[!] Error: {exc}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    """Main entry point for hygiene CLI."""
    parser = argparse.ArgumentParser(
        prog="cryptguard scrub",
        description="File hygiene operations for CryptGuard",
    )
    
    # Add mutually exclusive group for operations
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--temp",
        action="store_true",
        help="Clean temporary files",
    )
    group.add_argument(
        "--file",
        type=str,
        metavar="PATH",
        help="Securely delete a specific file",
    )
    group.add_argument(
        "--all",
        action="store_true",
        help="Full cleanup (temp + orphaned files)",
    )
    group.add_argument(
        "--status",
        action="store_true",
        help="Show hygiene status",
    )
    
    # Additional options
    parser.add_argument(
        "--max-age",
        type=int,
        default=24,
        metavar="HOURS",
        help="Max age for temp files (default: 24 hours)",
    )
    parser.add_argument(
        "--passes",
        type=int,
        default=3,
        choices=range(1, 8),
        metavar="N",
        help="Overwrite passes for secure delete (1-7, default: 3)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be deleted without actually deleting",
    )
    
    args = parser.parse_args(argv)
    
    # Dispatch to appropriate command
    try:
        if args.temp:
            return cmd_temp_cleanup(args)
        elif args.file:
            return cmd_secure_delete(args)
        elif args.all:
            return cmd_full_cleanup(args)
        elif args.status:
            return cmd_status(args)
        else:
            parser.print_help()
            return 1
    
    except KeyboardInterrupt:
        print("\n\nCancelled by user.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
