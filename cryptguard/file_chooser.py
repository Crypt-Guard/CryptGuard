# file_chooser.py
"""
Provides a graphical interface for selecting files to encrypt or decrypt.
"""

import tkinter as tk
from tkinter import filedialog

def select_file_for_encryption() -> str:
    """
    Opens a dialog to select a single file for encryption.
    Returns the absolute path or an empty string if canceled or on error.
    """
    try:
        root = tk.Tk()
        root.withdraw()

        # Force the window to the top
        root.attributes('-topmost', True)
        root.lift()
        root.focus_force()
        root.update()

        file_path = filedialog.askopenfilename(
            title="Select the file to encrypt",
            filetypes=[("All files", "*.*")]
        )

        root.destroy()
        return file_path if file_path else ""
    except Exception as e:
        print(f"Error opening file dialog: {e}")
        return ""


def select_files_for_decryption() -> tuple:
    """
    Opens a dialog to select one or more files for decryption (e.g., .enc and .meta).
    Returns (file1, file2) or (None, None) if canceled or on error.
    """
    try:
        root = tk.Tk()
        root.withdraw()

        # Force the window to the top
        root.attributes('-topmost', True)
        root.lift()
        root.focus_force()
        root.update()

        files = filedialog.askopenfilenames(
            title="Select file(s) for decryption (.enc, .meta)",
            filetypes=[
                ("Encrypted files", "*.enc"),
                ("Metadata files", "*.meta"),
                ("All files", "*.*")
            ]
        )

        root.destroy()

        if not files:
            return None, None

        # Limit to 2 files for simplicity
        file1 = files[0] if len(files) > 0 else None
        file2 = files[1] if len(files) > 1 else None

        return file1, file2
    except Exception as e:
        print(f"Error opening file dialog: {e}")
        return None, None
