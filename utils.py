"""
Cross-platform utility helpers.
"""
import os
import sys
import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

def get_project_dir():
    """Project base directory (where the code lives)."""
    return BASE_DIR

def get_logs_dir():
    return get_project_dir() / "logs"

def get_captures_dir():
    return get_project_dir() / "captures"

def get_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def is_windows():
    return sys.platform.startswith("win")

def is_linux():
    return sys.platform.startswith("linux")

def is_macos():
    return sys.platform == "darwin"

def is_admin():
    """
    Return True if running with administrative privileges on current platform.
    - Linux/macOS: checks UID == 0
    - Windows: tries to use ctypes to check admin (best-effort)
    """
    try:
        if is_windows():
            import ctypes
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                # If ctypes check fails, return False (best-effort)
                return False
        else:
            # POSIX (Linux/macOS)
            return os.geteuid() == 0
    except AttributeError:
        return False
