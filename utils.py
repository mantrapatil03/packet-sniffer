"""
Cross-platform utility helpers.
Enhanced for Wireshark-style sniffing.
"""

import os
import sys
import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Directory helpers
# ---------------------------------------------------------------------------

def get_project_dir():
    return BASE_DIR


def get_logs_dir():
    d = get_project_dir() / "logs"
    d.mkdir(exist_ok=True)
    return d


def get_captures_dir():
    d = get_project_dir() / "captures"
    d.mkdir(exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def get_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_monotonic_ms():
    """High-precision timer (for packet deltas)."""
    try:
        return int(datetime.timedelta(seconds=os.times().elapsed).total_seconds() * 1000)
    except Exception:
        import time
        return int(time.monotonic() * 1000)


# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

def is_windows():
    return sys.platform.startswith("win")


def is_linux():
    return sys.platform.startswith("linux")


def is_macos():
    return sys.platform == "darwin"


# ---------------------------------------------------------------------------
# Admin privilege detection
# ---------------------------------------------------------------------------

def is_admin():
    """
    Return True if running with administrative privileges.
    - Linux/macOS: UID == 0
    - Windows: uses ctypes (best-effort)
    """

    # Linux / macOS
    if not is_windows():
        try:
            return os.geteuid() == 0
        except Exception:
            return False

    # Windows path
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        # final fallback: check environment permissions
        try:
            temp_file = Path(os.getenv("TEMP", "C:/Windows/Temp")) / "admin_test.tmp"
            with open(temp_file, "w") as f:
                f.write("test")
            temp_file.unlink()
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Network Interface helpers (Wireshark-like)
# ---------------------------------------------------------------------------

def list_interfaces():
    """Return a list of available network interfaces (cross-platform)."""
    try:
        import netifaces
        return netifaces.interfaces()
    except Exception:
        return ["lo"]


def get_default_iface():
    """
    Auto-detect the system's active network interface.
    Logic:
    - Use default gateway interface (best)
    - Else, return first non-loopback interface
    - Else, fallback to 'lo'
    """

    try:
        import netifaces

        gws = netifaces.gateways()

        # 1️⃣ Default gateway first (Wireshark logic)
        if 'default' in gws and netifaces.AF_INET in gws['default']:
            return gws['default'][netifaces.AF_INET][1]

        # 2️⃣ First non-loopback interface
        for iface in netifaces.interfaces():
            if iface != "lo":
                return iface

        # 3️⃣ Fallback
        return "lo"

    except Exception:
        return "lo"


def get_iface_ip(iface):
    """Return IPv4 address of an interface."""
    try:
        import netifaces
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            return addrs[netifaces.AF_INET][0].get("addr")
        return None
    except Exception:
        return None
