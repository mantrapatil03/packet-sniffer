"""
Logging + PCAP saving with cross-platform safe paths.
Uses scapy.utils.PcapWriter to write PCAP incrementally.
"""

import threading
from scapy.utils import PcapWriter
from pathlib import Path
from utils import get_logs_dir, get_captures_dir, get_timestamp

_logs_dir = Path(get_logs_dir())
_captures_dir = Path(get_captures_dir())

LOG_FILE = _logs_dir / "captured.log"
PCAP_FILE = _captures_dir / "capture.pcap"

_pcap_writer = None
_pcap_lock = threading.Lock()
_log_lock = threading.Lock()

def ensure_dirs():
    _logs_dir.mkdir(parents=True, exist_ok=True)
    _captures_dir.mkdir(parents=True, exist_ok=True)

def init_pcap_writer(append=True):
    """
    Initialize a thread-safe PcapWriter.
    Call once before writing packets (if pcap enabled).
    """
    global _pcap_writer
    ensure_dirs()
    if _pcap_writer is None:
        _pcap_writer = PcapWriter(str(PCAP_FILE), append=append, sync=True)

def write_pcap(packet):
    """
    Write a single scapy packet to the PCAP file.
    """
    global _pcap_writer
    if _pcap_writer is None:
        init_pcap_writer(append=True)
    with _pcap_lock:
        try:
            _pcap_writer.write(packet)
        except Exception as e:
            # don't crash sniffer for pcap write errors
            print(f"[logger] PCAP write error: {e}")

def log_packet(packet_data, log_enabled=True):
    """
    Append a human-readable entry to logs/captured.log
    packet_data: dict returned by packet_parser.parse_packet
    """
    if not log_enabled:
        return
    ensure_dirs()
    lines = []
    lines.append("="*60)
    lines.append(f"Timestamp: {get_timestamp()}")
    lines.append(f"Protocol: {packet_data.get('protocol_readable', packet_data.get('protocol', 'UNKNOWN'))}")
    src = packet_data.get("src_ip", "-")
    dst = packet_data.get("dst_ip", "-")
    if packet_data.get("src_port"):
        src = f"{src}:{packet_data.get('src_port')}"
    if packet_data.get("dst_port"):
        dst = f"{dst}:{packet_data.get('dst_port')}"
    lines.append(f"Source: {src}")
    lines.append(f"Destination: {dst}")
    if packet_data.get("flags") is not None:
        lines.append(f"Flags: {packet_data.get('flags')}")
    if "payload_size" in packet_data:
        lines.append(f"Payload Size: {packet_data.get('payload_size')} bytes")
    if "extra" in packet_data and packet_data["extra"]:
        lines.append(f"Extra: {packet_data['extra']}")
    lines.append("="*60)
    text = "\n".join(lines) + "\n\n"
    try:
        with _log_lock:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(text)
    except Exception as e:
        print(f"[logger] Log write error: {e}")