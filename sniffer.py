#!/usr/bin/env python3
"""
Main CLI sniffer. Cross-platform. Uses scapy.
Run with admin/root privileges to capture packets.
"""

import argparse
import sys
import time
from scapy.all import sniff
from filters import match_protocol, match_ip, match_port
from packet_parser import parse_packet
import logger
from utils import is_admin, get_timestamp

def should_display(packet, args):
    if not match_protocol(packet, args.protocol):
        return False
    if not match_ip(packet, args.ip):
        return False
    if not match_port(packet, args.port):
        return False
    return True

def pretty_print(info):
    """Print packet summary to console (same layout as logs)."""
    print("="*60)
    print(f"Timestamp: {get_timestamp()}")
    proto = info.get("protocol_readable", info.get("protocol", "UNKNOWN"))
    print(f"Protocol: {proto}")
    src = info.get("src_ip", "-")
    dst = info.get("dst_ip", "-")
    if info.get("src_port"):
        src = f"{src}:{info.get('src_port')}"
    if info.get("dst_port"):
        dst = f"{dst}:{info.get('dst_port')}"
    print(f"Source: {src}")
    print(f"Destination: {dst}")
    if info.get("flags") is not None:
        print(f"Flags: {info.get('flags')}")
    print(f"Payload Size: {info.get('payload_size', 0)} bytes")
    if info.get("extra"):
        print(f"Extra: {info.get('extra')}")
    print("="*60)

def process_packet(packet, args):
    """Called for every packet captured by scapy."""
    try:
        if not should_display(packet, args):
            return
        info = parse_packet(packet)
        pretty_print(info)
        # Log (human-readable)
        if args.log.lower() in ("yes", "y", "true", "1"):
            logger.log_packet(info, log_enabled=True)
        # Save to pcap
        if args.pcap.lower() in ("yes", "y", "true", "1"):
            logger.write_pcap(packet)
    except Exception as e:
        print(f"[sniffer] Error processing packet: {e}")

def main():
    parser = argparse.ArgumentParser(description="Cross-platform CLI Packet Sniffer (Scapy)")
    parser.add_argument("--protocol", default="all", help="tcp/udp/icmp/arp/all")
    parser.add_argument("--ip", default=None, help="filter by IP (src or dst)")
    parser.add_argument("--port", default=None, help="filter by port number")
    parser.add_argument("--log", default="yes", help="write human-readable log yes/no")
    parser.add_argument("--pcap", default="no", help="save raw packets to captures/capture.pcap yes/no")
    parser.add_argument("--iface", default=None, help="network interface to sniff on (optional)")
    parser.add_argument("--count", default=0, type=int, help="number of packets to capture (0 = unlimited)")
    args = parser.parse_args()

    # warn if not admin but continue (user may be testing without root)
    if not is_admin():
        print("[WARNING] Not running with administrative privileges. Packet capture may fail or be limited.")
        print(" - Linux/macOS: run with sudo")
        print(" - Windows: run PowerShell/CMD as Administrator")
        # do not exit: allow user to run and see warning. sniff() will likely error if insufficient privilege.

    # Prepare logger if pcap writing requested
    if args.pcap.lower() in ("yes", "y", "true", "1"):
        try:
            logger.init_pcap_writer(append=True)
        except Exception as e:
            print(f"[sniffer] Failed to init pcap writer: {e}")

    print("Starting packet capture. Press Ctrl+C to stop.")
    sniff_kwargs = {
        "prn": lambda p: process_packet(p, args),
        "store": False
    }
    if args.iface:
        sniff_kwargs["iface"] = args.iface
    if args.count and args.count > 0:
        sniff_kwargs["count"] = args.count

    try:
        sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        print("\nCapture stopped by user (KeyboardInterrupt).")
    except Exception as e:
        print(f"[sniffer] Sniffing error: {e}")
    finally:
        # finalize / flush pcap writer if present
        print("Exiting.")
        try:
            # close pcap writer if available (scapy's PcapWriter has close())
            if hasattr(logger, "_pcap_writer") and logger._pcap_writer is not None:
                try:
                    logger._pcap_writer.flush()
                    logger._pcap_writer.close()
                except Exception:
                    pass
        except Exception:
            pass

if __name__ == "__main__":
    main()
