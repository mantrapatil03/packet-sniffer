"""
Filtering logic: protocol, IP, and port filters.
"""

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP

def match_protocol(packet, protocol):
    """
    protocol: 'tcp' / 'udp' / 'icmp' / 'arp' / 'all' (case-insensitive)
    """
    if not protocol or protocol.lower() in ("", "all"):
        return True
    proto = protocol.lower()
    if proto == "tcp" and packet.haslayer(TCP):
        return True
    if proto == "udp" and packet.haslayer(UDP):
        return True
    if proto == "icmp" and packet.haslayer(ICMP):
        return True
    if proto == "arp" and packet.haslayer(ARP):
        return True
    return False

def match_ip(packet, ip):
    """
    If ip is None or empty -> True.
    Otherwise match if src or dst IP equals ip (string).
    """
    if not ip:
        return True
    if packet.haslayer(IP):
        try:
            src = packet[IP].src
            dst = packet[IP].dst
            return ip == src or ip == dst
        except Exception:
            return False
    return False

def match_port(packet, port):
    """
    If port is None or empty -> True.
    Matches TCP or UDP src/dst ports.
    """
    if not port:
        return True
    try:
        p = int(port)
    except Exception:
        return False
    if packet.haslayer(TCP):
        try:
            return packet[TCP].sport == p or packet[TCP].dport == p
        except Exception:
            return False
    if packet.haslayer(UDP):
        try:
            return packet[UDP].sport == p or packet[UDP].dport == p
        except Exception:
            return False
    return False
