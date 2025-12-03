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
    Match packet IP.
    Supports:
    - Exact IP: "192.168.1.10"
    - Subnet wildcard: "192.168.1.*"
    - None/empty: match all
    """
    if not ip:
        return True

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        # Subnet wildcard (e.g., 192.168.1.*)
        if ip.endswith(".*"):
            prefix = ip[:-2]
            return src.startswith(prefix) or dst.startswith(prefix)

        # Exact match
        return ip == src or ip == dst

    return False

def match_port(packet, port):
    """
    If port is None or empty -> True.
    Matches TCP or UDP src/dst ports.
    """
    if not port:
        return True

    # Allow port ranges: "80-90" or single port "443"
    try:
        if "-" in str(port):
            start, end = map(int, str(port).split("-"))
            port_range = range(start, end + 1)
        else:
            port_range = [int(port)]
    except Exception:
        return False

    if packet.haslayer(TCP):
        try:
            return packet[TCP].sport in port_range or packet[TCP].dport in port_range
        except Exception:
            return False

    if packet.haslayer(UDP):
        try:
            return packet[UDP].sport in port_range or packet[UDP].dport in port_range
        except Exception:
            return False

    return False
