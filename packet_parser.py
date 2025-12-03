"""
Parse Scapy packet into a dictionary with clean fields.
Supports: ARP, IP (TCP/UDP/ICMP), DNS (basic), HTTP (basic via Raw).
"""
from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse  # optional; may not be present on all installs

def parse_packet(packet):
    info = {}
    # timestamp from packet (epoch) if present, else None
    info["timestamp"] = getattr(packet, "time", None)

    # ARP
    if packet.haslayer(ARP):
        arp = packet[ARP]
        info["protocol_readable"] = "ARP"
        info["protocol"] = "ARP"
        info["src_mac"] = arp.hwsrc
        info["dst_mac"] = arp.hwdst
        info["src_ip"] = arp.psrc
        info["dst_ip"] = arp.pdst
        return info

    # IP stack
    if packet.haslayer(IP):
        ip = packet[IP]
        info["src_ip"] = ip.src
        info["dst_ip"] = ip.dst
        # Default set
        info["protocol"] = ip.proto
        info["protocol_readable"] = "IP"

        # TCP
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            info["protocol_readable"] = "TCP"
            info["src_port"] = tcp.sport
            info["dst_port"] = tcp.dport
            info["flags"] = str(tcp.flags)
            # payload
            if packet.haslayer(Raw):
                raw = packet[Raw].load
                info["payload_size"] = len(raw)
                # Try very basic HTTP detection (text-match)
                try:
                    txt = raw.decode("utf-8", errors="ignore")
                    if txt.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ")):
                        info.setdefault("extra", "")
                        info["extra"] += f"HTTP Request: {txt.splitlines()[0][:200]}"
                    elif "HTTP/" in txt or txt.startswith("HTTP/"):
                        info.setdefault("extra", "")
                        info["extra"] += f"HTTP Response: {txt.splitlines()[0][:200]}"
                except Exception:
                    pass
            else:
                info["payload_size"] = 0

        # UDP
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            info["protocol_readable"] = "UDP"
            info["src_port"] = udp.sport
            info["dst_port"] = udp.dport
            if packet.haslayer(Raw):
                info["payload_size"] = len(packet[Raw].load)
            else:
                info["payload_size"] = 0

            # DNS basic
            if packet.haslayer(DNS):
                try:
                    dns = packet[DNS]
                    info.setdefault("extra", "")
                    if dns.qr == 0 and dns.qd:
                        # query
                        qname = dns.qd.qname.decode() if getattr(dns.qd, "qname", None) else None
                        info["extra"] += f" DNS Query: {qname}"
                    elif dns.qr == 1:
                        info["extra"] += " DNS Response"
                except Exception:
                    pass

        # ICMP
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            info["protocol_readable"] = "ICMP"
            info["icmp_type"] = icmp.type

        else:
            info["protocol_readable"] = "IP-OTHER"

    else:
        info["protocol_readable"] = "NON-IP"

    return info
