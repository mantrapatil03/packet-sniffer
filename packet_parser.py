"""
Wireshark-style packet parser.
Extracts detailed fields from ARP, IP, TCP, UDP, ICMP, DNS, HTTP, TLS.
"""

from scapy.all import (
    IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw, Ether
)
from scapy.layers.http import HTTPRequest, HTTPResponse  # may not exist everywhere


def safe_get_raw(packet):
    """Return raw payload bytes if available, else b''."""
    try:
        if packet.haslayer(Raw):
            return bytes(packet[Raw].load)
        return b""
    except Exception:
        return b""


def try_decode(data):
    """Decode bytes to text (ignore errors)."""
    try:
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def parse_packet(packet):
    info = {}

    # Timestamp (- Wireshark uses epoch internally)
    info["timestamp"] = getattr(packet, "time", None)

    # MAC addresses (Wireshark shows these prominently)
    if packet.haslayer(Ether):
        eth = packet[Ether]
        info["src_mac"] = eth.src
        info["dst_mac"] = eth.dst

    # ---- ARP (non-IP) -----------------------------------------------------
    if packet.haslayer(ARP):
        arp = packet[ARP]
        info.update({
            "protocol": "ARP",
            "protocol_readable": "ARP",
            "src_ip": arp.psrc,
            "dst_ip": arp.pdst,
            "opcode": "request" if arp.op == 1 else "reply"
        })
        return info

    # ---- IP ---------------------------------------------------------------
    if packet.haslayer(IP):
        ip = packet[IP]
        info["src_ip"] = ip.src
        info["dst_ip"] = ip.dst
        info["ttl"] = ip.ttl
        info["len"] = ip.len
        info["protocol"] = ip.proto
    else:
        info["protocol"] = "NON-IP"
        info["protocol_readable"] = "NON-IP"
        return info

    raw_bytes = safe_get_raw(packet)
    raw_text = try_decode(raw_bytes)
    info["payload_size"] = len(raw_bytes)

    # ---- TCP --------------------------------------------------------------
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        info.update({
            "protocol_readable": "TCP",
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "seq": tcp.seq,
            "ack": tcp.ack,
            "flags": tcp.sprintf("%TCP.flags%"),
            "window": tcp.window,
        })

        # --- HTTP detection ------------------------------------------------
        if packet.haslayer(HTTPRequest):
            http = packet[HTTPRequest]
            info.setdefault("extra", "")
            info["extra"] += f"HTTP Request: {http.Method.decode()} {http.Path.decode()}"
            return info

        if packet.haslayer(HTTPResponse):
            info.setdefault("extra", "")
            status = raw_text.split("\n")[0][:200]
            info["extra"] += f"HTTP Response: {status}"
            return info

        # fallback manual HTTP detection
        if raw_text.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ")):
            info.setdefault("extra", "")
            info["extra"] += f"HTTP Request: {raw_text.splitlines()[0][:200]}"
            return info

        if raw_text.startswith("HTTP/"):
            info.setdefault("extra", "")
            info["extra"] += f"HTTP Response: {raw_text.splitlines()[0][:200]}"
            return info

        # --- TLS detection -------------------------------------------------
        if raw_bytes and tcp.dport in (443, 8443) or tcp.sport in (443, 8443):
            if raw_bytes.startswith(b"\x16\x03"):  # TLS handshake
                hs = raw_bytes[5]
                if hs == 1:
                    info.setdefault("extra", "")
                    info["extra"] += "TLS ClientHello"
                elif hs == 2:
                    info.setdefault("extra", "")
                    info["extra"] += "TLS ServerHello"

        return info

    # ---- UDP --------------------------------------------------------------
    if packet.haslayer(UDP):
        udp = packet[UDP]
        info.update({
            "protocol_readable": "UDP",
            "src_port": udp.sport,
            "dst_port": udp.dport,
            "udp_length": udp.len,
        })

        # --- DNS -----------------------------------------------------------
        if packet.haslayer(DNS):
            dns = packet[DNS]
            info.setdefault("extra", "")

            if dns.qr == 0 and dns.qd:
                q = dns.qd.qname.decode() if isinstance(dns.qd, DNSQR) else None
                info["extra"] += f"DNS Query: {q}"

            elif dns.qr == 1:
                info["extra"] += "DNS Response:"
                if dns.an and isinstance(dns.an, DNSRR):
                    try:
                        ans = dns.an.rdata
                        domain = dns.an.rrname.decode()
                        info["extra"] += f" {domain} → {ans}"
                    except Exception:
                        pass

        return info

    # ---- ICMP -------------------------------------------------------------
    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        info.update({
            "protocol_readable": "ICMP",
            "icmp_type": icmp.type,
            "icmp_code": icmp.code,
        })
        return info

    # ---- Fallback ---------------------------------------------------------
    info["protocol_readable"] = "OTHER"
    return info
