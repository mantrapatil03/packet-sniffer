#!/usr/bin/env python3
"""
Wireshark-style CLI Packet Sniffer (single-file, drop-in)

Features:
- Auto-detect active interface (falls back sensibly)
- Kernel-level BPF filters (fast)
- Promiscuous mode
- Protocol decoding: IP/TCP/UDP/ICMP/ARP/DNS/HTTP/TLS (best-effort)
- Colored real-time output (colorama)
- Live packet counters / throughput
- Optional pcap saving (scapy.PcapWriter)
- Optional hexdump output
- Graceful error handling

Dependencies (add to requirements.txt):
scapy
colorama
netifaces  # optional but recommended for robust iface detection

Usage examples:
sudo python3 sniffer_wireshark_style.py --ip 192.168.1.10 --pcap yes --hexdump no
sudo python3 sniffer_wireshark_style.py --protocol tcp --port 80

Drop-in: copy this file into your project and run.
"""

import argparse
import threading
import time
import sys
import os
from datetime import datetime

try:
    # scapy imports
    from scapy.all import (
        sniff,
        hexdump,
        conf,
        PcapWriter,
        raw,
        Ether,
    )
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP
    # optional higher-level layers (may not be present in minimal scapy)
    try:
        from scapy.layers.dns import DNS
    except Exception:
        DNS = None
    try:
        from scapy.layers.http import HTTPRequest, HTTPResponse
    except Exception:
        HTTPRequest = HTTPResponse = None
    # TLS layer in modern scapy may be under scapy.layers.tls
    try:
        from scapy.layers.tls.record import TLS
    except Exception:
        try:
            from scapy.layers.ssl_tls import TLS
        except Exception:
            TLS = None
except Exception as e:
    print("[FATAL] Scapy is required. Install with: pip install scapy")
    print(f"Details: {e}")
    sys.exit(1)

# colorama for colored output
try:
    from colorama import init as colorama_init
    from colorama import Fore, Style
    colorama_init()
except Exception:
    # fallback: define no-op color codes
    class _NoColor:
        RESET_ALL = ""
    Fore = Style = _NoColor()

# optional netifaces for robust default interface detection
try:
    import netifaces
except Exception:
    netifaces = None

# ----------------------- Helpers ---------------------------------

def is_root():
    """Return True if running as root/admin."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows: fallback
        return ctypes.windll.shell32.IsUserAnAdmin() != 0 if 'ctypes' in globals() else True


def get_default_iface():
    """Try to auto-detect the system's default network interface.
    Uses netifaces if available, else uses scapy.conf.route.
    Returns interface name string or None.
    """
    # Preferred: netifaces
    if netifaces:
        try:
            gws = netifaces.gateways()
            if 'default' in gws and netifaces.AF_INET in gws['default']:
                iface = gws['default'][netifaces.AF_INET][1]
                return iface
        except Exception:
            pass
        # fallback to first non-loopback
        try:
            for i in netifaces.interfaces():
                if i and i != 'lo':
                    return i
        except Exception:
            pass

    # Fallback: scapy route
    try:
        # conf.route.route("0.0.0.0") returns (dest, gw, iface)
        route = conf.route.route("0.0.0.0")
        if route and len(route) >= 3:
            iface = route[0][2] if isinstance(route[0], tuple) else route[2]
            # older scapy returns (dst, gw, iface)
            # try robust extraction
            if isinstance(route, tuple) and len(route) >= 3:
                iface = route[2]
            return iface
    except Exception:
        pass

    # last resort: first non-loopback interface from scapy
    try:
        ifaces = list(conf.ifaces.data.keys())
        for i in ifaces:
            if i and i != 'lo' and not i.startswith('Loopback'):
                return i
    except Exception:
        pass
    return None


def build_bpf(args):
    """Construct a BPF string from args (ip, port, protocol)."""
    cond = []
    if args.ip:
        # allow user to pass subnet forms too; BPF accepts 'net' and 'host' etc.
        ip = args.ip.strip()
        # accept trailing .* as simple net mask -> convert to net mask if possible
        if ip.endswith('.*'):
            prefix = ip[:-2]
            # attempt /24
            cond.append(f"net {prefix}.0/24")
        else:
            cond.append(f"host {ip}")
    if args.port:
        cond.append(f"port {args.port}")
    proto = args.protocol.lower() if args.protocol else 'all'
    if proto in ('tcp', 'udp', 'icmp', 'arp'):
        cond.append(proto)
    if cond:
        return ' and '.join(cond)
    return None


def color_for_proto(proto):
    p = (proto or "").upper()
    if 'TCP' in p:
        return Fore.CYAN
    if 'UDP' in p:
        return Fore.MAGENTA
    if 'ICMP' in p:
        return Fore.YELLOW
    if 'ARP' in p:
        return Fore.GREEN
    return Fore.WHITE


def get_timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]


# ----------------------- Parser & Printer ------------------------

def parse_packet(packet):
    """Lightweight parse returning a dict of useful fields."""
    info = {}
    info['timestamp'] = get_timestamp()
    info['raw_len'] = len(packet)

    # defaults
    info['protocol'] = 'UNKNOWN'
    info['protocol_readable'] = 'UNKNOWN'
    info['src_ip'] = '-'
    info['dst_ip'] = '-'
    info['src_port'] = None
    info['dst_port'] = None
    info['flags'] = None
    info['extra'] = None

    # L2
    if packet.haslayer(Ether):
        info['src_mac'] = packet[Ether].src
        info['dst_mac'] = packet[Ether].dst

    # ARP
    if packet.haslayer(ARP):
        info['protocol'] = 'ARP'
        info['protocol_readable'] = 'ARP'
        try:
            info['src_ip'] = packet[ARP].psrc
            info['dst_ip'] = packet[ARP].pdst
        except Exception:
            pass
        return info

    # IP and above
    if packet.haslayer(IP):
        ip = packet[IP]
        info['src_ip'] = ip.src
        info['dst_ip'] = ip.dst

        if packet.haslayer(TCP):
            t = packet[TCP]
            info['protocol'] = 'TCP'
            info['protocol_readable'] = 'TCP'
            info['src_port'] = t.sport
            info['dst_port'] = t.dport
            info['flags'] = t.flags
            # try to extract some app layer hints
            # HTTP
            if HTTPRequest and packet.haslayer(HTTPRequest):
                try:
                    http = packet[HTTPRequest]
                    method = http.Method.decode() if isinstance(http.Method, bytes) else http.Method
                    host = http.Host.decode() if isinstance(http.Host, bytes) else http.Host
                    path = http.Path.decode() if isinstance(http.Path, bytes) else http.Path
                    info['extra'] = f"HTTP {method} {host}{path}"
                except Exception:
                    pass
            # TLS hint
            elif TLS and packet.haslayer(TLS):
                info['extra'] = 'TLS/SSL'
            # generic payload length
            return info

        if packet.haslayer(UDP):
            u = packet[UDP]
            info['protocol'] = 'UDP'
            info['protocol_readable'] = 'UDP'
            info['src_port'] = u.sport
            info['dst_port'] = u.dport
            # DNS
            if DNS and packet.haslayer(DNS):
                try:
                    dns = packet[DNS]
                    # queries
                    if dns.qr == 0 and dns.qdcount > 0:
                        qname = dns.qd.qname.decode() if isinstance(dns.qd.qname, bytes) else dns.qd.qname
                        info['extra'] = f"DNS Query: {qname}"
                    elif dns.qr == 1 and dns.ancount > 0:
                        info['extra'] = 'DNS Response'
                except Exception:
                    pass
            return info

        if packet.haslayer(ICMP):
            info['protocol'] = 'ICMP'
            info['protocol_readable'] = 'ICMP'
            return info

    # fallback protocol
    return info


def pretty_print(info, args):
    """Print a concise, colored single-line summary similar to Wireshark's list pane.
    Optionally print hexdump when requested.
    """
    proto = info.get('protocol_readable', info.get('protocol', 'UNKNOWN'))
    color = color_for_proto(proto)
    src = info.get('src_ip', '-')
    dst = info.get('dst_ip', '-')
    if info.get('src_port'):
        src = f"{src}:{info.get('src_port')}"
    if info.get('dst_port'):
        dst = f"{dst}:{info.get('dst_port')}"

    line = f"{info.get('timestamp')}  {proto:5}  {src} -> {dst}  len={info.get('raw_len',0)}"
    if info.get('extra'):
        line += f"  {info.get('extra')}"

    # print colored
    try:
        print(color + line + Style.RESET_ALL)
    except Exception:
        print(line)

    if args.hexdump and args.hexdump.lower() in ('yes','y','true','1'):
        # raw packet hexdump
        try:
            print('\n------ HEXDUMP ------')
            hexdump(raw(packet))
            print('---------------------\n')
        except Exception:
            pass


# ----------------------- Logging & PCAP -------------------------

_pcap_writer = None
_pcap_lock = threading.Lock()


def init_pcap_writer(filename='captures/capture.pcap', append=True):
    global _pcap_writer
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    mode = 'ab' if append else 'wb'
    try:
        _pcap_writer = PcapWriter(filename, append=append, sync=True)
    except Exception as e:
        print(f"[pcap] Failed to create PcapWriter: {e}")
        _pcap_writer = None


def write_pcap(packet):
    global _pcap_writer
    if _pcap_writer is None:
        return
    with _pcap_lock:
        try:
            _pcap_writer.write(packet)
        except Exception as e:
            print(f"[pcap] Write failed: {e}")


# ----------------------- Stats ---------------------------------

class Stats:
    def __init__(self):
        self.packet_count = 0
        self.byte_count = 0
        self.lock = threading.Lock()
        self.start_ts = time.time()

    def add(self, pkt_len):
        with self.lock:
            self.packet_count += 1
            self.byte_count += pkt_len

    def snapshot(self):
        with self.lock:
            return self.packet_count, self.byte_count, time.time() - self.start_ts


stats = Stats()


def stats_printer(stop_event):
    last_packets = 0
    last_bytes = 0
    while not stop_event.is_set():
        time.sleep(1)
        pkt, byt, elapsed = stats.snapshot()
        pps = pkt - last_packets
        bps = byt - last_bytes
        last_packets = pkt
        last_bytes = byt
        # human readable
        def human(n):
            for unit in ['','K','M','G','T']:
                if n < 1000:
                    return f"{n:.0f}{unit}"
                n /= 1000.0
            return f"{n:.0f}P"
        print(f"[STATS] total={pkt} pkts ({human(pps)}/s)  bytes={byt} ({human(bps)}/s)  elapsed={int(elapsed)}s", end='\r')
    print()  # newline after stop


# ----------------------- Main capture --------------------------

# packet handler needs closure access to args

def make_packet_handler(args):
    def handler(packet):
        try:
            # Build a quick check for protocol/ip/port if user provided but rely on BPF where possible
            info = parse_packet(packet)

            # If args provided and BPF didn't run (no filter), apply simple checks
            if args.protocol and args.protocol.lower() not in ('', 'all'):
                if info.get('protocol','').lower() != args.protocol.lower():
                    return
            if args.ip:
                ip = args.ip
                # allow simple wildcard like 192.168.1.* -> check prefix
                if ip.endswith('.*'):
                    pref = ip[:-2]
                    if not (str(info.get('src_ip','')).startswith(pref) or str(info.get('dst_ip','')).startswith(pref)):
                        return
                else:
                    if not (str(info.get('src_ip','')) == ip or str(info.get('dst_ip','')) == ip):
                        return
            if args.port:
                try:
                    p = int(args.port)
                    if not (info.get('src_port') == p or info.get('dst_port') == p):
                        return
                except Exception:
                    pass

            # show
            pretty_print(info, args)

            # update stats
            stats.add(len(packet))

            # write pcap
            if args.pcap and args.pcap.lower() in ('yes','y','true','1'):
                write_pcap(packet)

        except Exception as e:
            print(f"[handler] Error: {e}")
    return handler


def main():
    parser = argparse.ArgumentParser(description='Wireshark-style CLI sniffer (single-file)')
    parser.add_argument('--protocol', default='all', help='tcp/udp/icmp/arp/all')
    parser.add_argument('--ip', default=None, help='filter by IP (host or prefix like 192.168.1.*)')
    parser.add_argument('--port', default=None, help='filter by port number')
    parser.add_argument('--log', default='yes', help='(unused) keep for compatibility')
    parser.add_argument('--pcap', default='no', help='save raw packets to captures/capture.pcap yes/no')
    parser.add_argument('--iface', default=None, help='network interface to sniff on (optional)')
    parser.add_argument('--count', default=0, type=int, help='number of packets to capture (0 = unlimited)')
    parser.add_argument('--hexdump', default='no', help='print hexdump for each packet yes/no')
    parser.add_argument('--bpf', default=None, help='optional explicit BPF filter string')

    args = parser.parse_args()

    # choose interface
    if not args.iface:
        args.iface = get_default_iface()
        if args.iface:
            print(f"[+] Auto-selected interface: {args.iface}")
        else:
            print("[!] Could not auto-detect interface. Use --iface to specify one.")

    # friendly warning about privileges
    try:
        if os.name != 'nt' and os.geteuid() != 0:
            print("[WARNING] Not running as root. Capturing may be limited. Consider using sudo.")
    except Exception:
        pass

    # prepare pcap writer
    if args.pcap and args.pcap.lower() in ('yes','y','true','1'):
        init_pcap_writer()

    # build BPF
    bpf = args.bpf or build_bpf(args)
    if bpf:
        print(f"[+] Using BPF filter: {bpf}")

    print("Starting packet capture. Press Ctrl+C to stop.")

    sniff_kwargs = {
        'prn': make_packet_handler(args),
        'store': False,
        'promisc': True,
    }
    if args.iface:
        sniff_kwargs['iface'] = args.iface
    if bpf:
        sniff_kwargs['filter'] = bpf
    if args.count and args.count > 0:
        sniff_kwargs['count'] = args.count

    # start stats thread
    stop_event = threading.Event()
    t = threading.Thread(target=stats_printer, args=(stop_event,), daemon=True)
    t.start()

    try:
        sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        print('\nCapture stopped by user (KeyboardInterrupt).')
    except Exception as e:
        print(f"[sniffer] Sniffing error: {e}")
    finally:
        stop_event.set()
        # flush & close pcap writer
        global _pcap_writer
        if _pcap_writer is not None:
            try:
                _pcap_writer.flush()
                _pcap_writer.close()
            except Exception:
                pass
        print('Exiting.')


if __name__ == '__main__':
    main()
