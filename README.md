<h1 align="center">🛰️ Packet Sniffer CLI (Cross-Platform – Linux | Windows | macOS)</h1>

<p align="center">
  <b>A real-time, command-line network packet analyzer built using Python and Scapy</b><br>
  Works seamlessly on Linux, Windows, and macOS with admin/root permissions.
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.x-blue.svg?style=for-the-badge&logo=python"></a>
  <a href="https://github.com/mantrapatil03"><img src="https://img.shields.io/badge/Author-Mantra%20Patil-green.svg?style=for-the-badge"></a>
  <a href="https://www.linkedin.com/in/mantrapatil25"><img src="https://img.shields.io/badge/Connect-LinkedIn-blue?style=for-the-badge&logo=linkedin"></a>
  <img src="https://img.shields.io/github/stars/mantrapatil03/packet-sniffer?style=for-the-badge&logo=github" />
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge" />
</p>

---

## 🚀 Overview

**Packet Sniffer CLI** is a Python-based command-line tool that captures and analyzes live network packets.  
It provides detailed protocol information, supports filters, and can save logs and PCAP files for later analysis in **Wireshark**.

---

## 🧩 Features

✅ Live real-time packet capture using **Scapy**  
✅ Decode **TCP**, **UDP**, **ICMP**, **ARP**, and **DNS**  
✅ Display **source/destination IPs**, **ports**, and **payload size**  
✅ Save results in:
- Human-readable logs → `logs/captured.log`
- PCAP format → `captures/capture.pcap` (for Wireshark)  
✅ Apply filters:
- by protocol (`tcp`, `udp`, `icmp`, `arp`, `dns`)
- by IP address
- by port number  
✅ Cross-platform: Linux, Windows, macOS  
✅ Auto-creates required directories (`logs/`, `captures/`)  
✅ Error-safe and permission-aware  

---

## 🏗️ Repository Structure
```
packet-sniffer/
│
├── sniffer.py                     # Main entry point – CLI & packet capture
├── packet_parser.py               # Decodes and extracts packet details
├── filters.py                     # Filtering logic (protocol/IP/port)
├── logger.py                      # Logs and PCAP saving
├── utils.py                       # Helper functions (timestamp, admin check)
│
├── requirements.txt               # Dependencies
├── README.md                      # Project documentation
├── LICENSE                        # MIT License
├── .gitignore
├── .gitattributes
│
├── captures/                      # Auto-created; stores PCAP files
└── logs/                          # Auto-created; stores log files
```


## ⚙️ Installation

### 1️⃣ Clone the repository
```bash
git clone https://github.com/mantrapatil03/packet-sniffer.git
cd packet-sniffer
```

### 2️⃣ Install dependencies
```
pip install -r requirements.txt
```

## 🔧 Usage
### Linux / macOS
```
sudo python3 sniffer.py
```
### Windows
Run Command Prompt or PowerShell as Administrator:
```
python sniffer.py
```
**Examples**
```
# Capture only TCP packets
sudo python3 sniffer.py --protocol tcp

# Capture packets from specific IP
sudo python3 sniffer.py --ip 192.168.1.10

# Capture packets for port 80 (HTTP)
sudo python3 sniffer.py --port 80
```

**📁 Output Files**
✅ Logs

Human-readable output
```
logs/captured.log
```
✅ PCAP

Raw packet data (open in Wireshark)
```
captures/capture.pcap
```

## 🧠 Supported Protocols
| Protocol | Supported | Details                    |
| -------- | --------- | -------------------------- |
| **TCP**  | ✅         | Ports, flags, payload size |
| **UDP**  | ✅         | Ports, payload size        |
| **ICMP** | ✅         | Type, code                 |
| **ARP**  | ✅         | Who-has / is-at            |
| **DNS**  | ✅         | Query name, type           |

## 🧩 Filters
| Filter Type | Example             | Description                         |
| ----------- | ------------------- | ----------------------------------- |
| Protocol    | `--protocol tcp`    | Capture only TCP packets            |
| IP          | `--ip 192.168.1.10` | Capture packets to/from given IP    |
| Port        | `--port 80`         | Capture packets using specific port |

✅ Filters can be combined, e.g.
```
sudo python3 sniffer.py --protocol tcp --port 443
```
## 🔒 Permissions
| Platform    | Required Privilege                                 |
| ----------- | -------------------------------------------------- |
| Linux/macOS | Run with `sudo`                                    |
| Windows     | Run as **Administrator**                           |
| macOS Extra | Run `sudo chmod +r /dev/bpf*` if permission denied |

## 🧰 Troubleshooting

❌ **Permission Denied**
→ Use `sudo` or Administrator privileges

❌ **No Packets Captured**
→ Try specifying a network interface:
```
sudo python3 sniffer.py --iface eth0
```
List interfaces:
```bash
python3 - <<EOF
from scapy.all import get_if_list
print(get_if_list())
EOF
```

❌ **PCAP Not Saving**
→ Ensure captures/ and logs/ exist (auto-created).
Check file permissions.

**Windows Note:**
Scapy requires Npcap — install it from https://npcap.com

## 🧑‍💻 Developer Guide
Main Modules
| File               | Description                                   |
| ------------------ | --------------------------------------------- |
| `sniffer.py`       | CLI arguments, interface selection, main loop |
| `packet_parser.py` | Extracts IPs, ports, and protocol details     |
| `filters.py`       | Filtering by protocol/IP/port                 |
| `logger.py`        | Writes logs and saves PCAP                    |
| `utils.py`         | Helpers (timestamp, admin check, OS info)     |

- **Adding New Protocol Decoders**
1. Edit packet_parser.py
2. Add new parsing logic for your protocol (e.g., HTTP)
3. Update CLI filter options if needed

## 🤝 Contributing
Contributions are welcome!

If you’d like to improve or extend this tool:
- 1️⃣ Fork the repo
- 2️⃣ Create a feature branch
- 3️⃣ Write clean, well-documented code
- 4️⃣ Submit a pull request

For major changes, open an issue first.

## 👨‍💻 Author
**Mantra Patil**

✉️ techmantrapatil@gmail.com




<h2 align="center">💫 Thanks for Visiting! 💫</h2> <p align="center"> <i>Made with ❤️ & Python by <b>Mantra Patil</b></i><br><br> <img src="https://img.shields.io/badge/Keep%20Coding-Python-blue?style=for-the-badge&logo=python" /> <img src="https://img.shields.io/badge/Follow%20on-LinkedIn-0A66C2?style=for-the-badge&logo=linkedin" /> <img src="https://img.shields.io/badge/Star%20This%20Repo-GitHub-black?style=for-the-badge&logo=github" /> </p> <p align="center"> 🌟 <b>If you found this project helpful, please give it a star!</b> 🌟<br> Your support motivates further open-source work and new features. </p>
