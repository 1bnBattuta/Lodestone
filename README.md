# Lodestone

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-Linux-blue.svg)]()
[![C Standard](https://img.shields.io/badge/C-C99-blue.svg)]()

A feature-rich, high-performance network packet capture and analysis tool written in C for Linux systems.

##  Features

### Core Capabilities
- **High-Performance Capture**
  - Standard AF_PACKET raw socket capture
  - Memory-mapped (mmap) zero-copy capture for extreme performance (10Gbps+)
  - Large kernel buffers to prevent packet drops
  - Multi-threaded architecture

- **Protocol Support**
  - **Layer 2**: Ethernet, ARP
  - **Layer 3**: IPv4, IPv6 (with extension headers)
  - **Layer 4**: TCP, UDP, ICMP, ICMPv6
  - **Application**: DNS, HTTP detection

- **Advanced Analysis**
  - TCP stream reassembly and tracking
  - Real-time anomaly detection (port scans, SYN floods, ARP spoofing)
  - Connection tracking and flow analysis
  - Protocol statistics and top talkers

- **Flexible Output**
  - Live terminal display with colors (brief, detailed, hex, full modes)
  - PCAP format (Wireshark compatible)
  - Multiple log formats (Text, CSV, JSON, XML)
  - Real-time statistics

- **Powerful Filtering**
  - BPF (Berkeley Packet Filter) support
  - Kernel-level filtering for efficiency
  - Complex filter combinations

##  Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Filter Examples](#filter-examples)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)
- [Authors](#authors)

##  Requirements

### System Requirements
- **Operating System**: Linux (kernel 2.6.27 or higher)
- **Architecture**: x86_64, ARM64 (any architecture supported by Linux)
- **RAM**: Minimum 512MB (2GB+ recommended for high-traffic captures)
- **Privileges**: Root access (for raw socket operations)

### Software Dependencies
- **GCC**: 7.0 or higher
- **Make**: GNU Make 3.81+
- **libpcap**: 1.9.0+ (libpcap-dev)
- **libc**: glibc 2.17+ or musl

### Tested On
- Arch Linux (latest)

##  Installation

### From Source

#### Arch Linux
````bash
# Install dependencies
sudo pacman -S base-devel libpcap git

# Clone and build
git clone https://github.com/1bnBattuta/Lodestone.git
cd Lodestone
make
sudo make install
````

### Build Options
````bash
# Standard optimized build
make

# Debug build (with symbols, no optimization)
make debug

# Build with checksum validation enabled
make checksums

# Clean build artifacts
make clean

# Uninstall
sudo make uninstall
````

##  Quick Start
````bash
# Basic packet capture
sudo ./bin/Lodestone -i eth0

# Capture 100 packets
sudo ./bin/Lodestone -i eth0 -c 100

# Capture HTTP traffic
sudo ./bin/Lodestone -i eth0 -f "tcp port 80"

# Save to PCAP file
sudo ./bin/Lodestone -i eth0 -o capture.pcap

# Detailed analysis with statistics
sudo ./bin/Lodestone -i eth0 -c 1000 -s -d detailed
````

##  Usage

### Command Line Options
````
Usage: Lodestone [OPTIONS]

Capture Options:
  -i, --interface <name>     Network interface (required)
  -c, --count <num>          Capture N packets then stop
  -f, --filter <expr>        BPF filter expression
  -p, --promiscuous          Enable promiscuous mode (default)
  -P, --no-promiscuous       Disable promiscuous mode
  -m, --mmap                 Use zero-copy mmap capture

Output Options:
  -o, --output <file>        Save packets to PCAP file
  -l, --log <file>           Log packets to file
  -F, --log-format <fmt>     Log format: text, csv, json, xml
  -d, --display <mode>       Display: brief, detailed, hex, full
  -C, --no-color             Disable colored output
  -q, --quiet                Quiet mode (no display)
  -v, --verbose              Verbose output

Analysis Options:
  -r, --reassemble           Enable TCP stream reassembly
  -a, --detect-anomalies     Enable anomaly detection
  -A, --show-alerts          Show security alerts
  -s, --stats                Show detailed statistics

Other:
  -h, --help                 Show help message
````

### Examples

#### Basic Capture
````bash
# Capture all traffic
sudo ./bin/Lodestone -i eth0

# Capture 1000 packets with statistics
sudo ./bin/Lodestone -i eth0 -c 1000 -s

# Quiet capture to file
sudo ./bin/Lodestone -i eth0 -q -o capture.pcap
````

#### Protocol-Specific
````bash
# HTTP traffic
sudo ./bin/Lodestone -i eth0 -f "tcp port 80" -d detailed

# HTTPS traffic
sudo ./bin/Lodestone -i eth0 -f "tcp port 443"

# DNS queries
sudo ./bin/Lodestone -i eth0 -f "udp port 53"

# SSH connections
sudo ./bin/Lodestone -i eth0 -f "tcp port 22"

# ICMP (ping)
sudo ./bin/Lodestone -i eth0 -f "icmp"
````

#### IPv6
````bash
# All IPv6 traffic
sudo ./bin/Lodestone -i eth0 -f "ip6"

# IPv6 HTTP
sudo ./bin/Lodestone -i eth0 -f "ip6 and tcp port 80"

# ICMPv6
sudo ./bin/Lodestone -i eth0 -f "icmp6"
````

#### Advanced Analysis
````bash
# TCP stream reassembly
sudo ./bin/Lodestone -i eth0 -f "tcp port 80" -r -v

# Anomaly detection
sudo ./bin/Lodestone -i eth0 -a -A

# Full security analysis
sudo ./bin/Lodestone-i eth0 -r -a -A -s -o security.pcap

# High-performance capture
sudo ./bin/Lodestone -i eth0 -m -q -o highspeed.pcap
````

#### Logging
````bash
# Log to CSV
sudo ./bin/Lodestone -i eth0 -l packets.csv -F csv

# Log to JSON
sudo ./bin/Lodestone -i eth0 -l packets.json -F json

# Log DNS to JSON
sudo ./bin/Lodestone -i eth0 -f "port 53" -l dns.json -F json -q
````

##  Filter Examples

### Basic Filters
````bash
# Protocol filters
sudo ./bin/Lodestone -i eth0 -f "tcp"
sudo ./bin/Lodestone -i eth0 -f "udp"
sudo ./bin/Lodestone -i eth0 -f "icmp"

# Port filters
sudo ./bin/Lodestone -i eth0 -f "port 80"
sudo ./bin/Lodestone -i eth0 -f "src port 443"
sudo ./bin/Lodestone -i eth0 -f "dst port 22"

# IP address filters
sudo ./bin/Lodestone -i eth0 -f "host 192.168.1.100"
sudo ./bin/Lodestone -i eth0 -f "src host 8.8.8.8"
sudo ./bin/Lodestone -i eth0 -f "net 192.168.0.0/16"
````

### Combined Filters
````bash
# HTTP or HTTPS
sudo ./bin/Lodestone -i eth0 -f "port 80 or port 443"

# TCP to specific host
sudo ./bin/Lodestone -i eth0 -f "tcp and host 192.168.1.100"

# Exclude SSH
sudo ./bin/Lodestone -i eth0 -f "not port 22"

# Web traffic from subnet
sudo ./bin/Lodestone -i eth0 -f "src net 192.168.1.0/24 and (port 80 or port 443)"
````

### Advanced Filters
````bash
# TCP SYN packets
sudo ./bin/Lodestone -i eth0 -f "tcp[tcpflags] & tcp-syn != 0"

# Large packets
sudo ./bin/Lodestone -i eth0 -f "greater 1000"

# Port range
sudo ./bin/Lodestone -i eth0 -f "portrange 1000-2000"
````

See [FILTER_GUIDE.md](docs/FILTER_GUIDE.md) for comprehensive filter documentation.

##  Architecture
````
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                     │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐ │
│  │   Display   │  │    Logger    │  │   Statistics   │ │
│  └─────────────┘  └──────────────┘  └────────────────┘ │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────┴────────────────────────────────┐
│                    Analysis Layer                        │
│  ┌────────────────┐  ┌────────────────────────────────┐ │
│  │ Stream Tracker │  │    Anomaly Detector            │ │
│  │ (TCP Reassembly)│  │ (Scans, Floods, Spoofing)      │ │
│  └────────────────┘  └────────────────────────────────┘ │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────┴────────────────────────────────┐
│                     Parser Layer                         │
│  ┌──────┐  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐│
│  │ Eth  │→ │ IP  │→ │IPv6 │→ │ TCP │→ │ UDP │→ │ICMP ││
│  └──────┘  └─────┘  └─────┘  └─────┘  └─────┘  └─────┘│
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────┴────────────────────────────────┐
│                    Capture Layer                         │
│  ┌────────────────────────┐  ┌─────────────────────────┐│
│  │  AF_PACKET Raw Socket  │  │  TPACKET_V3 (mmap)      ││
│  │  (Standard Capture)    │  │  (Zero-Copy Capture)    ││
│  └────────────────────────┘  └─────────────────────────┘│
└────────────────────────┬────────────────────────────────┘
                         │
                  ┌──────┴───────┐
                  │  BPF Filter  │
                  │   (Kernel)   │
                  └──────────────┘
````

##  Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

### Quick Contribution Guide

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Commit (`git commit -m 'Add amazing feature'`)
6. Push (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Areas Needing Help

- Windows/macOS support
- Additional protocol parsers
- GUI interface
- Machine learning integration
- Performance optimizations

##  License

This project is licensed under the GNU General Public License v3.0 with additional terms for commercial use - see the [LICENSE](LICENSE) file for details.

### Commercial Use

Commercial use requires explicit written permission. Contact hostilewire@proton.me for licensing inquiries.

##  Authors

- **Merroun Omar** - *Initial work* - [GitHub Profile](https://github.com/1bnBattuta)


##  Acknowledgments

- Linux kernel networking stack developers
- libpcap/tcpdump team
- All contributors and testers

##  Contact

- **Issues**: [GitHub Issues](https://github.com/1bnBattuta/Lodestone/issues)
- **Email**: [hostilewire@proton.me]

