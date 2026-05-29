# Sentinel PortScan

A multithreaded TCP port scanner designed for attack surface discovery, service identification, banner collection, and exposure prioritization.

Unlike traditional port scanners that only identify open ports, Sentinel PortScan performs service probing, banner grabbing, protocol fingerprinting, and assigns an **Exposure Score** to help security professionals prioritize findings during reconnaissance and security assessments.

> **Disclaimer:** Use this tool only against systems you own or are explicitly authorized to test.

---

# Overview

Sentinel PortScan was created to bridge the gap between simple port scanners and full attack surface analysis tools.

Most scanners answer a simple question:

> "Is the port open?"

Sentinel PortScan goes one step further:

> "How interesting is this service from a security perspective?"

By combining banner grabbing, protocol detection, and exposure scoring, the tool helps identify services that deserve further investigation.

---

# Features

### High-Speed Multithreaded Scanning

* Concurrent TCP scanning
* Configurable worker pool
* Supports large target lists
* Optimized for reconnaissance workflows

### Banner Grabbing

* Passive banner collection
* Service-specific probes
* Protocol-aware requests
* Service identification

### HTTP and HTTPS Detection

* Automatic HTTP probing
* Basic HTTPS/TLS detection
* HTTP response fingerprinting

### Exposure Scoring

Each open service receives an exposure score between **0 and 100** based on:

* Service type
* Administrative access exposure
* Database exposure
* Known high-risk services
* Banner information
* Protocol characteristics

### Multiple Export Formats

* CSV
* JSON
* TXT

### Asset Intelligence

Collected information includes:

* Hostname
* IP Address
* Port
* Service Name
* Banner
* Protocol Hint
* Exposure Score
* Response Time

---

# Why Sentinel PortScan?

Most scanners produce output similar to:

```text
22/tcp open ssh
80/tcp open http
3306/tcp open mysql
```

Sentinel PortScan produces:

```text
22/tcp  OPEN  SSH
Score: 45
Reason: Remote administration service

3306/tcp OPEN MySQL
Score: 80
Reason: Exposed database service

6379/tcp OPEN Redis
Score: 95
Reason: High-risk exposed service
```

This allows security researchers to prioritize targets more effectively.

---

# Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/sentinel-portscan.git
cd sentinel-portscan
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Required packages:

```bash
pip install dnspython
```

---

# Usage

## Scan a Single Host

```bash
python3 sentinel_portscan.py \
    --target example.com \
    --ports 80,443,22
```

---

## Scan Multiple Targets

```bash
python3 sentinel_portscan.py \
    --file targets.txt \
    --ports 1-1000
```

---

## Export Results to CSV

```bash
python3 sentinel_portscan.py \
    --file targets.txt \
    --ports 1-1024 \
    --output results.csv
```

---

## Export Results to JSON

```bash
python3 sentinel_portscan.py \
    --file targets.txt \
    --ports 80,443 \
    --output results.json
```

---

## Save Only Open Ports

```bash
python3 sentinel_portscan.py \
    --file targets.txt \
    --ports 1-65535 \
    --only-open
```

---

## Increase Scan Speed

```bash
python3 sentinel_portscan.py \
    --file targets.txt \
    --ports 1-65535 \
    --workers 500
```

---

# Command Line Options

| Option            | Description              |
| ----------------- | ------------------------ |
| `-t`, `--target`  | Single target            |
| `-f`, `--file`    | File containing targets  |
| `-p`, `--ports`   | Ports or ranges to scan  |
| `-w`, `--workers` | Number of worker threads |
| `--timeout`       | Connection timeout       |
| `-o`, `--output`  | Output file              |
| `--format`        | Force output format      |
| `--only-open`     | Store only open ports    |

---

# Input File Format

One host per line:

```text
example.com
api.example.com
192.168.1.1
10.0.0.0
```

Comments are supported:

```text
# Production
app.example.com

# Internal
vpn.example.com
```

---

# Exposure Scoring

Sentinel PortScan automatically prioritizes services.

### Example Categories

| Service       | Typical Score |
| ------------- | ------------- |
| HTTP          | 20-30         |
| HTTPS         | 20-30         |
| SSH           | 45-60         |
| FTP           | 60-75         |
| SMB           | 70-90         |
| Redis         | 85-100        |
| Elasticsearch | 85-100        |
| MongoDB       | 85-100        |
| MySQL         | 70-90         |
| PostgreSQL    | 70-90         |
| RDP           | 70-90         |

The score is intended to assist prioritization and does not represent a vulnerability rating.

---

# Example Output

```text
Target: app.example.com
IP: 34.120.10.5

Port: 443
Status: OPEN
Service: HTTPS
Protocol: TLS
Score: 25

Port: 22
Status: OPEN
Service: SSH
Score: 55

Port: 6379
Status: OPEN
Service: Redis
Score: 95
Notes: High-risk exposed service
```

---

# Typical Workflow

```text
Subdomain Enumeration
        │
        ▼
HTTP Validation
        │
        ▼
Sentinel PortScan
        │
        ▼
Exposure Prioritization
        │
        ▼
Service Enumeration
        │
        ▼
Vulnerability Assessment
```

---

# Future Roadmap

Planned improvements include:

* ASN scanning
* CIDR/range support
* Screenshot collection
* TLS certificate analysis
* WAF detection
* HTTP technology fingerprinting
* CVE enrichment
* Service-specific enumeration
* Shodan-style asset reports
* HTML and PDF reporting
* Machine learning based exposure ranking

---

# Integration with Synex

Sentinel PortScan was designed to fit naturally into reconnaissance pipelines such as Synex.

Potential integrations include:

* Host discovery
* Service fingerprinting
* CVE correlation
* Exposure classification
* Attack surface prioritization
* Recon orchestration

---

# Author

Arthur Witt

Built for bug bounty hunting, attack surface management, penetration testing, red team operations, and security research.
