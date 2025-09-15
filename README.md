# Personal Cybersecurity Homelab

> _Isolated, educational environment for practicing offensive and defensive security techniques._

---

## Project Overview

This repository documents my personal homelab built to practice cybersecurity techniques end-to-end: **attack → capture → analyze → detect → mitigate**. The environment consists of multiple virtual machines (VMs) running different roles and purpose-built distributions, connected via an isolated virtual network. The goal is to safely recreate real-world scenarios (vulnerable hosts, phishing, malware analysis, monitoring) without touching production networks.

> **Important:** All activity is contained within isolated VMs and virtual networks. Do NOT use any tools or payloads from this lab against systems you do not own or have explicit authorization to test.

---

## Table of Contents

- [Project Overview](#project-overview)
- [VM Inventory & Descriptions](#vm-inventory--descriptions)
- [Network Architecture](#network-architecture)
- [IP Addressing: Public vs Private, Static vs Dynamic](#ip-addressing-public-vs-private-static-vs-dynamic)
- [Useful Commands & Output Examples](#useful-commands--output-examples)
- [Sample Exercises / Labs](#sample-exercises--labs)
- [Data, Artifacts & Sanitization](#data-artifacts--sanitization)
- [Automation & Scripts](#automation--scripts)
- [Security, Ethics & Safety](#security-ethics--safety)
- [References & Tools](#references--tools)
- [License](#license)

---

## VM Inventory & Descriptions

Include each VM in your repository README with the following fields: name, role, OS/image, purpose, key tools installed, snapshot notes, and any important credentials (sanitized). Below are template descriptions you can copy and adapt.

### 1. **Attacker (Kali Linux)**
- **Role:** Offensive toolkit / attacker workstation
- **OS:** Kali Linux (VM)
- **Image file:** [Kali Linux (VM) ](https://www.kali.org/get-kali/#kali-virtual-machines)
- **Purpose:** Scanning, enumeration, exploitation, payload crafting, web app testing
- **Key tools:** Nmap, Metasploit, Burp Suite, Nikto, sqlmap, wget, curl, netcat, john
- **Snapshot notes:** Keep a clean snapshot "kali-base" to revert after destructive tests


---

### 2. **Vulnerable Target (Metasploitable / Ubuntu vulnerable VM)**
- **Role:** Intentionally vulnerable host
- **OS** Metasploitable 2 / custom vulnerable Ubuntu image
- **Image file** [Metasploitable 2 / custom vulnerable Ubuntu image](https://sourceforge.net/projects/metasploitable/)
- **Purpose:** Practice exploitation, privilege escalation, web app vulnerabilities
- **Key services:** FTP, SSH, MySQL, Apache, vulnerable web applications
- **Snapshot notes:** Keep a pre-exploitation snapshot and a post-exploitation snapshot for analysis


---

### 3. **Windows Lab (Windows Server / Windows 10)**
- **Role:** Typical enterprise endpoint or server
- **OS/Image:** Windows Server / Windows 10 VM
- **Purpose:** Simulate AD, domain join, Windows privilege escalation, lateral movement, and Windows-specific attacks
- **Key tools:** Sysinternals (Autoruns, Procmon), PowerShell, Windows Event Viewer, RDP
- **Snapshot notes:** Keep snapshots before AD changes or group policy experiments



## Network Architecture

Add a network diagram file to the repo (e.g., `network-diagram.png`). Describe whether you use NAT, host-only, or bridged adapters, and which VMs are on which subnets.

**Suggested sections to include in the diagram and README:**
- Virtual network names and types (Host-only, NAT, Internal)
- VM roles mapped to IP addresses (private ranges only in the repo)
- Firewall / routing rules (if any)
- Monitoring tap/port-mirroring placement (where Suricata/Zeek sees traffic)


```
Topology: [Kali] -- [Internal Network 10.0.0.0/24] -- [Targets: Metasploitable (10.0.0.10), Windows (10.0.0.11), REMnux (10.0.0.12)]
SIEM/IDS: Suricata/ELK connected to internal switch mirror to capture traffic from attacker and targets.
Host-only adapter used for isolated communication; NAT adapter used for internet access from analysis VM (for safe download or sandboxing with care).
```

---

## IP Addressing: Public vs Private, Static vs Dynamic

### Public vs Private IPs (short)
- **Private IPs** are used inside local networks and are not routable on the public internet. Common ranges include `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`.
- **Public IPs** are assigned by ISPs and are routable on the internet. VMs in host-only/internal networks typically only have private IPs.

### Static vs Dynamic IPs (short)
- **Static IP:** Manually assigned; does not change unless you change it.
- **Dynamic IP:** Assigned by DHCP (router/VM manager); can change on DHCP lease renewal or if the device reconnects.

### What `ipconfig` / `ifconfig` / `ip addr` shows
- `ipconfig` (Windows) or `ip a` / `ifconfig` (Linux) show the machine's **local** interface addresses, subnet masks, and gateways.
- These commands show **private** IPs for VMs on host-only/internal networks.

### What `whatsmyip.com` shows
- `whatsmyip.com` (or `curl ifconfig.me`) shows the **public** IP address seen by external services — i.e., your NAT/gateway/router's public IP. For most home lab setups behind NAT, all VMs share the same public IP as the host.

**Example to include in README (copy & edit with your actual outputs):**

```
# Example Windows `ipconfig` output
Ethernet adapter Ethernet0:
   IPv4 Address. . . . . . . . . . . : 10.0.0.11
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.0.0.1

# Example Linux `ip a` output
3: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    inet 10.0.0.12/24 brd 10.0.0.255 scope global dynamic ens33

# Example public IP (whatismyip / ifconfig.me)
Public IP: 203.0.113.42

Notes:
- The private IPs above are in the 10.0.0.0/24 subnet and are not directly reachable from the public internet.
- Public IP 203.0.113.42 belongs to the ISP and is used for outbound traffic unless the host is behind a VPN or additional NAT.
```

## Useful Commands & Output Examples

Add the most-used commands and a one-line description. Encourage the reader to sanitize outputs before committing.

- `ipconfig /all` (Windows) — shows IPs, DNS, DHCP lease
- `ip a` or `ifconfig` (Linux) — show network interfaces
- `route print` / `ip route` — routing table
- `curl ifconfig.me` — fetch public IP
- `nmap -sC -sV -oA scans/initial 10.0.0.10` — example scanning command
- `tcpdump -i any -w capture.pcap` — capture network traffic
- `volatility -f memory.dmp --profile=Win7SP1x64 pslist` — memory analysis (example)

---

## Sample Exercises / Labs

Describe small, shareable exercises with objective, steps, and expected results. Examples:

1. **Simple Port Scanning & Service Enumeration**
   - **Objective:** Identify open services on Metasploitable.
   - **Tools:** Nmap
   - **Commands:** `nmap -sC -sV -p- 10.0.0.10`
   - **Expected:** List of open ports and banner versions; follow-up: research CVEs for discovered versions.

2. **Exploit a Vulnerable Web App (Metasploitable)**
   - **Objective:** Exploit a known web vulnerability and gain a shell.
   - **Tools:** Browser, Burp, Metasploit
   - **Notes:** Keep sanitized writeup; don’t commit exploit code or any unauthorized payloads.

3. **Malware Triage on REMnux**
   - **Objective:** Analyze a suspicious Word document containing macros.
   - **Tools:** oledump, olevba, YARA, a VM snapshot
   - **Steps:** Extract macros -> analyze strings -> run in isolated REMnux snapshot -> capture network traffic -> create YARA rule.

4. **Detection Rule: Suricata / YARA**
   - **Objective:** Create a rule to detect SMB brute-force attempts or a specific malicious string pattern.
   - **Deliverable:** Rule, test pcap or simulated traffic, and dashboard screenshot showing an alert.

---

## Data, Artifacts & Sanitization

- Store only sanitized logs and outputs in the public repo. Remove IPs that identify your home network or provider.
- Do NOT upload malware binaries, full PCAPs with sensitive data, private keys, or credentials.
- When you include screenshots, blur or redact hostnames, MACs, or public IPs.
- Keep a private folder (not in this repo) for real samples if needed for personal study.

---


## Security, Ethics & Safety

Short policy to include in the README:

- All testing performed only on VMs and isolated virtual networks. No testing on systems without explicit permission.
- No distribution of live malware, exploit payloads, or private credentials.
- Follow responsible disclosure if any vulnerabilities discovered on third-party systems by mistake.


---
