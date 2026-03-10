# Week 11 — Network Traffic Analysis with Wireshark

## Overview

This week focused on network traffic analysis using **Wireshark**, the industry-standard packet capture and analysis tool. The exercise covered two phases: capturing and filtering live traffic on a Windows host, then analyzing a real-world malicious PCAP from **Palo Alto Networks Unit 42** containing a **RedLine Stealer** infection.

---

## Learning Objectives

- Understand the Wireshark workflow: capture → filter → analyze → document
- Use display filters to isolate specific traffic types
- Use Statistics tools (Protocol Hierarchy, Conversations) to rapidly triage a PCAP
- Follow TCP streams to read complete plaintext C2 conversations
- Identify attacker TTPs from network evidence alone
- Understand how RedLine Stealer operates at the network level

---

## Lab Environment

| Component | Details |
|-----------|---------|
| Analysis Tool | Wireshark (Windows host) |
| Live Capture Interface | Windows Wi-Fi / Ethernet adapter |
| Malicious PCAP Source | Unit 42 / Palo Alto Networks RedLine Stealer Quiz |
| PCAP URL | https://unit42.paloaltonetworks.com/wireshark-quiz-redline-stealer/ |

---

## Part 1: Live Traffic Capture

### Capture Process
1. Opened Wireshark on Windows host
2. Selected active network interface
3. Browsed to `http://example.com` using `curl http://example.com` (forced HTTP to generate visible traffic)
4. Stopped capture after ~15 seconds

### Display Filters Applied

| Filter | Purpose | Result |
|--------|---------|--------|
| `http` | Isolate HTTP traffic | Showed GET request and response to example.com |
| `http.request` | Outbound requests only | Showed Host header and request details |
| `tcp.flags.syn == 1` | TCP handshakes | Showed all connection initiations |

> **Note:** DNS traffic was not visible because Windows uses DNS over HTTPS (DoH) by default — a good real-world lesson about what is and isn't visible on the wire.

---

## Part 2: Malicious PCAP Analysis — RedLine Stealer

### Key Findings

| Field | Value |
|-------|-------|
| Victim IP | 10.7.10.47 |
| C2 Server | 194.26.135.119:12432 |
| Protocol | HTTP (plaintext) — WCF / tempuri.org |
| Traffic Volume | 787 packets / 592KB |
| Initial Infection Vector | mystery_file.ps1 (PowerShell dropper) |
| Victim Username | rwalters |

### Analysis Methodology

**Step 1 — Protocol Hierarchy** (`Statistics → Protocol Hierarchy`)
Revealed: NTP (sandbox evasion check), NetBIOS/SMB (background noise), HTTP (C2 traffic).

**Step 2 — Conversations** (`Statistics → Conversations → IPv4`)
Identified 194.26.135.119 as dominant external IP — 787 packets / 592KB. This is the C2 server.

**Step 3 — TCP Stream Follow** (`Right-click → Follow → TCP Stream`)
Revealed complete plaintext C2 conversation and stolen data.

### What RedLine Stole

- **System recon**: Machine ID, OS, CPU, RAM, running processes, installed AV
- **Browser credentials**: rwalters@coolweathercoat.com : My_p@ssw0rd
- **File exfiltrated**: Top_secret_ducment.docx
- **Targeting scope**: 30+ browsers, 20+ crypto wallets, 50+ API key types, Desktop/Documents files

---

## Screenshots

| Screenshot | Description |
|-----------|-------------|
| `screenshots/01-live-capture.png` | Live Wireshark capture |
| `screenshots/02-http-filter.png` | HTTP filter applied |
| `screenshots/03-protocol-hierarchy.png` | Protocol hierarchy of malicious PCAP |
| `screenshots/04-conversations.png` | Conversations view — C2 IP identified |
| `screenshots/05-tcp-stream.png` | TCP stream — stolen data visible |

---

## Indicators of Compromise (IoCs)

| Type | Value |
|------|-------|
| C2 IP | 194.26.135.119 |
| C2 Port | 12432 |
| Auth Token | c75a68098b33270de4b87af925fb5ffd |
| Dropper | mystery_file.ps1 |

---

## Key Concepts Learned

- **Protocol Hierarchy** — fastest way to understand an unknown PCAP, start here every time
- **Conversations view** — identifies C2 candidate in seconds, look for disproportionately high traffic
- **TCP stream following** — most powerful technique for reading plaintext C2 content
- **RedLine uses HTTP deliberately** — simpler, faster, detectable via network monitoring
- **Infostealer speed** — entire cycle completes in seconds, preventative controls matter more than reactive detection
- **MITRE ATT&CK**: T1071.001, T1041, T1555.003

---

## Deliverables

- **[report](week11-report.pdf)** — Professional report following blueteam standards.

---

*Part of a self-designed cybersecurity pre-master's portfolio program.*
