# USB HID Attack Analysis — Rubber Ducky, MITRE ATT&CK Mapping, Detection and Mitigation

> **TL;DR.** Two USB Rubber Ducky payloads (Windows and Linux) are dissected step by step. Every action is mapped to a MITRE ATT&CK technique. Four academic detection approaches are evaluated. Practical mitigations are listed at the end. Useful for SOC analysts, red teamers, and anyone studying for Security+ or SC-200 who wants a real-world example of credential dumping, defence evasion, and indicator removal in one chain.

MSc Cyber Security lab, University of the West of England, 2024.

---

## Why USB HID Attacks Matter

A **USB Human Interface Device (HID) attack** abuses the implicit trust an operating system gives to keyboards and mice.

A device like the Hak5 Rubber Ducky looks like a keyboard to the host. The OS plugs it in, no questions asked. The "keyboard" then types attacker-controlled commands at machine speed, hundreds of keystrokes per second, executing a payload before any human could intervene.

What makes this dangerous:

- **Anti-malware does not flag the device.** It is a keyboard, by definition.
- **No malware sits on disk.** Everything runs from typed commands.
- **Standard endpoint controls do not apply.** USB storage policies, autorun blocks and disk-level scanning miss this entire attack class.
- **Detection has to come from behaviour, not signatures.**

This repo walks through exactly what a Ducky payload does, why it works, and what defenders can do about it.

---

## Lab Setup

Two virtual machines, one Windows target and one Linux target. The Ducky payload was loaded onto a USB device and triggered against each VM in turn. All actions and resulting telemetry were logged for analysis.

Attack outcomes per system:

| System | Outcome of payload execution |
|---|---|
| Windows 10 | Defender disabled, firewall down, rogue local admin created, registry hives exfiltrated, browser data copied, event logs cleared |
| Ubuntu Linux | Rogue sudo user created, `/etc/shadow` and `/etc/passwd` exfiltrated, xrdp installed and exposed, UFW disabled, logs and bash history wiped |

Full payload scripts are in `/payloads/windows_ducky.txt` and `/payloads/linux_ducky.txt`.

---

## Attack Walkthrough — Plain English

### Windows Payload, in order

1. Pop a Run dialog with `Win+R` and launch elevated PowerShell.
2. Disable Windows Firewall across all profiles.
3. Disable every protective component of Windows Defender: real-time monitoring, IOAV, script scanning, intrusion prevention, behaviour monitoring, block-at-first-seen.
4. Run `systeminfo` and dump network configuration to an attacker-controlled SMB share.
5. Enable Remote Desktop via a registry edit. Open inbound TCP 4444 in the firewall as a backdoor.
6. Create a local user `CNSTEST` and add it to the Administrators group.
7. Save the SAM, SECURITY, SOFTWARE and SYSTEM registry hives to the attacker share. These hives contain hashed credentials and system secrets.
8. Copy the entire Chrome and Edge user data folders, including saved cookies and credentials.
9. Delete the rogue `CNSTEST` user once the work is done, to remove the obvious trail.
10. Clear the System, Security and Application event logs.

### Linux Payload, in order

1. Open a terminal with `Ctrl+Alt+T`.
2. Create a user `cnstest` with a known password and add it to the sudo group.
3. Mount an attacker-controlled SMB share locally.
4. Copy `/etc/shadow`, `/etc/passwd`, `/etc/group` to the share — every credential hash on the box.
5. Copy `/etc/hosts`, `/etc/crontab`, `/etc/fstab`, `/etc/resolv.conf`, `/etc/profile` for environment reconnaissance.
6. Copy Apache and MySQL config files.
7. Install and start `xrdp`, open inbound TCP 3389, disable UFW, leave RDP credentials in a text file on the share.
8. Wipe `/var/log` and clear bash history.
9. Delete the `cnstest` user and home directory.

The whole chain runs in seconds. A user walking past their own machine could miss it.

---

## MITRE ATT&CK Mapping — Windows Payload

| Step | Action | MITRE ATT&CK |
|---|---|---|
| 1 | Open elevated PowerShell via Win+R | T1059.001 — Command and Scripting Interpreter: PowerShell |
| 2 | Disable Windows Firewall | T1562.004 — Impair Defenses: Disable or Modify System Firewall |
| 3 | Disable Defender real-time monitoring, IOAV, script scanning, behaviour monitoring | T1562.001 — Impair Defenses: Disable or Modify Tools |
| 4 | Exfiltrate `systeminfo` and IP configuration to attacker SMB share | T1041 — Exfiltration Over C2 Channel |
| 5 | Enable RDP via registry edit, open inbound TCP 4444 | T1021.001 — Remote Services: RDP, T1562.004 — Disable Firewall |
| 6 | Create local user `CNSTEST`, add to Administrators | T1136.001 — Create Account: Local Account, T1078.003 — Valid Accounts: Local Accounts |
| 7 | Save SAM, SECURITY, SOFTWARE, SYSTEM registry hives | T1003.002 — OS Credential Dumping: Security Account Manager |
| 8 | Copy Chrome and Edge user data | T1555.003 — Credentials from Web Browsers |
| 9 | Delete the rogue user | T1070 — Indicator Removal |
| 10 | Clear System, Security and Application event logs | T1070.001 — Indicator Removal: Clear Windows Event Logs |

## MITRE ATT&CK Mapping — Linux Payload

| Step | Action | MITRE ATT&CK |
|---|---|---|
| 1 | Open terminal via Ctrl+Alt+T | T1059.004 — Command and Scripting Interpreter: Unix Shell |
| 2 | Create user `cnstest`, add to sudo group | T1136.001 — Create Local Account, T1078.003 — Valid Accounts: Local Accounts |
| 3 | Mount attacker SMB share via CIFS | T1021.002 — Remote Services: SMB |
| 4 | Copy `/etc/shadow`, `/etc/passwd`, `/etc/group` to share | T1003.008 — OS Credential Dumping: /etc/passwd and /etc/shadow |
| 5 | Copy `/etc/hosts`, `/etc/crontab`, `/etc/fstab`, `/etc/resolv.conf`, `/etc/profile` | T1005 — Data from Local System |
| 6 | Copy Apache and MySQL config files | T1005 — Data from Local System |
| 7 | Install and start xrdp | T1021.001 — Remote Services: RDP |
| 8 | Open TCP 3389, disable UFW | T1562.004 — Impair Defenses: Disable Firewall |
| 9 | Delete `/var/log` files, clear bash history | T1070.002 — Clear Linux Logs, T1070.003 — Clear Command History |
| 10 | Delete user and home directory | T1070 — Indicator Removal |

---

## Detection Approaches Evaluated

### 1. Keystroke Dynamics

Monitors typing rhythm, speed and inter-key timing. A Ducky injects keystrokes at machine-perfect intervals, a pattern no human produces. Useful as a first-line behavioural detection.

**Limits:** requires per-user baselines, offers no protection on shared workstations, can be evaded by Duckies that randomise delays.

Source: Barbhuiya et al. (2012), *International Symposium on Cyberspace Safety and Security*.

### 2. Event Graph Analysis

Builds a graph from process-creation, registry and file events triggered after a USB device is connected. Compares the graph against known-good patterns. Strong against multi-stage payloads like the ones in this repo, where the action chain itself is the signal.

Source: Huang and Hahn-Ming (2019), *ACM Conference Proceedings*.

### 3. Hardware-Assisted Detection

Captures USB descriptor traffic at the physical layer and feeds it into a machine-learning classifier. Detects malicious devices regardless of payload obfuscation. Effective but requires dedicated hardware, limiting deployment outside high-security environments.

Source: Denney et al. (2019), *Conference on Security and Privacy in Wireless and Mobile Networks*.

### 4. Hybrid Intrusion Detection

Combines signature-based and anomaly-based detection with a random-forest classifier. Trades single-method blind spots for higher coverage at the cost of complexity.

Source: Debnath (2020), *IEEE CCWC*.

---

## Mitigations

- **USB device whitelisting.** Group Policy on Windows, `usbguard` on Linux. Blocks any device whose vendor/product ID is not pre-approved. The single highest-impact control.
- **Disable HID auto-mount and autorun** on shared kiosks, reception machines, and any unattended workstation.
- **Defender Tamper Protection.** Stops the `Set-MpPreference -DisableRealtimeMonitoring` step from succeeding on modern Windows builds. Should be on by default in 2024+ but worth verifying in your environment.
- **Sysmon plus SIEM coverage.** Even if the keystroke injection itself is missed, the post-injection action chain (process creation, registry edits, mass log clearing, hive exports) is highly detectable. Splunk, Sentinel and similar tools catch this with off-the-shelf detection rules.
- **Physical port restrictions** in regulated environments. Port blockers, epoxy, monitored ports.
- **User awareness training.** Many HID attacks rely on a baited "found USB" left in a car park or a coffee shop. The cheapest mitigation in the list.

---

## How to Use This Repo

- **Read this README** for the full walkthrough.
- `/payloads/windows_ducky.txt` — full Windows payload script with comments.
- `/payloads/linux_ducky.txt` — full Linux payload script with comments.
- `/docs/` — original lab report (Word format, archived for completeness).

This repo is for **educational and defensive research only**. The payloads are documented so analysts can learn to recognise the pattern and write detections. Running them against systems you do not own is illegal and unethical.

---

## Video Demonstration Link

- Video - https://drive.google.com/file/d/1VCvTkB9t1vIpSdaf5M4zYezUef1zv6vv/view?usp=drive_link


## Limitations and Honest Notes

- Lab analysis only. The payloads were studied and executed in an isolated test environment.
- Detection methods are summarised from cited literature, not implemented in code in this repo. Building a basic event-graph detector is open as future work.
- MITRE mappings are the author's interpretation. Corrections via GitHub issues are welcome.

---

## References

- Barbhuiya, T.S. and S.N. (2012). An anomaly-based approach for HID attack detection using keystroke dynamics. *International Symposium on Cyberspace Safety and Security*.
- Huang, Chia-Yu and Hahn-Ming, P.-M.L. (2019). Identifying HID-based Attacks through Process Event. *ACM*.
- Denney, K. et al. (2019). Dynamically detecting USB attacks in hardware: poster. *Conference on Security and Privacy in Wireless and Mobile Networks*.
- Debnath, F.A.D. (2020). HID-SMART: Hybrid Intrusion Detection Model for Home. *IEEE CCWC*.
- MITRE ATT&CK Framework, https://attack.mitre.org
- Hak5 USB Rubber Ducky documentation, https://docs.hak5.org/hak5-usb-rubber-ducky

---

**Author**

Muhammad Suhaib
MSc Cyber Security (Distinction), University of the West of England
CompTIA Security+
[LinkedIn](https://linkedin.com/in/muhsuhaib) · suhaibkhan916@gmail.com
