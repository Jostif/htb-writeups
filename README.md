# htb-writeups

HackTheBox machine writeups by J0stif.
Full walkthroughs with methodology, commands, and techniques.

> Writeups are published only after machine retirement per HTB policy.

---

## Machine index

### Windows — Active Directory

| Machine | Difficulty | Techniques | User | Root | Writeup |
|---|---|---|---|---|---|
| [Eighteen](./Eighteen/) | 🔴 Hard | CVE-2025-8110 (Gogs RCE), BadSuccessor, dMSA abuse | ✓ | ✓ | [→](./Eighteen/README.md) |
| [EscapeTwo](./EscapeTwo/) | 🟢 Easy | ADCS ESC4→ESC1, MSSQL | ✓ | ✓ | [→](./EscapeTwo/README.md) |
| [Support](./Support/) | 🟢 Easy | SMB, LDAP, Reverse Engineering, RBCD | ✓ | ✓ | [→](./Support/README.md) |
| [Overwatch](./Overwatch/) | 🟡 Medium | SMB, WCF/SOAP Injection, DNS Poisoning, AD | ✓ | ✓ | [→](./Overwatch/README.md) |

### Windows — Standalone

| Machine | Difficulty | Techniques | User | Root | Writeup |
|---|---|---|---|---|---|
| [Unika](./Unika/) | 🟢 Easy | LFI, NTLMv2, Hashcat | ✓ | ✓ | [→](./Unika/README.md) |
| [Timelapse](./Timelapse/) | 🟢 Easy | SMB, PFX, LAPS | ✓ | ✓ | [→](./Timelapse/README.md) |

### Linux

| Machine | Difficulty | Techniques | User | Root | Writeup |
|---|---|---|---|---|---|
| [Browsed](./Browsed/) | 🟡 Medium | Chrome Extension, Bash Arithmetic Injection, SSRF, pyc Hijack | ✓ | ✓ | [→](./Browsed/README.md) |

---

## Coming soon (pending retirement)

| Machine | Difficulty | Techniques |
|---|---|---|
| Logging | 🔴 Hard | Shadow Credentials, ADCS ESC1, DLL Hijack, WSUS |
| Garfield | 🔴 Hard | WriteDacl, RBCD, KeyList (RODC), SYSVOL |
| Interpreter | 🟡 Medium | CVE-2023-43208, Deserialization, PBKDF2, eval() Injection |

---

## Technique index

| Technique | Machines |
|---|---|
| ADCS / ESC1 | EscapeTwo |
| ADCS / ESC4 | EscapeTwo |
| BadSuccessor / dMSA | Eighteen |
| CVE exploitation | Eighteen (CVE-2025-8110) |
| Gogs RCE | Eighteen |
| SMB enumeration | Support, Timelapse, Overwatch |
| LDAP enumeration | Support |
| Reverse engineering (.NET) | Support |
| RBCD | Support |
| LAPS | Timelapse |
| PFX cracking | Timelapse |
| LFI | Unika |
| NTLMv2 / Responder | Unika, Overwatch |
| WCF / SOAP injection | Overwatch |
| DNS poisoning | Overwatch |
| Chrome extension abuse | Browsed |
| SSRF | Browsed |
| Bash arithmetic injection | Browsed |
| Python pyc hijack | Browsed |

---

## Methodology

Every writeup follows the same structure:

```
1. Enumeration     — nmap, service fingerprinting, web/SMB recon
2. Foothold        — initial access vector
3. User flag       — lateral movement or privilege escalation to user
4. Root/System     — privilege escalation to root/SYSTEM
5. Key takeaways   — what the machine teaches
```

---

## Tools used

| Category | Tools |
|---|---|
| Recon | nmap, gobuster, feroxbuster, enum4linux-ng, smbclient |
| AD attacks | impacket, certipy, bloodyAD, pywhisker, PKINITtools |
| BloodHound | bloodhound-python, custom queries |
| Web | burpsuite, nuclei |
| Cracking | hashcat, john, zip2john, pfx2john |
| Post-exploit | evil-winrm, netexec, secretsdump |

---

## Related repos

- [ad-attack-chain](https://github.com/Jostif/ad-attack-chain) — automates AD attack chains
- [ad-lab](https://github.com/Jostif/ad-lab) — local AD lab to reproduce techniques
- [nuclei-templates](https://github.com/Jostif/nuclei-templates) — custom web vulnerability templates

---

## Author

**J0stif** — penetration tester, bug bounty hunter
OSCP (in progress) · HTB CPTS (in progress) · HTB CWES (in progress)

[HTB Profile](https://app.hackthebox.com/profile/) · [Site & Writeups](https://jostif.pages.dev)
