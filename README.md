# htb-writeups

HackTheBox machine writeups by J0stif.
Full walkthroughs with methodology, commands, and techniques.

> Writeups are published only after machine retirement per HTB policy.

---

## Machine index

### Windows — Active Directory

| Machine | Difficulty | Techniques | User | Root | Writeup |
|---|---|---|---|---|---|
| [Eighteen](./Eighteen/) | 🟢 Easy | CVE-2025-8110 (Gogs RCE), BadSuccessor, dMSA abuse | ✓ | ✓ | [→](./Eighteen/README.md) |
| [Blackfield](./Blackfield/) | 🔴 Hard | AS-REP Roasting, ForceChangePassword, lsass dump, SeBackupPrivilege, NTDS.dit | ✓ | ✓ | [→](./Blackfield/README.md) |
| [Flight](./Flight/) | 🔴 Hard | vhost fuzzing, LFI→NTLM, desktop.ini NTLM, PHP webshell, RunasCs, chisel, GodPotato | ✓ | ✓ | [→](./Flight/README.md) |
| [TombWatcher](./TombWatcher/) | 🟡 Medium | Kerberoasting, gMSA, AddSelf, ForceChangePassword, WriteOwner, Deleted Object Restore, ESC15, Enrollment Agent | ✓ | ✓ | [→](./TombWatcher/README.md) |
| [Cicada](./Cicada/) | 🟢 Easy | SMB guest, Password Spray, Backup Operators, SeBackupPrivilege, secretsdump | ✓ | ✓ | [→](./Cicada/README.md) |
| [Sauna](./Sauna/) | 🟢 Easy | OSINT, Username Generation, AS-REP Roasting, AutoLogon creds, DCSync | ✓ | ✓ | [→](./Sauna/README.md) |
| [Forest](./Forest/) | 🟢 Easy | AS-REP Roasting, BloodHound, WriteDACL, Exchange Windows Permissions, DCSync | ✓ | ✓ | [→](./Forest/README.md) |
| [Active](./Active/) | 🟢 Easy | GPP cpassword, gpp-decrypt, Kerberoasting, psexec | ✓ | ✓ | [→](./Active/README.md) |
| [EscapeTwo](./EscapeTwo/) | 🟢 Easy | ADCS ESC4→ESC1, MSSQL | ✓ | ✓ | [→](./EscapeTwo/README.md) |
| [Support](./Support/) | 🟢 Easy | SMB, LDAP, Reverse Engineering, RBCD | ✓ | ✓ | [→](./Support/README.md) |
| [Overwatch](./Overwatch/) | 🟡 Medium | SMB, WCF/SOAP Injection, DNS Poisoning, AD | ✓ | ✓ | [→](./Overwatch/README.md) |
| [Escape](./Escape/) | 🟡 Medium | MSSQL xp_dirtree, NTLM coercion, ERRORLOG cred leak, ADCS ESC1 | ✓ | ✓ | [→](./Escape/README.md) |

### Windows — Standalone

| Machine | Difficulty | Techniques | User | Root | Writeup |
|---|---|---|---|---|---|
| [Unika](./Unika/) | 🟢 Easy | LFI, NTLMv2, Hashcat | ✓ | ✓ | [→](./Unika/README.md) |
| [Timelapse](./Timelapse/) | 🟢 Easy | SMB, PFX, LAPS | ✓ | ✓ | [→](./Timelapse/README.md) |
| [ServMon](./ServMon/) | 🟢 Easy | Anonymous FTP, CVE-2019-20085 (NVMS traversal), NSClient++ API abuse | ✓ | ✓ | [→](./ServMon/README.md) |

### Linux

| Machine | Difficulty | Techniques | User | Root | Writeup |
|---|---|---|---|---|---|
| [Browsed](./Browsed/) | 🟡 Medium | Chrome Extension, Bash Arithmetic Injection, SSRF, pyc Hijack | ✓ | ✓ | [→](./Browsed/README.md) |
| [Sea](./Sea/) | 🟢 Easy | CVE-2023-41425 (WonderCMS XSS→RCE), bcrypt crack, command injection, SUID bash | ✓ | ✓ | [→](./Sea/README.md) |

---

## Coming soon (pending retirement)

| Machine | Difficulty | Techniques |
|---|---|---|
| Logging | 🟡 Medium | Shadow Credentials, ADCS ESC1, DLL Hijack, WSUS |
| Garfield | 🔴 Hard | WriteDacl, RBCD, KeyList (RODC), SYSVOL |
| Interpreter | 🟡 Medium | CVE-2023-43208, Deserialization, PBKDF2, eval() Injection |

---

## Technique index

| Technique | Machines |
|---|---|
| ADCS / ESC1 | EscapeTwo |
| ADCS / ESC4 | EscapeTwo |
| ADCS / ESC15 (CVE-2024-49019) | TombWatcher |
| Enrollment Agent abuse (ESC3) | TombWatcher |
| BadSuccessor / dMSA | Eighteen |
| CVE exploitation | Eighteen (CVE-2025-8110), TombWatcher (CVE-2024-49019), Sea (CVE-2023-41425) |
| WonderCMS XSS → RCE | Sea |
| bcrypt cracking | Sea |
| Command injection (newline) | Sea |
| SUID bash | Sea |
| Internal service port forward | Sea |
| Gogs RCE | Eighteen |
| Kerberoasting | TombWatcher |
| AS-REP Roasting | TombWatcher, Sauna, Blackfield |
| ForceChangePassword | TombWatcher, Blackfield |
| lsass memory dump (pypykatz) | Blackfield |
| diskshadow + NTDS.dit extraction | Blackfield |
| Anonymous FTP credential leak | ServMon |
| Path traversal CVE | ServMon (CVE-2019-20085), Sea (CVE-2023-41425) |
| NSClient++ API abuse | ServMon |
| SSH port forwarding (privesc) | ServMon |
| DCSync (GetChangesAll) | Sauna |
| OSINT / username generation | Sauna |
| AutoLogon registry credentials | Sauna |
| gMSA password dump | TombWatcher |
| AddSelf ACE abuse | TombWatcher |
| ForceChangePassword | TombWatcher |
| WriteOwner | TombWatcher |
| Deleted object restore | TombWatcher |
| SMB enumeration | Support, Timelapse, Overwatch, Cicada |
| Password spray | Cicada |
| Backup Operators / SeBackupPrivilege | Cicada |
| secretsdump (offline hives) | Cicada |
| LDAP enumeration | Support |
| Reverse engineering (.NET) | Support |
| RBCD | Support |
| LAPS | Timelapse |
| PFX cracking | Timelapse |
| LFI | Unika |
| GPP cpassword (MS14-025) | Active |
| gpp-decrypt | Active |
| WriteDACL → DCSync | Forest |
| Exchange Windows Permissions abuse | Forest |
| Virtual host fuzzing | Flight |
| LFI → UNC → NTLM capture | Flight |
| desktop.ini NTLM capture | Flight |
| RunasCs lateral movement | Flight |
| chisel port forwarding | Flight |
| GodPotato SeImpersonate | Flight |
| ASPX webshell (IIS) | Flight |
| NTLM capture (Responder) | Unika, Overwatch, Escape |
| ADCS / ESC1 | EscapeTwo, Escape |
| Password in log files | Escape |
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
PNPT · PWPA · CEH | OSCP (in progress) · HTB CPTS (in progress) · HTB CWES (in progress)

[HTB Profile](https://app.hackthebox.com/users/2209690) · [Site & Writeups](https://jostif.pages.dev) · [Twitter/X](https://x.com/J0stif)
