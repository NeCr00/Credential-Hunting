<h1 align="center">🔎 CredHunter</h1>

<p align="center">
  <em>Single-file hardcoded credential hunter for authorized pentesting — Linux &amp; Windows.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Bash-4EAA25?logo=gnubash&logoColor=white" alt="Bash">
  <img src="https://img.shields.io/badge/PowerShell-5391FE?logo=powershell&logoColor=white" alt="PowerShell">
  <img src="https://img.shields.io/badge/Dependencies-None-success" alt="No dependencies">
  <img src="https://img.shields.io/badge/Use-Authorized%20testing%20only-critical" alt="Authorized testing only">
</p>

---

A two-script credential triage kit for post-exploitation, lab work, and CTF / OSCP / HTB boxes.

- **`credhunter.sh`** — pure Bash + GNU grep (PCRE) for Linux targets
- **`CredHunter.ps1`** — pure PowerShell 5.1+ for Windows targets

No installs. No agents. No background indexing. Drop the script on a target, point it at a directory, and watch hits stream live with category, file, line, and snippet.

## Quick start

```bash
# Linux
chmod +x credhunter.sh
./credhunter.sh /etc                  # smart mode
./credhunter.sh -a -c /var/www        # all files, with context
./credhunter.sh -s 5M -q /home        # 5MB cap, quiet
```

```powershell
# Windows
.\CredHunter.ps1 C:\inetpub
.\CredHunter.ps1 -All -Context C:\Users
.\CredHunter.ps1 -MaxSizeMB 5 -Quiet C:\

# Bypass execution policy for a one-shot run:
powershell -ExecutionPolicy Bypass -File .\CredHunter.ps1 C:\target
```

## What it catches

| Category | Sample finding |
|---|---|
| 🔑 **PRIVATE_KEY** | OpenSSH / RSA / DSA / EC private keys, PuTTY `.ppk` |
| 🔓 **PASSWORD** | `DB_PASSWORD=…`, `define('DB_PASSWORD', …)`, `'password' => '…'`, `password: …`, `.my.cnf`, `.netrc` |
| 🔗 **CONN_STRING** | `Server=…;…;Password=…`, JDBC URLs with credentials |
| 🌐 **URL_CREDS** | `mongodb://user:pw@host`, `postgres://…`, `https://user:pw@…` |
| ☁️ **AWS / AZURE / GCP** | `AKIA…` keys, storage `AccountKey=…`, service-account JSON |
| 🎫 **TOKEN** | `ghp_…`, `glpat-…`, `sk-…`, `AIza…`, `xox[abprs]-…`, `npm_…`, `SG.…` |
| ⌨️ **JWT** | three-segment `eyJ…eyJ…sig` |
| 🧾 **API_KEY / SECRET** | `api_key=`, `client_secret=`, `JWT_SECRET=`, ASP.NET `<machineKey …>` |
| 🔁 **AUTH_HEADER / NETRC** | `Authorization: Bearer …`, full `machine X login Y password Z` |
| 🔢 **HASH** | `$1$/$2$/$5$/$6$/$y$`, `$apr1$`, NTLM `LM:NT`, `$krb5tgs$/$krb5asrep$` |

**Windows-only extras** (`CredHunter.ps1`):

| Category | Why it matters |
|---|---|
| 🔥 **GPP_CPASSWD** | `cpassword="…"` in SYSVOL — AES with Microsoft's published key. Fully reversible. |
| 🪟 **UNATTEND** | `<AdministratorPassword>` in `unattend.xml` / `autounattend.xml` / `sysprep.xml` |
| ⚙️ **SECURESTRING** | `ConvertTo-SecureString "literal" -AsPlainText` — the classic PS anti-pattern |
| 🖥️ **RDP / WINSCP** | `.rdp` stored creds (DPAPI blob), `WinSCP.ini` `Password=A35C…` (reversible) |
| 📡 **WLAN_KEY** | `<keyMaterial>…</keyMaterial>` in exported WLAN profiles |
| 💻 **NET_USE / PS_ENCODED** | `net use … /user:…`, `runas /savecred`, `powershell -enc <base64>` |

## What the output looks like

```text
[PRIVATE_KEY] /tmp/credtest/home/user/id_rsa:1  -----BEGIN OPENSSH PRIVATE KEY-----
[PASSWORD   ] /tmp/credtest/var/www/app/.env:4  DB_PASSWORD=SuperSecret123!
[PASSWORD   ] /tmp/credtest/var/www/app/wp-config.php:4  define('DB_PASSWORD', 'P@ssw0rdW0rdPr3ss');
[URL_CREDS  ] /tmp/credtest/var/www/app/db.php:8  $mongo = "mongodb://reader:readonly99@mongo.svc:27017/logs";
[AWS        ] /tmp/credtest/var/www/app/settings.py:11  AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
[TOKEN      ] /tmp/credtest/var/www/app/config.json:4  "apiKey": "sk-proj-abc123def456..."
[JWT        ] /tmp/credtest/var/www/app/config.json:5  "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIi..."
[HASH       ] /etc/shadow:1                          root:$6$randomsalt$3xPasswordHash...

──────────────  summary  ──────────────
Total hits: 30   Files scanned: 13

  PASSWORD     10
  TOKEN        4
  SECRET       3
  URL_CREDS    2
  NETRC        2
  HASH         2
  …
```

## Options

| Linux | Windows | Meaning |
|---|---|---|
| `-a, --all` | `-All` / `-a` | Scan every readable file (default targets only credential-bearing file types) |
| `-s, --max-size 5M` | `-MaxSizeMB 5` / `-s 5` | Skip files larger than this |
| `-c, --context` | `-Context` / `-c` | Print one line of surrounding context per hit |
| `-q, --quiet` | `-Quiet` / `-q` | Hide banner / progress |
| `-h, --help` | `-Help` / `-h` | Show help |

Both modes auto-skip: build / cache / vendor noise (`.git`, `node_modules`, `__pycache__`, `WinSxS`, `WindowsApps`, `$Recycle.Bin`, …), files over the size cap, and binary files (NUL-byte heuristic with BOM awareness on Windows so UTF-16 LE `.ps1` files aren't dropped).
