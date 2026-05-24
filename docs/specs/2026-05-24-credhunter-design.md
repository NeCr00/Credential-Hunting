# CredHunter — Design Spec

**Date:** 2026-05-24
**Status:** Approved
**Target users:** internal-pentest operators performing authorized privilege-escalation and lateral-movement assessments
**Deliverables:** `credhunter.sh` (Bash, Linux targets) and `credhunter.ps1` (PowerShell, Windows targets) — one self-contained file per OS

---

## 1. Goal

Find **hardcoded passwords** and **easily-identified credential material** (SSH/PKI private keys, Unix shadow hashes, NTLM/NetNTLMv2 hashes, Kerberos AS-REP/TGS-REP roastable hashes, GPP cpassword blobs, .netrc/.pgpass/.my.cnf/.htpasswd/Tomcat XML/Jenkins XML/Cisco config patterns, embedded-credential URIs, PowerShell `ConvertTo-SecureString` anti-patterns, Docker config.json base64 auth, Ansible vault headers, PuTTY/WinSCP/MobaXterm saved sessions) on a single compromised host. The tool feeds privilege escalation and lateral movement.

**Out of scope** (deliberate exclusions, called out in `--help`):
- API keys / OAuth tokens / JWT / cloud bearer tokens (regex is hard, FPs are high — user decision)
- LSASS / `/proc/[pid]/mem` memory dumping (different tool category — mimikatz/dumpert)
- DPAPI / browser-password decryption (requires user logon password)
- KeePass / Bitwarden / 1Password vault cracking (requires master password — flag file, let analyst crack offline)
- Network share enumeration, AD enumeration, EDR evasion

---

## 2. Architecture — phase pipeline

A single self-contained script per OS, runs five ordered phases. Each phase emits findings to a shared collector deduplicated by `dedup_key`.

```
[Phase 1 Recon] → [Phase 2 Known Locations] → [Phase 3 Filename Hunt] → [Phase 4 Content Scan] → [Phase 5 Render]
```

Parallelism applied inside phase 4 (the heaviest). Phases 2/3 stay serial — they're fast and have ordering dependencies (e.g., probe registry, then derive paths).

### Phase 1 — Recon (<1 s)
- Detect OS+version, hostname, current user, EUID/SID, admin/root status, mount type of scan roots
- Plan phases, parallelism level, output paths
- One-line banner; `recon` section in report header
- `id -u` / `[Security.Principal.WindowsPrincipal]` for privilege detection

### Phase 2 — Known credential locations
Per-OS hard-coded path inventory. Each entry: `{path_or_glob, classifier, privilege_needed, decoder_optional}`. Permission-denied silently caught, counted, summarized.

**Linux inventory** (see Appendix A for full list):
- Shell/REPL history (`~/.bash_history`, `~/.zsh_history`, `~/.mysql_history`, `~/.psql_history`, `~/.python_history`, `~/.lesshst`, `~/.viminfo`)
- SSH (`~/.ssh/*`, `/etc/ssh/ssh_host_*_key`)
- System auth (`/etc/shadow`, `/etc/sudoers`, `/etc/security/opasswd`, `/etc/krb5.keytab`, `/tmp/krb5cc_*`)
- Backups (`/var/backups/*shadow*`, `/var/backups/*passwd*`)
- Service configs (`/etc/mysql/debian.cnf`, `~/.my.cnf`, `~/.pgpass`, `~/.netrc`, `/etc/redis/redis.conf`, `/etc/samba/*`, `/etc/freeradius/clients.conf`, `/etc/openvpn/*`, `/etc/wireguard/*`, `/etc/dovecot/*`, `/etc/postfix/sasl_passwd`, `/etc/ipsec.secrets`, etc.)
- App/CI (`/var/lib/jenkins/credentials.xml`, `secrets/master.key`, `~/.docker/config.json`, `~/.kube/config`, `/etc/kubernetes/admin.conf`, `.env` walk, Ansible inventories)
- Cron/systemd (`/etc/cron*`, `/etc/systemd/system/*.service` with `Environment=`/`EnvironmentFile=`)
- `/proc` (`/proc/*/environ`, `/proc/*/cmdline` — own UID always, others if privileged)

**Windows inventory** (see Appendix B for full list):
- PSReadLine history per user
- Unattend (`Panther\Unattend*.xml`, `Sysprep\Unattend*.xml`, `C:\unattend.xml`, `C:\autounattend.xml`)
- GPP cache (`ProgramData\Microsoft\Group Policy\History\**\{Groups,Services,ScheduledTasks,Drives,Printers,DataSources}.xml`) + SYSVOL if reachable
- Registry probes (Winlogon `DefaultPassword`/`AutoAdminLogon`; PuTTY/WinSCP/MobaXterm/TightVNC/RealVNC sessions)
- Credential Manager (`cmdkey /list`, `vaultcmd /list`)
- DPAPI blob enumeration (`%APPDATA%\Microsoft\Credentials\*`, `%LOCALAPPDATA%\Microsoft\Credentials\*`, `%APPDATA%\Microsoft\Vault\*`) — paths only, no decrypt
- Hive backups (`C:\Windows\Repair\{SAM,SYSTEM,SECURITY}`, `C:\Windows\System32\config\RegBack\*`)
- Setup/install logs (`C:\Windows\Panther\*`, `C:\Windows\Debug\NetSetup.log`, `C:\Windows\Debug\PASSWD.LOG`)
- IIS (`applicationHost.config`, all `web.config` under `C:\inetpub`)
- Saved sessions (`*.rdp`, `*.rdg`, `*.ovpn`, `WinSCP.ini`, `sitemanager.xml`, `recentservers.xml`, `confCons.xml`, `MobaXterm.ini`)
- WSL roots (`%LOCALAPPDATA%\Packages\*\LocalState\rootfs\home\*` — re-runs Linux inventory)
- SCCM/CCM cache (`C:\Windows\ccmcache\*`, `C:\Windows\CCM\Logs\*.log`)

### Phase 3 — Filename-pattern hunt
Walk user-supplied scan roots and match filenames against:
- **Class A — known credential files** (always emit, even without content read): `*.kdbx`, `*.kdb`, `*.ppk`, `*.pem`, `*.pfx`, `*.p12`, `*.jks`, `*.keystore`, `id_rsa*`, `id_ed25519*`, `id_ecdsa*`, `id_dsa*`, `*.ovpn`, `Groups.xml`, `Services.xml`, `unattend*.xml`, `autounattend*.xml`, `WinSCP.ini`, `sitemanager.xml`, `recentservers.xml`, `*.rdg`, `confCons.xml`, `.netrc`, `_netrc`, `.pgpass`, `.my.cnf`, `.mylogin.cnf`, `.htpasswd`, `.git-credentials` (full list in Appendix C)
- **Keyword filename patterns**: case-insensitive `password*`, `pass*.txt`, `cred*`, `*credential*`, `*secret*`, `pw.txt`, `pwd.txt`, `*.passwd`, `*.pass`, `*.creds`

### Phase 4 — Content scan
Walk user-supplied scan roots. For each file:
1. Apply exclusion list (path/extension/size/binary/inode-dedup) — see §6
2. If `--all` not set: only files whose extension matches the "likely-to-contain-creds" list (configs/scripts/source/SQL/CI/etc., Appendix D)
3. If `--all` set: every file passing binary detection
4. Run regex pack (§4) and emit findings with confidence

Parallelism: workers = CPU count by default, `--serial` disables, `--workers N` overrides.

### Phase 5 — Render
Three output sinks per `--output`:
- **Console** — colored, grouped by confidence (HIGH→LOW), summary line
- **`findings.txt`** — human-readable, paginated
- **`findings.jsonl`** — one JSON object per finding for `jq`/grep
- **`skipped.log`** — every path skipped + reason (perm/size by default; excluded entries with `-v`)
- **`recon.json`** — structured recon banner for cross-host correlation

---

## 3. CLI surface

```
credhunter.sh   [options] [PATH ...]
credhunter.ps1  [options] [PATH ...]
```

Default scan roots if no `PATH` given:
- Linux: `/home`, `/root`, `/etc`, `/opt`, `/srv`, `/var/www`, `/var/backups`, `/var/log`, `/var/spool`, `/tmp`, `/usr/local/etc`
- Windows: `C:\Users`, `C:\inetpub`, `C:\Windows\Panther`, `C:\Windows\System32\config\RegBack`, `C:\Windows\Sysprep`, `C:\Windows\debug`, `C:\ProgramData`, `C:\Temp`, `C:\Backup`, `C:\Install`

(Each script also unconditionally runs Phase 2 — known-location sweep — against the OS-specific path inventory regardless of these scan roots. The roots only bound Phases 3 and 4.)

User-supplied paths override defaults and limit phases 3–4 to those paths.

| Flag | Default | Purpose |
|---|---|---|
| `-o, --output {console,file,both}` | `both` | Output mode |
| `--out-dir PATH` | `./credhunter-loot-<host>-<ts>` | Directory for report files |
| `--all` | off | Scan EVERY filetype for hardcoded creds (not just known config extensions) |
| `--include-archives` | off | Recurse into .zip/.tar.gz/.7z |
| `--include-office` | off | Run text extractors on .pdf/.docx/.xlsx |
| `--include-compressed` | off | Scan .gz/.bz2/.xz log files via stream decompressor |
| `--include-temp` | off | Scan `%LOCALAPPDATA%\Temp\` etc. |
| `--scan-sqlite` | off | Open SQLite DBs (browser Login Data, etc.) instead of just enumerating |
| `--max-size SIZE` | `10M` | Skip files larger than this for content scan |
| `--min-confidence {HIGH,MEDIUM,LOW}` | `LOW` | Filter findings under this tier |
| `--show-secrets` | off | Print full match values; default redacts middle bytes |
| `--collect-loot` | off | Copy Class A files into `./out-dir/loot/` |
| `--serial` | off | Disable parallelism |
| `--workers N` | CPU count | Parallel worker count |
| `--follow-symlinks` | off | Follow symlinks |
| `--cross-mounts` | off | Cross filesystem boundaries |
| `--exclude PATTERN` | — | Additional path/glob to exclude (repeatable) |
| `--include-ext EXT` | — | Additional extension to scan (repeatable) |
| `--skip-known-locations` | off | Skip phase 2 |
| `--skip-content-scan` | off | Skip phase 4 |
| `-q, --quiet` | off | Suppress progress; summary only |
| `-v, --verbose` | off | Verbose tracing (lists excluded paths) |
| `--no-color` | off | Strip ANSI |
| `-h, --help` | — | Usage |

**Exit codes:** `0` no findings, `1` findings emitted, `2` argument/runtime error.

**PowerShell invocation:** `powershell -ExecutionPolicy Bypass -NoProfile -File credhunter.ps1`

---

## 4. Detection model

### 4.1 Rule taxonomy

Each rule is a structured record inside the script:
```
id           string  — e.g. "gpp.cpassword", "pem.openssh", "pw.assign.generic"
category     enum    — PASSWORD | PRIVATE_KEY | HASH:<algo> | URI_CREDS | STORED_CRED:<fmt> | REFERENCE
base_conf    enum    — HIGH | MEDIUM | LOW (before contextual demotion)
target       glob    — file pattern this rule applies to ("*" for all eligible)
pattern      regex   — PCRE form
ere_pattern  regex   — ERE form (when different; for grep -E fallback)
multiline    bool    — PEM blocks, vault headers
post_filter  fn      — placeholder check, entropy, etc.
decoder      fn      — derive plaintext from ciphertext (GPP, docker auth, etc.)
```

Rules execute in **specificity order**: PEM → GPP → Kerberos → shadow → known-format (.netrc/.pgpass/.htpasswd/Tomcat XML/Jenkins XML/Cisco) → URI → PowerShell anti-pattern → generic key=value. First-match-wins per `(file, line, byte-range)` — generic rule does not double-report what a specific rule already caught.

### 4.2 The regex pack (final, lifted from research)

**HIGH-confidence shape-anchored rules** (almost never FP):

| ID | Pattern (PCRE) |
|---|---|
| `pem.private_key` | `(?ms)-----BEGIN (RSA \| DSA \| EC \| OPENSSH \| ENCRYPTED \| PGP \| SSH2 ENCRYPTED )?PRIVATE KEY[\s\S]+?-----END [A-Z ]*PRIVATE KEY` |
| `putty.ppk` | `^PuTTY-User-Key-File-[23]:` |
| `wireguard.privkey` | `^\s*PrivateKey\s*=\s*[A-Za-z0-9+/]{43}=` |
| `gpp.cpassword` | `\bcpassword\s*=\s*"([A-Za-z0-9+/]{8,}={0,2})"` |
| `shadow.hash` | `^([A-Za-z_][A-Za-z0-9_.-]{0,31}):(\$(1\|2[abxy]?\|5\|6\|7\|y\|argon2(i\|d\|id))\$[A-Za-z0-9./$,=+\-]{10,}):` |
| `htpasswd.line` | `^([A-Za-z0-9._-]+):(\$(apr1\|2[axyb]?\|5\|6)\$\S+\|\{SHA\}[A-Za-z0-9+/=]{27,28}\|[A-Za-z0-9./]{13})$` |
| `netntlmv2` | `[^:\s]{1,64}::[^:\s]{1,64}:[A-Fa-f0-9]{16}:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32,}` |
| `pwdump.ntlm` | `^[^:\s]{1,256}:\d+:([A-Fa-f0-9]{32}):([A-Fa-f0-9]{32}):::` |
| `krb5.asrep` | `\$krb5asrep\$(17\|18\|23)\$[^:\s]{1,256}:[A-Fa-f0-9]{16,}\$[A-Fa-f0-9]{32,}` |
| `krb5.tgs` | `\$krb5tgs\$(17\|18\|23)\$\*[^*\s]{1,256}\*\$[A-Fa-f0-9]{16,}\$[A-Fa-f0-9]{32,}` |
| `uri.basic_creds` | `\b(mongodb(\+srv)?\|postgres(ql)?\|mysql\|mariadb\|redis(s)?\|amqps?\|ldaps?\|ftps?\|sftp\|ssh\|mssql\|jdbc:[a-z0-9]+\|https?)://[^/\s:@"'<>]{1,128}:[^/\s@"'<>]{1,256}@[^\s"'<>]{1,256}` |
| `netrc.cred` | `(?im)^\s*machine\s+\S+\s+login\s+(\S+)\s+password\s+(\S{1,256})` |
| `pgpass.cred` | `(?m)^([*A-Za-z0-9.\-]+):(\*\|\d{1,5}):(\*\|[^:\r\n]+):([^:\r\n]+):((\\:\|[^:\r\n])+)$` |
| `mycnf.password` | `(?im)^\s*\[(client\|mysql\|mysqldump)\][\s\S]{0,2048}?^\s*password\s*=\s*("\|')?(.{4,256}?)\2\s*$` |
| `tomcat.user` | `(?i)<user\b[^>]*\bpassword\s*=\s*"([^"]{1,256})"` |
| `cisco.secret` | `(?im)^\s*(enable\s+)?(secret\|password)\s+(0\|5\|7\|8\|9)\s+(\S{4,256})\s*$` |
| `dotnet.connstr` | `(?i)(Server\|Data Source)\s*=\s*[^;]+;[^"\r\n]*?(User\s*ID\|UID)\s*=\s*[^;]+;[^"\r\n]*?(Password\|Pwd)\s*=\s*([^;"\r\n]{1,256})` |
| `jdbc.password` | `(?i)\bjdbc:[a-z0-9]+://[^?\s"']+\?[^"'\r\n]*?(password\|pwd)=([^&"'\r\n]{1,256})` |
| `ps.securestring_plain` | `(?i)ConvertTo-SecureString\s+(-String\s+)?(["'])([^"'\r\n]{4,512})\2\s+(-AsPlainText\s+-Force\|-Force\s+-AsPlainText)` |
| `docker.auth_b64` | `"auths"\s*:\s*\{[\s\S]*?"auth"\s*:\s*"([A-Za-z0-9+/=]{8,})"` |
| `ansible.vault_header`† | `^\$ANSIBLE_VAULT;\d+\.\d+;AES256` |

† `ansible.vault_header` matches shape with HIGH confidence but is reclassified as `REFERENCE` MEDIUM in the finding record — we can't decrypt it without the vault password, so it's an informational pointer ("ask the engagement team for the vault password"), not an extractable credential.

**Windows script-context rules** (base MEDIUM unless placeholder-checked):
```
(?i)\bnet\s+user\s+\S+\s+(\S{4,256})\s+/add
(?i)\bpsexec(\.exe)?\b[^\r\n]*-p\s+(\S{1,256})
(?i)\bsqlcmd\b[^\r\n]*-P\s+(\S{1,256})
(?i)\bcurl\b[^\r\n]*-u\s+[^\s:]+:(\S{1,256})
(?i)\bsshpass\s+-p\s+(\S{1,256})
(?i)\bDefault(User)?Password\s*[:=]\s*"?([^"\r\n]{1,256})"?
(?i)\bAutoAdminLogon\s*=\s*"?1"?
```

**Generic key=value rule** (catch-all, with full confidence demotion):
```regex
(?im)^[^\r\n]{0,200}?
\b(?<key>password|passwd|pwd|pass|passphrase|secret|cred(ential)?s?|requirepass|bindpw|
  db[_-]?pass(word)?|smtp[_-]?pass(word)?|
  ansible[_-]?(ssh[_-]?pass|become[_-]?pass|password)|
  admin[_-]?pass(word)?|root[_-]?pass(word)?|master[_-]?pass(word)?)\b
\s*(?:[:=]{1,2}|:=|=>)\s*
(?<q>["'`]?)
(?<val>(?!\s*$)
  (?!\$\{|<%|%\(|\{\{|os\.environ|process\.env|ENV\[|System\.getenv)
  [^\r\n"'`]{4,512})
\k<q>
```

### 4.3 Confidence-scoring pipeline

Every regex hit runs through this pipeline producing final HIGH/MEDIUM/LOW. Each demotion is recorded in the `demotions[]` field of the finding so analysts see *why*.

```
start: base_conf from rule
  │
  ├─ value ∈ placeholder list (§4.4)? ───YES──> LOW (fp_reason="placeholder")
  │
  ├─ value matches identifier shape ^[A-Za-z_$][A-Za-z0-9_.$]*$  AND  unquoted?
  │       YES──> LOW (fp_reason="variable_reference")
  │
  ├─ value matches env-var reference (${VAR}, os.environ, process.env, <%= %>, {{...}})?
  │       YES──> demote one tier, reclassify as REFERENCE
  │
  ├─ value length < 4 (or < 3 for `pin` keyword)?
  │       YES──> LOW (fp_reason="too_short")
  │
  ├─ value length > 512?
  │       YES──> LOW (fp_reason="too_long_likely_blob")
  │
  ├─ inside a comment line (per-language prefix)?
  │       YES──> demote one tier
  │       EXCEPT PEM/Kerberos/shadow/cpassword (never demoted)
  │
  ├─ file path matches test-fixture heuristic?
  │       YES──> demote one tier
  │       EXCEPT PEM/private-key rules (real keys in /test/ are still real)
  │
  ├─ entropy in expected band for length bucket?
  │       OUT_OF_BAND──> demote one tier
  │
  └─ final tier
```

### 4.4 FP control specifics

**Placeholder list** (case-insensitive, exact match on trimmed value, ~75 entries):
```
password passw0rd p@ssw0rd p@ssword pass passwd pwd secret test testing
changeme change-me change_me changeit default defaultpassword
your_password yourpassword yoursecret your-secret-here
example examplepassword sample samplepassword dummy placeholder
redacted xxx xxxx xxxxx xxxxxx xxxxxxxx *** **** ********
<password> [password] {password} {{password}} ${password} <%= password %>
%PASSWORD% $PASSWORD $PASSWD null none nil n/a na tbd todo fixme
??? !!! foo bar foobar hello world helloworld
insert_password enter_password type_password_here secret_here password_here
my_password mypassword admin administrator root user guest anonymous
123456 12345678 qwerty abc123 letmein monkey dragon
```

**Entropy bands** (Shannon, base-2; tie-breaker only):
| Length | LOW if H < | HIGH if H ≥ |
|---|---|---|
| 4–7 | n/a — always LOW unless strong keyword anchor | 3.0 |
| 8–15 | 2.0 | 3.0 |
| 16–31 | 2.5 | 3.5 |
| ≥32 | 3.0 | 4.0 |

Entropy never overrides placeholder check or shape-anchored rules. Real human passwords like `Summer2024!` (~3.2) pass HIGH for 8–15 marginally — acceptable.

**Comment prefixes detected**: `#`, `//`, `--`, `/* */`, `<!-- -->`, `;`, `%`, `"""`, `'''`, `<# #>`.

**Test-path heuristic globs** (case-insensitive):
```
/test/ /tests/ /spec/ /specs/ /fixture/ /fixtures/ /sample/ /samples/
/example/ /examples/ /demo/ /demos/ /mock/ /mocks/ /__tests__/ /__mocks__/
/e2e/ /testdata/ /test-data/ /testresources/
_test. .test. .spec. _spec. .example. .sample. .demo.
```

### 4.5 Decoders

Run after matching, before reporting. Each successful decode emits a **derived finding** alongside the original.

**GPP cpassword decoder** — deterministic, ships in both scripts:
- AES-256-CBC, IV = 16 NUL bytes
- Fixed key (hex): `4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b`
- Pad base64 to multiple of 4, decrypt, decode plaintext as UTF-16LE
- Bash: `openssl enc -d -aes-256-cbc -K ... -iv 0...0 | iconv -f UTF-16LE -t UTF-8`
- PowerShell: inline `[System.Security.Cryptography.Aes]::Create()`
- Emits `gpp.cpassword.plaintext` HIGH

**Docker config.json `auth` decoder** — base64 → `user:password`, emits `URI_CREDS:docker` HIGH

**URL-percent decoder** — applied to user/pass from URIs before placeholder check (so `%40MyPass%21` becomes `@MyPass!`)

**HTML-entity decoder** — applied to values from XML/HTML before placeholder/entropy check

**WinSCP XOR-deobfuscator** — mask derived from hostname+username; PowerShell only; applied to `Password=` in `WinSCP.ini`/registry

**Cisco Type 7 deobfuscator** — XOR with fixed key `dsfd;kfoA,.iyewrkldJKDHSUB`

**Jenkins credentials.xml** — flagged + path to `master.key` + offline recipe in report; no on-host decrypt

**Not attempted on-host** (flagged with offline recipe in report):
- DPAPI blobs (browser passwords, Credential Manager) — needs user logon password
- KeePass `.kdbx` — needs master password
- Ansible Vault — needs vault password
- Encrypted PEM keys — needs passphrase
- PKCS#12 `.pfx` — needs passphrase

These emit `STORED_CRED:<fmt>` HIGH with a recommended offline command (`hashcat -m`, `john`, `keepass2john`, etc.).

### 4.6 Finding record schema (JSONL output)

```json
{
  "rule_id": "uri.basic_creds",
  "category": "URI_CREDS",
  "confidence": "HIGH",
  "base_confidence": "HIGH",
  "demotions": [],
  "host": "WEBSRV01",
  "scan_user": "svc_scan",
  "scan_user_priv": "user",
  "abs_path": "C:\\inetpub\\wwwroot\\app\\web.config",
  "rel_path": "wwwroot/app/web.config",
  "line_no": 47,
  "col_start": 22,
  "col_end": 98,
  "line_text": "  <add key=\"DSN\" value=\"mongodb://app:Sp01l3r!@db.int:27017/orders\" />",
  "pre_context": "  <appSettings>",
  "post_context": "  </appSettings>",
  "match_text": "mongodb://app:Sp01l3r!@db.int:27017/orders",
  "match_redacted": "mongodb://ap*****rs",
  "key_name": null,
  "extracted": {"user":"app","password":"Sp01l3r!","host":"db.int","port":27017,"db":"orders"},
  "is_comment": false,
  "is_test_path": false,
  "entropy": 3.71,
  "file_mtime": "2024-08-12T14:33:08Z",
  "file_size": 4218,
  "file_mode": "0644",
  "file_owner": "IIS_IUSRS",
  "dedup_key": "8b13e9...",
  "decoder_applied": null,
  "fp_reason": null,
  "notes": null
}
```

**Dedup:**
- Identical `dedup_key` (sha256 of `rule_id + abs_path + line_no + sha256(match_text)`) collapses to single finding
- Same `(rule_id, sha256(match_text))` across many files emits one finding with `seen_in: [path, ...]` list (capped at 100)
- Default reports show `match_redacted`; `--show-secrets` required for plaintext

---

## 5. Output

### 5.1 Console example (when `--output console` or `both`)

```
credhunter v1.0 — internal pentest credential hunter
─────────────────────────────────────────────────────
[ recon ] host=WEBSRV01  user=svc_scan(uid=1001)  priv=user  os=Ubuntu 22.04
[ recon ] scan roots: /home /etc /opt /srv /var/backups
[ recon ] phases: known-locations, filename-hunt, content-scan(default-ext)
[ recon ] workers: 8  max-size: 10M  output: ./credhunter-loot-20260524-141207/

[ phase 2/5 ] known-locations sweep ............... 47 findings ( 12 HIGH, 22 MED, 13 LOW )
[ phase 3/5 ] filename-pattern hunt ............... 18 findings (  9 HIGH,  7 MED,  2 LOW )
[ phase 4/5 ] content scan (4,231 files) .......... 86 findings ( 24 HIGH, 38 MED, 24 LOW )
[ phase 5/5 ] rendering report ..................... done

═════════════════════════════════════════════════════
  HIGH-confidence findings (45)
─────────────────────────────────────────────────────
  [HIGH] pem.private_key           /home/admin/.ssh/id_rsa
         OPENSSH PRIVATE KEY  unencrypted  2048b
  [HIGH] gpp.cpassword.plaintext   /var/cache/sysvol/Groups.xml:3
         decrypted: "Local@dmin2024!"  user=svcLocalAdmin
  [HIGH] uri.basic_creds           /etc/cron.daily/backup-mysql:12
         mysql://backup:H0t-B@ckup-2024@db01:3306/main
  [HIGH] shadow.hash               /var/backups/shadow.bak:1
         root:$6$rounds=...   algo=sha512crypt  hashcat -m 1800
  ...
═════════════════════════════════════════════════════
  Summary
─────────────────────────────────────────────────────
   Total findings:       151    (HIGH: 45, MEDIUM: 67, LOW: 39)
   Scanned files:      4,231
   Skipped (size):        18
   Skipped (binary):     219
   Skipped (perm):        87
   Skipped (excluded):  1,442  (use -v to list)
   Walltime:        00:00:42
   Report:    ./credhunter-loot-20260524-141207/findings.txt
              ./credhunter-loot-20260524-141207/findings.jsonl
              ./credhunter-loot-20260524-141207/skipped.log
═════════════════════════════════════════════════════
```

- Color: HIGH=bright red, MEDIUM=yellow, LOW=dim cyan; `--no-color` strips ANSI

### 5.2 Output directory layout

```
credhunter-loot-<host>-<ts>/
├── findings.txt
├── findings.jsonl
├── recon.json
├── skipped.log
└── loot/                  # opt-in via --collect-loot
    ├── ssh-keys/
    ├── kdbx/
    └── shadow/
```

---

## 6. Cross-cutting

### 6.1 Exclusions ("credential desert" — applied at file-walker stage, before any open/stat)

**Linux unconditional excludes:**
- `/proc/`, `/sys/`, `/dev/`, `/run/`, `/var/run/`
- `/usr/share/{locale,man,doc,info,help,fonts,icons,themes,pixmaps,sounds,backgrounds,zoneinfo,X11,mime,applications}/`
- `/usr/include/`, `/usr/lib/{firmware,modules,locale}/`
- `/lib/`, `/lib32/`, `/lib64/`, `/libx32/`
- `/boot/`, `/lost+found/`, `/selinux/`, `/sysroot/`
- `/var/cache/{apt,yum,dnf,pacman,zypper,apk,man,fontconfig}/`
- `/var/lib/{apt,dpkg,rpm,pacman}/`, `/var/lib/snapd/cache/`, `/var/lib/flatpak/repo/`
- `/var/log/journal/`, `/var/log/{lastlog,wtmp,btmp,faillog}`
- `/snap/`, `/var/lib/docker/{overlay2,image}/`, `/var/lib/containerd/io.containerd.*/`
- `/var/lib/kubelet/pods/*/volumes/`
- Per-user: `~/.cache/`, `~/.thumbnails/`, `~/.local/share/{Trash,RecentDocuments,icons,themes,fonts,applications}/`, `~/.fonts/`, `~/.themes/`, `~/.icons/`
- Per-user: `~/.cargo/registry/`, `~/.cargo/git/`, `~/.rustup/toolchains/`, `~/.nvm/versions/`, `~/.pyenv/versions/`, `~/.rbenv/versions/`, `~/.gem/ruby/*/cache/`
- Per-user: `~/.npm/_cacache/`, `~/.yarn/cache/`, `~/.pnpm-store/`, `~/.gradle/caches/`, `~/.m2/repository/` (keep `~/.m2/settings.xml`)
- Per-user: `~/.cache/{pip,go-build,yarn,bazel}/`, `~/.ccache/`, `~/.sccache/`
- Per-user: `~/.mozilla/firefox/*/{cache2,startupCache,jumpListCache,shader-cache,offlineCache}/`
- Per-user: `~/.config/{google-chrome,chromium,BraveSoftware,microsoft-edge}/*/{Cache,Code Cache,GPUCache,Service Worker/CacheStorage}/`
- Per-user: `~/snap/*/common/.cache/`, `~/.var/app/*/cache/`
- Build/VCS: `node_modules/`, `vendor/`, `target/`, `build/`, `dist/`, `out/`, `__pycache__/`, `.pytest_cache/`, `.mypy_cache/`, `.tox/`, `.eggs/`, `.terraform/`, `.gradle/`, `.cache/`, `.next/`, `.nuxt/`, `.svelte-kit/`, `.angular/`, `.parcel-cache/`
- `.git/{objects,pack,lfs}/`, `.svn/pristine/`, `.hg/store/`

**Windows unconditional excludes:**
- `%WINDIR%\{WinSxS,Installer,Servicing,assembly,SchCache,Fonts,IME,Globalization,Help,Resources,schemas,PolicyDefinitions,diagnostics,WinStore,SystemApps,ShellExperiences,ShellComponents,Boot,PrintDialog,InfusedApps}\`
- `%WINDIR%\SoftwareDistribution\Download\`
- `%WINDIR%\System32\{DriverStore\FileRepository,spool\drivers,catroot,catroot2,winevt\Logs,WDI,Migration}\`
- `%WINDIR%\System32\Tasks\Microsoft\` (system tasks; keep root for custom)
- `%WINDIR%\System32\config\{TxR,Journal}\`
- `%WINDIR%\Microsoft.NET\Framework*\v*\Temporary ASP.NET Files\`, `%WINDIR%\Microsoft.NET\assembly\`
- `%WINDIR%\Logs\{CBS,DISM,WindowsUpdate,waasmedic}\`
- `C:\$Recycle.Bin\`, `C:\System Volume Information\`, `C:\Recovery\`, `C:\$WINDOWS.~BT\`, `C:\$WINDOWS.~WS\`
- `C:\Boot\`, `hiberfil.sys`, `pagefile.sys`, `swapfile.sys`, `DumpStack.log*`
- `%ProgramData%\Microsoft\{Windows Defender,Search\Data,Diagnosis,Crypto,Windows\WER,NetFramework\BreadcrumbStore}\`, `%ProgramData%\Package Cache\`
- Per-user: `AppData\Local\Microsoft\Windows\{WebCache,INetCache,INetCookies,Explorer,Notifications,FontCache,Caches}\`
- Per-user: `AppData\Local\Microsoft\WindowsApps\`
- Per-user: `AppData\Local\Microsoft\Internet Explorer\Recovery\`
- Per-user: browser `Cache/Code Cache/GPUCache/Service Worker/ShaderCache` directories for Edge/Chrome/Firefox
- Per-user: `AppData\Local\ConnectedDevicesPlatform\`, `AppData\Local\D3DSCache\`
- Per-user: `AppData\Local\Packages\*\AC\` (keep `\LocalState\`)
- Per-user: `AppData\Local\Microsoft\Office\*\{WefCache,OfficeFileCache,UnsavedFiles}\`
- Per-user: `AppData\Local\Adobe\{ARM,OOBE,Color}\`
- Per-user: `AppData\Local\Temp\` (opt back in via `--include-temp`)
- Dev: `.nuget\packages\`, `packages\`, `.vs\`, `bin\`, `obj\`, `node_modules\`, `Pods\`, `.gradle\caches\`

**Explicitly NOT excluded** (kept scannable despite being "system" trees — these have credentials):
- `C:\Windows.old\**` (old install — forgotten unattend, hive backups, user files)
- `C:\Windows\{Panther,Sysprep,Repair}\**`, `C:\Windows\System32\config\RegBack\**`, `C:\Windows\System32\config\{SAM,SYSTEM,SECURITY}`
- `C:\Windows\debug\{NetSetup.log,PASSWD.LOG}`, `C:\Windows\Panther\setupact.log`
- `C:\Windows\System32\inetsrv\Config\applicationHost.config`, `C:\inetpub\**\web.config`
- `C:\Windows\ccmcache\**`, `C:\Windows\CCM\Logs\*.log`
- `%PROGRAMDATA%\Microsoft\Group Policy\History\**`
- `%LOCALAPPDATA%\Microsoft\Credentials\**`, `%APPDATA%\Microsoft\{Credentials,Vault}\**` (enumerate only)
- `/var/backups/**`, `/etc/shadow*`, `/etc/sudoers*`, `/etc/security/opasswd`
- `~/.bash_history`, `~/.zsh_history`, all REPL histories
- `~/.ssh/**`, `/etc/ssh/ssh_host_*_key`
- `~/.docker/config.json`, `~/.kube/config`, `~/.netrc`, `~/.pgpass`, `~/.my.cnf`, `~/.git-credentials`, all `.env*`
- `%APPDATA%\Microsoft\Windows\PowerShell\PSReadline\` history files
- `%LOCALAPPDATA%\Packages\*\LocalState\rootfs\home\` (WSL Linux homes)

**Override behavior:** explicit user-supplied scan root always wins (e.g., `credhunter.sh /usr/share/doc/myapp` works even though `/usr/share/doc/` is in the default deny list).

### 6.2 Sizing / content gating

- **Size cap**: 10 MB default for content scan; Class A files always emitted regardless of size (filename match alone)
- **Binary detection**: NUL-byte sniff in first 8 KiB
- **UTF-16 awareness**: detect BOM (`EF BB BF`, `FF FE`, `FE FF`, `FF FE 00 00`, `00 00 FE FF`); if UTF-16 BOM present, decode before NUL-sniff. No-BOM UTF-16 heuristic: ≥25% NUL in first 1 KiB with every-other-byte pattern
- **Min size**: none (12-byte `.env` is a finding)
- **Symlinks**: not followed by default; `--follow-symlinks` opts in
- **Mount crossings**: disabled by default (`find -xdev` equivalent); `--cross-mounts` opts in
- **Inode/device dedup**: `(device,inode)` pair tracked; skip second sighting (handles hard links, bind mounts)
- **Long lines**: 64 KiB cap per line; `line_text` field truncated to 4 KiB in report

### 6.3 Privilege handling

- Detected at startup via `id -u`/`[Security.Principal.WindowsPrincipal]`
- Every path try wrapped in EACCES catch — silently caught, counted, summarized in `skipped (perm)`
- Privileged-only paths still attempted (so we discover loose ACLs)
- If running as root/admin: phase 2 adds other-user homes, /etc/shadow, /proc/N/environ for other UIDs, SAM/SYSTEM/SECURITY hives, LSA Secrets enumeration

### 6.4 Parallelism

- Phase 4 pre-builds candidate list (fast, single-threaded), then dispatches files to workers
- **Bash**: `xargs -P $WORKERS -I {} bash -c '_scan_one "$@"' _ {}` with sourced helper; fallback to backgrounded `&` + `wait` pool if `xargs -P` unsupported
- **PowerShell 7+**: `ForEach-Object -Parallel { … } -ThrottleLimit $WORKERS`
- **PowerShell 5.1**: `Start-ThreadJob` pool with `Wait-Job`/`Receive-Job` aggregation
- Each worker writes to its own temp jsonl; merged + deduped at end (no mutex contention)
- `--serial` runs phase 4 single-threaded (predictable CPU, friendlier for C2)

---

## 7. Edge cases / known caveats

1. **Sparse / device files** — never opened; `S_ISREG` check at stat()
2. **Anti-loop** — symlinks disabled by default; inode/device dedup prevents hard-link double-scan
3. **Long lines** — 64 KiB scan cap; 4 KiB report truncation
4. **Compressed logs** — opt-in via `--include-compressed`; uses `zcat`/`bzcat`/`xzcat` (Bash), `GZipStream` (PowerShell)
5. **Scan-root inside excluded tree** — explicit user-supplied path always wins
6. **`/proc/[pid]` cross-UID** — caught as EACCES, counted in `skipped (perm)`
7. **PowerShell ExecutionPolicy** — script preamble notes invocation form; no bypass logic in code
8. **No persistence / no networking** — pure read-only file/registry inspection; no sockets opened, no scheduled tasks, no services, no startup hooks
9. **Sensitive output** — `--show-secrets` writes plaintext; output dir should be cleaned up post-engagement

---

## 8. Risks

- **Misuse outside authorized scope** — no built-in auth gate; analyst operates under signed rules of engagement
- **Performance on huge filesystems** — `--all` on a 1 TB FS will take time; default extension-gated mode keeps walltime bounded
- **False positives in source code** — demotion ladder + placeholder list aggressively suppress; `--min-confidence HIGH` is the analyst's last filter
- **Sensitive-data residue** — `--show-secrets` plaintext + collected loot must be deleted post-engagement; tool emits a reminder line in summary when `--show-secrets` or `--collect-loot` was used

---

## Appendix A — Full Linux known-location inventory (Phase 2)

(Lifted from research; each entry resolves to one or more concrete files at runtime.)

**Shell/REPL history (per user dir + /root):**
`.bash_history`, `.zsh_history`, `.ash_history`, `.sh_history`, `.history`, `.local/share/fish/fish_history`, `.python_history`, `.node_repl_history`, `.irb_history`, `.lua_history`, `.psql_history`, `.mysql_history`, `.sqlite_history`, `.rediscli_history`, `.mongo_history`, `.lesshst`, `.viminfo`

**SSH / remote:**
`~/.ssh/{id_rsa,id_dsa,id_ecdsa,id_ed25519,id_ed25519_sk,id_ecdsa_sk,id_xmss,identity,config,authorized_keys,authorized_keys2,known_hosts}`, `~/.ssh/*.pem`, `~/.ssh/*.key`, `/etc/ssh/{sshd_config,ssh_config,ssh_host_*_key}`, `/etc/ssh/ssh_config.d/*`, `$SSH_AUTH_SOCK`, `/tmp/ssh-*/agent.*`

**System auth:**
`/etc/{shadow,gshadow,passwd,master.passwd,spwd.db,sudoers,login.defs,securetty}`, `/etc/sudoers.d/*`, `/etc/security/opasswd`, `/etc/pam.d/*`, `/etc/krb5.{keytab,conf}`, `/var/lib/krb5kdc/principal*`, `/tmp/krb5cc_*`, `$KRB5CCNAME`, `/run/user/<uid>/krb5cc_*`, `/var/lib/sss/{db,secrets}/*`, `/var/backups/{shadow,passwd,group}*`

**Web/proxy:**
`/etc/{apache2,httpd,nginx,lighttpd,caddy,haproxy}/**`, `.htpasswd` (anywhere), `/etc/squid/{squid.conf,passwd}`

**Databases:**
`/etc/mysql/{my.cnf,conf.d/*,mariadb.conf.d/*,debian.cnf}`, `~/.my.cnf`, `/etc/postgresql/*/main/{postgresql.conf,pg_hba.conf,pg_ident.conf}`, `~/.pgpass`, `/etc/mongod.conf`, `/etc/redis/{redis.conf,redis-sentinel.conf}`, `/etc/clickhouse-server/{users.xml,users.d/*}`, `/etc/elasticsearch/{elasticsearch.yml,users,users_roles}`, `/etc/influxdb/influxdb.conf`, `/etc/couchdb/local.ini`

**App servers / CI / config mgmt:**
`$CATALINA_HOME/conf/{tomcat-users.xml,server.xml,context.xml}`, JBoss/WildFly `standalone/configuration/standalone.xml` + `mgmt-users.properties`, `/var/lib/jenkins/{credentials.xml,users/*/config.xml,secrets/master.key,secrets/hudson.util.Secret,secrets/initialAdminPassword,jobs/*/config.xml}`, `/etc/gitlab/{gitlab.rb,gitlab-secrets.json}`, Atlassian `<home>/{dbconfig.xml,confluence.cfg.xml}`, `/etc/ansible/{ansible.cfg,hosts}`, `group_vars/*`, `host_vars/*`, `*.yml` (vault headers), `/etc/puppet/{puppet.conf,hieradata/*.yaml}`, `~/.chef/knife.rb`, `/etc/salt/{master,minion}`, `/srv/{pillar,salt}/*`, `~/.docker/config.json`, `/root/.docker/config.json`, `/etc/docker/daemon.json`, `~/.kube/config`, `/etc/kubernetes/{admin.conf,kubelet.conf}`, `/var/lib/kubelet/config.yaml`, `/etc/rancher/{k3s,rke2}/*.yaml`, `~/.config/helm/repositories.yaml`

**Auth/directory/mail:**
`/etc/sssd/sssd.conf`, `/etc/{openldap,ldap,pam_ldap,libnss-ldap}/ldap.conf`, `/etc/nslcd.conf`, `/etc/samba/{smb.conf,smbpasswd}`, `/var/lib/samba/private/{passdb.tdb,secrets.tdb}`, `/etc/postfix/{main.cf,master.cf,sasl_passwd}`, `/etc/dovecot/{dovecot.conf,conf.d/*,dovecot-{sql,ldap}.conf.ext,users,passwd-file}`, `/etc/exim4/passwd.client`, `/etc/sasldb2`

**Network services/VPN:**
`/etc/openvpn/{*.conf,*.ovpn,easy-rsa/pki/private/*}`, `/etc/wireguard/*.conf`, `/etc/ipsec.secrets`, `/etc/ipsec.conf`, `/etc/swanctl/swanctl.conf`, FreeRADIUS `raddb/{users,clients.conf,proxy.conf}`, `/etc/bind/`, `/etc/named.conf`, `/etc/rndc.{key,conf}`, `/etc/snmp/snmpd.conf`, `/etc/{proftpd,vsftpd,pure-ftpd}/*`, `/etc/cups/{printers.conf,cupsd.conf}`

**Backups:**
`/var/backups/*`, `/backup/*`, `/backups/*`, `/opt/backups/*`, `/srv/backup/*`, `/tmp/*`, `/var/tmp/*`, `/dev/shm/*`, `*.bak`/`*.old`/`*.orig`/`*.save`/`*~` siblings of credential files

**Cron/systemd:**
`/etc/crontab`, `/etc/cron.{d,hourly,daily,weekly,monthly}/*`, `/etc/anacrontab`, `/var/spool/cron/{,crontabs/}*`, `/etc/at.{allow,deny}`, `/var/spool/at/*`, `/etc/systemd/system/*.service`, `/lib/systemd/system/*.service`, `/usr/lib/systemd/system/*.service`, `~/.config/systemd/user/*.service`, `/etc/systemd/system/*.service.d/override.conf`, `/etc/init.d/*`, `/etc/rc.local`, `/etc/default/*`, `/etc/sysconfig/*`

**App configs:**
`.env*` (walk from scan roots), `wp-config.php`, `sites/default/settings.php`, `configuration.php` (Joomla), `app/etc/{local.xml,env.php}` (Magento), `config/{database.yml,secrets.yml,master.key,credentials.yml.enc}` (Rails), `settings.py`/`local_settings.py` (Django), `application{.properties,.yml,-*.yml,bootstrap.yml}` (Spring), `~/.m2/settings.xml`, `~/.gradle/gradle.properties`, `~/.composer/auth.json`, `~/.npmrc`, `~/.pypirc`, `~/.gem/credentials`, `~/.bundle/config`, `.git/config`, `.gitconfig`, `~/.git-credentials`, `~/.hgrc`, `~/.subversion/auth/svn.simple/*`, `~/.aws/{credentials,config}`, `~/.azure/*`, `~/.config/gcloud/*`, `~/.config/rclone/rclone.conf`

**/proc:**
`/proc/*/environ`, `/proc/*/cmdline`, `/proc/*/status`, `/proc/self/environ`

---

## Appendix B — Full Windows known-location inventory (Phase 2)

**PSReadLine/RDP/MRU:**
`%APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`, `%USERPROFILE%\Documents\PowerShell_transcript.*.txt`, `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`, `HKCU\Software\Microsoft\Terminal Server Client\{Servers\*,Default}`, `%USERPROFILE%\Documents\Default.rdp`, `%APPDATA%\Microsoft\Windows\Recent\*.lnk`, `%APPDATA%\Microsoft\Windows\Recent\{AutomaticDestinations,CustomDestinations}\*`

**Unattend:**
`C:\Windows\Panther\Unattend*.xml`, `C:\Windows\Panther\Unattend\Unattend.xml`, `C:\Windows\Panther\autounattend.xml`, `C:\Windows\System32\Sysprep\Unattend.xml`, `C:\Windows\System32\Sysprep\Panther\Unattend.xml`, `C:\Windows\System32\sysprep\{sysprep.xml,sysprep.inf}`, `C:\unattend.{xml,txt,inf}`, `A:\Unattend.xml`

**GPP:**
`\\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\*\{Machine,User}\Preferences\**\{Groups,Services,ScheduledTasks,Drives,Printers,DataSources}.xml`, `C:\ProgramData\Microsoft\Group Policy\History\**`, `C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history\**`

**Registry probes:**
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` (`AutoAdminLogon`, `DefaultUserName`, `DefaultDomainName`, `DefaultPassword`, `AltDefaultPassword`)
- `HKCU\Software\SimonTatham\PuTTY\Sessions\*` (HostName, UserName, ProxyPassword, PublicKeyFile)
- `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions\*` (Password value — XOR with hostname+username, reversible)
- `HKCU\Software\Mobatek\MobaXterm` (M/C/P sub-values)
- `HKLM\Software\TightVNC\Server`, `HKCU\Software\TightVNC\Server` (Password, ControlPassword)
- `HKLM\SOFTWARE\RealVNC\{vncserver,WinVNC4}` (Password)
- `HKCU\Software\Microsoft\RAS Phonebook`, `HKCU\Software\Palo Alto Networks\GlobalProtect`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss\*` (WSL distros)
- `HKCU\Software\GitCredentialManager`

**Credential Manager:** `cmdkey /list`, `vaultcmd /list`, `vaultcmd /listcreds:"Windows Credentials" /all`, `vaultcmd /listcreds:"Web Credentials" /all`

**DPAPI blob enum (no decrypt):** `%LOCALAPPDATA%\Microsoft\Credentials\*`, `%APPDATA%\Microsoft\Credentials\*`, `%LOCALAPPDATA%\Microsoft\Vault\*`, `%APPDATA%\Microsoft\Vault\*`, `C:\Windows\System32\config\systemprofile\AppData\{Local,Roaming}\Microsoft\{Credentials,Vault}\*`

**Hives + backups (priv):** `C:\Windows\System32\config\{SAM,SYSTEM,SECURITY,SOFTWARE,DEFAULT}`, `C:\Windows\Repair\{SAM,SYSTEM,SECURITY}`, `C:\Windows\System32\config\RegBack\*`, `C:\Windows\NTDS\ntds.dit`

**Install/setup logs:** `C:\Windows\Panther\*`, `C:\Windows\Debug\{NetSetup.log,PASSWD.LOG,mrt.log}`, `C:\Windows\System32\LogFiles\setupcln\*`, `C:\Windows\inf\setupapi.{dev,app}.log`, `C:\Windows\WindowsUpdate.log`, `C:\inetpub\logs\LogFiles\*`

**IIS / Tomcat / DBs / mail (Windows):** `C:\Windows\System32\inetsrv\Config\{applicationHost.config,administration.config}`, `C:\inetpub\wwwroot\**\web.config`, `%CATALINA_HOME%\conf\{tomcat-users.xml,server.xml,context.xml}`, `C:\Apache24\conf\httpd.conf`, `C:\ProgramData\MySQL\MySQL Server *\my.ini`, `C:\Program Files\MySQL\**\my.ini`, `%USERPROFILE%\.my.cnf`, `%APPDATA%\MySQL\Workbench\connections.xml`, MSSQL ERRORLOG, `%APPDATA%\postgresql\pgpass.conf`, `C:\Program Files\Redis\redis.windows.conf`

**Third-party tools:** `*.ppk`, `WinSCP.ini` (under `%APPDATA%` or portable), `%APPDATA%\FileZilla\{sitemanager.xml,recentservers.xml,filezilla.xml}`, `%APPDATA%\MobaXterm\MobaXterm.ini`, `%USERPROFILE%\Documents\*.rdg`, `%LOCALAPPDATA%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings`, `%LOCALAPPDATA%\Devolutions\RemoteDesktopManager\*.xml`, `%APPDATA%\SuperPuTTY\Sessions.xml`, `%APPDATA%\mRemoteNG\confCons.xml`, `C:\Program Files\UltraVNC\{ultravnc.ini,MSLogonACL.ini}`

**Password managers (path enum):** `*.kdbx`/`*.kdb`/`*.key`/`*.keyx` (anywhere), `%APPDATA%\KeePass\KeePass.config.xml`, `%LOCALAPPDATA%\1Password\data\*`, `%APPDATA%\Bitwarden CLI\data.json`, `%APPDATA%\Bitwarden\data.json`

**VPN:** `C:\Program Files\OpenVPN\config\*.ovpn`, `%USERPROFILE%\OpenVPN\config\*.ovpn`, `%PROGRAMDATA%\OpenVPN\config\*.ovpn`, `C:\Program Files\WireGuard\Data\Configurations\*.conf*`, `%PROGRAMDATA%\Cisco\Cisco AnyConnect Secure Mobility Client\Profile\*.xml`, `%APPDATA%\Microsoft\Network\Connections\Pbk\rasphone.pbk`

**Browsers (path enum, no decrypt):** `%LOCALAPPDATA%\{Google\Chrome,Microsoft\Edge,BraveSoftware\Brave-Browser,Vivaldi}\User Data\<Profile>\{Login Data,Local State,Cookies,Web Data}`, `%APPDATA%\Mozilla\Firefox\Profiles\*.default*\{logins.json,key4.db}`

**Mail/chat:** `HKCU\Software\Microsoft\Office\<ver>\Outlook\Profiles\<profile>\*` (DPAPI blobs `01020fff`), `%APPDATA%\Thunderbird\Profiles\*\{logins.json,key4.db,signons.sqlite}`, `%APPDATA%\Signal\config.json`

**Devops / cloud (path enum):** `%USERPROFILE%\.{kube\config,aws\credentials,aws\config,azure\*,docker\config.json,git-credentials,netrc,_netrc,ssh\*}`, `%APPDATA%\gcloud\{credentials.db,legacy_credentials\*,application_default_credentials.json}`, Ansible inventories, `terraform.tfvars`, `*.tfstate`

**WSL:** `%LOCALAPPDATA%\Packages\<DistroPackage>\LocalState\rootfs\home\<user>\` — re-run Linux inventory

**Backup/repair/recycled:** `C:\Windows\Repair\*`, `C:\Windows\System32\config\RegBack\*`, Volume Shadow Copies (enumerate via `vssadmin list shadows`), `C:\Windows\Panther\*`, `%TEMP%`, `%LOCALAPPDATA%\Temp\*`, `%LOCALAPPDATA%\Microsoft\Windows\WER\Report{Archive,Queue}\*`, `C:\$Recycle.Bin\<SID>\$R*`, `C:\Windows\ccmcache\**`, `C:\Windows\CCM\Logs\*.log`, `C:\Windows\CCMSetup\Logs\*.log`, `C:\Windows\Provisioning\{Autopilot,Diagnostics}\*`

---

## Appendix C — Class A "always-pull" filename globs (Phase 3)

Password managers: `*.kdbx`, `*.kdb`, `*.psafe3`, `*.agilekeychain`, `*.opvault`, `*.1pif`, `*.bitwarden_export.json`, `bw_export_*.csv`, `lastpass_export*.csv`, `LastPassExport*.csv`, `Dashlane Export*.csv`, `enpass*.json`, `key3.db`, `key4.db`, `logins.json`, `signons.sqlite`, `cert9.db`, `Login Data`, `Login Data For Account`, `Cookies` (Chrome SQLite), `Web Data`, `Local State`

SSH/PKI: `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`, `id_xmss`, `id_ecdsa_sk`, `id_ed25519_sk`, `*.pem`, `*.key`, `*.priv`, `*.pk8`, `*.pkcs8`, `*.rsa`, `*.dsa`, `*.ec`, `*.ppk`, `*.openssh`, `authorized_keys`, `known_hosts`, `ssh_host_*_key`

Certificate containers: `*.pfx`, `*.p12`, `*.jks`, `*.keystore`, `*.bks`, `*.uber`, `*.pkcs12`

Auth state / token files: `.netrc`, `_netrc`, `.pgpass`, `.my.cnf`, `.mylogin.cnf`, `.htpasswd`, `.smbcredentials`, `.cifs-credentials`, `.credentials`, `.git-credentials`, `.npmrc`, `.yarnrc.yml`, `.yarnrc`, `config.json` (under `.docker/`), `kubeconfig`, `*.kubeconfig`, `*.ovpn`, `wg0.conf`, `*.conf` (under `/etc/wireguard/`), `krb5.keytab`, `*.keytab`, `krb5cc_*`, `credentials` (under `~/.aws/`), `azureProfile.json`, `accessTokens.json`, `application_default_credentials.json`, `credentials.db` (under `gcloud/`), `rclone.conf`

GPP cpassword XML: `Groups.xml`, `Services.xml`, `ScheduledTasks.xml`, `Drives.xml`, `Printers.xml`, `DataSources.xml`

Windows unattend: `unattend.xml`, `Unattend.xml`, `autounattend.xml`, `Autounattend.xml`, `sysprep.inf`, `sysprep.xml`

Shadow/passwd backups + hives: `shadow.bak`, `shadow.old`, `shadow-`, `passwd.bak`, `passwd-`, `gshadow.bak`, `SAM`, `SYSTEM`, `SECURITY` (outside `System32\config`), `ntds.dit`

Saved-session app files: `WinSCP.ini`, `sitemanager.xml`, `recentservers.xml`, `filezilla.xml`, `confCons.xml` (mRemoteNG), `MobaXterm.ini`, `*.rtsz`, `*.rtsx`, `*.rdp`, `*.ica`, `*.rdg`, `RDCMan.settings`, `*.tds`

Specific known files: `settings.xml` (Maven `~/.m2/`), `application.properties`, `application*.properties`, `application.yml`, `application*.yml`, `bootstrap.yml`, `credentials.xml`, `master.key`, `hudson.util.Secret`, `initialAdminPassword` (Jenkins), `.env`, `.env.*`, `wp-config.php`, `wp-config-sample.php`, `configuration.php`, `LocalSettings.php`, `local.xml`, `database.yml`, `web.config`, `app.config`, `machine.config`, `connectionStrings.config`, `tnsnames.ora`, `sqlnet.ora`, `wallet.sso`, `cwallet.sso`

Shell/DB history (also picked up in Phase 2 but listed here for filename-walk): `.bash_history`, `.zsh_history`, `.fish_history`, `.mysql_history`, `.psql_history`, `.sqlite_history`, `ConsoleHost_history.txt`

Keyword-name patterns (case-insensitive): `password*`, `pass*.txt`, `cred*`, `*credential*`, `*secret*`, `pw.txt`, `pwd.txt`, `*.passwd`, `*.pass`, `*.creds`

---

## Appendix D — Default-on content-scan extensions (Phase 4 without `--all`)

Config: `.conf`, `.cnf`, `.cfg`, `.config`, `.ini`, `.properties`, `.toml`, `.yaml`, `.yml`, `.json`, `.xml`, `.plist`, `.env`, `.reg`, `.inf`
Scripts: `.sh`, `.bash`, `.zsh`, `.ksh`, `.fish`, `.ps1`, `.psm1`, `.psd1`, `.bat`, `.cmd`, `.vbs`, `.vbe`, `.wsf`, `.wsc`
Source: `.py`, `.rb`, `.pl`, `.pm`, `.php`, `.phtml`, `.js`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.jsx`, `.vue`, `.svelte`, `.java`, `.scala`, `.kt`, `.kts`, `.groovy`, `.go`, `.rs`, `.swift`, `.m`, `.mm`, `.cs`, `.vb`, `.fs`, `.fsx`, `.c`, `.cpp`, `.cc`, `.cxx`, `.h`, `.hpp`, `.lua`, `.r`, `.R`, `.dart`, `.ex`, `.exs`, `.erl`, `.hs`, `.clj`, `.cljs`
Web templates: `.htm`, `.html`, `.jsp`, `.jspx`, `.asp`, `.aspx`, `.cshtml`, `.razor`, `.ejs`, `.pug`, `.twig`, `.blade.php`, `.erb`, `.haml`, `.mustache`, `.hbs`
Notebooks: `.ipynb`, `.rmd`, `.qmd`
DB/SQL: `.sql`, `.ddl`, `.dml`, `.psql`, `.mysql`, `.pgsql`
Build/CI/IaC: `Dockerfile`, `Containerfile`, `*.dockerfile`, `docker-compose.y*ml`, `compose.y*ml`, `Jenkinsfile`, `*.Jenkinsfile`, `.gitlab-ci.yml`, `.github/workflows/*.yml`, `.circleci/config.yml`, `.travis.yml`, `azure-pipelines.yml`, `bitbucket-pipelines.yml`, `cloudbuild.yaml`, `buildspec.yml`, `Makefile`, `GNUmakefile`, `*.mk`, `*.gradle`, `*.gradle.kts`, `pom.xml`, `package.json`, `*.tf`, `*.tfvars`, `*.bicep`, `*.arm.json`, `azuredeploy.json`, `parameters.json`, `*.pp`
Logs: `.log`, `.out`, `.err`, `.trace`, `*.access.log`, `*.error.log`, `messages*`, `syslog*`, `auth.log*`, `secure*`, `audit.log*`
Backups (scanned as underlying type): suffix `.bak`, `.backup`, `.old`, `.orig`, `.save`, `.swp`, `.swo`, `.tmp`, `~`, `.copy`, `.original`, `.dist`, `.sample`, `.example`

---

## Appendix E — Default-skip extensions (always excluded unless `--include-ext`)

Media: `.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp`, `.tiff`, `.tif`, `.ico`, `.webp`, `.heic`, `.heif`, `.raw`, `.cr2`, `.nef`, `.psd`, `.ai`, `.eps`, `.mp3`, `.mp4`, `.mov`, `.avi`, `.mkv`, `.wmv`, `.flv`, `.wav`, `.flac`, `.ogg`, `.opus`, `.webm`, `.m4a`, `.m4v`, `.aac`, `.svg`
Fonts: `.ttf`, `.otf`, `.woff`, `.woff2`, `.eot`, `.fon`
Archives (gated by `--include-archives`): `.zip`, `.gz`, `.bz2`, `.xz`, `.lz`, `.lzma`, `.7z`, `.rar`, `.tar`, `.tgz`, `.tbz2`, `.txz`, `.cab`, `.arj`, `.jar`, `.war`, `.ear`, `.apk`, `.aab`, `.ipa`, `.nupkg`
Compiled: `.exe`, `.dll`, `.so`, `.so.[0-9]*`, `.dylib`, `.o`, `.a`, `.lib`, `.obj`, `.class`, `.pyc`, `.pyo`, `.pyd`, `.wasm`, `.bin`, `.iso`, `.img`, `.dmg`, `.msi`, `.msu`, `.cab`, `.deb`, `.rpm`, `.snap`, `.appx`, `.appxbundle`, `.efi`, `.sys`
Databases (binary, gated by `--scan-sqlite`): `.db`, `.sqlite`, `.sqlite3`, `.sqlite-journal`, `.mdb`, `.accdb`, `.dbf`, `.idx`, `.frm`, `.ibd`, `.myd`, `.myi`, `.aof`, `.rdb`
Office (gated by `--include-office`): `.pdf`, `.doc`, `.xls`, `.ppt`, `.odt`, `.ods`, `.odp`, `.epub`, `.mobi`, `.azw`, `.azw3`, `.djvu`, `.vsd`, `.vsdx`
Locale/lockfile/maps: `*.po`, `*.pot`, `*.mo`, `*.xliff`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`, `go.sum`, `mix.lock`, `flake.lock`, `pubspec.lock`, `*.min.js`, `*.min.css`, `*.map`

---

## References

Sources for path inventories, regex patterns, and decoder recipes — anything load-bearing in this design has a citation here.

- HackTricks — [Windows Local Privilege Escalation](https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html), [DPAPI](https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords.html), [Linux Privilege Escalation](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html), [Kerberos ticket harvesting](https://book.hacktricks.xyz/network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux), [Credentials cheatsheet](https://book.hacktricks.xyz/windows-hardening/authentication-credentials-uac-and-efs)
- PayloadsAllTheThings — [Windows privilege escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md), [Linux privilege escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md), [Windows credentials usage](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Using%20credentials.md)
- InternalAllTheThings — [Windows DPAPI](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-dpapi/), [Linux PE](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/linux-privilege-escalation/), [GPP cpassword](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/pwd-group-policy-preferences/)
- PEASS-ng — [linPEAS](https://github.com/peass-ng/PEASS-ng/blob/master/linPEAS/README.md), [winPEAS](https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/winPEASps1/winPEAS.ps1)
- GhostPack — [SharpUp unattend](https://docs.specterops.io/ghostpack-docs/SharpUp-mdx/checks/unattendedinstallfiles), [SharpDPAPI rdg](https://docs.specterops.io/ghostpack-docs/SharpDPAPI-mdx/commands/rdg)
- PowerSploit `Get-GPPPassword`, [Invoke-WCMDump](https://github.com/peewpw/Invoke-WCMDump), [SessionGopher](https://github.com/Arvanaghi/SessionGopher), [WinSCPPasswdExtractor](https://github.com/NeffIsBack/WinSCPPasswdExtractor), [gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt), [gimmecredz](https://github.com/0xmitsurugi/gimmecredz)
- Mimikatz docs — `lsadump::sam`, `lsadump::secrets`, `dpapi::cred`, `dpapi::masterkey`, `sekurlsa::dpapi`, `vault::list`/`vault::cred`
- MITRE ATT&CK — [T1552](https://attack.mitre.org/techniques/T1552/), [T1552.001 Files](https://attack.mitre.org/techniques/T1552/001/), [T1552.003 Bash History](https://attack.mitre.org/techniques/T1552/003/), [T1552.004 Private Keys](https://attack.mitre.org/techniques/T1552/004/), [T1552.006 GPP](https://attack.mitre.org/techniques/T1552/006/), [T1003.008 /etc/shadow](https://attack.mitre.org/techniques/T1003/008/), [T1555](https://attack.mitre.org/techniques/T1555/)
- Microsoft — [KB2962486 MS14-025 GPP](https://support.microsoft.com/en-us/help/2962486/), [Answer Files](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/update-windows-settings-and-scripts-create-your-own-answer-file-sxs), [applicationHost.config password mgmt](https://learn.microsoft.com/en-us/archive/blogs/alikl/iis-7-configuration-file-applicationhost-config-password-management), [PowerShell character encoding](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_character_encoding)
- AdSecurity — [Finding Passwords in SYSVOL & Exploiting GPP](https://adsecurity.org/?p=2288)
- NetSPI — [Decrypting IIS Passwords part 1](https://www.netspi.com/blog/technical-blog/network-pentesting/decrypting-iis-passwords-to-break-out-of-the-dmz-part-1/), [part 2](https://www.netspi.com/blog/technical-blog/network-pentesting/decrypting-iis-passwords-to-break-out-of-the-dmz-part-2/)
- Black Hills InfoSec — [SeriousSAM CVE-2021-36934](https://www.blackhillsinfosec.com/what-to-know-about-microsofts-registry-hive-flaw-serioussam/)
- pentestlab — [Stored Credentials](https://pentestlab.blog/2017/04/19/stored-credentials/), [SeBackupPrivilege](https://pentestlab.blog/tag/sebackupprivilege/), [Unattend](https://pentestlab.blog/tag/unattend/)
- juggernaut-sec — [Password Hunting Windows](https://juggernaut-sec.com/password-hunting/), [Password Hunting Linux](https://juggernaut-sec.com/password-hunting-lpe/)
- XMCyber — [Extracting Encrypted Credentials from Common Tools](https://xmcyber.com/blog/extracting-encrypted-credentials-from-common-tools-2/)
- BetweenOneAndZero — [WinSCP and MobaXterm saved-cred hunting](https://betweenoneandzero.com/hunting-for-saved-credentials-in-winscp-and-mobaxterm/)
- XenArmor — [TightVNC password recovery](https://xenarmor.com/how-to-recover-remote-desktop-password-from-tightvnc/)
- 0xczr.com — [Windows & Linux Credential Hunting Cheatsheet](https://www.0xczr.com/tools/cred_hunting/)
- 0xss0rZ — [Credentials Hunting GitBook](https://0xss0rz.gitbook.io/0xss0rz/pentest/privilege-escalation/windows/credentials-hunting)
- Sckalath — [Windows Blind Files](https://gist.github.com/sckalath/da1a232f362a700ab459)
- Hashcat example hashes — [hashcat.net wiki](https://hashcat.net/wiki/doku.php?id=example_hashes)
- gitleaks — [config/gitleaks.toml](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml), [allowlist.go](https://github.com/gitleaks/gitleaks/blob/master/config/allowlist.go)
- trufflehog — [filesystem docs](https://docs.trufflesecurity.com/filesystem), [repo](https://github.com/trufflesecurity/trufflehog)
- Yelp detect-secrets — [keyword.py](https://github.com/Yelp/detect-secrets/blob/master/detect_secrets/plugins/keyword.py)
- Semgrep — [generic-secrets docs](https://semgrep.dev/docs/semgrep-secrets/generic-secrets), [secrets ruleset](https://semgrep.dev/p/secrets)
- ripgrep — [GUIDE.md filtering rules](https://github.com/BurntSushi/ripgrep/blob/master/GUIDE.md)
- Microsoft `[MS-GPPREF]` AES key — published in MSDN; used by every public GPP exploit since 2014
- Cisco Type 7 XOR key `dsfd;kfoA,.iyewrkldJKDHSUB` — public, used by every cisco password decoder
- Ubuntu `crypt(5)` manpage — [shadow hash format](https://manpages.ubuntu.com/manpages/focal/en/man5/crypt.5.html)
- Baeldung — [shadow / yescrypt](https://www.baeldung.com/linux/shadow-passwords)
- PostgreSQL — [.pgpass format](https://www.postgresql.org/docs/current/libpq-pgpass.html)
- git-scm — [git-credential-store](https://git-scm.com/docs/git-credential-store)
- npm — [.npmrc](https://docs.npmjs.com/cli/v11/configuring-npm/npmrc/)
- Ansible — [vault encrypted content](https://docs.ansible.com/projects/ansible/latest/vault_guide/vault_using_encrypted_content.html), [become](https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_privilege_escalation.html)
- Jenkins — [storing secrets](https://www.jenkins.io/doc/developer/security/secrets/), [Codurance dumping creds](https://www.codurance.com/publications/2019/05/30/accessing-and-dumping-jenkins-credentials)
- Microsoft Learn — [ConvertTo-SecureString anti-pattern](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring)
- nickvourd — [Windows-Local-Privilege-Escalation-Cookbook](https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook)
- v4resk red-book — [Kubernetes data exfiltration](https://github.com/v4resk/red-book/blob/main/cloud-cicd-pentesting/kubernetes/data-exfiltration.md)
