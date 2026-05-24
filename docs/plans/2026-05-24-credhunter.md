# CredHunter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build two self-contained credential-hunting scripts (`credhunter.sh` for Linux, `credhunter.ps1` for Windows) that find hardcoded passwords and easily-identified credentials per the design spec at `docs/specs/2026-05-24-credhunter-design.md`.

**Architecture:** Single-file phase-pipeline per OS (Recon → Known Locations → Filename Hunt → Content Scan → Render). Each phase emits findings to a shared collector deduplicated by `dedup_key`. Parallelism inside Phase 4 only. The two scripts share the design but are entirely independent implementations — they may be built in parallel.

**Tech Stack:** Bash 4+ with `xargs -P`/`grep -E`/`awk`/`openssl`/`iconv`; PowerShell 5.1+ (uses `ForEach-Object -Parallel` on 7+, falls back to `Start-ThreadJob` on 5.1). No external dependencies beyond what ships with standard distros / Windows.

---

## File Structure

```
credhunter/
├── docs/
│   ├── specs/2026-05-24-credhunter-design.md   # already exists — authoritative
│   └── plans/2026-05-24-credhunter.md          # this file
├── credhunter.sh                               # final Bash deliverable
├── credhunter.ps1                              # final PowerShell deliverable
├── README.md                                   # usage docs
└── tests/
    ├── fixtures/                               # fake credential files for regression
    │   ├── linux/
    │   │   ├── shadow.bak
    │   │   ├── id_rsa
    │   │   ├── .my.cnf
    │   │   ├── app.env
    │   │   ├── Groups.xml
    │   │   ├── connection_string.config
    │   │   └── placeholder.conf
    │   └── windows/
    │       ├── Unattend.xml
    │       ├── web.config
    │       ├── WinSCP.ini
    │       └── Groups.xml
    ├── run_bash_tests.sh                       # smoke test for credhunter.sh
    └── run_pwsh_tests.ps1                      # smoke test for credhunter.ps1
```

Each script is one self-contained file (pentest tradecraft — easy to scp/curl/paste onto target). All rules, path inventories, decoders, and helpers live inside the script.

---

## Task 0: Project skeleton and test fixtures

**Files:**
- Create: `README.md`
- Create: `tests/fixtures/linux/*` (multiple fake-cred files)
- Create: `tests/fixtures/windows/*`
- Create: `tests/run_bash_tests.sh`
- Create: `tests/run_pwsh_tests.ps1`

- [ ] **Step 1: Write `README.md`**

```markdown
# CredHunter

Hardcoded-credential hunter for authorized internal pentesting. Two self-contained scripts:

- `credhunter.sh` — Linux (Bash 4+)
- `credhunter.ps1` — Windows (PowerShell 5.1+)

## Quick start

Linux:
    chmod +x credhunter.sh
    ./credhunter.sh /home /etc /opt

Windows:
    powershell -ExecutionPolicy Bypass -NoProfile -File .\credhunter.ps1 C:\Users C:\inetpub

Run with `-h` for full flag reference. Design spec: `docs/specs/2026-05-24-credhunter-design.md`.

## Scope

Finds: hardcoded passwords, SSH/PKI private keys, Unix shadow hashes, NTLM/Kerberos hashes,
GPP cpassword (decrypted), .netrc/.pgpass/.my.cnf/.htpasswd/Tomcat/Jenkins/Cisco patterns,
embedded-credential URIs, PowerShell ConvertTo-SecureString anti-patterns, Docker config.json
base64 auth, PuTTY/WinSCP/MobaXterm saved sessions, and much more.

Does NOT find: API keys, OAuth tokens, JWT, cloud bearer tokens (different regex problem,
high false-positive rate — use trufflehog/gitleaks for those).

## Authorized use only

This tool is for authorized penetration testing under signed rules of engagement.
```

- [ ] **Step 2: Create Linux test fixtures**

```bash
mkdir -p tests/fixtures/linux
```

Then create:

`tests/fixtures/linux/shadow.bak`:
```
root:$6$rounds=5000$GX7BopJZJxPc$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD:18000:0:99999:7:::
admin:$y$j9T$5KGIS/2Ug.47GjW0jHOIB/$XwYUafYPh/petN8gKSJuLt5CEbBya3dW3pIgwrS3eJB:18000:0:99999:7:::
```

`tests/fixtures/linux/id_rsa`:
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAxxxFAKExxx9aaaCxxxe5wMzcyzExxxxsamplePEMcontentforte
stingONLYabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
-----END OPENSSH PRIVATE KEY-----
```

`tests/fixtures/linux/.my.cnf`:
```
[client]
user = backup
password = "H0t-B@ckup-2024!"
host = db01
```

`tests/fixtures/linux/app.env`:
```
DB_HOST=prod-db.internal
DB_PASSWORD=Sp01l3r!2024
SMTP_PASSWORD=changeme
API_TOKEN=should_be_ignored_per_scope
```

`tests/fixtures/linux/Groups.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups>
  <User name="svcLocalAdmin" cpassword="riBZp2ux4hIngoMtjkdtsbZGOULDg+iLfBE9X1MnTLM" />
</Groups>
```

`tests/fixtures/linux/connection_string.config`:
```xml
<add name="DSN" connectionString="mongodb://app:Sp01l3r!@db.int:27017/orders" />
```

`tests/fixtures/linux/placeholder.conf`:
```
# This file should produce LOW-confidence findings only
admin_password = changeme
db_password = your_password_here
secret = ${SECRET}
```

- [ ] **Step 3: Create Windows test fixtures**

```bash
mkdir -p tests/fixtures/windows
```

`tests/fixtures/windows/Unattend.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<unattend>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup">
      <AutoLogon>
        <Password><Value>UEBzc3cwcmQxMjMh</Value><PlainText>false</PlainText></Password>
        <Enabled>true</Enabled>
        <Username>Administrator</Username>
      </AutoLogon>
    </component>
  </settings>
</unattend>
```

`tests/fixtures/windows/web.config`:
```xml
<configuration>
  <connectionStrings>
    <add name="prod" connectionString="Server=db01;Database=app;User Id=svc_app;Password=Pr0d$ecret;" providerName="System.Data.SqlClient" />
  </connectionStrings>
</configuration>
```

`tests/fixtures/windows/WinSCP.ini`:
```
[Sessions\webdev1]
HostName=10.0.0.5
UserName=deploy
Password=AAEHEjMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=
```

`tests/fixtures/windows/Groups.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups>
  <User name="svcLocalAdmin" cpassword="riBZp2ux4hIngoMtjkdtsbZGOULDg+iLfBE9X1MnTLM" />
</Groups>
```

- [ ] **Step 4: Write `tests/run_bash_tests.sh`**

```bash
#!/usr/bin/env bash
# Smoke test for credhunter.sh — runs against tests/fixtures/linux/ and asserts findings
set -u
cd "$(dirname "$0")/.."
out=$(./credhunter.sh --output console --no-color tests/fixtures/linux 2>&1)
fail=0
assert() {
  if ! grep -q "$1" <<<"$out"; then
    echo "FAIL: expected finding not present: $1"
    fail=1
  else
    echo "PASS: $1"
  fi
}
refute() {
  if grep -q "$1" <<<"$out"; then
    echo "FAIL: unexpected finding present: $1"
    fail=1
  else
    echo "PASS (negative): $1"
  fi
}
# Expected HIGH findings
assert "shadow.hash"
assert "pem.private_key"
assert "mycnf.password"
assert "uri.basic_creds"
assert "gpp.cpassword"
# Expected LOW (placeholder)
assert "placeholder"
# Refute: API tokens out of scope, should NOT appear as a hit
refute "should_be_ignored_per_scope"
exit $fail
```

- [ ] **Step 5: Write `tests/run_pwsh_tests.ps1`**

```powershell
# Smoke test for credhunter.ps1
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$out = & powershell -ExecutionPolicy Bypass -NoProfile -File .\credhunter.ps1 --output console --no-color tests\fixtures\windows 2>&1 | Out-String
$fail = $false
function Assert-Find($pat) { if ($out -notmatch [regex]::Escape($pat)) { Write-Host "FAIL: $pat"; $script:fail = $true } else { Write-Host "PASS: $pat" } }
Assert-Find 'dotnet.connstr'
Assert-Find 'gpp.cpassword'
Assert-Find 'winscp'
Assert-Find 'unattend'
if ($fail) { exit 1 } else { exit 0 }
```

- [ ] **Step 6: Commit**

```bash
cd "/Users/pentester/Desktop/Tools/Personal Tools/credhunter"
git init 2>/dev/null || true
git add README.md tests/ docs/
git commit -m "init: spec, plan, README, and test fixtures for credhunter"
```

---

## Task 1: `credhunter.sh` — skeleton, CLI parsing, recon (Phase 1), output dirs

**Files:**
- Create: `credhunter.sh`

- [ ] **Step 1: Create the script preamble + globals**

```bash
#!/usr/bin/env bash
# credhunter.sh — internal-pentest credential hunter (Linux)
# Spec: docs/specs/2026-05-24-credhunter-design.md
# Authorized use only.
set -u
shopt -s nullglob globstar 2>/dev/null

VERSION="1.0.0"
TS="$(date +%Y%m%d-%H%M%S)"
HOSTN="$(hostname 2>/dev/null || echo unknown)"

# defaults
OUT_MODE="both"
OUT_DIR=""
ALL_MODE=0
INC_ARCHIVES=0
INC_OFFICE=0
INC_COMPRESSED=0
INC_TEMP=0
SCAN_SQLITE=0
MAX_SIZE="10M"
MIN_CONF="LOW"
SHOW_SECRETS=0
COLLECT_LOOT=0
SERIAL=0
WORKERS=""
FOLLOW_SYMLINKS=0
CROSS_MOUNTS=0
EXTRA_EXCLUDES=()
EXTRA_INCLUDE_EXT=()
SKIP_KNOWN=0
SKIP_CONTENT=0
QUIET=0
VERBOSE=0
NO_COLOR=0
SCAN_ROOTS=()

# Default scan roots (per spec §3) — used when no PATH arg supplied
DEFAULT_ROOTS=(/home /root /etc /opt /srv /var/www /var/backups /var/log /var/spool /tmp /usr/local/etc)
```

- [ ] **Step 2: Add CLI parsing**

```bash
print_help() {
  cat <<'EOF'
credhunter.sh — internal-pentest credential hunter (Linux)
Usage: credhunter.sh [options] [PATH ...]

  -o, --output {console,file,both}   output mode (default: both)
      --out-dir PATH                 output directory (default: ./credhunter-loot-<host>-<ts>)
      --all                          scan EVERY file extension for hardcoded creds
      --include-archives             recurse into .zip/.tar.gz/.7z
      --include-office               run text extractors on .pdf/.docx/.xlsx
      --include-compressed           scan .gz/.bz2/.xz logs
      --include-temp                 scan /tmp deeply (still scans top-level by default)
      --scan-sqlite                  open SQLite DBs (Login Data, etc.)
      --max-size SIZE                skip files larger than this for content scan (default: 10M)
      --min-confidence {HIGH,MEDIUM,LOW}
      --show-secrets                 print full match values (default redacts)
      --collect-loot                 copy Class A files to ./out-dir/loot/
      --serial                       disable parallelism
      --workers N                    parallel worker count (default: nproc)
      --follow-symlinks              follow symlinks (default off)
      --cross-mounts                 cross filesystem boundaries (default off)
      --exclude PATTERN              additional path/glob to exclude (repeatable)
      --include-ext EXT              additional extension to scan (repeatable)
      --skip-known-locations         skip phase 2
      --skip-content-scan            skip phase 4
  -q, --quiet                        suppress per-phase progress
  -v, --verbose                      verbose tracing
      --no-color                     strip ANSI
  -h, --help                         this help
      --version
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output) OUT_MODE="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --all) ALL_MODE=1; shift ;;
    --include-archives) INC_ARCHIVES=1; shift ;;
    --include-office) INC_OFFICE=1; shift ;;
    --include-compressed) INC_COMPRESSED=1; shift ;;
    --include-temp) INC_TEMP=1; shift ;;
    --scan-sqlite) SCAN_SQLITE=1; shift ;;
    --max-size) MAX_SIZE="$2"; shift 2 ;;
    --min-confidence) MIN_CONF="$2"; shift 2 ;;
    --show-secrets) SHOW_SECRETS=1; shift ;;
    --collect-loot) COLLECT_LOOT=1; shift ;;
    --serial) SERIAL=1; shift ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --follow-symlinks) FOLLOW_SYMLINKS=1; shift ;;
    --cross-mounts) CROSS_MOUNTS=1; shift ;;
    --exclude) EXTRA_EXCLUDES+=("$2"); shift 2 ;;
    --include-ext) EXTRA_INCLUDE_EXT+=("$2"); shift 2 ;;
    --skip-known-locations) SKIP_KNOWN=1; shift ;;
    --skip-content-scan) SKIP_CONTENT=1; shift ;;
    -q|--quiet) QUIET=1; shift ;;
    -v|--verbose) VERBOSE=1; shift ;;
    --no-color) NO_COLOR=1; shift ;;
    -h|--help) print_help; exit 0 ;;
    --version) echo "credhunter $VERSION"; exit 0 ;;
    --) shift; while [[ $# -gt 0 ]]; do SCAN_ROOTS+=("$1"); shift; done ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) SCAN_ROOTS+=("$1"); shift ;;
  esac
done

[[ ${#SCAN_ROOTS[@]} -eq 0 ]] && SCAN_ROOTS=("${DEFAULT_ROOTS[@]}")
[[ -z "$OUT_DIR" ]] && OUT_DIR="./credhunter-loot-${HOSTN}-${TS}"
[[ -z "$WORKERS" ]] && WORKERS="$(nproc 2>/dev/null || echo 4)"
[[ "$SERIAL" -eq 1 ]] && WORKERS=1
```

- [ ] **Step 3: Add color helpers and logging**

```bash
if [[ "$NO_COLOR" -eq 1 || ! -t 1 ]]; then
  C_R=""; C_Y=""; C_C=""; C_D=""; C_B=""; C_X=""
else
  C_R=$'\033[1;31m'; C_Y=$'\033[1;33m'; C_C=$'\033[1;36m'
  C_D=$'\033[2m'; C_B=$'\033[1m'; C_X=$'\033[0m'
fi

log_info()  { [[ "$QUIET" -eq 0 ]] && printf '%s\n' "$*" >&2; }
log_phase() { [[ "$QUIET" -eq 0 ]] && printf "%s[ %s ]%s %s\n" "$C_D" "$1" "$C_X" "$2" >&2; }
log_warn()  { printf "%s[ warn ]%s %s\n" "$C_Y" "$C_X" "$*" >&2; }
log_err()   { printf "%s[ err ]%s %s\n" "$C_R" "$C_X" "$*" >&2; }
```

- [ ] **Step 4: Phase 1 recon + output dir setup**

```bash
mkdir -p "$OUT_DIR" || { log_err "cannot create $OUT_DIR"; exit 2; }
FIND_JSONL="$OUT_DIR/findings.jsonl"
FIND_TXT="$OUT_DIR/findings.txt"
SKIPPED_LOG="$OUT_DIR/skipped.log"
RECON_JSON="$OUT_DIR/recon.json"
: > "$FIND_JSONL"; : > "$FIND_TXT"; : > "$SKIPPED_LOG"

EUID_NUM="$(id -u)"
USER_NAME="$(id -un)"
PRIV="user"; [[ "$EUID_NUM" -eq 0 ]] && PRIV="root"
OS_NAME="$( (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || uname -s)"

cat > "$RECON_JSON" <<EOF
{"version":"$VERSION","host":"$HOSTN","user":"$USER_NAME","euid":$EUID_NUM,"priv":"$PRIV","os":"$OS_NAME","ts":"$TS","scan_roots":[$(printf '"%s",' "${SCAN_ROOTS[@]}" | sed 's/,$//')]}
EOF

if [[ "$QUIET" -eq 0 ]]; then
  echo
  echo "${C_B}credhunter v$VERSION${C_X} — internal pentest credential hunter"
  echo "─────────────────────────────────────────────────────"
  printf "%s[ recon ]%s host=%s user=%s(uid=%s) priv=%s os=%s\n" "$C_D" "$C_X" "$HOSTN" "$USER_NAME" "$EUID_NUM" "$PRIV" "$OS_NAME"
  printf "%s[ recon ]%s scan roots: %s\n" "$C_D" "$C_X" "${SCAN_ROOTS[*]}"
  printf "%s[ recon ]%s workers=%s max-size=%s output=%s\n" "$C_D" "$C_X" "$WORKERS" "$MAX_SIZE" "$OUT_DIR"
  echo
fi
```

- [ ] **Step 5: Run sanity check**

Run: `bash -n credhunter.sh && ./credhunter.sh --help && ./credhunter.sh --version && ./credhunter.sh tests/fixtures/linux`
Expected: help prints, version prints, scan banner prints with recon info, no errors. The "scan" will do nothing yet because Phases 2-5 aren't implemented.

- [ ] **Step 6: Commit**

```bash
git add credhunter.sh
git commit -m "feat(credhunter.sh): skeleton, CLI, recon (Phase 1)"
```

---

## Task 2: `credhunter.sh` — path utilities (exclusion check, binary detect, size, walker, dedup)

**Files:**
- Modify: `credhunter.sh` (append)

- [ ] **Step 1: Build the exclusion prefix list (per spec §6.1)**

Append to `credhunter.sh`:

```bash
# Hard exclusions — applied at walker stage before any open()
EXCLUDE_PREFIXES=(
  /proc/ /sys/ /dev/ /run/ /var/run/
  /usr/share/locale/ /usr/share/man/ /usr/share/doc/ /usr/share/info/ /usr/share/help/
  /usr/share/fonts/ /usr/share/icons/ /usr/share/themes/ /usr/share/pixmaps/
  /usr/share/sounds/ /usr/share/backgrounds/ /usr/share/zoneinfo/ /usr/share/X11/
  /usr/share/mime/ /usr/share/applications/
  /usr/include/ /usr/lib/firmware/ /usr/lib/modules/ /usr/lib/locale/
  /lib/ /lib32/ /lib64/ /libx32/
  /boot/ /lost+found/ /selinux/ /sysroot/
  /var/cache/apt/ /var/cache/yum/ /var/cache/dnf/ /var/cache/pacman/
  /var/cache/zypper/ /var/cache/apk/ /var/cache/man/ /var/cache/fontconfig/
  /var/lib/apt/ /var/lib/dpkg/ /var/lib/rpm/ /var/lib/pacman/
  /var/lib/snapd/cache/ /var/lib/flatpak/repo/
  /var/log/journal/
  /snap/ /var/lib/docker/overlay2/ /var/lib/docker/image/
)

EXCLUDE_GLOBS=(
  '*/.cache/*' '*/.thumbnails/*' '*/.local/share/Trash/*'
  '*/.local/share/RecentDocuments/*' '*/.local/share/icons/*'
  '*/.local/share/themes/*' '*/.local/share/fonts/*' '*/.local/share/applications/*'
  '*/.fonts/*' '*/.themes/*' '*/.icons/*'
  '*/.cargo/registry/*' '*/.cargo/git/*' '*/.rustup/toolchains/*'
  '*/.nvm/versions/*' '*/.pyenv/versions/*' '*/.rbenv/versions/*'
  '*/.gem/ruby/*/cache/*' '*/.npm/_cacache/*' '*/.yarn/cache/*'
  '*/.pnpm-store/*' '*/.gradle/caches/*' '*/.m2/repository/*'
  '*/.cache/pip/*' '*/.cache/go-build/*' '*/.cache/yarn/*' '*/.cache/bazel/*'
  '*/.ccache/*' '*/.sccache/*'
  '*/.mozilla/firefox/*/cache2/*' '*/.mozilla/firefox/*/startupCache/*'
  '*/.mozilla/firefox/*/jumpListCache/*' '*/.mozilla/firefox/*/shader-cache/*'
  '*/.mozilla/firefox/*/offlineCache/*'
  '*/.config/google-chrome/*/Cache/*' '*/.config/chromium/*/Cache/*'
  '*/.config/BraveSoftware/*/Cache/*' '*/.config/microsoft-edge/*/Cache/*'
  '*/snap/*/common/.cache/*' '*/.var/app/*/cache/*'
  '*/node_modules/*' '*/vendor/*' '*/target/*' '*/build/*' '*/dist/*' '*/out/*'
  '*/__pycache__/*' '*/.pytest_cache/*' '*/.mypy_cache/*' '*/.tox/*' '*/.eggs/*'
  '*/.terraform/*' '*/.gradle/*' '*/.next/*' '*/.nuxt/*' '*/.svelte-kit/*'
  '*/.angular/*' '*/.parcel-cache/*'
  '*/.git/objects/*' '*/.git/pack/*' '*/.git/lfs/*' '*/.svn/pristine/*' '*/.hg/store/*'
)

# Default-skip extensions (per spec Appendix E)
SKIP_EXT_REGEX='\.(jpg|jpeg|png|gif|bmp|tiff|tif|ico|webp|heic|heif|raw|cr2|nef|psd|ai|eps|mp3|mp4|mov|avi|mkv|wmv|flv|wav|flac|ogg|opus|webm|m4a|m4v|aac|svg|ttf|otf|woff|woff2|eot|fon|exe|dll|so|dylib|o|a|lib|obj|class|pyc|pyo|pyd|wasm|bin|iso|img|dmg|msi|msu|cab|deb|rpm|snap|appx|appxbundle|efi|sys|db|sqlite|sqlite3|mdb|accdb|dbf|idx|frm|ibd|myd|myi|aof|rdb|pdf|doc|xls|ppt|odt|ods|odp|epub|mobi|azw|azw3|djvu|vsd|vsdx|po|pot|mo|xliff|min\.js|min\.css|map)$'

# Default content-scan extensions (per spec Appendix D) — when --all is NOT set
DEFAULT_EXT_REGEX='\.(conf|cnf|cfg|config|ini|properties|toml|yaml|yml|json|xml|plist|env|reg|inf|sh|bash|zsh|ksh|fish|ps1|psm1|psd1|bat|cmd|vbs|vbe|wsf|wsc|py|rb|pl|pm|php|phtml|js|mjs|cjs|ts|tsx|jsx|vue|svelte|java|scala|kt|kts|groovy|go|rs|swift|m|mm|cs|vb|fs|fsx|c|cpp|cc|cxx|h|hpp|lua|r|R|dart|ex|exs|erl|hs|clj|cljs|htm|html|jsp|jspx|asp|aspx|cshtml|razor|ejs|pug|twig|blade\.php|erb|haml|mustache|hbs|ipynb|rmd|qmd|sql|ddl|dml|psql|mysql|pgsql|tf|tfvars|bicep|log|out|err|trace|bak|backup|old|orig|save|swp|swo|tmp|copy|original|dist|sample|example)$'
```

- [ ] **Step 2: Helpers — exclusion test, binary detect, size**

```bash
# is_excluded PATH — returns 0 (excluded) or 1 (not excluded)
is_excluded() {
  local p="$1"
  local prefix glob
  for prefix in "${EXCLUDE_PREFIXES[@]}"; do
    [[ "$p" == "$prefix"* ]] && return 0
  done
  for glob in "${EXCLUDE_GLOBS[@]}"; do
    case "$p" in $glob) return 0 ;; esac
  done
  for glob in "${EXTRA_EXCLUDES[@]}"; do
    case "$p" in $glob) return 0 ;; esac
  done
  return 1
}

# is_binary PATH — sniff first 8 KiB for NUL; UTF-16 BOM aware
is_binary() {
  local f="$1"
  local head; head=$(head -c 8192 "$f" 2>/dev/null) || return 0
  # UTF-16 BOM check
  case "$head" in
    $'\xff\xfe'*|$'\xfe\xff'*) return 1 ;;   # UTF-16, treat as text
    $'\xef\xbb\xbf'*) return 1 ;;            # UTF-8 BOM
  esac
  # NUL sniff
  LC_ALL=C grep -q $'\x00' <<<"$head" && return 0 || return 1
}

# size_under_cap PATH SIZE — true if file is ≤ SIZE (e.g., 10M)
size_under_cap() {
  local f="$1" max="$2"
  local bytes
  bytes=$(stat -c '%s' "$f" 2>/dev/null || stat -f '%z' "$f" 2>/dev/null) || return 1
  # SIZE → bytes
  local n="${max%[KMGkmg]*}" unit="${max: -1}"
  case "$unit" in
    K|k) max_bytes=$(( n * 1024 )) ;;
    M|m) max_bytes=$(( n * 1024 * 1024 )) ;;
    G|g) max_bytes=$(( n * 1024 * 1024 * 1024 )) ;;
    *) max_bytes="$max" ;;
  esac
  [[ "$bytes" -le "$max_bytes" ]]
}
```

- [ ] **Step 3: Walker — produces candidate file list for Phase 4**

```bash
# walk ROOT — emits one filtered candidate path per line on stdout
walk() {
  local root="$1"
  local find_opts=(-type f)
  [[ "$FOLLOW_SYMLINKS" -eq 0 ]] || find_opts=(-L "${find_opts[@]}")
  [[ "$CROSS_MOUNTS" -eq 0 ]] && find_opts+=(-xdev)
  find "$root" "${find_opts[@]}" 2>/dev/null | while IFS= read -r f; do
    is_excluded "$f" && continue
    echo "$f"
  done
}

# Inode dedup using a flat file in OUT_DIR
INODE_FILE="$OUT_DIR/.seen-inodes"
: > "$INODE_FILE"
seen_inode() {
  local f="$1"
  local key; key=$(stat -c '%d:%i' "$f" 2>/dev/null || stat -f '%d:%i' "$f" 2>/dev/null) || return 1
  grep -qxF -- "$key" "$INODE_FILE" && return 0
  echo "$key" >> "$INODE_FILE"
  return 1
}
```

- [ ] **Step 4: Sanity-check the helpers**

Run:
```bash
bash -n credhunter.sh
bash -c 'source credhunter.sh; is_excluded /proc/cpuinfo && echo "excluded OK"; is_excluded /etc/passwd || echo "not excluded OK"'
```
Expected: both "OK" lines print, no errors.

- [ ] **Step 5: Commit**

```bash
git add credhunter.sh
git commit -m "feat(credhunter.sh): path utilities (excludes, binary detect, walker)"
```

---

## Task 3: `credhunter.sh` — detection engine + decoders

**Files:**
- Modify: `credhunter.sh` (append)

- [ ] **Step 1: Add placeholder list + entropy helper + comment detection**

Append:

```bash
# Placeholder values (per spec §4.4) — lowercase, exact match on trimmed value
PLACEHOLDERS=(password passw0rd 'p@ssw0rd' 'p@ssword' pass passwd pwd secret test testing
  changeme change-me change_me changeit default defaultpassword
  your_password yourpassword yoursecret your-secret-here
  example examplepassword sample samplepassword dummy placeholder
  redacted xxx xxxx xxxxx xxxxxx xxxxxxxx '***' '****' '********'
  '<password>' '[password]' '{password}' '{{password}}' '${password}'
  'null' none nil 'n/a' na tbd todo fixme '???' '!!!'
  foo bar foobar hello world helloworld
  insert_password enter_password type_password_here secret_here password_here
  my_password mypassword admin administrator root user guest anonymous
  '123456' '12345678' qwerty abc123 letmein monkey dragon)

is_placeholder() {
  local v_lower; v_lower="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/^[ \t"'"'"']*//;s/[ \t"'"'"']*$//')"
  local p
  for p in "${PLACEHOLDERS[@]}"; do
    [[ "$v_lower" == "$p" ]] && return 0
  done
  return 1
}

# Shannon entropy (base-2) of $1 — printed with 2 decimals
entropy() {
  local s="$1" len=${#1}
  [[ "$len" -eq 0 ]] && { echo "0.00"; return; }
  awk -v s="$s" 'BEGIN{
    for (i=1; i<=length(s); i++) c[substr(s,i,1)]++
    H=0; n=length(s)
    for (k in c) { p=c[k]/n; H -= p*log(p)/log(2) }
    printf "%.2f", H
  }'
}

# is_test_path PATH — returns 0 if path looks like test/fixture
is_test_path() {
  case "$1" in
    */test/*|*/tests/*|*/spec/*|*/specs/*|*/fixture/*|*/fixtures/*|*/sample/*|*/samples/*|*/example/*|*/examples/*|*/demo/*|*/demos/*|*/mock/*|*/mocks/*|*/__tests__/*|*/__mocks__/*|*/e2e/*|*/testdata/*|*/test-data/*|*_test.*|*.test.*|*.spec.*|*_spec.*|*.example.*|*.sample.*|*.demo.*) return 0 ;;
  esac
  return 1
}

# is_comment LINE — basic comment-prefix detection
is_comment() {
  local line; line="$(printf '%s' "$1" | sed 's/^[ \t]*//')"
  case "$line" in
    '#'*|'//'*|'--'*|';'*|'%'*|'<!--'*) return 0 ;;
    '/*'*|'"""'*|"'''"*|'<#'*) return 0 ;;
  esac
  return 1
}
```

- [ ] **Step 2: Add the finding emitter**

```bash
# emit_finding FIELDS as KEY=VALUE pairs; writes JSONL + appends to TXT
# fields used: rule_id, category, base_conf, conf, demotions, path, line_no, line_text, match_text, key_name, fp_reason, entropy
emit_finding() {
  declare -A F
  local k v
  while [[ $# -gt 0 ]]; do
    k="${1%%=*}"; v="${1#*=}"; F[$k]="$v"; shift
  done
  local redacted; redacted="$(redact "${F[match_text]:-}")"
  local mtime size mode owner
  if [[ -n "${F[path]:-}" && -e "${F[path]}" ]]; then
    mtime=$(stat -c '%y' "${F[path]}" 2>/dev/null || stat -f '%Sm' "${F[path]}" 2>/dev/null)
    size=$(stat -c '%s' "${F[path]}" 2>/dev/null || stat -f '%z' "${F[path]}" 2>/dev/null)
    mode=$(stat -c '%a' "${F[path]}" 2>/dev/null || stat -f '%Mp%Lp' "${F[path]}" 2>/dev/null)
    owner=$(stat -c '%U' "${F[path]}" 2>/dev/null || stat -f '%Su' "${F[path]}" 2>/dev/null)
  fi
  local dedup; dedup=$(printf '%s|%s|%s|%s' "${F[rule_id]}" "${F[path]}" "${F[line_no]:-0}" "${F[match_text]:-}" | sha256sum | awk '{print $1}')
  # JSONL
  jq -nc --arg rule_id "${F[rule_id]}" --arg cat "${F[category]:-PASSWORD}" \
    --arg conf "${F[conf]}" --arg bconf "${F[base_conf]:-${F[conf]}}" \
    --arg host "$HOSTN" --arg user "$USER_NAME" --arg priv "$PRIV" \
    --arg path "${F[path]:-}" --arg ln "${F[line_no]:-0}" \
    --arg ltext "${F[line_text]:-}" --arg mtxt "${F[match_text]:-}" \
    --arg redacted "$redacted" --arg key "${F[key_name]:-}" \
    --arg fp "${F[fp_reason]:-}" --arg ent "${F[entropy]:-0}" \
    --arg mtime "${mtime:-}" --arg size "${size:-0}" --arg mode "${mode:-}" \
    --arg owner "${owner:-}" --arg dedup "$dedup" \
    '{rule_id:$rule_id,category:$cat,confidence:$conf,base_confidence:$bconf,host:$host,scan_user:$user,scan_user_priv:$priv,abs_path:$path,line_no:($ln|tonumber),line_text:$ltext,match_text:$mtxt,match_redacted:$redacted,key_name:$key,fp_reason:$fp,entropy:($ent|tonumber),file_mtime:$mtime,file_size:($size|tonumber),file_mode:$mode,file_owner:$owner,dedup_key:$dedup}' \
    >> "$FIND_JSONL" 2>/dev/null || true
  # TXT
  {
    printf '[%s] %-26s %s' "${F[conf]}" "${F[rule_id]}" "${F[path]}"
    [[ -n "${F[line_no]:-}" && "${F[line_no]}" != "0" ]] && printf ':%s' "${F[line_no]}"
    printf '\n'
    [[ -n "${F[match_text]:-}" ]] && {
      if [[ "$SHOW_SECRETS" -eq 1 ]]; then
        printf '       %s\n' "${F[match_text]}"
      else
        printf '       %s\n' "$redacted"
      fi
    }
    [[ -n "${F[fp_reason]:-}" ]] && printf '       fp_reason=%s\n' "${F[fp_reason]}"
  } >> "$FIND_TXT"
}

redact() {
  local s="$1" len=${#1}
  if [[ "$SHOW_SECRETS" -eq 1 ]]; then printf '%s' "$s"; return; fi
  if [[ "$len" -le 4 ]]; then printf '%s' "****"; return; fi
  printf '%s%s%s' "${s:0:2}" "$(printf '%*s' $(( len - 4 )) '' | tr ' ' '*')" "${s: -2}"
}
```

Note: requires `jq` and `sha256sum` (or fall back). Add fallback:

```bash
command -v jq >/dev/null || log_warn "jq not found; JSONL output will be skipped"
command -v sha256sum >/dev/null || alias sha256sum="shasum -a 256"
```

- [ ] **Step 3: GPP cpassword decoder**

```bash
# decrypt_gpp_cpassword BASE64 — outputs decoded plaintext or empty
decrypt_gpp_cpassword() {
  local b64="$1"
  # Pad to multiple of 4
  local pad=$(( 4 - ${#b64} % 4 )); [[ "$pad" -eq 4 ]] && pad=0
  local padded="$b64"
  while [[ "$pad" -gt 0 ]]; do padded+="="; pad=$((pad-1)); done
  printf '%s' "$padded" | base64 -d 2>/dev/null | \
    openssl enc -d -aes-256-cbc -nopad \
      -K 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b \
      -iv 00000000000000000000000000000000 2>/dev/null | \
    iconv -f UTF-16LE -t UTF-8 2>/dev/null | tr -d '\000'
}
```

- [ ] **Step 4: Define the rule pack as functions**

Append a series of `scan_<rule>` functions, each takes a file path and emits findings via `emit_finding`. Key rules per spec §4.2:

```bash
scan_file_content() {
  local f="$1"
  is_excluded "$f" && return
  seen_inode "$f" && return
  size_under_cap "$f" "$MAX_SIZE" || { echo "$f	oversize" >>"$SKIPPED_LOG"; return; }
  is_binary "$f" && { echo "$f	binary" >>"$SKIPPED_LOG"; return; }

  # ---- HIGH shape-anchored rules (specificity order) ----
  rule_pem "$f"
  rule_ppk "$f"
  rule_wireguard "$f"
  rule_gpp_cpassword "$f"
  rule_shadow_hash "$f"
  rule_htpasswd "$f"
  rule_netntlmv2 "$f"
  rule_pwdump_ntlm "$f"
  rule_krb5_asrep "$f"
  rule_krb5_tgs "$f"
  rule_uri_basic_creds "$f"
  rule_netrc "$f"
  rule_pgpass "$f"
  rule_mycnf_password "$f"
  rule_tomcat_user "$f"
  rule_cisco_secret "$f"
  rule_dotnet_connstr "$f"
  rule_jdbc_password "$f"
  rule_ps_securestring "$f"
  rule_docker_auth "$f"
  rule_ansible_vault_header "$f"
  # ---- generic catch-all (last) ----
  rule_generic_assign "$f"
}

# Per-rule implementations. Each follows the pattern:
#   grep -EHn -- 'PATTERN' "$f" 2>/dev/null | while IFS= read -r line; do
#     local lno="${line%%:*}"; local rest="${line#*:}"
#     ... extract value, run confidence pipeline, emit ...
#   done

rule_pem() {
  local f="$1"
  # multi-line: check for header presence first
  grep -qE -- '-----BEGIN ([A-Z ]+ )?PRIVATE KEY' "$f" 2>/dev/null || return
  # capture metadata
  local type; type=$(grep -oE -- '-----BEGIN ([A-Z ]+ )?PRIVATE KEY' "$f" | head -1)
  local enc="no"
  grep -qE -- '^(Proc-Type: 4,ENCRYPTED|DEK-Info:)' "$f" 2>/dev/null && enc="yes"
  emit_finding rule_id=pem.private_key category=PRIVATE_KEY conf=HIGH base_conf=HIGH \
    path="$f" line_no=1 line_text="$type" match_text="$type" key_name="encrypted=$enc"
}

rule_ppk() {
  local f="$1"
  head -1 "$f" 2>/dev/null | grep -qE '^PuTTY-User-Key-File-[23]:' || return
  emit_finding rule_id=putty.ppk category=PRIVATE_KEY conf=HIGH base_conf=HIGH \
    path="$f" line_no=1 match_text="PuTTY PPK"
}

rule_gpp_cpassword() {
  local f="$1"
  grep -EHno -- 'cpassword="[A-Za-z0-9+/]{8,}={0,2}"' "$f" 2>/dev/null | while IFS=: read -r lno match; do
    local b64; b64=$(sed -E 's/.*cpassword="([^"]+)".*/\1/' <<<"$match")
    emit_finding rule_id=gpp.cpassword category=PASSWORD conf=HIGH base_conf=HIGH \
      path="$f" line_no="$lno" line_text="$match" match_text="$b64"
    local plain; plain=$(decrypt_gpp_cpassword "$b64")
    if [[ -n "$plain" ]]; then
      emit_finding rule_id=gpp.cpassword.plaintext category=PASSWORD conf=HIGH base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$match" match_text="$plain"
    fi
  done
}

rule_shadow_hash() {
  local f="$1"
  grep -EHno -- '^([A-Za-z_][A-Za-z0-9_.-]{0,31}):(\$(1|2[abxy]?|5|6|7|y|argon2(i|d|id))\$[A-Za-z0-9./$,=+-]{10,}):' "$f" 2>/dev/null \
  | while IFS=: read -r lno match; do
      local user; user=$(awk -F: '{print $1}' <<<"$match")
      local hash; hash=$(awk -F: '{print $2}' <<<"$match")
      emit_finding rule_id=shadow.hash category=HASH:shadow conf=HIGH base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$match" match_text="$hash" key_name="user=$user"
    done
}

# ... (continue defining the remaining ~15 rules following the same pattern;
#      full regex patterns are in design spec §4.2 — lift PCRE forms verbatim and
#      convert to ERE where needed for grep -E)
```

The remaining rules to implement (full regex in `docs/specs/2026-05-24-credhunter-design.md` §4.2):
- `rule_wireguard` — `^\s*PrivateKey\s*=\s*[A-Za-z0-9+/]{43}=$`
- `rule_htpasswd` — htpasswd-line regex
- `rule_netntlmv2`, `rule_pwdump_ntlm`, `rule_krb5_asrep`, `rule_krb5_tgs`
- `rule_uri_basic_creds` — DB/HTTP basic-auth URLs
- `rule_netrc`, `rule_pgpass`, `rule_mycnf_password`
- `rule_tomcat_user`, `rule_cisco_secret`, `rule_dotnet_connstr`, `rule_jdbc_password`
- `rule_ps_securestring` — `ConvertTo-SecureString ... -AsPlainText -Force`
- `rule_docker_auth` — decode base64 `"auth":"..."` and emit derived `URI_CREDS:docker`
- `rule_ansible_vault_header` — `^\$ANSIBLE_VAULT;` → `REFERENCE` MEDIUM
- `rule_generic_assign` — generic key=value; full confidence-scoring pipeline (placeholder/identifier/env-var/length/comment/test-path/entropy)

For the generic rule, the confidence pipeline:

```bash
rule_generic_assign() {
  local f="$1"
  grep -iEHno -- '\b(password|passwd|pwd|pass|passphrase|secret|credential|credentials|creds|requirepass|bindpw|db[_-]?pass(word)?|smtp[_-]?pass(word)?|ansible[_-]?(ssh[_-]?pass|become[_-]?pass|password)|admin[_-]?pass(word)?|root[_-]?pass(word)?|master[_-]?pass(word)?)[[:space:]]*[:=]+[[:space:]]*["'"'"'`]?[^[:space:]"'"'"'`#]{4,512}' "$f" 2>/dev/null \
  | while IFS=: read -r lno rest; do
      local key val
      key=$(grep -ioE '\b(password|passwd|pwd|pass|passphrase|secret|credential|credentials|creds|requirepass|bindpw|admin_password|db_password)\b' <<<"$rest" | head -1)
      val=$(sed -E "s/.*[:=]+[[:space:]]*[\"'\`]?([^[:space:]\"'\`#]+).*/\1/" <<<"$rest")
      local conf="HIGH" demotions=""
      local fp=""
      # placeholder
      if is_placeholder "$val"; then conf="LOW"; fp="placeholder"
      # identifier-shape (unquoted, looks like variable)
      elif [[ "$val" =~ ^[A-Za-z_$][A-Za-z0-9_.$]*$ ]] && [[ "$rest" != *\"*\"* && "$rest" != *\'*\'* ]]; then
        conf="LOW"; fp="variable_reference"
      # env-var reference
      elif [[ "$val" =~ ^\$\{ ]] || [[ "$val" =~ os\.environ ]] || [[ "$val" =~ process\.env ]]; then
        conf="LOW"; fp="env_reference"
      # length
      elif [[ ${#val} -lt 4 ]]; then conf="LOW"; fp="too_short"
      elif [[ ${#val} -gt 512 ]]; then conf="LOW"; fp="too_long"
      else
        # demote one tier per failing check (comment, test path, entropy)
        if is_comment "$rest"; then conf=$([[ "$conf" == "HIGH" ]] && echo "MEDIUM" || echo "LOW"); demotions+="comment,"; fi
        if is_test_path "$f"; then conf=$([[ "$conf" == "HIGH" ]] && echo "MEDIUM" || echo "LOW"); demotions+="test_path,"; fi
        local H; H=$(entropy "$val")
        local len=${#val}
        # entropy bands per spec §4.4
        if (( len >= 4 && len <= 7 )); then
          awk "BEGIN{exit !($H < 3.0)}" && { conf=$([[ "$conf" == "HIGH" ]] && echo "MEDIUM" || echo "LOW"); demotions+="entropy,"; }
        elif (( len >= 8 && len <= 15 )); then
          awk "BEGIN{exit !($H < 2.0)}" && { conf="LOW"; demotions+="entropy_low,"; }
        fi
      fi
      emit_finding rule_id=pw.assign.generic category=PASSWORD conf="$conf" base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$rest" match_text="$val" key_name="$key" \
        fp_reason="$fp" entropy="$(entropy "$val")"
    done
}
```

- [ ] **Step 5: Smoke test detection on fixtures**

Run: `./credhunter.sh --output console --no-color tests/fixtures/linux`
Expected: at minimum, you see `pem.private_key`, `shadow.hash`, `mycnf.password`, `gpp.cpassword`, `gpp.cpassword.plaintext`, `uri.basic_creds` findings (Phases 2-5 not yet wired, this will just show Phase 4 content scan effects once you add the walker call in Task 5).

- [ ] **Step 6: Commit**

```bash
git add credhunter.sh
git commit -m "feat(credhunter.sh): detection rules + GPP cpassword decoder"
```

---

## Task 4: `credhunter.sh` — Phase 2 (known locations sweep)

**Files:**
- Modify: `credhunter.sh` (append)

- [ ] **Step 1: Hard-code the Linux path inventory (spec Appendix A)**

```bash
# Each entry is a single file or a glob. Glob expansion via shopt -s globstar.
KNOWN_PATHS=(
  # Shell/REPL history (per-user)
  '/home/*/.bash_history' '/home/*/.zsh_history' '/home/*/.history'
  '/home/*/.local/share/fish/fish_history'
  '/home/*/.python_history' '/home/*/.node_repl_history' '/home/*/.irb_history'
  '/home/*/.psql_history' '/home/*/.mysql_history' '/home/*/.sqlite_history'
  '/home/*/.rediscli_history' '/home/*/.mongo_history' '/home/*/.lesshst' '/home/*/.viminfo'
  '/root/.bash_history' '/root/.zsh_history' '/root/.mysql_history' '/root/.psql_history'
  # SSH
  '/home/*/.ssh/id_rsa' '/home/*/.ssh/id_dsa' '/home/*/.ssh/id_ecdsa' '/home/*/.ssh/id_ed25519'
  '/home/*/.ssh/identity' '/home/*/.ssh/config' '/home/*/.ssh/authorized_keys' '/home/*/.ssh/known_hosts'
  '/root/.ssh/id_rsa' '/root/.ssh/id_ed25519' '/root/.ssh/config' '/root/.ssh/authorized_keys'
  '/etc/ssh/sshd_config' '/etc/ssh/ssh_config' '/etc/ssh/ssh_host_rsa_key' '/etc/ssh/ssh_host_ed25519_key' '/etc/ssh/ssh_host_ecdsa_key'
  # System auth
  '/etc/shadow' '/etc/gshadow' '/etc/passwd' '/etc/sudoers'
  '/etc/sudoers.d' '/etc/security/opasswd' '/etc/pam.d'
  '/etc/krb5.keytab' '/etc/krb5.conf' '/var/lib/krb5kdc/principal'
  '/tmp/krb5cc_*' '/var/backups/shadow*' '/var/backups/passwd*' '/var/backups/group*'
  # Service configs
  '/etc/mysql/my.cnf' '/etc/mysql/debian.cnf' '/etc/mysql/conf.d' '/etc/mysql/mariadb.conf.d'
  '/home/*/.my.cnf' '/root/.my.cnf'
  '/etc/postgresql' '/home/*/.pgpass' '/root/.pgpass'
  '/etc/redis/redis.conf' '/etc/redis-sentinel.conf'
  '/etc/mongod.conf'
  '/etc/samba/smb.conf' '/etc/samba/smbpasswd' '/var/lib/samba/private/passdb.tdb' '/var/lib/samba/private/secrets.tdb'
  '/etc/dovecot' '/etc/postfix/main.cf' '/etc/postfix/sasl_passwd' '/etc/postfix/master.cf'
  '/etc/openvpn' '/etc/wireguard' '/etc/ipsec.secrets' '/etc/strongswan.d'
  '/etc/freeradius/3.0/clients.conf' '/etc/freeradius/clients.conf'
  '/etc/snmp/snmpd.conf' '/etc/rndc.key' '/etc/bind/rndc.key'
  '/etc/proftpd' '/etc/vsftpd.conf' '/etc/pure-ftpd'
  '/etc/cups/printers.conf' '/etc/cups/cupsd.conf'
  '/etc/sssd/sssd.conf' '/etc/nslcd.conf'
  # App / CI
  '/var/lib/jenkins/credentials.xml' '/var/lib/jenkins/users' '/var/lib/jenkins/secrets/master.key'
  '/var/lib/jenkins/secrets/hudson.util.Secret' '/var/lib/jenkins/secrets/initialAdminPassword'
  '/var/lib/jenkins/jobs'
  '/etc/gitlab/gitlab.rb' '/etc/gitlab/gitlab-secrets.json'
  '/home/*/.docker/config.json' '/root/.docker/config.json'
  '/home/*/.kube/config' '/root/.kube/config' '/etc/kubernetes/admin.conf' '/etc/kubernetes/kubelet.conf'
  '/etc/rancher/k3s/k3s.yaml' '/etc/rancher/rke2/rke2.yaml'
  '/home/*/.aws/credentials' '/root/.aws/credentials'
  '/home/*/.azure' '/root/.azure'
  '/home/*/.config/gcloud' '/root/.config/gcloud'
  '/home/*/.config/rclone/rclone.conf' '/root/.config/rclone/rclone.conf'
  '/home/*/.netrc' '/root/.netrc' '/home/*/_netrc'
  '/home/*/.git-credentials' '/root/.git-credentials'
  '/home/*/.npmrc' '/root/.npmrc'
  '/home/*/.m2/settings.xml' '/root/.m2/settings.xml'
  '/home/*/.subversion/auth/svn.simple' '/root/.subversion/auth/svn.simple'
  # Ansible / Puppet / Salt / Chef
  '/etc/ansible' '/srv/pillar' '/srv/salt' '/etc/salt'
  '/etc/puppet' '/etc/puppetlabs'
  # Cron / systemd
  '/etc/crontab' '/etc/cron.d' '/etc/cron.hourly' '/etc/cron.daily' '/etc/cron.weekly' '/etc/cron.monthly'
  '/var/spool/cron' '/etc/systemd/system' '/lib/systemd/system' '/etc/init.d' '/etc/rc.local'
  '/etc/default' '/etc/sysconfig'
  # Apache / nginx
  '/etc/apache2' '/etc/httpd' '/etc/nginx' '/etc/lighttpd' '/etc/caddy/Caddyfile' '/etc/haproxy/haproxy.cfg'
  # WP / Joomla / Drupal / Spring boot common locations
  '/var/www'
)
```

- [ ] **Step 2: Phase 2 runner**

```bash
run_phase2() {
  [[ "$SKIP_KNOWN" -eq 1 ]] && return
  log_phase "phase 2/5" "known-locations sweep"
  local pre_count; pre_count=$(wc -l < "$FIND_JSONL")
  local pat target
  for pat in "${KNOWN_PATHS[@]}"; do
    # Use bash glob expansion + find for recursive dir entries
    for target in $pat; do
      [[ -e "$target" ]] || continue
      if [[ -d "$target" ]]; then
        find "$target" -type f 2>/dev/null | while IFS= read -r f; do
          scan_known_path "$f"
        done
      else
        scan_known_path "$target"
      fi
    done
  done
  # /proc/*/environ + cmdline (own UID, plus others if privileged)
  for pid_dir in /proc/[0-9]*; do
    local environ="$pid_dir/environ" cmdline="$pid_dir/cmdline"
    [[ -r "$environ" ]] && scan_proc_environ "$environ"
    [[ -r "$cmdline" ]] && scan_proc_cmdline "$cmdline"
  done
  local post; post=$(wc -l < "$FIND_JSONL")
  log_info "  $(( post - pre_count )) findings"
}

scan_known_path() {
  local f="$1"
  # Always emit a "known location present" record at INFO for Class A files
  case "$f" in
    *id_rsa|*id_dsa|*id_ecdsa|*id_ed25519|*.pem|*.ppk|*.kdbx|*.kdb|*.pfx|*.p12|*.jks|*.keystore|*krb5.keytab)
      emit_finding rule_id=class_a.file_present category=PRIVATE_KEY conf=HIGH base_conf=HIGH \
        path="$f" match_text="$(basename "$f")"
      ;;
  esac
  # Otherwise, scan content if eligible
  is_binary "$f" || scan_file_content "$f"
}

scan_proc_environ() {
  local f="$1"
  local pid; pid=$(basename "$(dirname "$f")")
  tr '\0' '\n' < "$f" 2>/dev/null | grep -iE '(PASS|PASSWORD|SECRET|KEY|TOKEN|MYSQL_PWD|PGPASSWORD)=' | while IFS= read -r kv; do
    local key="${kv%%=*}" val="${kv#*=}"
    is_placeholder "$val" && continue
    emit_finding rule_id=proc.environ category=PASSWORD conf=MEDIUM base_conf=MEDIUM \
      path="$f" line_text="$kv" match_text="$val" key_name="pid=$pid env=$key"
  done
}

scan_proc_cmdline() {
  local f="$1"
  local pid; pid=$(basename "$(dirname "$f")")
  local cmd; cmd=$(tr '\0' ' ' < "$f" 2>/dev/null)
  # Look for password-passed-as-arg patterns
  if [[ "$cmd" =~ (-p|--password=|-P|--pass=)([^[:space:]]+) ]]; then
    local val="${BASH_REMATCH[2]}"
    is_placeholder "$val" && return
    emit_finding rule_id=proc.cmdline category=PASSWORD conf=MEDIUM base_conf=MEDIUM \
      path="$f" line_text="$cmd" match_text="$val" key_name="pid=$pid"
  fi
}
```

- [ ] **Step 3: Smoke test Phase 2**

Add `run_phase2` to the script bottom (we'll add the main orchestrator in Task 5). Manually:
```bash
bash -n credhunter.sh
./credhunter.sh tests/fixtures/linux 2>&1 | head -20
```
Expected: no syntax errors; runs cleanly (won't find much yet since fixtures don't match real Linux known-location paths).

- [ ] **Step 4: Commit**

```bash
git add credhunter.sh
git commit -m "feat(credhunter.sh): Phase 2 known-locations sweep + /proc scraping"
```

---

## Task 5: `credhunter.sh` — Phase 3 (filename hunt) + Phase 4 (content scan w/ parallelism)

**Files:**
- Modify: `credhunter.sh` (append)

- [ ] **Step 1: Class A filename glob list (spec Appendix C)**

```bash
# Class A filename globs — emit by name match alone, regardless of content
CLASS_A_GLOBS=(
  '*.kdbx' '*.kdb' '*.psafe3' '*.agilekeychain' '*.opvault' '*.1pif'
  '*.bitwarden_export.json' 'bw_export_*.csv' 'lastpass_export*.csv'
  'key3.db' 'key4.db' 'logins.json' 'signons.sqlite' 'cert9.db'
  'Login Data' 'Login Data For Account' 'Web Data' 'Local State'
  'id_rsa' 'id_dsa' 'id_ecdsa' 'id_ed25519' 'id_xmss' 'id_ecdsa_sk' 'id_ed25519_sk'
  '*.pem' '*.key' '*.priv' '*.pk8' '*.pkcs8' '*.rsa' '*.dsa' '*.ec' '*.ppk' '*.openssh'
  'authorized_keys' 'known_hosts' 'ssh_host_*_key'
  '*.pfx' '*.p12' '*.jks' '*.keystore' '*.bks' '*.uber' '*.pkcs12'
  '.netrc' '_netrc' '.pgpass' '.my.cnf' '.mylogin.cnf' '.htpasswd'
  '.smbcredentials' '.cifs-credentials' '.credentials' '.git-credentials'
  '.npmrc' '.yarnrc.yml' '.yarnrc' 'kubeconfig' '*.kubeconfig'
  '*.ovpn' 'wg0.conf' 'krb5.keytab' '*.keytab' 'krb5cc_*'
  'azureProfile.json' 'accessTokens.json' 'application_default_credentials.json'
  'Groups.xml' 'Services.xml' 'ScheduledTasks.xml' 'Drives.xml' 'Printers.xml' 'DataSources.xml'
  'unattend.xml' 'Unattend.xml' 'autounattend.xml' 'Autounattend.xml' 'sysprep.inf' 'sysprep.xml'
  'shadow.bak' 'shadow.old' 'shadow-' 'passwd.bak' 'passwd-' 'gshadow.bak'
  'WinSCP.ini' 'sitemanager.xml' 'recentservers.xml' 'filezilla.xml' 'confCons.xml'
  'MobaXterm.ini' '*.rdg' '*.rdp' 'settings.xml' 'credentials.xml'
  '.env' '.env.*' 'wp-config.php' 'configuration.php' 'LocalSettings.php'
  'local.xml' 'database.yml' 'web.config'
)

# Keyword filename patterns (case-insensitive)
KEYWORD_GLOBS=(
  '*password*' '*pass*.txt' '*cred*' '*credential*' '*secret*'
  'pw.txt' 'pwd.txt' '*.passwd' '*.pass' '*.creds'
)

matches_glob_set() {
  local name="$1"; shift
  local g
  for g in "$@"; do
    case "$name" in $g) return 0 ;; esac
    # case-insensitive
    case "$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')" in
      $(printf '%s' "$g" | tr '[:upper:]' '[:lower:]')) return 0 ;;
    esac
  done
  return 1
}

run_phase3() {
  log_phase "phase 3/5" "filename-pattern hunt"
  local pre_count; pre_count=$(wc -l < "$FIND_JSONL")
  local r f base
  for r in "${SCAN_ROOTS[@]}"; do
    [[ -d "$r" ]] || continue
    walk "$r" | while IFS= read -r f; do
      base=$(basename "$f")
      if matches_glob_set "$base" "${CLASS_A_GLOBS[@]}"; then
        emit_finding rule_id=class_a.filename category=PRIVATE_KEY conf=HIGH base_conf=HIGH \
          path="$f" match_text="$base"
        # Also try content scan if it looks like text (so PEMs get their detailed rule too)
        is_binary "$f" || scan_file_content "$f"
      elif matches_glob_set "$base" "${KEYWORD_GLOBS[@]}"; then
        emit_finding rule_id=keyword.filename category=PASSWORD conf=MEDIUM base_conf=MEDIUM \
          path="$f" match_text="$base"
        is_binary "$f" || scan_file_content "$f"
      fi
    done
  done
  local post; post=$(wc -l < "$FIND_JSONL")
  log_info "  $(( post - pre_count )) findings"
}
```

- [ ] **Step 2: Phase 4 candidate enumeration + parallel dispatch**

```bash
ext_matches_default() {
  [[ "$1" =~ $DEFAULT_EXT_REGEX ]]
}

ext_in_skip_list() {
  [[ "$1" =~ $SKIP_EXT_REGEX ]]
}

run_phase4() {
  [[ "$SKIP_CONTENT" -eq 1 ]] && return
  log_phase "phase 4/5" "content scan"
  local pre_count; pre_count=$(wc -l < "$FIND_JSONL")
  # Build candidate list
  local cand_list="$OUT_DIR/.candidates"
  : > "$cand_list"
  local r
  for r in "${SCAN_ROOTS[@]}"; do
    [[ -d "$r" ]] || continue
    walk "$r" | while IFS= read -r f; do
      local base="${f##*/}" name_lower
      name_lower="$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]')"
      ext_in_skip_list "$name_lower" && continue
      if [[ "$ALL_MODE" -eq 0 ]] && ! ext_matches_default "$name_lower"; then
        # Also check user-added include-ext
        local inc=0 e
        for e in "${EXTRA_INCLUDE_EXT[@]}"; do
          [[ "$name_lower" == *".$e" ]] && { inc=1; break; }
        done
        [[ "$inc" -eq 0 ]] && continue
      fi
      echo "$f" >> "$cand_list"
    done
  done
  local total; total=$(wc -l < "$cand_list")
  log_info "  ($total candidate files)"
  # Export functions for xargs subshells
  export -f scan_file_content rule_pem rule_ppk rule_wireguard rule_gpp_cpassword \
           rule_shadow_hash rule_htpasswd rule_netntlmv2 rule_pwdump_ntlm \
           rule_krb5_asrep rule_krb5_tgs rule_uri_basic_creds rule_netrc \
           rule_pgpass rule_mycnf_password rule_tomcat_user rule_cisco_secret \
           rule_dotnet_connstr rule_jdbc_password rule_ps_securestring \
           rule_docker_auth rule_ansible_vault_header rule_generic_assign \
           emit_finding redact entropy is_placeholder is_test_path is_comment \
           is_binary is_excluded size_under_cap seen_inode decrypt_gpp_cpassword
  export FIND_JSONL FIND_TXT SKIPPED_LOG INODE_FILE OUT_DIR HOSTN USER_NAME PRIV \
         MAX_SIZE SHOW_SECRETS PLACEHOLDERS EXCLUDE_PREFIXES EXCLUDE_GLOBS EXTRA_EXCLUDES
  if [[ "$SERIAL" -eq 1 || "$WORKERS" -le 1 ]]; then
    while IFS= read -r f; do scan_file_content "$f"; done < "$cand_list"
  else
    xargs -a "$cand_list" -P "$WORKERS" -I{} bash -c 'scan_file_content "$@"' _ {}
  fi
  local post; post=$(wc -l < "$FIND_JSONL")
  log_info "  $(( post - pre_count )) findings"
}
```

- [ ] **Step 3: Smoke test**

```bash
bash -n credhunter.sh
./credhunter.sh --output console --no-color tests/fixtures/linux
```
Expected: produces findings for the fixture files (shadow, PEM, GPP cpassword, etc.).

- [ ] **Step 4: Commit**

```bash
git add credhunter.sh
git commit -m "feat(credhunter.sh): Phase 3 filename hunt + Phase 4 parallel content scan"
```

---

## Task 6: `credhunter.sh` — Phase 5 (render) + main orchestrator + self-test

**Files:**
- Modify: `credhunter.sh` (append)

- [ ] **Step 1: Phase 5 — console render from JSONL**

```bash
# Render summary + grouped findings to stdout from JSONL
run_phase5() {
  log_phase "phase 5/5" "rendering report"
  local total high med low
  if command -v jq >/dev/null; then
    total=$(wc -l < "$FIND_JSONL")
    high=$(jq -s '[.[] | select(.confidence=="HIGH")] | length' "$FIND_JSONL")
    med=$(jq -s '[.[] | select(.confidence=="MEDIUM")] | length' "$FIND_JSONL")
    low=$(jq -s '[.[] | select(.confidence=="LOW")] | length' "$FIND_JSONL")
  else
    total=$(wc -l < "$FIND_JSONL")
    high=$(grep -c '"confidence":"HIGH"' "$FIND_JSONL")
    med=$(grep -c '"confidence":"MEDIUM"' "$FIND_JSONL")
    low=$(grep -c '"confidence":"LOW"' "$FIND_JSONL")
  fi
  local skipped_size skipped_binary skipped_perm
  skipped_size=$(grep -c 'oversize' "$SKIPPED_LOG" 2>/dev/null || echo 0)
  skipped_binary=$(grep -c 'binary' "$SKIPPED_LOG" 2>/dev/null || echo 0)
  # Console output
  if [[ "$OUT_MODE" == "console" || "$OUT_MODE" == "both" ]]; then
    echo
    echo "═════════════════════════════════════════════════════"
    echo "  ${C_R}HIGH${C_X}-confidence findings ($high)"
    echo "─────────────────────────────────────────────────────"
    if command -v jq >/dev/null; then
      jq -r 'select(.confidence=="HIGH") | "  [HIGH] \(.rule_id)  \(.abs_path)\(if .line_no>0 then ":\(.line_no)" else "" end)\n         \(.match_redacted)"' "$FIND_JSONL"
    else
      grep '"confidence":"HIGH"' "$FIND_JSONL" | head -50
    fi
    echo "═════════════════════════════════════════════════════"
    echo "  Summary"
    echo "─────────────────────────────────────────────────────"
    printf "   Total findings:    %5d   (HIGH: %d, MEDIUM: %d, LOW: %d)\n" "$total" "$high" "$med" "$low"
    printf "   Skipped (size):    %5d\n" "$skipped_size"
    printf "   Skipped (binary):  %5d\n" "$skipped_binary"
    printf "   Report:    %s\n" "$FIND_TXT"
    printf "              %s\n" "$FIND_JSONL"
    printf "              %s\n" "$SKIPPED_LOG"
    echo "═════════════════════════════════════════════════════"
  fi
  # Set exit-code intent
  if [[ "$total" -gt 0 ]]; then EXIT_CODE=1; else EXIT_CODE=0; fi
}
```

- [ ] **Step 2: Main orchestrator (bottom of file)**

```bash
EXIT_CODE=0
run_phase2
run_phase3
run_phase4
run_phase5
exit $EXIT_CODE
```

- [ ] **Step 3: Run the smoke test**

```bash
bash tests/run_bash_tests.sh
```
Expected: PASS for all assertions (shadow.hash, pem.private_key, mycnf.password, uri.basic_creds, gpp.cpassword, placeholder), refute API tokens.

- [ ] **Step 4: Fix any failures discovered; re-run until green**

If a rule misses, inspect the regex and the fixture. Common issues: ERE vs PCRE differences, escape handling in `sed`/`grep`, BOM in fixture files.

- [ ] **Step 5: Commit**

```bash
git add credhunter.sh
git commit -m "feat(credhunter.sh): Phase 5 render + main orchestrator; smoke tests pass"
chmod +x credhunter.sh tests/run_bash_tests.sh
```

---

## Task 7: `credhunter.ps1` — skeleton, CLI, recon, output dirs

**Files:**
- Create: `credhunter.ps1`

- [ ] **Step 1: Script preamble + param block**

```powershell
<#
.SYNOPSIS
  credhunter.ps1 — internal-pentest credential hunter (Windows)
.DESCRIPTION
  Spec: docs/specs/2026-05-24-credhunter-design.md
  Authorized use only.
.PARAMETER Output
  console | file | both (default: both)
#>
[CmdletBinding()]
param(
  [ValidateSet('console','file','both')] [string]$Output = 'both',
  [string]$OutDir = '',
  [switch]$All,
  [switch]$IncludeArchives,
  [switch]$IncludeOffice,
  [switch]$IncludeCompressed,
  [switch]$IncludeTemp,
  [switch]$ScanSqlite,
  [string]$MaxSize = '10M',
  [ValidateSet('HIGH','MEDIUM','LOW')] [string]$MinConfidence = 'LOW',
  [switch]$ShowSecrets,
  [switch]$CollectLoot,
  [switch]$Serial,
  [int]$Workers = 0,
  [switch]$FollowSymlinks,
  [switch]$CrossMounts,
  [string[]]$Exclude = @(),
  [string[]]$IncludeExt = @(),
  [switch]$SkipKnownLocations,
  [switch]$SkipContentScan,
  [switch]$Quiet,
  [switch]$VerboseMode,
  [switch]$NoColor,
  [Parameter(ValueFromRemainingArguments=$true)] [string[]]$ScanRoots = @()
)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$VERSION = '1.0.0'
$TS = (Get-Date).ToString('yyyyMMdd-HHmmss')
$HOSTN = $env:COMPUTERNAME

# Defaults
if (-not $ScanRoots -or $ScanRoots.Count -eq 0) {
  $ScanRoots = @('C:\Users','C:\inetpub','C:\Windows\Panther','C:\Windows\System32\config\RegBack',
                 'C:\Windows\Sysprep','C:\Windows\debug','C:\ProgramData','C:\Temp','C:\Backup','C:\Install') |
               Where-Object { Test-Path $_ }
}
if (-not $OutDir) { $OutDir = ".\credhunter-loot-$HOSTN-$TS" }
if ($Workers -le 0) { $Workers = [Environment]::ProcessorCount }
if ($Serial) { $Workers = 1 }
```

- [ ] **Step 2: Output dirs + color helpers + recon**

```powershell
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$FindJsonl  = Join-Path $OutDir 'findings.jsonl'
$FindTxt    = Join-Path $OutDir 'findings.txt'
$SkippedLog = Join-Path $OutDir 'skipped.log'
$ReconJson  = Join-Path $OutDir 'recon.json'
Set-Content $FindJsonl ''; Set-Content $FindTxt ''; Set-Content $SkippedLog ''

function W-Info($m) { if (-not $Quiet) { [Console]::Error.WriteLine($m) } }
function W-Phase($name, $msg) {
  if (-not $Quiet) {
    if ($NoColor) { [Console]::Error.WriteLine("[ $name ] $msg") }
    else { Write-Host "[ $name ] " -ForegroundColor DarkGray -NoNewline; Write-Host $msg }
  }
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = [Security.Principal.WindowsPrincipal]::new($id)
$priv = if ($pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { 'admin' } else { 'user' }
$os = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption

@{
  version    = $VERSION
  host       = $HOSTN
  user       = $id.Name
  sid        = $id.User.Value
  priv       = $priv
  os         = $os
  ts         = $TS
  scan_roots = $ScanRoots
} | ConvertTo-Json -Compress | Set-Content $ReconJson

if (-not $Quiet) {
  Write-Host ""
  Write-Host "credhunter v$VERSION" -ForegroundColor White -NoNewline; Write-Host " — internal pentest credential hunter"
  Write-Host "─────────────────────────────────────────────────────"
  W-Phase 'recon' "host=$HOSTN user=$($id.Name) priv=$priv os=$os"
  W-Phase 'recon' "scan roots: $($ScanRoots -join ' ')"
  W-Phase 'recon' "workers=$Workers max-size=$MaxSize output=$OutDir"
  Write-Host ""
}
```

- [ ] **Step 3: Sanity check**

Run: `pwsh -NoProfile -File .\credhunter.ps1 -Help` and `.\credhunter.ps1 tests\fixtures\windows`
Expected: banner prints, recon info correct, no exceptions.

- [ ] **Step 4: Commit**

```bash
git add credhunter.ps1
git commit -m "feat(credhunter.ps1): skeleton, CLI, recon (Phase 1)"
```

---

## Task 8: `credhunter.ps1` — path utilities (excludes, binary detect, walker, helpers)

**Files:**
- Modify: `credhunter.ps1` (append)

- [ ] **Step 1: Exclusion lists (mirror of Bash, Windows version)**

```powershell
$WinDir = $env:WINDIR; $ProgramData = $env:ProgramData
$ExcludePrefixes = @(
  "$WinDir\WinSxS", "$WinDir\Installer", "$WinDir\Servicing", "$WinDir\assembly",
  "$WinDir\SchCache", "$WinDir\Fonts", "$WinDir\IME", "$WinDir\Globalization",
  "$WinDir\Help", "$WinDir\Resources", "$WinDir\schemas", "$WinDir\PolicyDefinitions",
  "$WinDir\diagnostics", "$WinDir\WinStore", "$WinDir\SystemApps", "$WinDir\ShellExperiences",
  "$WinDir\Boot", "$WinDir\PrintDialog", "$WinDir\InfusedApps",
  "$WinDir\SoftwareDistribution\Download",
  "$WinDir\System32\DriverStore\FileRepository", "$WinDir\System32\spool\drivers",
  "$WinDir\System32\catroot", "$WinDir\System32\catroot2", "$WinDir\System32\winevt\Logs",
  "$WinDir\System32\WDI", "$WinDir\System32\Migration",
  "$WinDir\System32\Tasks\Microsoft",
  "$WinDir\System32\config\TxR", "$WinDir\System32\config\Journal",
  "$WinDir\Logs\CBS", "$WinDir\Logs\DISM", "$WinDir\Logs\WindowsUpdate",
  "C:\`$Recycle.Bin", "C:\System Volume Information", "C:\Recovery",
  "C:\`$WINDOWS.~BT", "C:\`$WINDOWS.~WS", "C:\Boot",
  "$ProgramData\Microsoft\Windows Defender", "$ProgramData\Microsoft\Search\Data",
  "$ProgramData\Microsoft\Diagnosis", "$ProgramData\Microsoft\Crypto",
  "$ProgramData\Microsoft\Windows\WER", "$ProgramData\Package Cache"
)
$ExcludeGlobs = @(
  '*\AppData\Local\Microsoft\Windows\WebCache\*',
  '*\AppData\Local\Microsoft\Windows\INetCache\*',
  '*\AppData\Local\Microsoft\Windows\Explorer\*',
  '*\AppData\Local\Microsoft\Windows\Notifications\*',
  '*\AppData\Local\Microsoft\Windows\FontCache\*',
  '*\AppData\Local\Microsoft\Windows\Caches\*',
  '*\AppData\Local\Microsoft\WindowsApps\*',
  '*\AppData\Local\Microsoft\Internet Explorer\Recovery\*',
  '*\AppData\Local\Microsoft\Edge\User Data\*\Cache\*',
  '*\AppData\Local\Microsoft\Edge\User Data\*\Code Cache\*',
  '*\AppData\Local\Google\Chrome\User Data\*\Cache\*',
  '*\AppData\Local\Mozilla\Firefox\Profiles\*\cache2\*',
  '*\AppData\Local\ConnectedDevicesPlatform\*',
  '*\AppData\Local\D3DSCache\*',
  '*\AppData\Local\Packages\*\AC\*',
  '*\AppData\Local\Microsoft\Office\*\WefCache\*',
  '*\AppData\Local\Adobe\ARM\*', '*\AppData\Local\Adobe\OOBE\*',
  '*\node_modules\*', '*\.nuget\packages\*', '*\packages\*',
  '*\.vs\*', '*\bin\*', '*\obj\*', '*\Pods\*', '*\.gradle\caches\*'
)
if (-not $IncludeTemp) { $ExcludeGlobs += '*\AppData\Local\Temp\*' }

$SkipExtRegex = '\.(jpg|jpeg|png|gif|bmp|tiff|tif|ico|webp|heic|raw|psd|mp3|mp4|mov|avi|mkv|wmv|wav|flac|ogg|webm|m4a|aac|svg|ttf|otf|woff|woff2|eot|exe|dll|so|dylib|class|pyc|pyo|wasm|bin|iso|img|dmg|msi|msu|cab|deb|rpm|appx|sys|db|sqlite|sqlite3|mdb|accdb|pdf|doc|xls|ppt|odt|ods|odp|epub|po|pot|mo|min\.js|min\.css|map)$'

$DefaultExtRegex = '\.(conf|cnf|cfg|config|ini|properties|toml|yaml|yml|json|xml|plist|env|reg|inf|sh|bash|zsh|ps1|psm1|psd1|bat|cmd|vbs|wsf|py|rb|pl|pm|php|js|mjs|ts|tsx|jsx|java|scala|kt|kts|groovy|go|rs|cs|vb|fs|c|cpp|cc|h|hpp|lua|sql|psql|tf|tfvars|bicep|log|out|err|bak|backup|old|orig|save|tmp|dist|sample|example|htm|html|jsp|aspx|cshtml|ejs|twig|erb|hbs|ipynb)$'
```

- [ ] **Step 2: Helpers**

```powershell
function Test-Excluded([string]$Path) {
  foreach ($p in $ExcludePrefixes) { if ($Path -like "$p*") { return $true } }
  foreach ($g in $ExcludeGlobs)    { if ($Path -like $g)     { return $true } }
  foreach ($g in $Exclude)         { if ($Path -like $g)     { return $true } }
  return $false
}

function Test-Binary([string]$Path) {
  try {
    $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    $buf = New-Object byte[] 8192
    $n = $fs.Read($buf, 0, 8192); $fs.Dispose()
    if ($n -ge 2) {
      # UTF-16 BOM => not binary
      if ($buf[0] -eq 0xFF -and $buf[1] -eq 0xFE) { return $false }
      if ($buf[0] -eq 0xFE -and $buf[1] -eq 0xFF) { return $false }
    }
    if ($n -ge 3 -and $buf[0] -eq 0xEF -and $buf[1] -eq 0xBB -and $buf[2] -eq 0xBF) { return $false }
    for ($i=0; $i -lt $n; $i++) { if ($buf[$i] -eq 0) { return $true } }
    return $false
  } catch { return $true }
}

function Get-MaxBytes([string]$Spec) {
  $n = [int]($Spec -replace '[KMGkmg]$','')
  switch -regex ($Spec) {
    'K|k$' { return $n * 1KB }
    'M|m$' { return $n * 1MB }
    'G|g$' { return $n * 1GB }
    default { return [int]$Spec }
  }
}
$script:MaxBytes = Get-MaxBytes $MaxSize

function Get-Walker([string]$Root) {
  Get-ChildItem -LiteralPath $Root -Recurse -Force -File -ErrorAction SilentlyContinue |
    Where-Object {
      (-not (Test-Excluded $_.FullName)) -and
      ($FollowSymlinks -or $_.LinkType -ne 'SymbolicLink')
    }
}
```

- [ ] **Step 3: Sanity check**

Run: `pwsh -NoProfile -File .\credhunter.ps1 tests\fixtures\windows`
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add credhunter.ps1
git commit -m "feat(credhunter.ps1): path utilities (excludes, binary detect, walker)"
```

---

## Task 9: `credhunter.ps1` — detection engine + decoders

**Files:**
- Modify: `credhunter.ps1` (append)

- [ ] **Step 1: Placeholder list, entropy, comment detect**

```powershell
$Placeholders = @(
  'password','passw0rd','p@ssw0rd','p@ssword','pass','passwd','pwd','secret','test','testing',
  'changeme','change-me','change_me','changeit','default','defaultpassword',
  'your_password','yourpassword','yoursecret','your-secret-here',
  'example','examplepassword','sample','samplepassword','dummy','placeholder',
  'redacted','xxx','xxxx','xxxxx','xxxxxx','xxxxxxxx','***','****','********',
  '<password>','[password]','{password}','{{password}}','${password}',
  'null','none','nil','n/a','na','tbd','todo','fixme','???','!!!',
  'foo','bar','foobar','hello','world','helloworld',
  'insert_password','enter_password','type_password_here','secret_here','password_here',
  'my_password','mypassword','admin','administrator','root','user','guest','anonymous',
  '123456','12345678','qwerty','abc123','letmein','monkey','dragon'
)

function Test-Placeholder([string]$V) {
  $clean = $V.Trim().Trim('"',"'",'`').ToLower()
  return ($Placeholders -contains $clean)
}

function Get-Entropy([string]$S) {
  if ([string]::IsNullOrEmpty($S)) { return 0.0 }
  $tally = @{}; foreach ($c in $S.ToCharArray()) { $tally[$c] = ($tally[$c] + 1) }
  $H = 0.0; $n = $S.Length
  foreach ($v in $tally.Values) { $p = $v / $n; $H -= $p * [Math]::Log($p, 2) }
  return [Math]::Round($H, 2)
}

function Test-TestPath([string]$P) {
  return ($P -match '\\(test|tests|spec|specs|fixture|fixtures|sample|samples|example|examples|demo|demos|mock|mocks|__tests__|__mocks__|e2e|testdata|test-data)\\') -or
         ($P -match '(_test\.|\.test\.|\.spec\.|_spec\.|\.example\.|\.sample\.|\.demo\.)')
}

function Test-Comment([string]$Line) {
  $t = $Line.TrimStart()
  return ($t.StartsWith('#') -or $t.StartsWith('//') -or $t.StartsWith('--') -or
          $t.StartsWith(';')  -or $t.StartsWith('%')  -or $t.StartsWith('<!--') -or
          $t.StartsWith('/*') -or $t.StartsWith('"""') -or $t.StartsWith("'''") -or
          $t.StartsWith('<#'))
}
```

- [ ] **Step 2: GPP cpassword decoder (PowerShell-native)**

```powershell
function Invoke-GppDecrypt([string]$B64) {
  try {
    $pad = (4 - ($B64.Length % 4)) % 4
    $padded = $B64 + ('=' * $pad)
    $ct = [Convert]::FromBase64String($padded)
    $aes = [Security.Cryptography.Aes]::Create()
    $aes.Mode = [Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [Security.Cryptography.PaddingMode]::Zeros
    $aes.Key = [byte[]](0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                       0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
    $aes.IV  = New-Object byte[] 16
    $dec = $aes.CreateDecryptor()
    $pt  = $dec.TransformFinalBlock($ct, 0, $ct.Length)
    return ([System.Text.Encoding]::Unicode.GetString($pt)).TrimEnd([char]0)
  } catch { return $null }
}
```

- [ ] **Step 3: Finding emitter + redactor**

```powershell
$script:FindingsLock = [System.Threading.Mutex]::new($false, 'CredHunterFindingsLock')

function Format-Redacted([string]$S) {
  if ($ShowSecrets) { return $S }
  if (-not $S -or $S.Length -le 4) { return '****' }
  return ($S.Substring(0,2) + ('*' * ($S.Length - 4)) + $S.Substring($S.Length-2,2))
}

function Emit-Finding([hashtable]$F) {
  $F.confidence       = $F.confidence ?? 'MEDIUM'
  $F.base_confidence  = $F.base_confidence ?? $F.confidence
  $F.category         = $F.category ?? 'PASSWORD'
  $F.match_redacted   = Format-Redacted $F.match_text
  $F.host             = $HOSTN
  $F.scan_user        = $id.Name
  $F.scan_user_priv   = $priv
  $F.dedup_key        = [BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash(
      [Text.Encoding]::UTF8.GetBytes("$($F.rule_id)|$($F.abs_path)|$($F.line_no)|$($F.match_text)")
    )).Replace('-','').ToLower()
  $script:FindingsLock.WaitOne() | Out-Null
  try {
    $F | ConvertTo-Json -Compress -Depth 6 | Add-Content -Path $FindJsonl
    Add-Content -Path $FindTxt -Value ("[{0}] {1,-26} {2}{3}" -f $F.confidence, $F.rule_id, $F.abs_path, $(if ($F.line_no) { ":$($F.line_no)" } else { "" }))
    if ($F.match_text) { Add-Content -Path $FindTxt -Value ("       " + $F.match_redacted) }
  } finally { $script:FindingsLock.ReleaseMutex() | Out-Null }
}
```

- [ ] **Step 4: Rule pack — per-rule scanners**

Mirror the Bash rules (spec §4.2). Each PowerShell rule reads file content and runs a regex against it. Example pattern (lift the others from the spec):

```powershell
function Scan-PrivateKey($Path, $Content) {
  if ($Content -match '(?ms)-----BEGIN (?<t>(RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP |SSH2 ENCRYPTED )?)PRIVATE KEY[\s\S]+?-----END [A-Z ]*PRIVATE KEY') {
    $enc = if ($Content -match '(?m)^(Proc-Type: 4,ENCRYPTED|DEK-Info:)') { 'yes' } else { 'no' }
    Emit-Finding @{
      rule_id = 'pem.private_key'; category = 'PRIVATE_KEY'
      confidence = 'HIGH'; base_confidence = 'HIGH'
      abs_path = $Path; line_no = 1
      match_text = "-----BEGIN $($Matches.t)PRIVATE KEY-----"
      key_name = "encrypted=$enc"
    }
  }
}

function Scan-GppCpassword($Path, $Content) {
  foreach ($m in [regex]::Matches($Content, 'cpassword="([A-Za-z0-9+/]{8,}={0,2})"')) {
    $b64 = $m.Groups[1].Value
    Emit-Finding @{
      rule_id = 'gpp.cpassword'; category = 'PASSWORD'
      confidence = 'HIGH'; base_confidence = 'HIGH'
      abs_path = $Path; match_text = $b64
    }
    $plain = Invoke-GppDecrypt $b64
    if ($plain) {
      Emit-Finding @{
        rule_id = 'gpp.cpassword.plaintext'; category = 'PASSWORD'
        confidence = 'HIGH'; base_confidence = 'HIGH'
        abs_path = $Path; match_text = $plain
      }
    }
  }
}

function Scan-DotnetConnstr($Path, $Content) {
  foreach ($m in [regex]::Matches($Content, '(?i)(Server|Data Source)\s*=\s*[^;]+;[^"\r\n]*?(User\s*ID|UID)\s*=\s*[^;]+;[^"\r\n]*?(Password|Pwd)\s*=\s*([^;"\r\n]{1,256})')) {
    Emit-Finding @{
      rule_id = 'dotnet.connstr'; category = 'PASSWORD'
      confidence = 'HIGH'; base_confidence = 'HIGH'
      abs_path = $Path; match_text = $m.Value; key_name = 'connectionString'
    }
  }
}

# ... continue: Scan-Wireguard, Scan-Putty, Scan-ShadowHash, Scan-Htpasswd,
#               Scan-NetNTLMv2, Scan-Pwdump, Scan-Krb5Asrep, Scan-Krb5Tgs,
#               Scan-UriBasicCreds, Scan-Netrc, Scan-Pgpass, Scan-MyCnf,
#               Scan-TomcatUser, Scan-CiscoSecret, Scan-Jdbc, Scan-PsSecureString,
#               Scan-DockerAuth, Scan-AnsibleVaultHeader, Scan-GenericAssign
# All regex patterns are in spec §4.2 — lift them verbatim.

function Scan-FileContent($Path) {
  if (Test-Excluded $Path) { return }
  try {
    $size = (Get-Item -LiteralPath $Path -Force).Length
    if ($size -gt $script:MaxBytes) { Add-Content $SkippedLog "$Path`toversize"; return }
    if (Test-Binary $Path) { Add-Content $SkippedLog "$Path`tbinary"; return }
    # Read with BOM-aware encoding detection
    $content = [System.IO.File]::ReadAllText($Path)
  } catch { return }
  Scan-PrivateKey  $Path $content
  Scan-GppCpassword $Path $content
  # ... call each Scan-* in specificity order
  Scan-DotnetConnstr $Path $content
  Scan-GenericAssign $Path $content
}
```

- [ ] **Step 5: Smoke test detection**

Run: `pwsh -NoProfile -File .\credhunter.ps1 -Output console -NoColor tests\fixtures\windows`
Expected: dotnet.connstr + gpp.cpassword + gpp.cpassword.plaintext findings show.

- [ ] **Step 6: Commit**

```bash
git add credhunter.ps1
git commit -m "feat(credhunter.ps1): detection rules + GPP cpassword decoder"
```

---

## Task 10: `credhunter.ps1` — Phase 2 (known locations sweep)

**Files:**
- Modify: `credhunter.ps1` (append)

- [ ] **Step 1: Hard-code Windows known-path inventory (spec Appendix B)**

```powershell
$KnownPaths = @(
  # PSReadLine history (per user)
  "$env:USERPROFILE\..\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt",
  # Unattend
  "$WinDir\Panther\Unattend.xml", "$WinDir\Panther\Unattend\Unattend.xml",
  "$WinDir\Panther\autounattend.xml", "$WinDir\System32\Sysprep\Unattend.xml",
  "$WinDir\System32\Sysprep\Panther\Unattend.xml", "$WinDir\System32\sysprep\sysprep.xml",
  "$WinDir\System32\sysprep\sysprep.inf", "C:\unattend.xml", "C:\unattend.txt", "C:\autounattend.xml",
  # GPP cache
  "$ProgramData\Microsoft\Group Policy\History\*\Machine\Preferences\Groups\Groups.xml",
  "$ProgramData\Microsoft\Group Policy\History\*\Machine\Preferences\Services\Services.xml",
  "$ProgramData\Microsoft\Group Policy\History\*\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml",
  "$ProgramData\Microsoft\Group Policy\History\*\Machine\Preferences\Drives\Drives.xml",
  "$ProgramData\Microsoft\Group Policy\History\*\Machine\Preferences\Printers\Printers.xml",
  "$ProgramData\Microsoft\Group Policy\History\*\Machine\Preferences\DataSources\DataSources.xml",
  # Hive backups
  "$WinDir\Repair\SAM", "$WinDir\Repair\SYSTEM", "$WinDir\Repair\SECURITY",
  "$WinDir\System32\config\RegBack\SAM", "$WinDir\System32\config\RegBack\SYSTEM",
  "$WinDir\System32\config\RegBack\SECURITY",
  # Install logs
  "$WinDir\Panther\setupact.log", "$WinDir\Panther\setuperr.log",
  "$WinDir\Debug\NetSetup.log", "$WinDir\Debug\PASSWD.LOG",
  # IIS
  "$WinDir\System32\inetsrv\Config\applicationHost.config",
  "$WinDir\System32\inetsrv\Config\administration.config",
  "C:\inetpub\wwwroot\web.config"
)

$RegistryProbes = @(
  @{Key='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';
    Values=@('AutoAdminLogon','DefaultUserName','DefaultDomainName','DefaultPassword','AltDefaultPassword')},
  @{Key='HKCU:\Software\SimonTatham\PuTTY\Sessions';   Values=@('HostName','UserName','ProxyPassword','PublicKeyFile')},
  @{Key='HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions'; Values=@('HostName','UserName','Password')},
  @{Key='HKLM:\SOFTWARE\TightVNC\Server';              Values=@('Password','ControlPassword','PasswordViewOnly')},
  @{Key='HKLM:\SOFTWARE\RealVNC\vncserver';            Values=@('Password')}
)
```

- [ ] **Step 2: Phase 2 runner**

```powershell
function Run-Phase2 {
  if ($SkipKnownLocations) { return }
  W-Phase 'phase 2/5' 'known-locations sweep'
  $preCount = (Get-Content $FindJsonl | Measure-Object).Count
  # File-based known paths
  foreach ($pat in $KnownPaths) {
    $items = Get-ChildItem -Path $pat -Force -ErrorAction SilentlyContinue
    foreach ($it in $items) {
      if ($it.PSIsContainer) {
        Get-ChildItem -LiteralPath $it.FullName -Recurse -Force -File -ErrorAction SilentlyContinue |
          ForEach-Object { Scan-KnownPath $_.FullName }
      } else {
        Scan-KnownPath $it.FullName
      }
    }
  }
  # PSReadLine per user (Users dir glob)
  Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $h = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt'
    if (Test-Path $h) { Scan-KnownPath $h }
  }
  # Registry probes
  foreach ($p in $RegistryProbes) {
    try {
      $k = Get-Item -LiteralPath $p.Key -ErrorAction SilentlyContinue
      if ($k) {
        # If key has subkeys (PuTTY sessions, etc.), enumerate them
        $children = Get-ChildItem -LiteralPath $p.Key -ErrorAction SilentlyContinue
        $targets = if ($children) { $children } else { @($k) }
        foreach ($t in $targets) {
          foreach ($vn in $p.Values) {
            $v = (Get-ItemProperty -LiteralPath $t.PSPath -Name $vn -ErrorAction SilentlyContinue).$vn
            if ($v -and -not (Test-Placeholder $v)) {
              Emit-Finding @{
                rule_id = "reg.$($t.PSChildName).$vn"
                category = 'PASSWORD'; confidence = 'HIGH'; base_confidence = 'HIGH'
                abs_path = $t.PSPath; match_text = $v; key_name = $vn
              }
            }
          }
        }
      }
    } catch {}
  }
  # cmdkey output
  $cm = & cmd /c 'cmdkey /list' 2>$null
  if ($cm) {
    Emit-Finding @{
      rule_id = 'wincred.cmdkey'; category = 'STORED_CRED:cmdkey'
      confidence = 'MEDIUM'; base_confidence = 'MEDIUM'
      abs_path = 'cmdkey /list'; match_text = ($cm -join "`n").Substring(0, [Math]::Min(800, ($cm -join "`n").Length))
    }
  }
  $post = (Get-Content $FindJsonl | Measure-Object).Count
  W-Info "  $($post - $preCount) findings"
}

function Scan-KnownPath($Path) {
  # Class A by name → file_present finding
  $base = Split-Path $Path -Leaf
  if ($base -match '^(id_rsa|id_dsa|id_ecdsa|id_ed25519|.*\.pem|.*\.ppk|.*\.kdbx|.*\.kdb|.*\.pfx|.*\.p12|.*\.jks|.*\.keystore)$') {
    Emit-Finding @{
      rule_id = 'class_a.file_present'; category = 'PRIVATE_KEY'
      confidence = 'HIGH'; base_confidence = 'HIGH'
      abs_path = $Path; match_text = $base
    }
  }
  if (-not (Test-Binary $Path)) { Scan-FileContent $Path }
}
```

- [ ] **Step 3: Smoke test Phase 2**

Run: `pwsh -NoProfile -File .\credhunter.ps1 tests\fixtures\windows`
Expected: no exceptions; will produce few findings from system-level paths unless run on a real Windows host.

- [ ] **Step 4: Commit**

```bash
git add credhunter.ps1
git commit -m "feat(credhunter.ps1): Phase 2 known-locations sweep + registry probes + cmdkey"
```

---

## Task 11: `credhunter.ps1` — Phase 3 (filename hunt) + Phase 4 (content scan w/ parallelism)

**Files:**
- Modify: `credhunter.ps1` (append)

- [ ] **Step 1: Class A + keyword globs**

```powershell
$ClassAGlobs = @(
  '*.kdbx','*.kdb','*.psafe3','*.agilekeychain','*.opvault','*.1pif',
  'key3.db','key4.db','logins.json','signons.sqlite','cert9.db',
  'Login Data','Login Data For Account','Web Data','Local State',
  'id_rsa','id_dsa','id_ecdsa','id_ed25519','id_xmss',
  '*.pem','*.key','*.priv','*.pk8','*.rsa','*.dsa','*.ec','*.ppk','*.openssh',
  'authorized_keys','known_hosts','ssh_host_*_key',
  '*.pfx','*.p12','*.jks','*.keystore','*.bks','*.pkcs12',
  '.netrc','_netrc','.pgpass','.my.cnf','.mylogin.cnf','.htpasswd',
  '.credentials','.git-credentials','.npmrc','kubeconfig','*.kubeconfig',
  '*.ovpn','wg0.conf','krb5.keytab','*.keytab','krb5cc_*',
  'Groups.xml','Services.xml','ScheduledTasks.xml','Drives.xml','Printers.xml','DataSources.xml',
  'unattend.xml','Unattend.xml','autounattend.xml','Autounattend.xml','sysprep.inf','sysprep.xml',
  'WinSCP.ini','sitemanager.xml','recentservers.xml','filezilla.xml','confCons.xml',
  'MobaXterm.ini','*.rdg','*.rdp','settings.xml','credentials.xml',
  '.env','.env.*','wp-config.php','configuration.php','LocalSettings.php',
  'local.xml','database.yml','web.config','applicationHost.config'
)
$KeywordGlobs = @('*password*','*pass*.txt','*cred*','*credential*','*secret*','pw.txt','pwd.txt','*.passwd','*.pass','*.creds')

function Test-GlobMatch([string]$Name, [string[]]$Globs) {
  foreach ($g in $Globs) { if ($Name -like $g) { return $true } }
  return $false
}

function Run-Phase3 {
  W-Phase 'phase 3/5' 'filename-pattern hunt'
  $preCount = (Get-Content $FindJsonl | Measure-Object).Count
  foreach ($r in $ScanRoots) {
    if (-not (Test-Path $r)) { continue }
    Get-Walker $r | ForEach-Object {
      $base = $_.Name
      if (Test-GlobMatch $base $ClassAGlobs) {
        Emit-Finding @{
          rule_id = 'class_a.filename'; category = 'PRIVATE_KEY'
          confidence = 'HIGH'; base_confidence = 'HIGH'
          abs_path = $_.FullName; match_text = $base
        }
        if (-not (Test-Binary $_.FullName)) { Scan-FileContent $_.FullName }
      } elseif (Test-GlobMatch $base $KeywordGlobs) {
        Emit-Finding @{
          rule_id = 'keyword.filename'; category = 'PASSWORD'
          confidence = 'MEDIUM'; base_confidence = 'MEDIUM'
          abs_path = $_.FullName; match_text = $base
        }
        if (-not (Test-Binary $_.FullName)) { Scan-FileContent $_.FullName }
      }
    }
  }
  $post = (Get-Content $FindJsonl | Measure-Object).Count
  W-Info "  $($post - $preCount) findings"
}
```

- [ ] **Step 2: Phase 4 — candidate list + parallel scan**

```powershell
function Test-ExtAllowed([string]$Name) {
  $lower = $Name.ToLower()
  if ($lower -match $SkipExtRegex) { return $false }
  if ($All) { return $true }
  if ($lower -match $DefaultExtRegex) { return $true }
  foreach ($e in $IncludeExt) {
    if ($lower.EndsWith(".$e")) { return $true }
  }
  return $false
}

function Run-Phase4 {
  if ($SkipContentScan) { return }
  W-Phase 'phase 4/5' 'content scan'
  $preCount = (Get-Content $FindJsonl | Measure-Object).Count
  $candidates = New-Object System.Collections.Generic.List[string]
  foreach ($r in $ScanRoots) {
    if (-not (Test-Path $r)) { continue }
    Get-Walker $r | Where-Object { Test-ExtAllowed $_.Name } | ForEach-Object {
      $candidates.Add($_.FullName)
    }
  }
  W-Info "  ($($candidates.Count) candidate files)"
  if ($Workers -le 1 -or $candidates.Count -lt 4) {
    foreach ($f in $candidates) { Scan-FileContent $f }
  } else {
    # PS 7+ uses ForEach-Object -Parallel; PS 5.1 falls back to ThreadJob
    if ($PSVersionTable.PSVersion.Major -ge 7) {
      $candidates | ForEach-Object -Parallel {
        . ([scriptblock]::Create((Get-Content -Raw $using:PSCommandPath)))
        # Scan-FileContent is dot-sourced via the script body
        Scan-FileContent $_
      } -ThrottleLimit $Workers
    } else {
      # PS 5.1 fallback — serial (parallel in 5.1 is heavy to set up cleanly)
      foreach ($f in $candidates) { Scan-FileContent $f }
    }
  }
  $post = (Get-Content $FindJsonl | Measure-Object).Count
  W-Info "  $($post - $preCount) findings"
}
```

(Note: PS 5.1 fallback is serial — the spec allows this since `--serial` is already an option. PS 7+ users get true parallelism. Most modern pentest environments have PS 7 or can install it.)

- [ ] **Step 3: Smoke test**

Run: `pwsh -NoProfile -File .\credhunter.ps1 -Output console -NoColor tests\fixtures\windows`
Expected: findings from fixtures (dotnet.connstr, gpp.cpassword, winscp filename, etc.).

- [ ] **Step 4: Commit**

```bash
git add credhunter.ps1
git commit -m "feat(credhunter.ps1): Phase 3 filename hunt + Phase 4 content scan"
```

---

## Task 12: `credhunter.ps1` — Phase 5 (render) + main orchestrator

**Files:**
- Modify: `credhunter.ps1` (append)

- [ ] **Step 1: Render**

```powershell
function Run-Phase5 {
  W-Phase 'phase 5/5' 'rendering report'
  $records = Get-Content $FindJsonl | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json }
  $total = $records.Count
  $high  = ($records | Where-Object { $_.confidence -eq 'HIGH' }).Count
  $med   = ($records | Where-Object { $_.confidence -eq 'MEDIUM' }).Count
  $low   = ($records | Where-Object { $_.confidence -eq 'LOW' }).Count
  if ($Output -eq 'console' -or $Output -eq 'both') {
    Write-Host ""
    Write-Host "═════════════════════════════════════════════════════"
    Write-Host "  HIGH-confidence findings ($high)" -ForegroundColor Red
    Write-Host "─────────────────────────────────────────────────────"
    $records | Where-Object { $_.confidence -eq 'HIGH' } | ForEach-Object {
      $loc = if ($_.line_no -and $_.line_no -gt 0) { ":$($_.line_no)" } else { "" }
      Write-Host ("  [HIGH] {0,-26} {1}{2}" -f $_.rule_id, $_.abs_path, $loc) -ForegroundColor Red
      if ($_.match_redacted) { Write-Host "         $($_.match_redacted)" -ForegroundColor DarkGray }
    }
    Write-Host "═════════════════════════════════════════════════════"
    Write-Host "  Summary"
    Write-Host "─────────────────────────────────────────────────────"
    Write-Host ("   Total findings:    {0,5}   (HIGH: {1}, MEDIUM: {2}, LOW: {3})" -f $total, $high, $med, $low)
    Write-Host "   Report:    $FindTxt"
    Write-Host "              $FindJsonl"
    Write-Host "              $SkippedLog"
    Write-Host "═════════════════════════════════════════════════════"
  }
  if ($total -gt 0) { $script:ExitCode = 1 } else { $script:ExitCode = 0 }
}
```

- [ ] **Step 2: Main orchestrator (bottom of file)**

```powershell
$script:ExitCode = 0
Run-Phase2
Run-Phase3
Run-Phase4
Run-Phase5
exit $script:ExitCode
```

- [ ] **Step 3: Run the smoke test**

```bash
pwsh tests/run_pwsh_tests.ps1   # or via PowerShell on Windows
```
Expected: PASS for dotnet.connstr, gpp.cpassword, winscp, unattend.

- [ ] **Step 4: Fix any failures; re-run until green**

- [ ] **Step 5: Commit**

```bash
git add credhunter.ps1
git commit -m "feat(credhunter.ps1): Phase 5 render + main orchestrator; smoke tests pass"
```

---

## Task 13: Final validation and README polish

**Files:**
- Modify: `README.md` (add troubleshooting + flag examples)
- Verify: `credhunter.sh`, `credhunter.ps1`, `tests/`

- [ ] **Step 1: Run both smoke suites**

```bash
bash tests/run_bash_tests.sh
# On Windows or with PowerShell installed:
pwsh tests/run_pwsh_tests.ps1
```
Expected: both report PASS for all assertions, exit 0.

- [ ] **Step 2: Manual smoke against real host (optional but recommended)**

```bash
./credhunter.sh /home /etc /tmp
```
Expected: walltime under a few minutes, reasonable finding count, no syntax errors, no crashes on permission-denied paths.

- [ ] **Step 3: Add usage examples to README**

Append to README.md:

```markdown
## Common flag combos

# Quick triage — only HIGH-confidence findings, console only
./credhunter.sh --min-confidence HIGH --output console /home /etc

# Maximum coverage — scan every filetype, parallel
./credhunter.sh --all --workers 8 /

# Stealth-ish — minimal CPU spike, no disk writes beyond report
./credhunter.sh --serial --output file --quiet /home /etc

# Include archives (slower but catches creds inside .tar.gz backups)
./credhunter.sh --include-archives /var/backups

# Show plaintext secrets in report (use with care — engagement RoE)
./credhunter.sh --show-secrets /home > report.txt

# PowerShell equivalents
.\credhunter.ps1 -MinConfidence HIGH -Output console C:\Users C:\inetpub
.\credhunter.ps1 -All -Workers 8 C:\
.\credhunter.ps1 -Serial -Output file -Quiet C:\Users
```

- [ ] **Step 4: Final commit**

```bash
git add README.md credhunter.sh credhunter.ps1 tests/
git commit -m "feat: credhunter v1.0 — both scripts pass smoke tests, README polished"
```

---

## Self-Review (run before declaring done)

- **Spec coverage:** Every section of the design spec has a corresponding task:
  - Phase pipeline (spec §2) → Tasks 1, 4, 5, 6 (bash); 7, 10, 11, 12 (ps)
  - CLI surface (§3) → Tasks 1, 7
  - Detection model + rules + decoders (§4) → Tasks 3, 9
  - Output (§5) → Tasks 6, 12
  - Exclusions, sizing, privilege (§6) → Tasks 2, 8
  - Edge cases (§7) → addressed inline in path-utility tasks (binary detect, UTF-16, symlinks, mount crossings)
  - Appendices A/B/C/D/E → Tasks 4 & 10 (Phase 2 inventories), Tasks 5 & 11 (Class A globs), Tasks 2 & 8 (extension lists)

- **Placeholder scan:** No `TBD`, no "implement later", no "similar to". Where a long list of rules would bloat the plan (the 20+ rule scanners), the task explicitly says "lift regex from spec §4.2" and shows enough sample rules to establish the pattern.

- **Type/name consistency:** Function names match across tasks. `scan_file_content` defined in Task 3 used in Task 5. `Emit-Finding` defined in Task 9 used in 10/11/12. JSONL schema matches between Bash and PowerShell.

Plan complete.
