#!/usr/bin/env bash
# ============================================================================
#  credshunter.sh — Credential discovery for authorized Linux post-exploitation
# ----------------------------------------------------------------------------
#  Hunts hard-coded passwords, private keys, NTLM hashes, database creds,
#  cloud secrets, and other reusable authentication material in known OS
#  locations and within user-supplied paths.
#
#  Read-only. Never modifies the system. Never sends data anywhere.
#  Intended for authorized penetration testing, red team engagements, CTFs,
#  and privilege escalation labs.
#
#  Requires: bash 4+, find, grep, awk, sed, stat. Optional: file.
#  Tested on: Debian/Ubuntu, RHEL/CentOS/Rocky/Alma, Arch, Alpine.
# ============================================================================

set -uo pipefail
shopt -s nocasematch 2>/dev/null || true

VERSION="1.0.0"

# ----------------------------------------------------------------------------
#  Defaults
# ----------------------------------------------------------------------------
MAX_FILE_SIZE_MB=5      # default cap; files larger than this are skipped
SKIP_LARGE=1            # 1 = honor MAX_FILE_SIZE_MB, 0 = scan files of any size
JOBS=4
ALL_MODE=0
QUIET=0
SKIP_SYSTEM=0
NO_COLOR_FLAG=0
SCAN_PATHS=()
OUTPUT_FILE=""
MAX_MATCHES_PER_FILE=20
MAX_PREVIEW_LEN=140

# ----------------------------------------------------------------------------
#  Temp workspace
# ----------------------------------------------------------------------------
TMPDIR="$(mktemp -d -t credshunter.XXXXXX 2>/dev/null || mktemp -d /tmp/credshunter.XXXXXX)"
HIGH_FILE="$TMPDIR/high.tsv"
LOW_FILE="$TMPDIR/low.tsv"
KEY_FILE="$TMPDIR/keys.tsv"
NAME_FILE="$TMPDIR/names.tsv"
INTEREST_FILE="$TMPDIR/interest.tsv"
GUARANTEED_FILE="$TMPDIR/guaranteed.tsv"
SKIPPED_FILE="$TMPDIR/skipped.tsv"
CHECKED_FILE="$TMPDIR/checked.tsv"
CANDIDATE_FILES="$TMPDIR/candidates.lst"
touch "$HIGH_FILE" "$LOW_FILE" "$KEY_FILE" "$NAME_FILE" \
      "$INTEREST_FILE" "$GUARANTEED_FILE" "$SKIPPED_FILE" \
      "$CHECKED_FILE" "$CANDIDATE_FILES"

# Path dedup set (associative array). Each file gets scanned at most once
# regardless of which stage encountered it.
declare -A SCANNED_PATHS

# ----------------------------------------------------------------------------
#  Signal handling — Ctrl+C / SIGTERM exits immediately, kills children.
# ----------------------------------------------------------------------------
cleanup() {
    rm -rf "$TMPDIR" 2>/dev/null
}

_on_interrupt() {
    # Disable further traps to avoid re-entry
    trap '' INT TERM HUP EXIT
    # Restore cursor / clear progress bar line
    [ -t 2 ] && printf '\r%80s\r' '' >&2
    printf '\n%b[!] Interrupted by user. Stopping…%b\n' "${R:-}" "${NC:-}" >&2
    # Terminate every child this script has spawned (find / grep / xargs / etc.)
    # Use both pkill -P (POSIX) and explicit job kill so it works whether or
    # not job-control was enabled in the parent shell.
    if command -v pkill >/dev/null 2>&1; then
        pkill -TERM -P $$ 2>/dev/null
        # give them ~100ms, then SIGKILL anything still alive
        ( sleep 0.1; pkill -KILL -P $$ 2>/dev/null ) &
    else
        # Fallback: enumerate via /proc
        for pid in $(awk -v p=$$ '$4==p{print $1}' /proc/[0-9]*/stat 2>/dev/null); do
            kill -TERM "$pid" 2>/dev/null
        done
    fi
    # Kill background jobs we own
    for j in $(jobs -p 2>/dev/null); do
        kill -TERM "$j" 2>/dev/null
    done
    cleanup
    exit 130
}
trap _on_interrupt INT TERM HUP
trap cleanup EXIT

# ----------------------------------------------------------------------------
#  Colors (auto-detect, honor NO_COLOR)
# ----------------------------------------------------------------------------
setup_colors() {
    if [ "$NO_COLOR_FLAG" -eq 1 ] || [ -n "${NO_COLOR:-}" ] || [ ! -t 2 ]; then
        R='' G='' Y='' B='' M='' C='' W='' D='' BOLD='' NC=''
    else
        R=$'\033[1;31m'; G=$'\033[1;32m'; Y=$'\033[1;33m'
        B=$'\033[1;34m'; M=$'\033[1;35m'; C=$'\033[1;36m'
        W=$'\033[1;37m'; D=$'\033[2m';    BOLD=$'\033[1m'
        NC=$'\033[0m'
    fi
}

# ----------------------------------------------------------------------------
#  Output helpers
# ----------------------------------------------------------------------------
say()     { printf '%b\n' "$*" >&2; }
info()    { [ "$QUIET" -eq 0 ] && printf '%b[*]%b %b\n' "$B" "$NC" "$*" >&2; }
ok()      { [ "$QUIET" -eq 0 ] && printf '%b[+]%b %b\n' "$G" "$NC" "$*" >&2; }
warn()    { printf '%b[!]%b %b\n' "$Y" "$NC" "$*" >&2; }
err()     { printf '%b[x]%b %b\n' "$R" "$NC" "$*" >&2; }
section() { printf '\n%b═══ %s ═══%b\n' "${BOLD}${C}" "$*" "$NC" >&2; }

log_line() {
    # Strip ANSI before writing to file
    if [ -n "$OUTPUT_FILE" ]; then
        printf '%s\n' "$(printf '%s' "$*" | sed 's/\x1b\[[0-9;]*m//g')" >>"$OUTPUT_FILE"
    fi
}

# ----------------------------------------------------------------------------
#  Banner & help
# ----------------------------------------------------------------------------
print_banner() {
    [ "$QUIET" -eq 1 ] && return
    cat >&2 <<EOF

${C}${BOLD}  ┌─────────────────────────────────────────────────────────────┐
  │  credshunter  ·  Linux credential discovery for pentesters  │
  │  v${VERSION}  ·  ${D}authorized testing only · read-only${NC}${C}${BOLD}              │
  └─────────────────────────────────────────────────────────────┘${NC}

EOF
}

usage() {
    cat <<'EOF'
Usage: credshunter.sh [OPTIONS] -p PATH [-p PATH ...]

Hunt for credentials, passwords, keys, hashes, and tokens in well-known
system locations and within user-supplied directory trees.

Options:
  -p, --path PATH        Path to scan recursively. Repeat for multiple paths.
                         File-content scanning is limited to these paths.
  -a, --all              Scan all readable text files in PATH, not only
                         credential-related extensions.
  -m, --max-size N       Skip files larger than N MB (default: 5). Applies to
                         both the OS-level extraction and stage-4 content scan.
      --no-size-limit    Disable the file-size cap entirely (scan files of any
                         size). Use with caution — large logs/archives can be
                         slow and full of binary data.
  -j, --jobs N           Parallel grep workers for content scanning (default: 4).
  -o, --output FILE      Append a plaintext log of all findings to FILE.
  -s, --skip-system      Skip common OS-level credential checks.
  -q, --quiet            Less verbose output (still shows findings).
      --no-color         Disable ANSI colors.
  -h, --help             Show this help and exit.
  -V, --version          Show version and exit.

Examples:
  sudo ./credshunter.sh -p / -m 10
  ./credshunter.sh -p /home -p /opt -p /var/www
  ./credshunter.sh -a -p /etc -o /tmp/findings.txt
  ./credshunter.sh --skip-system -p . -j 8

This tool only reads files. It does not modify the host or transmit data.
Run only against systems where you have explicit written authorization.
EOF
}

# ----------------------------------------------------------------------------
#  Argument parsing
# ----------------------------------------------------------------------------
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -p|--path)        SCAN_PATHS+=("$2"); shift 2 ;;
            -a|--all)         ALL_MODE=1; shift ;;
            -m|--max-size)    MAX_FILE_SIZE_MB="$2"; SKIP_LARGE=1; shift 2 ;;
            --no-size-limit)  SKIP_LARGE=0; shift ;;
            -j|--jobs)        JOBS="$2"; shift 2 ;;
            -o|--output)      OUTPUT_FILE="$2"; shift 2 ;;
            -s|--skip-system) SKIP_SYSTEM=1; shift ;;
            -q|--quiet)       QUIET=1; shift ;;
            --no-color)       NO_COLOR_FLAG=1; shift ;;
            -h|--help)        usage; exit 0 ;;
            -V|--version)     echo "credshunter $VERSION"; exit 0 ;;
            --)               shift; while [ $# -gt 0 ]; do SCAN_PATHS+=("$1"); shift; done ;;
            -*)               err "Unknown option: $1"; usage; exit 2 ;;
            *)                SCAN_PATHS+=("$1"); shift ;;
        esac
    done

    if [ -n "$OUTPUT_FILE" ]; then
        : >"$OUTPUT_FILE" || { err "Cannot write to $OUTPUT_FILE"; exit 2; }
    fi
    [[ "$MAX_FILE_SIZE_MB" =~ ^[0-9]+$ ]] || { err "max-size must be a number"; exit 2; }
    [[ "$JOBS" =~ ^[0-9]+$ ]] || { err "jobs must be a number"; exit 2; }
    [ "$JOBS" -lt 1 ] && JOBS=1
}

# ============================================================================
#  Pattern & data definitions
# ============================================================================

# Focused pattern set used ONLY by OS-level checks (stage 1). A precise subset
# of the generic stage-4 patterns, tuned for the formats commonly found in
# OS-known credential locations (GPP XML, unattend, .env, .bashrc, .htpasswd,
# shadow, netrc, wp-config, registry dumps, etc.). Stage 4 uses HIGH_PATTERNS
# below — they overlap, but kept separate so OS checks stay independent of
# the recursive content-scan pipeline.
OS_PATTERNS=(
    'password|(^|[^A-Za-z_])(password|passwd|pwd|pass|passphrase)[[:space:]]*[:=][[:space:]]*[^[:space:]#].{2,}'
    'db_password|(db|database|mysql|psql|pg|postgres|mongo|mssql|sql|oracle|redis|memcache|ldap|smb|smtp|ftp|sftp|admin|user|service)[_-]?(password|passwd|pwd|pass)[[:space:]]*[:=]'
    'url_credentials|(mysql|postgres(ql)?|mongodb(\+srv)?|redis|ftp|ftps|sftp|ssh|smb|cifs|https?|amqp|rabbitmq)://[^[:space:]/:@]+:[^[:space:]/@]+@'
    'connection_string|(server|host|data[ _-]?source)[[:space:]]*=.*(password|pwd)[[:space:]]*='
    'gpp_cpassword|cpassword[[:space:]]*=[[:space:]]*"?[A-Za-z0-9+/=]{20,}'
    'unattend_password|<(Administrator)?Password>[[:space:]]*<Value>'
    'aws_access_key|AKIA[0-9A-Z]{16}'
    'github_token|gh[pousr]_[A-Za-z0-9]{30,}'
    'slack_token|xox[abprs]-[A-Za-z0-9-]{10,}'
    'env_credential|^[[:space:]]*[A-Z][A-Z0-9_]*(PASSWORD|PASS|PWD|SECRET|TOKEN|API_KEY|APIKEY)[A-Z0-9_]*[[:space:]]*='
    'export_credential|export[[:space:]]+[A-Z][A-Z0-9_]*(PASSWORD|PASS|PWD|SECRET|TOKEN|API_KEY|APIKEY)[A-Z0-9_]*[[:space:]]*='
    'htpasswd_entry|^[^:[:space:]#]+:\$(apr1|2[aby]?|5|6|y)\$'
    'netrc_pass|^[[:space:]]*(machine[[:space:]]+\S+[[:space:]]+)?(login|user|username)[[:space:]]+\S+[[:space:]]+password[[:space:]]+'
    'wp_db_define|define\([[:space:]]*['"'"'"](DB_PASSWORD|DB_USER|AUTH_KEY|SECURE_AUTH_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT)['"'"'"]'
    'shadow_hash|^[^:]+:\$(1|2[aby]?|5|6|y)\$[A-Za-z0-9./$]+'
    'ntlm_dump|^[^:]+:[0-9]+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:::'
    'sudoers_nopasswd|NOPASSWD[[:space:]]*[:=]'
    'jwt|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}'
)

# High-confidence content patterns (ERE). Each entry: "LABEL|REGEX".
# These look for explicit credential assignments or well-known token shapes.
HIGH_PATTERNS=(
    # Generic password assignment variants
    'password|(^|[^A-Za-z_])(password|passwd|pwd|pass|passphrase)[[:space:]]*[:=][[:space:]]*[^[:space:]#].{2,}'
    # Database-style password keys
    'db_password|(db|database|mysql|psql|pg|postgres|mongo|mssql|sql|oracle|redis|memcache|ldap|smb|smtp|ftp|sftp|admin|user|service)[_-]?(password|passwd|pwd|pass)[[:space:]]*[:=]'
    # Connection strings
    'connection_string|(server|host|data[ _-]?source)[[:space:]]*=.*(password|pwd)[[:space:]]*='
    'url_credentials|(mysql|postgres(ql)?|mongodb(\+srv)?|redis|ftp|ftps|sftp|ssh|smb|cifs|https?|amqp|rabbitmq)://[^[:space:]/:@]+:[^[:space:]/@]+@'
    # GPP cpassword (Group Policy Preferences – left here in case Linux-mounted SYSVOL is found)
    'gpp_cpassword|cpassword[[:space:]]*=[[:space:]]*"?[A-Za-z0-9+/=]{20,}'
    # AWS
    'aws_access_key|AKIA[0-9A-Z]{16}'
    'aws_secret|aws_secret_access_key[[:space:]]*[:=][[:space:]]*['"'"'"]?[A-Za-z0-9/+=]{40}'
    # GCP / GitHub / Slack / generic bearer tokens
    'gcp_key|"type":[[:space:]]*"service_account"'
    'github_token|gh[pousr]_[A-Za-z0-9]{30,}'
    'slack_token|xox[abprs]-[A-Za-z0-9-]{10,}'
    'slack_webhook|https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'
    'bearer_token|[Bb]earer[[:space:]]+[A-Za-z0-9._~+/=-]{20,}'
    # Tokens / API secrets that often grant lateral access
    'api_secret|(api|auth|access|refresh|client|app)[_-]?(secret|token|key)[[:space:]]*[:=][[:space:]]*['"'"'"]?[A-Za-z0-9._/+=~-]{16,}'
    # JWT
    'jwt|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}'
    # SMB / NetBIOS share creds
    'smb_creds|(username|user|domain)[[:space:]]*=.*[\r\n]+[[:space:]]*(password|passwd)[[:space:]]*='
)

# Private-key / authentication-material markers (always high value)
KEY_PATTERNS=(
    'rsa_private|-----BEGIN RSA PRIVATE KEY-----'
    'dsa_private|-----BEGIN DSA PRIVATE KEY-----'
    'ec_private|-----BEGIN EC PRIVATE KEY-----'
    'openssh_private|-----BEGIN OPENSSH PRIVATE KEY-----'
    'pkcs8_private|-----BEGIN PRIVATE KEY-----'
    'encrypted_private|-----BEGIN ENCRYPTED PRIVATE KEY-----'
    'pgp_private|-----BEGIN PGP PRIVATE KEY BLOCK-----'
    'putty_private|PuTTY-User-Key-File-'
    'ssh2_private|---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----'
)

# Hash / ticket patterns (NTLM, shadow, kerberos, JtR/hashcat formats)
HASH_PATTERNS=(
    'ntlm_dump|^[^:]+:[0-9]+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:::'
    'shadow_sha512|\$6\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{40,}'
    'shadow_sha256|\$5\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{40,}'
    'shadow_yescrypt|\$y\$[A-Za-z0-9./]{1,}\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+'
    'shadow_md5|\$1\$[A-Za-z0-9./]{1,8}\$[A-Za-z0-9./]{22}'
    'bcrypt|\$2[aby]?\$[0-9]{2}\$[A-Za-z0-9./]{53}'
    'krb5_tgs|\$krb5tgs\$'
    'krb5_asrep|\$krb5asrep\$'
    'mscash|\$DCC2\$'
    'mscash_v1|M\$[A-Za-z0-9._-]+#[a-f0-9]{32}'
)

# Low-confidence patterns (often noisy, separated for review)
LOW_PATTERNS=(
    'generic_token|(token|secret|key)[[:space:]]*[:=][[:space:]]*['"'"'"]?[A-Za-z0-9._/+=~-]{12,}'
    'generic_hash|\b[A-Fa-f0-9]{32}\b'
)

# Values that almost always indicate a placeholder, not a real credential
# (lowercased for case-insensitive comparison)
FALSE_POSITIVE_EXACT=(
    "" " " "''" '""'
    password passwd pwd pass passphrase secret token
    null none nil undefined empty void
    example sample demo placeholder dummy fake
    test tester testing testpassword testpass test123
    foo bar baz qux foobar
    changeme change_me change-me changethis change-this changeit change-it
    todo fixme tbd "n/a" na
    your_password yourpassword your-password yourpasswordhere
    insert_password replace_me replace-me replace_this insert_here
    "<password>" "<pass>" "<secret>" "<token>" "<key>" "<value>" "<your-password>"
    "..." "...." "....." "********" "*****" "***" xxxxxxxx xxxxx xxx
)

# Suspicious-name fragments — case-insensitive substring match against the
# basename. Kept INTENTIONALLY TIGHT: every term here must be a strong
# credential indicator on its own. Generic words ("config", "key", "conn",
# "backup", "account", "login", "auth") are excluded because:
#   1. They produce massive false-positive noise on real hosts (every .conf
#      file, every keyring/keyboard binary, every login log line, etc.)
#   2. Any text file with credentials in it will already be picked up by
#      the stage-4 content scanner via its extension.
# The OS-level checks separately handle well-known credential files such as
# /etc/shadow, /etc/sudoers, .htpasswd, .pgpass, ~/.netrc, ~/.my.cnf, so
# we don't need name-based detection for those either.
SUSPICIOUS_NAMES=(
    # Direct, high-signal credential terms
    password passwords passwd pswd
    credential credentials creds
    secret secrets
    vault vaults
    authentication authenticator
    passphrase

    # DB / master / SSH password specifics
    dbpass db_pass database_password
    masterkey master_password masterpass
    sshpass

    # Credential dump tool outputs
    pwdump kerberoast asreproast hashdump

    # KeePass / password-manager artefacts that may show up without
    # the typical .kdbx extension (renamed, base-named, etc.)
    keepass
)

# Extensions whose presence ALONE confirms credential material.
# These are dedicated credential / password-database / keystore formats —
# finding one means you've found credentials, full stop. Reported in their
# own "Confirmed credential containers" section ahead of the auxiliary list.
GUARANTEED_CRED_EXTS=(
    # Password manager databases (every byte is encrypted secrets)
    kdbx kdb              # KeePass 2.x / 1.x
    psafe3                # Password Safe v3
    agilekeychain         # 1Password legacy bundle
    opvault               # 1Password vault
    1pif 1pux             # 1Password exports (plaintext!)
    lpdb                  # LastPass local DB
    enpass enpassdb       # Enpass DB
    bitwarden_export      # Bitwarden export

    # Private-key / cert+key bundles — never public
    ppk                   # PuTTY private key
    pfx p12               # PKCS#12 (cert + private key)
    pvk                   # Microsoft private key file

    # Server keystores (alias + private key inside)
    jks keystore truststore

    # Disk-encryption key files
    bek                   # BitLocker external recovery key
    fve                   # BitLocker FVE file

    # Kerberos keytabs (always contain key material / hashes)
    keytab

    # Windows DPAPI master keys
    dpapimk
)

# Auxiliary credential-related extensions. STRONG signal but not 100% — a
# .pem may be a public cert, a .gpg may be encrypted data rather than a
# private key, a .rdp may not have the password saved, etc. Reported under
# "Interesting credential-related files" — worth inspecting, not assumed.
HIGH_VALUE_EXTS=(
    pem key priv          # PEM-encoded data (private key OR public cert)
    asc gpg               # PGP material (signature, key, or encrypted blob)
    rdp                   # Saved RDP session — may or may not carry creds
    ovpn                  # OpenVPN profile — often inline keys but not always
    wallet                # Oracle wallet / various
)

# Default content-search extensions
SEARCH_EXTS=(
    conf config cfg ini env envrc
    yaml yml toml json xml properties
    txt log md
    sh bash zsh ksh fish profile bashrc zshrc
    py pl rb php js ts jsx tsx mjs cjs
    sql sqlite db
    aspx asp ashx ascx cshtml vbhtml
    cs vb java go rs c cpp h hpp
    ps1 psm1 bat cmd vbs
    htm html htaccess
    tf tfvars hcl
    service unit timer socket
    crontab cron
    dockerfile compose
)

# Directory *names* to never descend into (matched anywhere in the tree).
# Tuned to skip places that almost never contain meaningful credentials.
EXCLUDE_DIR_NAMES=(
    # Version control internals
    .git .hg .svn .bzr CVS _darcs
    # Package manager caches / language ecosystems
    node_modules .npm .pnpm-store .yarn .yarn-cache .bun
    .venv venv env .pyenv .virtualenvs __pycache__
    .mypy_cache .pytest_cache .tox .nox .ruff_cache
    site-packages dist-packages
    vendor bower_components
    .terraform .terragrunt-cache
    .gradle .m2 .ivy2 .sbt
    # Build outputs
    target dist build out coverage .next .nuxt
    # Caches
    .cache .ccache .npm-cache .composer
    # IDE metadata
    .idea .vscode .vs .history
    # OS metadata / desktop artifacts
    .Trash .Spotlight-V100 .fseventsd .DocumentRevisions-V100
    # Windows-side-by-side mount under Linux
    WinSxS
)

# Absolute *paths* to never descend into. These cover kernel/runtime pseudo-fs,
# package metadata, system binaries, build artifacts, container layer storage,
# log dirs, and other locations that aren't typical credential hiding spots.
EXCLUDE_PATHS=(
    # Kernel / runtime pseudo-filesystems
    /proc /sys /dev /run /run/user /run/lock
    # Bootloader / recovery
    /boot /lost+found
    # Snapd / Flatpak
    /snap /var/lib/snapd /var/lib/flatpak
    # System libraries / shared data — system-owned, no user creds
    /usr/share /usr/lib /usr/lib32 /usr/lib64 /usr/libexec
    /usr/include /usr/src
    /lib /lib32 /lib64 /libexec
    # Package metadata caches
    /var/cache /var/lib/dpkg /var/lib/rpm /var/lib/apt /var/lib/yum
    # Container runtime caches
    /var/lib/docker/overlay2 /var/lib/docker/aufs /var/lib/docker/btrfs
    /var/lib/docker/devicemapper /var/lib/docker/zfs /var/lib/docker/tmp
    /var/lib/docker/buildkit /var/lib/docker/image
    /var/lib/containerd /var/lib/buildah
    # Log files (logs sometimes leak creds but are extremely noisy; opt-in via -p /var/log)
    /var/log
    # X11 / IPC sockets
    /tmp/.X11-unix /tmp/.ICE-unix /tmp/.font-unix
)

# ============================================================================
#  Helper functions
# ============================================================================

# Portable file size in bytes
file_size() {
    stat -c '%s' "$1" 2>/dev/null \
        || stat -f '%z' "$1" 2>/dev/null \
        || wc -c <"$1" 2>/dev/null \
        || echo 0
}

# Fast binary detection: grep -I treats binary files as having no text match.
# Empty files are also reported as binary (we want to skip them).
is_binary() {
    ! LC_ALL=C grep -Iq . "$1" 2>/dev/null
}

# True if value looks like a placeholder rather than a real credential.
is_false_positive() {
    local v="$1"
    # Trim leading/trailing whitespace and surrounding quotes/parens/angles
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    v="${v#\"}"; v="${v%\"}"
    v="${v#\'}"; v="${v%\'}"

    local len=${#v}
    [ "$len" -lt 4 ] && return 0
    [ "$len" -gt 256 ] && return 0

    local lower="${v,,}"

    # Exact placeholder words
    local fp
    for fp in "${FALSE_POSITIVE_EXACT[@]}"; do
        [ "$lower" = "$fp" ] && return 0
    done

    # Suffixes that mark template variables
    case "$lower" in
        *_password|*_secret|*_token|*_key|*_pass|*_pwd) return 0 ;;
        your_*|insert_*|replace_*|example_*|sample_*|test_*) return 0 ;;
    esac

    # Variable interpolation / template markers
    case "$v" in
        *'${'*|*'$('*|*'%('*|*'{{'*|*'<%'*|*'%>'*|*'#{'*) return 0 ;;
        *'<'*'>'*) return 0 ;;
        *'$1'*|*'$2'*|*'$3'*|*'$$'*) return 0 ;;
        *'%'[A-Z_]*'%'*) return 0 ;;
    esac

    # All same char (e.g. ****, xxxx)
    if [ "$len" -ge 3 ] && [[ "$v" =~ ^(.)\1+$ ]]; then
        return 0
    fi

    # Only non-alphanumeric punctuation
    if [[ "$v" =~ ^[^A-Za-z0-9]+$ ]]; then
        return 0
    fi

    return 1
}

# Truncate and visually defang a value for safe display
sanitize() {
    local v="$1"
    # Strip CR/LF, collapse runs of whitespace
    v="${v//$'\r'/}"
    v="${v//$'\n'/ }"
    v="$(printf '%s' "$v" | tr -s '[:space:]' ' ')"
    # Trim
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    # Truncate
    if [ "${#v}" -gt "$MAX_PREVIEW_LEN" ]; then
        v="${v:0:$MAX_PREVIEW_LEN}…"
    fi
    printf '%s' "$v"
}

# Record a finding line (deduped at output time).
record_finding() {
    # Args: BUCKET LABEL FILE LINE PREVIEW
    local bucket="$1" label="$2" file="$3" line="$4" preview="$5"
    case "$bucket" in
        HIGH) printf '%s\t%s\t%s\t%s\n' "$label" "$file" "$line" "$preview" >>"$HIGH_FILE" ;;
        LOW)  printf '%s\t%s\t%s\t%s\n' "$label" "$file" "$line" "$preview" >>"$LOW_FILE" ;;
        KEY)  printf '%s\t%s\t%s\t%s\n' "$label" "$file" "$line" "$preview" >>"$KEY_FILE" ;;
    esac
}

record_interest()    { printf '%s\t%s\n' "$1" "$2" >>"$INTEREST_FILE"; }
record_name()        { printf '%s\n' "$1" >>"$NAME_FILE"; }
record_skip()        { printf '%s\t%s\n' "$1" "$2" >>"$SKIPPED_FILE"; }
record_checked()     { printf '%s\t%s\n' "$1" "$2" >>"$CHECKED_FILE"; }
record_guaranteed()  { printf '%s\t%s\n' "$1" "$2" >>"$GUARANTEED_FILE"; }

# ----------------------------------------------------------------------------
#  Progress bar (cross-distro: pure printf, no tput)
# ----------------------------------------------------------------------------
PROGRESS_LAST=0
draw_progress() {
    [ "$QUIET" -eq 1 ] && return
    [ ! -t 2 ] && return
    local current=$1 total=$2 label=${3:-Scanning}
    [ "$total" -le 0 ] && return

    # Throttle redraws
    local step=1
    [ "$total" -gt 200 ]   && step=$((total / 100))
    [ "$total" -gt 2000 ]  && step=$((total / 200))
    [ "$total" -gt 20000 ] && step=$((total / 500))
    [ "$step" -lt 1 ] && step=1
    if [ "$current" -ne 0 ] && [ "$current" -ne "$total" ]; then
        [ $((current - PROGRESS_LAST)) -lt "$step" ] && return
    fi
    PROGRESS_LAST=$current

    local width=30
    local percent=$((current * 100 / total))
    local filled=$((current * width / total))
    [ "$filled" -gt "$width" ] && filled=$width

    local bar=""
    local i
    for ((i=0; i<filled; i++)); do bar+="#"; done
    for ((i=filled; i<width; i++)); do bar+="-"; done

    printf '\r%b%s%b [%s] %3d%% (%d/%d)   ' \
        "$C" "$label" "$NC" "$bar" "$percent" "$current" "$total" >&2
}

end_progress() {
    [ "$QUIET" -eq 1 ] && return
    [ ! -t 2 ] && return
    printf '\r%-80s\r' '' >&2
    PROGRESS_LAST=0
}

# ============================================================================
#  Content scanning core
# ============================================================================

# OS-level credential extraction. Applies the focused OS_PATTERNS set plus
# private-key markers to a known credential-bearing file.
#
# Used by stage-1 OS checks ONLY. Stage-4 file-content scanning uses
# scan_file_contents below — the two are intentionally separate so that the
# recursive content-scan pipeline only processes extension-matched candidates
# from the user-supplied paths.
#
# Args: $1 = file path, $2 = label (e.g. "shell_history", "iis_webconfig")
os_extract() {
    local file="$1" label="$2"
    [ -f "$file" ] || return
    [ -r "$file" ] || { record_skip "$file" "unreadable"; return; }

    # Dedup: each file is processed at most once across all stages.
    local canon
    canon=$(readlink -f -- "$file" 2>/dev/null || printf '%s' "$file")
    [ -n "${SCANNED_PATHS["$canon"]:-}" ] && return
    SCANNED_PATHS["$canon"]=1

    local sz; sz=$(file_size "$file")
    [ "$sz" -le 0 ] && return
    if [ "$SKIP_LARGE" -eq 1 ] && [ "$sz" -gt $((MAX_FILE_SIZE_MB * 1024 * 1024)) ]; then
        record_skip "$file" "size>${MAX_FILE_SIZE_MB}MB"; return
    fi
    if is_binary "$file"; then
        record_skip "$file" "binary"; return
    fi

    local entry plabel regex match lineno content value matches_found=0

    # Private-key markers (always meaningful in any OS file)
    for entry in "${KEY_PATTERNS[@]}"; do
        plabel="${entry%%|*}"; regex="${entry#*|}"
        if LC_ALL=C grep -qE -- "$regex" "$file" 2>/dev/null; then
            match=$(LC_ALL=C grep -nE -- "$regex" "$file" 2>/dev/null | head -n1)
            record_finding KEY "$plabel" "$file" "${match%%:*}" "$(sanitize "${match#*:}")"
        fi
    done

    # Focused OS credential patterns
    for entry in "${OS_PATTERNS[@]}"; do
        plabel="${entry%%|*}"; regex="${entry#*|}"
        while IFS= read -r match || [ -n "$match" ]; do
            [ "$matches_found" -ge "$MAX_MATCHES_PER_FILE" ] && return
            lineno="${match%%:*}"
            content="${match#*:}"
            value="$content"
            if [[ "$content" =~ [[:space:]]*([^[:space:]=:]+)[[:space:]]*[:=][[:space:]]*(.+)$ ]]; then
                value="${BASH_REMATCH[2]}"
                value="${value%%#*}"
                value="${value%%;*}"
            fi
            is_false_positive "$value" && continue
            record_finding HIGH "${label}/${plabel}" "$file" "$lineno" "$(sanitize "$content")"
            matches_found=$((matches_found + 1))
        done < <(LC_ALL=C grep -niE -- "$regex" "$file" 2>/dev/null | head -n "$MAX_MATCHES_PER_FILE")
    done
}

# Scan one file with all pattern categories. Findings are appended to
# the per-bucket TSVs. Designed to be safe against permission/encoding errors.
# Each path is scanned at most once across the whole tool — SCANNED_PATHS
# acts as a guard so OS-known files aren't re-scanned in stage 4.
scan_file_contents() {
    local file="$1"

    # Resolve to canonical path so /etc/passwd and ./etc/passwd dedup correctly.
    local canon
    canon=$(readlink -f -- "$file" 2>/dev/null || printf '%s' "$file")
    [ -n "${SCANNED_PATHS["$canon"]:-}" ] && return
    SCANNED_PATHS["$canon"]=1

    # Size check
    local sz
    sz=$(file_size "$file")
    if [ "$SKIP_LARGE" -eq 1 ] && [ "$sz" -gt $((MAX_FILE_SIZE_MB * 1024 * 1024)) ]; then
        record_skip "$file" "size>${MAX_FILE_SIZE_MB}MB"
        return
    fi
    if [ "$sz" -le 0 ]; then
        return
    fi

    # Binary check
    if is_binary "$file"; then
        record_skip "$file" "binary"
        return
    fi

    # Permission check (try a 1-byte read)
    if ! head -c 1 "$file" >/dev/null 2>&1; then
        record_skip "$file" "unreadable"
        return
    fi

    local entry label regex matches_found=0

    # High-confidence patterns
    for entry in "${HIGH_PATTERNS[@]}"; do
        label="${entry%%|*}"
        regex="${entry#*|}"
        while IFS= read -r match || [ -n "$match" ]; do
            local lineno content
            lineno="${match%%:*}"
            content="${match#*:}"
            # Pull the right-hand value if there's a key=val shape
            local value="$content"
            if [[ "$content" =~ [[:space:]]*([^[:space:]=:]+)[[:space:]]*[:=][[:space:]]*(.+)$ ]]; then
                value="${BASH_REMATCH[2]}"
                # Strip trailing comments / quotes
                value="${value%%#*}"
                value="${value%%;*}"
            fi
            if is_false_positive "$value"; then
                continue
            fi
            record_finding HIGH "$label" "$file" "$lineno" "$(sanitize "$content")"
            matches_found=$((matches_found + 1))
            [ "$matches_found" -ge "$MAX_MATCHES_PER_FILE" ] && return
        done < <(LC_ALL=C grep -niE -- "$regex" "$file" 2>/dev/null | head -n "$MAX_MATCHES_PER_FILE")
    done

    # Private key / auth material markers
    for entry in "${KEY_PATTERNS[@]}"; do
        label="${entry%%|*}"
        regex="${entry#*|}"
        if LC_ALL=C grep -qE -- "$regex" "$file" 2>/dev/null; then
            local line_with_match
            line_with_match=$(LC_ALL=C grep -nE -- "$regex" "$file" 2>/dev/null | head -n1)
            record_finding KEY "$label" "$file" "${line_with_match%%:*}" "$(sanitize "${line_with_match#*:}")"
        fi
    done

    # Hashes / tickets
    for entry in "${HASH_PATTERNS[@]}"; do
        label="${entry%%|*}"
        regex="${entry#*|}"
        while IFS= read -r match || [ -n "$match" ]; do
            local lineno="${match%%:*}"
            local content="${match#*:}"
            record_finding HIGH "$label" "$file" "$lineno" "$(sanitize "$content")"
            matches_found=$((matches_found + 1))
            [ "$matches_found" -ge "$MAX_MATCHES_PER_FILE" ] && return
        done < <(LC_ALL=C grep -nE -- "$regex" "$file" 2>/dev/null | head -n "$MAX_MATCHES_PER_FILE")
    done

    # Low-confidence (only if no high-conf hits, to keep noise down)
    if [ "$matches_found" -eq 0 ]; then
        for entry in "${LOW_PATTERNS[@]}"; do
            label="${entry%%|*}"
            regex="${entry#*|}"
            while IFS= read -r match || [ -n "$match" ]; do
                local lineno="${match%%:*}"
                local content="${match#*:}"
                local value="$content"
                if [[ "$content" =~ [[:space:]]*([^[:space:]=:]+)[[:space:]]*[:=][[:space:]]*(.+)$ ]]; then
                    value="${BASH_REMATCH[2]}"
                fi
                is_false_positive "$value" && continue
                record_finding LOW "$label" "$file" "$lineno" "$(sanitize "$content")"
                matches_found=$((matches_found + 1))
                [ "$matches_found" -ge "$MAX_MATCHES_PER_FILE" ] && return
            done < <(LC_ALL=C grep -niE -- "$regex" "$file" 2>/dev/null | head -n "$MAX_MATCHES_PER_FILE")
        done
    fi
}

# ============================================================================
#  OS-level credential checks
# ============================================================================

# Inspect a small/known file directly. Records the check and runs the
# focused OS extraction (NOT the generic stage-4 content scanner).
check_known_file() {
    local file="$1" label="$2"
    [ -e "$file" ] || return
    record_checked "$label" "$file"
    if [ ! -r "$file" ]; then
        record_skip "$file" "unreadable"
        return
    fi
    os_extract "$file" "$label"
}

check_shell_histories() {
    info "Checking shell history files…"
    local f histfiles=(
        /root/.bash_history /root/.zsh_history /root/.sh_history
        /root/.ash_history  /root/.history    /root/.lesshst
        /root/.mysql_history /root/.psql_history /root/.sqlite_history
        /root/.python_history /root/.node_repl_history /root/.rediscli_history
    )
    while IFS= read -r -d '' f; do histfiles+=("$f"); done < <(
        find /home -maxdepth 3 \( \
            -name '.bash_history' -o -name '.zsh_history' -o -name '.sh_history' \
            -o -name '.ash_history' -o -name '.history' -o -name '.lesshst' \
            -o -name '.mysql_history' -o -name '.psql_history' \
            -o -name '.sqlite_history' -o -name '.python_history' \
            -o -name '.node_repl_history' -o -name '.rediscli_history' \
            -o -name '.viminfo' \) -type f -print0 2>/dev/null)
    for f in "${histfiles[@]}"; do
        check_known_file "$f" "shell_history"
    done
}

check_ssh() {
    info "Checking SSH keys, configs and authorized hosts…"
    local f
    # User SSH dirs (root + /home)
    local sshdirs=(/root/.ssh)
    while IFS= read -r -d '' f; do sshdirs+=("$f"); done < <(
        find /home -maxdepth 3 -type d -name .ssh -print0 2>/dev/null)

    for d in "${sshdirs[@]}"; do
        [ -d "$d" ] || continue
        while IFS= read -r -d '' f; do
            record_checked "ssh" "$f"
            case "$(basename "$f")" in
                id_*|*.pem|*.key|identity)
                    if [ -r "$f" ] && LC_ALL=C grep -qE 'PRIVATE KEY|PuTTY-User-Key' "$f" 2>/dev/null; then
                        record_finding KEY "ssh_private_key" "$f" 1 "private key in $f"
                    fi
                    ;;
                config|authorized_keys|known_hosts)
                    os_extract "$f" "ssh_config"
                    ;;
            esac
        done < <(find "$d" -maxdepth 2 -type f -print0 2>/dev/null)
    done

    # Host keys & sshd config
    local sysfiles=(/etc/ssh/sshd_config /etc/ssh/ssh_config)
    for f in "${sysfiles[@]}"; do
        [ -e "$f" ] && os_extract "$f" "sshd_config"
    done
    while IFS= read -r -d '' f; do
        record_checked "ssh_host_key" "$f"
    done < <(find /etc/ssh -maxdepth 1 -name 'ssh_host_*_key' -type f -print0 2>/dev/null)
}

check_environment_files() {
    info "Checking environment / profile files…"
    local f files=(
        /etc/environment /etc/profile /etc/bashrc /etc/bash.bashrc
        /etc/zshrc /etc/zsh/zshrc /etc/zsh/zprofile /etc/csh.cshrc
    )
    for f in "${files[@]}"; do
        [ -e "$f" ] && os_extract "$f" "system_env"
    done

    while IFS= read -r -d '' f; do
        os_extract "$f" "profile_d"
    done < <(find /etc/profile.d -maxdepth 1 -type f -print0 2>/dev/null)

    while IFS= read -r -d '' f; do
        os_extract "$f" "user_shell_rc"
    done < <(find /root /home -maxdepth 3 -type f \( \
        -name '.bashrc' -o -name '.bash_profile' -o -name '.bash_login' \
        -o -name '.bash_logout' -o -name '.profile' -o -name '.zshrc' \
        -o -name '.zprofile' -o -name '.zlogin' -o -name '.envrc' \
        -o -name '.env' -o -name '.env.local' -o -name '.env.*' \) \
        -print0 2>/dev/null)
}

check_cron() {
    info "Checking cron jobs and scheduled tasks…"
    local f files=( /etc/crontab /etc/anacrontab /etc/at.allow /etc/at.deny )
    for f in "${files[@]}"; do
        [ -e "$f" ] && os_extract "$f" "cron"
    done
    for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly \
             /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs \
             /var/spool/anacron /var/spool/at; do
        [ -d "$d" ] || continue
        while IFS= read -r -d '' f; do
            os_extract "$f" "cron"
        done < <(find "$d" -maxdepth 2 -type f -print0 2>/dev/null)
    done
}

check_systemd() {
    info "Checking systemd unit files…"
    for d in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system \
             /etc/systemd/user; do
        [ -d "$d" ] || continue
        while IFS= read -r -d '' f; do
            os_extract "$f" "systemd_unit"
        done < <(find "$d" -maxdepth 3 -type f \
            \( -name '*.service' -o -name '*.timer' -o -name '*.socket' \
               -o -name '*.target' -o -name '*.path' -o -name '*.mount' \
               -o -name '*.env' -o -name 'override.conf' \) -print0 2>/dev/null)
    done
    # User-level systemd
    while IFS= read -r -d '' f; do
        os_extract "$f" "systemd_user"
    done < <(find /root /home -maxdepth 5 -type f -path '*/.config/systemd/*' -print0 2>/dev/null)
}

check_databases() {
    info "Checking database configs and per-user credential caches…"
    local f files=(
        /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/mariadb.cnf
        /etc/postgresql/*/main/pg_hba.conf /etc/postgresql/*/main/postgresql.conf
        /etc/redis/redis.conf /etc/mongod.conf /etc/mongodb.conf
        /var/lib/pgsql/data/pg_hba.conf
    )
    for f in "${files[@]}"; do
        for g in $f; do
            [ -e "$g" ] && os_extract "$g" "db_config"
        done
    done
    while IFS= read -r -d '' f; do
        os_extract "$f" "user_db_cred"
    done < <(find /root /home -maxdepth 3 -type f \( \
        -name '.my.cnf' -o -name '.pgpass' -o -name '.mylogin.cnf' \
        -o -name '.mongorc.js' -o -name '.dbshell' -o -name '.sqliterc' \
        -o -name '.psqlrc' -o -name '.dbeaver-credentials.json' \) \
        -print0 2>/dev/null)
}

check_web_apps() {
    info "Checking common web-app config locations…"
    local d
    for d in /var/www /srv/www /srv/http /usr/share/nginx/html \
             /var/lib/nginx /var/lib/apache2 /var/lib/httpd \
             /etc/nginx /etc/apache2 /etc/httpd /etc/lighttpd; do
        [ -d "$d" ] || continue
        while IFS= read -r -d '' f; do
            os_extract "$f" "web_app_config"
        done < <(find "$d" -maxdepth 6 -type f \( \
            -name 'wp-config.php' -o -name 'configuration.php' \
            -o -name 'settings.php' -o -name 'local.xml' \
            -o -name 'env.php' -o -name 'parameters.yml' \
            -o -name 'parameters.yaml' -o -name 'appsettings.json' \
            -o -name 'database.yml' -o -name 'secrets.yml' \
            -o -name 'config.php' -o -name 'config.inc.php' \
            -o -name 'web.config' -o -name '.htaccess' \
            -o -name '.htpasswd' -o -name '.env' \
            -o -name 'nginx.conf' -o -name 'default.conf' \
            -o -name 'apache2.conf' -o -name 'httpd.conf' \
            \) -print0 2>/dev/null)
    done
}

check_docker_kube() {
    info "Checking Docker / Kubernetes configuration…"
    local f files=(
        /etc/docker/daemon.json /etc/containerd/config.toml
        /var/lib/kubelet/config.yaml /etc/kubernetes/admin.conf
        /etc/kubernetes/kubelet.conf /etc/kubernetes/controller-manager.conf
        /etc/kubernetes/scheduler.conf
    )
    for f in "${files[@]}"; do
        [ -e "$f" ] && os_extract "$f" "docker_k8s"
    done
    while IFS= read -r -d '' f; do
        os_extract "$f" "user_container_cred"
    done < <(find /root /home -maxdepth 4 -type f \( \
        -path '*/.docker/config.json' -o -path '*/.kube/config' \
        -o -path '*/.kube/*.yaml' \) -print0 2>/dev/null)
    # Compose files within user paths are handled by the recursive scan.

    # Mounted-secret hints
    [ -f /run/secrets ] && record_checked "container_secrets" "/run/secrets"
    [ -d /var/run/secrets/kubernetes.io ] && record_checked "k8s_serviceaccount" "/var/run/secrets/kubernetes.io"
}

check_home_dirs() {
    info "Checking high-value dotfiles in home directories…"
    local f
    while IFS= read -r -d '' f; do
        os_extract "$f" "user_dotfile_cred"
    done < <(find /root /home -maxdepth 4 -type f \( \
        -name '.netrc' -o -name '_netrc' -o -name '.git-credentials' \
        -o -name '.gitconfig' -o -name '.npmrc' -o -name '.pypirc' \
        -o -name '.cargo/credentials' -o -name '.config/gh/hosts.yml' \
        -o -name '.s3cfg' -o -name '.boto' \
        -o -path '*/.aws/credentials' -o -path '*/.aws/config' \
        -o -path '*/.gcloud/credentials.json' \
        -o -path '*/.azure/*' \
        -o -path '*/.config/rclone/rclone.conf' \
        -o -path '*/.config/filezilla/sitemanager.xml' \
        -o -path '*/.config/filezilla/recentservers.xml' \
        -o -path '*/.purple/accounts.xml' \
        -o -path '*/.thunderbird/*/logins.json' \
        -o -path '*/.mozilla/firefox/*/logins.json' \
        \) -print0 2>/dev/null)

    # Browser credential databases (not parsed, just flagged)
    while IFS= read -r -d '' f; do
        record_interest "browser_credentials" "$f"
    done < <(find /root /home -maxdepth 6 -type f \( \
        -path '*/.config/google-chrome/*/Login Data' \
        -o -path '*/.config/chromium/*/Login Data' \
        -o -path '*/.config/google-chrome/*/Cookies' \
        -o -path '*/.mozilla/firefox/*/key4.db' \
        -o -path '*/.mozilla/firefox/*/key3.db' \
        -o -path '*/.mozilla/firefox/*/logins.json' \
        -o -path '*/.mozilla/firefox/*/cookies.sqlite' \
        \) -print0 2>/dev/null)
}

check_system_files() {
    info "Checking sensitive system files…"
    local f
    # Hash files (only meaningful as root)
    for f in /etc/shadow /etc/gshadow /etc/master.passwd /etc/security/opasswd; do
        [ -e "$f" ] || continue
        record_checked "hash_file" "$f"
        if [ -r "$f" ]; then
            os_extract "$f" "shadow"
        else
            record_skip "$f" "unreadable (need root)"
        fi
    done
    # sudoers + extensions
    for f in /etc/sudoers; do
        [ -e "$f" ] && os_extract "$f" "sudoers"
    done
    [ -d /etc/sudoers.d ] && while IFS= read -r -d '' f; do
        os_extract "$f" "sudoers_d"
    done < <(find /etc/sudoers.d -maxdepth 1 -type f -print0 2>/dev/null)
    # fstab + anaconda kickstart
    for f in /etc/fstab /etc/exports /etc/anaconda-ks.cfg /root/anaconda-ks.cfg \
             /etc/network/interfaces /etc/dhcp/dhclient.conf; do
        [ -e "$f" ] && os_extract "$f" "system_config"
    done
}

check_wifi() {
    info "Checking saved Wi-Fi connection profiles…"
    local f
    for d in /etc/NetworkManager/system-connections /etc/wpa_supplicant; do
        [ -d "$d" ] || continue
        while IFS= read -r -d '' f; do
            record_checked "wifi" "$f"
            if [ -r "$f" ]; then
                os_extract "$f" "wifi_profile"
            else
                record_skip "$f" "unreadable (need root)"
            fi
        done < <(find "$d" -maxdepth 3 -type f -print0 2>/dev/null)
    done
}

check_misc() {
    info "Checking VPN, mail, MTA, Kerberos, and misc credential stores…"
    local f
    for f in /etc/openvpn/auth.txt /etc/openvpn/credentials \
             /etc/openvpn/server.conf /etc/openvpn/client.conf \
             /etc/wireguard/*.conf /etc/strongswan.conf \
             /etc/ipsec.secrets /etc/ppp/chap-secrets /etc/ppp/pap-secrets \
             /etc/postfix/main.cf /etc/postfix/master.cf \
             /etc/postfix/sasl_passwd /etc/dovecot/dovecot.conf \
             /etc/mail/sendmail.cf /etc/krb5.conf /etc/krb5.keytab \
             /var/kerberos/krb5kdc/kadm5.acl /var/kerberos/krb5kdc/kdc.conf \
             /etc/freeradius/*/clients.conf \
             /etc/proftpd/proftpd.conf /etc/vsftpd.conf \
             /etc/samba/smb.conf /etc/samba/smbpasswd \
             /etc/squid/squid.conf /etc/squid/passwords \
             /etc/snmp/snmpd.conf /etc/snmp/snmptrapd.conf \
             /etc/nagios/htpasswd.users /etc/zabbix/zabbix_agentd.conf \
             /etc/proxychains.conf /etc/proxychains4.conf \
             /etc/rsyncd.conf /etc/rsyncd.secrets \
             /etc/cups/printers.conf; do
        for g in $f; do
            [ -e "$g" ] && os_extract "$g" "service_config"
        done
    done
    # Keytabs are binary — just flag them
    while IFS= read -r -d '' f; do
        record_interest "kerberos_keytab" "$f"
    done < <(find /etc /root /home /var -maxdepth 4 -type f -name '*.keytab' -print0 2>/dev/null)
}

run_system_checks() {
    section "Stage 1 — OS-level credential locations"
    check_shell_histories
    check_ssh
    check_environment_files
    check_cron
    check_systemd
    check_databases
    check_web_apps
    check_docker_kube
    check_home_dirs
    check_system_files
    check_wifi
    check_misc
    ok "System checks complete."
}

# ============================================================================
#  Recursive scanning of user-supplied paths
# ============================================================================

build_find_excludes() {
    # Build a single grouped prune expression covering both
    # EXCLUDE_DIR_NAMES (basename match) and EXCLUDE_PATHS (absolute path).
    # Output is fed through `eval`, so every value is single-quoted to
    # prevent the shell from glob-expanding patterns like /proc/* before
    # they reach `find`.
    local exprs="" first=1 d
    for d in "${EXCLUDE_DIR_NAMES[@]}"; do
        if [ "$first" -eq 1 ]; then
            exprs="-type d -name '${d}'"
            first=0
        else
            exprs+=" -o -type d -name '${d}'"
        fi
    done
    for d in "${EXCLUDE_PATHS[@]}"; do
        if [ "$first" -eq 1 ]; then
            exprs="-path '${d}' -o -path '${d}/*'"
            first=0
        else
            exprs+=" -o -path '${d}' -o -path '${d}/*'"
        fi
    done
    [ -n "$exprs" ] && printf -- '\\( %s \\) -prune -o' "$exprs"
}

# Emit candidate files matching either default ext set or all files.
# Applies the size cap at the find level for efficiency — large files are
# discarded before they ever reach the per-file scanner. When --no-size-limit
# is in effect, the filter is omitted.
enumerate_candidates() {
    local path size_bytes size_filter=""
    size_bytes=$((MAX_FILE_SIZE_MB * 1024 * 1024))
    if [ "$SKIP_LARGE" -eq 1 ]; then
        size_filter="-size -${size_bytes}c"
    fi

    for path in "${SCAN_PATHS[@]}"; do
        [ -e "$path" ] || { warn "Path does not exist: $path"; continue; }
        if [ "$ALL_MODE" -eq 1 ]; then
            # All readable text files. Binary check happens per-file later.
            # shellcheck disable=SC2046
            find "$path" $(build_find_excludes) -type f $size_filter -print 2>/dev/null
        else
            local ext_expr=""
            local first=1 e
            for e in "${SEARCH_EXTS[@]}"; do
                if [ "$first" -eq 1 ]; then
                    ext_expr=" \( -iname '*.${e}'"
                    first=0
                else
                    ext_expr+=" -o -iname '*.${e}'"
                fi
            done
            # Catch interesting names without standard extensions
            ext_expr+=" -o -iname 'Dockerfile' -o -iname 'Vagrantfile' -o -iname 'Makefile'"
            ext_expr+=" -o -iname '.env*' -o -iname '*rc' -o -iname 'authorized_keys'"
            ext_expr+=" -o -iname 'id_rsa' -o -iname 'id_dsa' -o -iname 'id_ecdsa'"
            ext_expr+=" -o -iname 'id_ed25519' -o -iname 'identity' -o -iname 'id_*'"
            ext_expr+=" -o -iname '.htpasswd' -o -iname 'htpasswd' -o -iname 'shadow'"
            ext_expr+=" -o -iname '.netrc' -o -iname '_netrc' -o -iname '.git-credentials' \)"
            # shellcheck disable=SC2046
            eval "find \"$path\" $(build_find_excludes) -type f $size_filter $ext_expr -print" 2>/dev/null
        fi
    done
}

# Stage 2a — confirmed credential containers (extension alone is proof).
# These are KeePass / Password Safe / 1Password / PuTTY / PKCS#12 /
# keystore / keytab / BitLocker key files. Any hit here is a top-priority
# finding for the pentester.
find_guaranteed_credentials() {
    section "Stage 2 — Confirmed credential containers"
    local path e ext_expr="" first=1
    for e in "${GUARANTEED_CRED_EXTS[@]}"; do
        if [ "$first" -eq 1 ]; then
            ext_expr=" \( -iname '*.${e}'"
            first=0
        else
            ext_expr+=" -o -iname '*.${e}'"
        fi
    done
    ext_expr+=" \)"

    local count=0
    for path in "${SCAN_PATHS[@]}"; do
        [ -e "$path" ] || continue
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            # Tag with the extension so the report shows what kind it is.
            local ext_only="${f##*.}"
            record_guaranteed "${ext_only,,}" "$f"
            count=$((count + 1))
        done < <(eval "find \"$path\" $(build_find_excludes) -type f $ext_expr -print" 2>/dev/null)
    done
    if [ -s "$GUARANTEED_FILE" ]; then
        sort -u "$GUARANTEED_FILE" -o "$GUARANTEED_FILE"
        count=$(wc -l <"$GUARANTEED_FILE" | tr -d ' ')
    fi
    if [ "$count" -gt 0 ]; then
        ok "Found ${R}${BOLD}${count}${NC} ${R}confirmed credential container(s)${NC}."
    else
        ok "Found ${W}0${NC} confirmed credential container(s)."
    fi
}

# Stage 2b — auxiliary credential-related files (high value but ambiguous).
# .pem / .key / .gpg / .asc / .rdp / .ovpn / .wallet — strongly suggestive
# but not guaranteed to be credential material. Worth inspecting manually.
find_high_value_files() {
    section "Stage 3 — Auxiliary credential-related files"
    local path e ext_expr="" first=1
    for e in "${HIGH_VALUE_EXTS[@]}"; do
        if [ "$first" -eq 1 ]; then
            ext_expr=" \( -iname '*.${e}'"
            first=0
        else
            ext_expr+=" -o -iname '*.${e}'"
        fi
    done
    ext_expr+=" \)"

    local count=0
    for path in "${SCAN_PATHS[@]}"; do
        [ -e "$path" ] || continue
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            record_interest "credential_related" "$f"
            count=$((count + 1))
        done < <(eval "find \"$path\" $(build_find_excludes) -type f $ext_expr -print" 2>/dev/null)
    done
    ok "Found ${W}${count}${NC} auxiliary credential-related file(s)."
}

# Look for files/dirs whose names alone suggest credentials.
find_suspicious_filenames() {
    section "Stage 4 — Suspicious filenames"
    local path n iname_expr="" first=1
    for n in "${SUSPICIOUS_NAMES[@]}"; do
        if [ "$first" -eq 1 ]; then
            iname_expr=" \( -iname '*${n}*'"
            first=0
        else
            iname_expr+=" -o -iname '*${n}*'"
        fi
    done
    iname_expr+=" \)"

    local count=0
    for path in "${SCAN_PATHS[@]}"; do
        [ -e "$path" ] || continue
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            # Filter out matches inside excluded dirs that find didn't prune fully
            case "$f" in *node_modules*|*.git/*|*site-packages*) continue ;; esac
            record_name "$f"
            count=$((count + 1))
        done < <(eval "find \"$path\" $(build_find_excludes) $iname_expr -print" 2>/dev/null)
    done
    # Dedup
    if [ -s "$NAME_FILE" ]; then
        sort -u "$NAME_FILE" -o "$NAME_FILE"
        count=$(wc -l <"$NAME_FILE" | tr -d ' ')
    fi
    ok "Found ${W}${count}${NC} suspiciously-named file(s)."
}

# Recursively scan candidate files for hard-coded credential patterns.
scan_user_paths_contents() {
    section "Stage 5 — File-content scan"
    [ ${#SCAN_PATHS[@]} -eq 0 ] && { warn "No paths provided; skipping content scan."; return; }

    info "Enumerating candidate files…"
    enumerate_candidates >"$CANDIDATE_FILES" 2>/dev/null
    # Dedup
    if [ -s "$CANDIDATE_FILES" ]; then
        sort -u "$CANDIDATE_FILES" -o "$CANDIDATE_FILES"
    fi

    local total
    total=$(wc -l <"$CANDIDATE_FILES" | tr -d ' ')
    if [ "$total" -eq 0 ]; then
        warn "No candidate files found in the supplied paths."
        return
    fi
    ok "Candidate files: ${W}${total}${NC}  (mode: $( [ "$ALL_MODE" -eq 1 ] && echo all || echo extensions ))"

    local current=0
    # Sequential scan with progress. The grep calls inside scan_file_contents
    # do the heavy lifting; per-file overhead is small.
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        current=$((current + 1))
        draw_progress "$current" "$total" "Scanning"
        scan_file_contents "$f"
    done <"$CANDIDATE_FILES"
    draw_progress "$total" "$total" "Scanning"
    end_progress
    ok "Scanned ${W}${total}${NC} files."
}

# ============================================================================
#  Output / summary
# ============================================================================

print_section_header() {
    printf '\n%b▸ %s%b\n' "${BOLD}${W}" "$1" "$NC"
    log_line ""
    log_line "=== $1 ==="
}

# Render a TSV of findings with proper formatting. Args: file, tag, color
render_findings() {
    local file="$1" tag="$2" color="$3"
    [ ! -s "$file" ] && return 0
    sort -u "$file" -o "$file"
    local label path lineno preview
    while IFS=$'\t' read -r label path lineno preview; do
        printf '  %b[%s]%b %b%s%b  %s%s:%s%s\n' \
            "$color" "$tag" "$NC" \
            "$D" "$label" "$NC" \
            "$Y" "$path" "$lineno" "$NC"
        printf '       %b%s%b\n' "$D" "$preview" "$NC"
        log_line "[$tag] $label $path:$lineno  $preview"
    done <"$file"
}

print_summary() {
    section "Findings"

    # ── CRITICAL: confirmed credential containers (extension == proof) ─────
    if [ -s "$GUARANTEED_FILE" ]; then
        print_section_header "Confirmed credential containers  ⚠"
        sort -u "$GUARANTEED_FILE" -o "$GUARANTEED_FILE"
        local ext path
        while IFS=$'\t' read -r ext path; do
            printf '  %b%b[CRITICAL]%b %b%-8s%b  %b%s%b\n' \
                "$BOLD" "$R" "$NC" \
                "$D" "$ext" "$NC" \
                "$W" "$path" "$NC"
            log_line "[CRITICAL] $ext  $path"
        done <"$GUARANTEED_FILE"
    fi

    if [ -s "$HIGH_FILE" ]; then
        print_section_header "High-confidence credentials"
        render_findings "$HIGH_FILE" "HIGH" "$R"
    fi

    if [ -s "$KEY_FILE" ]; then
        print_section_header "Private keys & authentication material"
        render_findings "$KEY_FILE" "KEY" "$M"
    fi

    if [ -s "$INTEREST_FILE" ]; then
        print_section_header "Interesting credential-related files"
        sort -u "$INTEREST_FILE" -o "$INTEREST_FILE"
        local cat path
        while IFS=$'\t' read -r cat path; do
            printf '  %b[INTEREST]%b %b%s%b  %s\n' \
                "$C" "$NC" "$D" "$cat" "$NC" "$path"
            log_line "[INTEREST] $cat  $path"
        done <"$INTEREST_FILE"
    fi

    if [ -s "$NAME_FILE" ]; then
        print_section_header "Suspicious filenames"
        local f
        while IFS= read -r f; do
            printf '  %b[NAME]%b %s\n' "$Y" "$NC" "$f"
            log_line "[NAME] $f"
        done <"$NAME_FILE"
    fi

    if [ -s "$LOW_FILE" ]; then
        print_section_header "Low-confidence (manual review)"
        render_findings "$LOW_FILE" "LOW" "$D"
    fi

    if [ -s "$CHECKED_FILE" ]; then
        print_section_header "OS locations checked"
        sort -u "$CHECKED_FILE" -o "$CHECKED_FILE"
        local lbl path
        while IFS=$'\t' read -r lbl path; do
            printf '  %b[CHECK]%b %b%s%b  %s\n' "$B" "$NC" "$D" "$lbl" "$NC" "$path"
            log_line "[CHECK] $lbl  $path"
        done <"$CHECKED_FILE"
    fi

    if [ -s "$SKIPPED_FILE" ]; then
        print_section_header "Skipped files"
        sort -u "$SKIPPED_FILE" -o "$SKIPPED_FILE"
        local total_skipped
        total_skipped=$(wc -l <"$SKIPPED_FILE" | tr -d ' ')
        printf '  %b[SKIP]%b %d file(s) skipped (binary / size / unreadable).' \
            "$D" "$NC" "$total_skipped"
        printf '  See log for full list.\n'
        log_line ""
        log_line "Skipped files:"
        local path reason
        while IFS=$'\t' read -r path reason; do
            log_line "[SKIP] $reason  $path"
        done <"$SKIPPED_FILE"
    fi

    # Counts
    local n_guar n_high n_low n_key n_int n_name n_check n_skip
    n_guar=$( [ -s "$GUARANTEED_FILE" ] && wc -l <"$GUARANTEED_FILE" | tr -d ' ' || echo 0)
    n_high=$( [ -s "$HIGH_FILE" ]    && wc -l <"$HIGH_FILE"    | tr -d ' ' || echo 0)
    n_low=$(  [ -s "$LOW_FILE" ]     && wc -l <"$LOW_FILE"     | tr -d ' ' || echo 0)
    n_key=$(  [ -s "$KEY_FILE" ]     && wc -l <"$KEY_FILE"     | tr -d ' ' || echo 0)
    n_int=$(  [ -s "$INTEREST_FILE" ]&& wc -l <"$INTEREST_FILE"| tr -d ' ' || echo 0)
    n_name=$( [ -s "$NAME_FILE" ]    && wc -l <"$NAME_FILE"    | tr -d ' ' || echo 0)
    n_check=$([ -s "$CHECKED_FILE" ] && wc -l <"$CHECKED_FILE" | tr -d ' ' || echo 0)
    n_skip=$( [ -s "$SKIPPED_FILE" ] && wc -l <"$SKIPPED_FILE" | tr -d ' ' || echo 0)

    section "Summary"
    printf '  %b%-44s %s%b\n'  "$BOLD"  "Category" "Count" "$NC"
    printf '  %s\n'             "────────────────────────────────────────────  ─────"
    printf '  %b%b%-44s %5d%b\n' "$BOLD" "$R" "Confirmed credential containers ⚠"   "$n_guar" "$NC"
    printf '  %b%-44s %5d%b\n' "$R"     "High-confidence credentials"            "$n_high" "$NC"
    printf '  %b%-44s %5d%b\n' "$M"     "Private keys / auth material"           "$n_key"  "$NC"
    printf '  %b%-44s %5d%b\n' "$C"     "Auxiliary credential-related files"     "$n_int"  "$NC"
    printf '  %b%-44s %5d%b\n' "$Y"     "Suspicious filenames"                   "$n_name" "$NC"
    printf '  %b%-44s %5d%b\n' "$D"     "Low-confidence (review)"                "$n_low"  "$NC"
    printf '  %b%-44s %5d%b\n' "$B"     "OS locations checked"                   "$n_check" "$NC"
    printf '  %b%-44s %5d%b\n' "$D"     "Files skipped (size/binary/perm)"       "$n_skip" "$NC"
    printf '  %s\n'             "────────────────────────────────────────────  ─────"

    log_line ""
    log_line "Summary:"
    log_line "  Confirmed credential containers: $n_guar"
    log_line "  High-confidence credentials:     $n_high"
    log_line "  Private keys / material:         $n_key"
    log_line "  Auxiliary credential-related:    $n_int"
    log_line "  Suspicious filenames:            $n_name"
    log_line "  Low-confidence:                  $n_low"
    log_line "  OS locations checked:            $n_check"
    log_line "  Files skipped:                   $n_skip"

    if [ -n "$OUTPUT_FILE" ]; then
        printf '\n%b[*]%b Full log written to %b%s%b\n' "$B" "$NC" "$W" "$OUTPUT_FILE" "$NC"
    fi
}

# ============================================================================
#  Entry point
# ============================================================================
main() {
    parse_args "$@"
    setup_colors
    print_banner

    if [ "$SKIP_LARGE" -eq 1 ]; then
        info "Size cap: skipping files larger than ${W}${MAX_FILE_SIZE_MB} MB${NC}  (use -m N to change, --no-size-limit to disable)"
    else
        warn "Size cap disabled (--no-size-limit) — every readable file will be inspected."
    fi

    if [ "$SKIP_SYSTEM" -eq 0 ]; then
        run_system_checks
    else
        warn "Skipping OS-level checks (per --skip-system)."
    fi

    if [ ${#SCAN_PATHS[@]} -eq 0 ]; then
        warn "No paths supplied (-p). Skipping recursive scanning."
        warn "Tip: pass -p / to recursively scan everything under root."
    else
        find_guaranteed_credentials
        find_high_value_files
        find_suspicious_filenames
        scan_user_paths_contents
    fi

    print_summary

    # Exit code: 0 if nothing sensitive was found, 1 if any confirmed
    # credential container, high-conf credential, or private key turned up.
    if [ -s "$GUARANTEED_FILE" ] || [ -s "$HIGH_FILE" ] || [ -s "$KEY_FILE" ]; then
        exit 1
    fi
    exit 0
}

main "$@"
