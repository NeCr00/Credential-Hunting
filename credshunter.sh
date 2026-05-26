#!/usr/bin/env bash
# ============================================================================
#  credshunter.sh — Reusable-credential discovery for authorized Linux
#                   post-exploitation (read-only)
# ----------------------------------------------------------------------------
#  Hunts for material a pentester can actually re-use to move laterally or
#  escalate privileges: plaintext passwords, DB connection strings, SSH /
#  PuTTY private keys, GPP cpassword, unattend autologon, NTLM / Kerberos /
#  shadow hashes, command-line credentials in shell history, sudoers
#  NOPASSWD, htpasswd / netrc / smb.conf passwords, etc.
#
#  Deliberately ignores cloud / SaaS access tokens (JWT, AWS keys, GitHub
#  tokens, Slack tokens, generic API keys) — those rarely help with lateral
#  movement inside a network and produce most of the noise on real hosts.
#
#  Read-only. Never modifies the system. Never transmits data.
#
#  Requires: bash 4+, find, grep, awk, sed, stat. Optional: realpath, file.
#  Tested on: Debian/Ubuntu, RHEL/CentOS/Rocky/Alma, Arch, Alpine.
# ============================================================================

set -uo pipefail
export LC_ALL=C   # consistent regex / sort behavior regardless of host locale

# Case-insensitive matching for bash [[ =~ ]] and `case` patterns. Our regex
# library is written in lowercase; without nocasematch, classify_line would
# miss content like "Password=..." even though grep -i finds it.
shopt -s nocasematch 2>/dev/null || true

VERSION="2.0.0"

# Pre-initialise color vars so `err()` and friends work BEFORE setup_colors
# runs (e.g. when parse_args reports a bad flag).
R='' G='' Y='' B='' M='' C='' W='' D='' BOLD='' NC=''

# Resolve the script's own canonical path so we never grep ourselves.
SCRIPT_PATH=$(readlink -f -- "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")

# ----------------------------------------------------------------------------
#  Defaults
# ----------------------------------------------------------------------------
MAX_FILE_SIZE_MB=5
SKIP_LARGE=1
ALL_MODE=0
QUIET=0
SKIP_SYSTEM=0
NO_COLOR_FLAG=0
SCAN_PATHS=()
USER_EXCLUDE_PATHS=()
OUTPUT_FILE=""
MAX_MATCHES_PER_FILE=20
MAX_PREVIEW_LEN=140

# ----------------------------------------------------------------------------
#  Temp workspace + per-path dedup
# ----------------------------------------------------------------------------
TMPDIR="$(mktemp -d -t credshunter.XXXXXX 2>/dev/null || mktemp -d /tmp/credshunter.XXXXXX)"
HIGH_FILE="$TMPDIR/high.tsv"
KEY_FILE="$TMPDIR/keys.tsv"
NAME_FILE="$TMPDIR/names.tsv"
EXACT_FILE="$TMPDIR/exact.tsv"
INTEREST_FILE="$TMPDIR/interest.tsv"
GUARANTEED_FILE="$TMPDIR/guaranteed.tsv"
SKIPPED_FILE="$TMPDIR/skipped.tsv"
CHECKED_FILE="$TMPDIR/checked.tsv"
CANDIDATE_FILES="$TMPDIR/candidates.lst"
FIND_EXCLUDES_CACHE=""
touch "$HIGH_FILE" "$KEY_FILE" "$NAME_FILE" "$EXACT_FILE" \
      "$INTEREST_FILE" "$GUARANTEED_FILE" "$SKIPPED_FILE" \
      "$CHECKED_FILE" "$CANDIDATE_FILES"

declare -A SCANNED_PATHS   # canonical path -> 1, dedup across all stages

# ----------------------------------------------------------------------------
#  Signal handling — Ctrl+C / SIGTERM exits immediately
# ----------------------------------------------------------------------------
cleanup() { rm -rf "$TMPDIR" 2>/dev/null; }

_on_interrupt() {
    trap '' INT TERM HUP EXIT
    [ -t 2 ] && printf '\r%80s\r' '' >&2
    printf '\n%b[!] Interrupted by user. Stopping…%b\n' "${R:-}" "${NC:-}" >&2
    if command -v pkill >/dev/null 2>&1; then
        pkill -TERM -P $$ 2>/dev/null
        ( sleep 0.1; pkill -KILL -P $$ 2>/dev/null ) &
    fi
    for j in $(jobs -p 2>/dev/null); do kill -TERM "$j" 2>/dev/null; done
    cleanup
    exit 130
}
trap _on_interrupt INT TERM HUP
trap cleanup EXIT

# ----------------------------------------------------------------------------
#  Color / output helpers
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

info()    { [ "$QUIET" -eq 0 ] && printf '%b[*]%b %b\n' "$B" "$NC" "$*" >&2; }
ok()      { [ "$QUIET" -eq 0 ] && printf '%b[+]%b %b\n' "$G" "$NC" "$*" >&2; }
warn()    { printf '%b[!]%b %b\n' "$Y" "$NC" "$*" >&2; }
err()     { printf '%b[x]%b %b\n' "$R" "$NC" "$*" >&2; }
section() { printf '\n%b═══ %s ═══%b\n' "${BOLD}${C}" "$*" "$NC" >&2; }

log_line() {
    [ -n "$OUTPUT_FILE" ] || return 0
    # Strip ANSI codes for the on-disk log
    printf '%s\n' "$(printf '%s' "$*" | sed 's/\x1b\[[0-9;]*m//g')" >>"$OUTPUT_FILE"
}

# ----------------------------------------------------------------------------
#  Banner & help
# ----------------------------------------------------------------------------
print_banner() {
    [ "$QUIET" -eq 1 ] && return
    cat >&2 <<EOF

${C}${BOLD}  ┌─────────────────────────────────────────────────────────────┐
  │  credshunter  ·  Linux reusable-credential discovery        │
  │  v${VERSION}  ·  ${D}authorized testing only · read-only${NC}${C}${BOLD}              │
  └─────────────────────────────────────────────────────────────┘${NC}

EOF
}

usage() {
    cat <<'EOF'
Usage: credshunter.sh [OPTIONS] -p PATH [-p PATH ...]

Hunt for reusable credentials a pentester can actually leverage (plaintext
passwords, DB connection strings, private keys, GPP cpassword, NTLM/Kerberos
hashes, sudoers NOPASSWD, command-line creds in shell history, etc.).

Cloud / SaaS access tokens (JWT, AWS, GitHub, Slack, generic API keys) are
deliberately *not* targeted — they rarely help with lateral movement and
they're the dominant source of false positives.

Options:
  -p, --path PATH       Path to scan recursively (repeatable).
  -x, --exclude PATH    Skip a directory tree (repeatable). Affects stages 2-5
                        only; stage 1 (OS-level checks) is unaffected.
  -a, --all             Stage 5 scans every readable text file, not only
                        credential-related extensions.
  -m, --max-size N      Skip files larger than N MB (default: 5).
      --no-size-limit   Disable the size cap entirely.
  -o, --output FILE     Append a plain-text log of all findings.
  -s, --skip-system     Skip stage 1 (OS-level credential checks).
  -q, --quiet           Reduce status noise. Findings still printed.
      --no-color        Strip ANSI escape codes.
  -h, --help            Show this help.
  -V, --version         Show version.

Examples:
  sudo ./credshunter.sh -p / -m 10 -o /tmp/findings.txt
  ./credshunter.sh -p /home -p /var/www -p /opt
  ./credshunter.sh --skip-system -p . -q
  ./credshunter.sh -p / -x /var/lib/customer-app

Exit codes:
  0 = nothing sensitive found
  1 = at least one critical/high/key/exact-name finding
  2 = argument / I/O error
  130 = interrupted (Ctrl+C / SIGTERM)
EOF
}

# ----------------------------------------------------------------------------
#  Argument parsing
# ----------------------------------------------------------------------------
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -p|--path)        SCAN_PATHS+=("$2"); shift 2 ;;
            -x|--exclude)     USER_EXCLUDE_PATHS+=("$2"); shift 2 ;;
            -a|--all)         ALL_MODE=1; shift ;;
            -m|--max-size)    MAX_FILE_SIZE_MB="$2"; SKIP_LARGE=1; shift 2 ;;
            --no-size-limit)  SKIP_LARGE=0; shift ;;
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

    # Normalise user exclusions WITHOUT canonicalising — `find` emits paths
    # using whatever prefix the start directory had (e.g. /tmp not /private/tmp
    # on macOS). Add the canonical form too as a fallback.
    local i raw abs canon
    for i in "${!USER_EXCLUDE_PATHS[@]}"; do
        raw="${USER_EXCLUDE_PATHS[$i]}"
        case "$raw" in /*) abs="$raw" ;; *) abs="$(pwd)/$raw" ;; esac
        [ "${#abs}" -gt 1 ] && abs="${abs%/}"
        USER_EXCLUDE_PATHS[$i]="$abs"
        EXCLUDE_PATHS+=("$abs")
        canon=$(readlink -f -- "$abs" 2>/dev/null || true)
        if [ -n "$canon" ] && [ "$canon" != "$abs" ]; then
            [ "${#canon}" -gt 1 ] && canon="${canon%/}"
            EXCLUDE_PATHS+=("$canon")
        fi
    done
}

# ============================================================================
#  Pattern data — PASSWORD-FOCUSED for lateral movement / priv-esc
# ============================================================================
#
# One unified list used by both OS-level extraction (stage 1) and the
# recursive content scan (stage 5). Each entry is "LABEL|ERE_REGEX".
#
# Design rules:
#   * Every pattern targets plaintext passwords, hashes, private keys, or
#     command-line credentials that are reusable for lateral movement or
#     privilege escalation.
#   * No JWT / AWS / GitHub / Slack / generic API-key patterns — they
#     dominate noise on real hosts and are rarely useful in-network.
#   * Every key=value pattern requires a value with at least 3 non-space,
#     non-comment, non-template chars to reduce empty / placeholder hits.

CRED_PATTERNS=(
    # ── Direct password assignments ──────────────────────────────────────
    'password_assign|(^|[^A-Za-z_])(password|passwd|passphrase)[[:space:]]*[:=][[:space:]]*['"'"'"]?[^[:space:]"#$<>{}]{3,}'

    # ── DB / service-prefixed passwords ──────────────────────────────────
    'db_password|(db|database|mysql|psql|pg|postgres|mongo|mssql|sql|oracle|redis|memcache|ldap|smtp|smb|ftp|sftp|imap|pop3|admin|user|service|svc|jenkins|jboss|tomcat|nexus|gitlab|jira|svn|backup|root|wp|wordpress|joomla|drupal|magento|laravel|django|proxy|vpn|sftp|cifs)[_-]?(password|passwd|passphrase|pwd|pass)[[:space:]]*[:=][[:space:]]*['"'"'"]?[^[:space:]"#$<>{}]{3,}'

    # ── Connection-string passwords (SQL Server / .NET / JDBC / generic) ─
    # Allow arbitrary content (incl. semicolons) between the server= clause
    # and the password= clause — a real connection string has the form
    # Server=X;Database=Y;User Id=Z;Password=P
    # Greedy quantifier — POSIX ERE has no lazy form; greedy still matches.
    'connection_string|(server|host|data[ _-]?source)[[:space:]]*=.{1,200}(password|pwd)[[:space:]]*=[[:space:]]*['"'"'"]?[^;&[:space:]"]{3,}'
    'jdbc_url|jdbc:[a-z]+://[^[:space:]"]*[?&;]password=[^;&[:space:]"]{3,}'

    # ── URL-embedded credentials (top source for lateral movement) ───────
    'url_credentials|(mysql|postgres(ql)?|mongodb(\+srv)?|redis|amqp|rabbitmq|ftp|ftps|sftp|ssh|smb|cifs|ldap[s]?|imap[s]?|smtp[s]?|https?)://[^[:space:]/:@]+:[^[:space:]/@]{2,}@'

    # ── GPP cpassword (CRITICAL for AD lateral) ──────────────────────────
    'gpp_cpassword|cpassword[[:space:]]*=[[:space:]]*"[A-Za-z0-9+/=]{20,}"'

    # ── Windows unattend / autologon ─────────────────────────────────────
    'unattend_password|<(Administrator)?Password>[[:space:]]*<Value>[^<]{2,}'
    'autologon_password|(DefaultPassword|AltDefaultPassword)[[:space:]]*[:=][[:space:]"]*[^[:space:]"#]{2,}'

    # ── Environment-variable credentials ─────────────────────────────────
    'env_password|(^|[[:space:]])(set[[:space:]]+|export[[:space:]]+|setx[[:space:]]+)?[A-Z][A-Z0-9_]*(PASSWORD|PASSWD|PASSPHRASE)[A-Z0-9_]*[[:space:]]*=[[:space:]]*['"'"'"]?[^[:space:]"$<>]{3,}'
    'pgpassword_env|PGPASSWORD[[:space:]]*=[[:space:]]*['"'"'"]?[^[:space:]"#]{3,}'
    'mysql_pwd_env|MYSQL_PWD[[:space:]]*=[[:space:]]*['"'"'"]?[^[:space:]"#]{3,}'

    # ── Shell-history / command-line credentials ─────────────────────────
    # (Massively expanded from research: HTB Resolute PowerShell transcripts,
    #  Snaffler classifiers, linpeas pwd_inside_history detector.)
    'sshpass_cmd|sshpass[[:space:]]+(-p|--password)[[:space:]]*['"'"'"]?[^[:space:]'"'"'"]{2,}'
    'mysql_cmd|(mysql|mysqladmin|mysqldump|mysqlimport)[[:space:]].*[[:space:]]-p[^[:space:]"#-][^[:space:]"#]{2,}'
    'psql_cmd|psql[[:space:]].*(-W|--password=|host=[^[:space:]]+.*password=)[^[:space:]"#]{2,}'
    'mongo_cmd|(mongo|mongosh|mongodump|mongorestore)[[:space:]].*(-p|--password)[[:space:]=]+['"'"'"]?[^[:space:]'"'"'"]{2,}'
    'redis_cmd|redis-cli[[:space:]].*(-a|--pass)[[:space:]=]+['"'"'"]?[^[:space:]'"'"'"]{2,}'
    'curl_basic|(curl|wget)[[:space:]].*--?(u|user|http-user)[[:space:]=]+[^:[:space:]]+:[^[:space:]'"'"'"]{3,}'
    'wget_pass|wget[[:space:]].*--(http-password|password|ftp-password)[[:space:]=]+[^[:space:]"]{3,}'
    'smbclient_pass|smbclient[[:space:]].*-U[[:space:]]+[^%[:space:]]+%[^[:space:]]{3,}'
    'smbmount_pass|mount[[:space:]]+(-t[[:space:]]+cifs|//).*-o[[:space:]].*(pass|password)=[^,[:space:]"]{3,}'
    'freerdp_pass|(xfreerdp|freerdp|rdesktop)[[:space:]].*(-p|/p:)[[:space:]]?['"'"'"]?[^[:space:]"]{2,}'
    'plink_pass|plink[[:space:]].*-pw[[:space:]]+['"'"'"]?[^[:space:]'"'"'"]{2,}'
    'net_use_pass|net[[:space:]]+use[[:space:]]+.*[[:space:]]/user:[^[:space:]]+[[:space:]]+[^[:space:]/"]{3,}'
    'ldap_pass|(ldapsearch|ldapadd|ldapmodify|ldapdelete|ldapcompare)[[:space:]].*-w[[:space:]]+['"'"'"]?[^[:space:]'"'"'"]{2,}'
    'kinit_pass|kinit[[:space:]].*<[[:space:]]*[^[:space:]]+'
    'rsync_pass|rsync[[:space:]].*--password-file=[^[:space:]]+'
    'snmp_cmd|snmpwalk[[:space:]].*(-A|-X|-c)[[:space:]]+['"'"'"]?[^[:space:]'"'"'"]{3,}'
    'mosquitto_pass|mosquitto_(pub|sub)[[:space:]].*(-P|--pw)[[:space:]]+['"'"'"]?[^[:space:]'"'"'"]{2,}'
    'archive_pass|(7z|zip|unzip|gpg)[[:space:]].*(-P|-p|--passphrase)[[:space:]=]+['"'"'"]?[^[:space:]'"'"'"]{2,}'
    'openssl_pass|openssl[[:space:]].*(-(pass(in|out)?|passphrase|k))[[:space:]]+(pass:|file:|env:)[^[:space:]"]{2,}'
    'htpasswd_create|htpasswd[[:space:]]+(-nb?|-b)[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]"]{2,}'
    'nmcli_wifi|nmcli[[:space:]].*wifi[[:space:]]+(connect|hotspot)[[:space:]].*(password|key)[[:space:]]+[^[:space:]"]{2,}'
    'sqlcmd_pass|(sqlcmd|osql|bcp)[[:space:]].*-P[[:space:]]+['"'"'"]?[^[:space:]'"'"'"]{2,}'
    'runas_savecred|runas[[:space:]].*/(user|savecred)[[:space:]:][^|]{3,}'
    'wmic_pass|wmic[[:space:]].*/password:[^[:space:]"]{2,}'
    'psexec_pass|(psexec|PsExec64?)[[:space:]].*-p[[:space:]]+['"'"'"]?[^[:space:]'"'"'"]{2,}'
    'cmdkey_add|cmdkey[[:space:]]+/(add|generic):[^[:space:]]+.*(/pass:|/p:)[^[:space:]"]{2,}'
    'sc_config_pass|sc(\.exe)?[[:space:]]+config[[:space:]].*password=[[:space:]]*[^[:space:]"]{2,}'
    'schtasks_pass|schtasks[[:space:]].*/rp[[:space:]]+['"'"'"]?[^[:space:]'"'"'"]{2,}'
    'evilwinrm_cmd|evil-winrm[[:space:]].*-p[[:space:]]+['"'"'"]?[^[:space:]'"'"'"]{2,}'
    'impacket_cred|(impacket-\S+|psexec\.py|wmiexec\.py|smbexec\.py|secretsdump\.py|GetUserSPNs\.py|GetNPUsers\.py)[[:space:]].*[^[:space:]/]+/[^:[:space:]]+:[^@[:space:]]{3,}@'
    'expect_send|send[[:space:]]+['"'"'"][^"'"'"']+['"'"'"]'

    # ── Web framework specifics ──────────────────────────────────────────
    'wp_db_password|define\([[:space:]]*['"'"'"]DB_PASSWORD['"'"'"][[:space:]]*,[[:space:]]*['"'"'"][^'"'"'"]{2,}'
    'joomla_password|public[[:space:]]+\$(password|smtppass|dbpass|secret)[[:space:]]*=[[:space:]]*['"'"'"][^'"'"'"]{2,}'
    'drupal_password|['"'"'"]password['"'"'"][[:space:]]*=>[[:space:]]*['"'"'"][^'"'"'"]{4,}'

    # ── Linux auth files ─────────────────────────────────────────────────
    'htpasswd_hash|^[^:[:space:]#]+:\$(apr1|2[aby]?|5|6|y)\$'
    'htpasswd_md5|^[^:[:space:]#]+:[A-Za-z0-9./]{13}$'
    'netrc_password|^[[:space:]]*(machine[[:space:]]+\S+[[:space:]]+)?(login|user|username)[[:space:]]+\S+[[:space:]]+password[[:space:]]+\S{2,}'
    'sudoers_nopasswd|^[[:space:]]*[^#][^[:space:]]*[[:space:]].*NOPASSWD[[:space:]]*[:=]'
    'samba_password|^[[:space:]]*(passwd|password|smb[[:space:]]+passwd)[[:space:]]*=[[:space:]]*[^[:space:]]{3,}'

    # ── Hash dumps (cracking / pass-the-hash) ────────────────────────────
    'ntlm_dump|^[^:[:space:]#]+:[0-9]+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:::'
    'ntds_dump|^[^:[:space:]#]+\\[^:]+:[0-9]+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:::'

    # ── Linux shadow / hash formats ──────────────────────────────────────
    'shadow_md5|\$1\$[A-Za-z0-9./]{1,8}\$[A-Za-z0-9./]{22}'
    'shadow_sha256|\$5\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{40,}'
    'shadow_sha512|\$6\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{40,}'
    'shadow_yescrypt|\$y\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+'
    'shadow_bcrypt|\$2[aby]?\$[0-9]{2}\$[A-Za-z0-9./]{53}'
    'shadow_argon2|\$argon2(id|i|d)\$'

    # ── Kerberos roasting output ─────────────────────────────────────────
    'krb5_tgs|\$krb5tgs\$[0-9]'
    'krb5_asrep|\$krb5asrep\$[0-9]'
    'mscash_v1|M\$[A-Za-z0-9._-]+#[a-fA-F0-9]{32}'
    'mscash_v2|\$DCC2\$[0-9]+#'
)

# Private-key markers — always interesting, separate bucket
KEY_PATTERNS=(
    'rsa_private|-----BEGIN RSA PRIVATE KEY-----'
    'dsa_private|-----BEGIN DSA PRIVATE KEY-----'
    'ec_private|-----BEGIN EC PRIVATE KEY-----'
    'openssh_private|-----BEGIN OPENSSH PRIVATE KEY-----'
    'pkcs8_private|-----BEGIN PRIVATE KEY-----'
    'encrypted_private|-----BEGIN ENCRYPTED PRIVATE KEY-----'
    'pgp_private|-----BEGIN PGP PRIVATE KEY BLOCK-----'
    'putty_private|PuTTY-User-Key-File-'
)

# Combined single regex (built once at startup) for fast prefiltering.
# Format: just the ERE bodies joined with `|`.
COMBINED_CRED_REGEX=""
COMBINED_KEY_REGEX=""
build_combined_regex() {
    local entry first=1
    for entry in "${CRED_PATTERNS[@]}"; do
        if [ "$first" -eq 1 ]; then
            COMBINED_CRED_REGEX="${entry#*|}"; first=0
        else
            COMBINED_CRED_REGEX="${COMBINED_CRED_REGEX}|${entry#*|}"
        fi
    done
    first=1
    for entry in "${KEY_PATTERNS[@]}"; do
        if [ "$first" -eq 1 ]; then
            COMBINED_KEY_REGEX="${entry#*|}"; first=0
        else
            COMBINED_KEY_REGEX="${COMBINED_KEY_REGEX}|${entry#*|}"
        fi
    done
}

# ============================================================================
#  False-positive filter
# ============================================================================

FALSE_POSITIVE_EXACT=(
    "" " " "''" '""'
    password passwd pwd pass passphrase secret token
    null none nil undefined empty void true false
    example sample demo placeholder dummy fake stub mock lorem ipsum
    test tester testing testpassword testpass test123 testing123
    foo bar baz qux foobar barbaz
    abc 123 abc123 12345 123456 1234567 12345678 123456789
    qwerty letmein iloveyou monkey dragon hunter2 'correct horse'
    "p@ssw0rd" password123 password1 admin1 admin123
    changeme change_me change-me changethis change-this changeit change-it
    todo fixme tbd "n/a" na
    your_password yourpassword your-password yourpasswordhere yourpwd
    insert_password replace_me replace-me replace_this insert_here
    "<password>" "<pass>" "<secret>" "<token>" "<key>" "<value>" "<your-password>"
    "<input>" "<enter>" "<here>" "<...>"
    "..." "...." "....." "********" "*****" "***" xxxxxxxx xxxxx xxx
    redacted hidden masked sanitized
    # MS sysprep "Password" default placeholder, base64 UTF-16LE
    "uabhahmacwbvahiazaa=="
    # Common sysprep-cleaned marker
    "*sensitive*data*deleted*"
)

is_false_positive() {
    local v="$1"
    # Trim leading/trailing whitespace, surrounding quotes
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    v="${v#\"}"; v="${v%\"}"
    v="${v#\'}"; v="${v%\'}"

    local len=${#v}
    [ "$len" -lt 3 ] && return 0
    [ "$len" -gt 256 ] && return 0

    local lower="${v,,}"
    local fp
    for fp in "${FALSE_POSITIVE_EXACT[@]}"; do
        [ "$lower" = "$fp" ] && return 0
    done

    # Suffix-based template vars (FOO_PASSWORD as placeholder name)
    case "$lower" in
        *_password|*_secret|*_token|*_key|*_pass|*_pwd|*passwordhere) return 0 ;;
        your_*|insert_*|replace_*|example_*|sample_*|test_*|my_*|fake_*) return 0 ;;
    esac

    # Variable interpolation / template markers
    case "$v" in
        *'${'*|*'$('*|*'%('*|*'{{'*|*'<%'*|*'%>'*|*'#{'*) return 0 ;;
        *'<'*'>'*) return 0 ;;
        *'$1'*|*'$2'*|*'$3'*|*'$$'*) return 0 ;;
        *'%'[A-Z_]*'%'*) return 0 ;;
        *'@@'*|*'__'*'__'*) return 0 ;;
    esac

    # Programming-language references that look like passwords but aren't
    # (Python `self.password`, Java `this.password`, PHP `$_POST['password']`)
    case "$v" in
        'self.'*|'this.'*|'cls.'*|'@self.'*) return 0 ;;
        '$_POST['*|'$_GET['*|'$_REQUEST['*|'$_SERVER['*|'$_ENV['*|'$_SESSION['*|'$_COOKIE['*) return 0 ;;
        '$'[a-zA-Z_]*) return 0 ;;
        # Dotted identifier referencing another field (no quotes)
    esac

    # Already-encrypted / vaulted markers — these mean the secret is
    # protected at rest; we don't double-report them as plaintext.
    case "$v" in
        'ENC('*')')         return 0 ;;  # Jasypt
        '{cipher}'*)        return 0 ;;  # Spring Cloud Config
        'vault:v'[0-9]*':'*) return 0 ;;  # HashiCorp Vault
        '$ANSIBLE_VAULT;'*) return 0 ;;  # Ansible Vault header
        'pbkdf2_sha'*'$'*)  return 0 ;;  # Django password hash format
        # Django-style hashed already
    esac

    # SQL Server / .NET trusted/integrated connection strings have no password
    case "$lower" in
        *'integrated security=true'*|*'integrated security=sspi'*) return 0 ;;
        *'trusted_connection=yes'*|*'trusted_connection=true'*) return 0 ;;
    esac

    # Single repeating char (e.g. "xxxx", "****")
    if [ "$len" -ge 3 ] && [[ "$v" =~ ^(.)\1+$ ]]; then
        return 0
    fi

    # Only non-alphanumeric punctuation
    if [[ "$v" =~ ^[^A-Za-z0-9]+$ ]]; then
        return 0
    fi

    return 1
}

# ============================================================================
#  Helper utilities
# ============================================================================

file_size() {
    stat -c '%s' "$1" 2>/dev/null \
        || stat -f '%z' "$1" 2>/dev/null \
        || wc -c <"$1" 2>/dev/null \
        || echo 0
}

# Binary detection: examine first 4 KB only. Empty files are also flagged
# as "binary" because there's nothing to scan.
is_binary() {
    ! head -c 4096 -- "$1" 2>/dev/null | grep -qI . 2>/dev/null
}

sanitize() {
    local v="$1"
    v="${v//$'\r'/}"
    v="${v//$'\n'/ }"
    v="$(printf '%s' "$v" | tr -s '[:space:]' ' ')"
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    if [ "${#v}" -gt "$MAX_PREVIEW_LEN" ]; then
        v="${v:0:$MAX_PREVIEW_LEN}…"
    fi
    printf '%s' "$v"
}

record_finding() {
    # Args: BUCKET LABEL FILE LINE PREVIEW
    local bucket="$1" label="$2" file="$3" line="$4" preview="$5"
    case "$bucket" in
        HIGH) printf '%s\t%s\t%s\t%s\n' "$label" "$file" "$line" "$preview" >>"$HIGH_FILE" ;;
        KEY)  printf '%s\t%s\t%s\t%s\n' "$label" "$file" "$line" "$preview" >>"$KEY_FILE"  ;;
    esac
}
record_interest()    { printf '%s\t%s\n' "$1" "$2" >>"$INTEREST_FILE"; }
record_name()        { printf '%s\n' "$1" >>"$NAME_FILE"; }
record_exact()       { printf '%s\n' "$1" >>"$EXACT_FILE"; }
record_skip()        { printf '%s\t%s\n' "$1" "$2" >>"$SKIPPED_FILE"; }
record_checked()     { printf '%s\t%s\n' "$1" "$2" >>"$CHECKED_FILE"; }
record_guaranteed()  { printf '%s\t%s\n' "$1" "$2" >>"$GUARANTEED_FILE"; }

# ----------------------------------------------------------------------------
#  Progress bar
# ----------------------------------------------------------------------------
PROGRESS_LAST=0
draw_progress() {
    [ "$QUIET" -eq 1 ] && return
    [ ! -t 2 ] && return
    local current=$1 total=$2 label=${3:-Scanning}
    [ "$total" -le 0 ] && return
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
    local bar=""; local i
    for ((i=0; i<filled; i++)); do bar+="#"; done
    for ((i=filled; i<width; i++)); do bar+="-"; done
    printf '\r%b%s%b [%s] %3d%% (%d/%d)   ' "$C" "$label" "$NC" "$bar" "$percent" "$current" "$total" >&2
}
end_progress() {
    [ "$QUIET" -eq 1 ] && return
    [ ! -t 2 ] && return
    printf '\r%-80s\r' '' >&2
    PROGRESS_LAST=0
}

# ============================================================================
#  Content scanning core
#
#  Two phases per file:
#    1. ONE grep call with combined alternation → fast filter, gives us the
#       candidate lines that match SOME credential pattern.
#    2. For each candidate line, classify which sub-pattern matched (in-shell
#       via [[ =~ ]] — no subprocess fork) and apply the FP filter.
#
#  Same routine handles stage 1 (OS files) and stage 5 (recursive candidates).
#  Per-path SCANNED_PATHS guard ensures we scan each file at most once.
# ============================================================================

# Classify a single line: try each CRED_PATTERN and record the first match.
# Returns 0 on a real finding (after FP filter), 1 otherwise.
classify_line() {
    local content="$1" file="$2" lineno="$3" source_label="$4"
    local entry label regex value
    for entry in "${CRED_PATTERNS[@]}"; do
        label="${entry%%|*}"
        regex="${entry#*|}"
        if [[ "$content" =~ $regex ]]; then
            # Extract right-hand-side value for FP filtering
            value="$content"
            if [[ "$content" =~ [[:space:]]*([^[:space:]=:]+)[[:space:]]*[:=][[:space:]]*(.+)$ ]]; then
                value="${BASH_REMATCH[2]}"
                value="${value%%#*}"
                value="${value%%;*}"
            fi
            # Skip FP filter for hash dumps and key markers (they aren't kv shaped)
            case "$label" in
                ntlm_dump|ntds_dump|shadow_*|krb5_*|mscash_*|htpasswd_*|gpp_cpassword)
                    ;;
                *)
                    is_false_positive "$value" && return 1
                    ;;
            esac
            record_finding HIGH "${source_label}/${label}" "$file" "$lineno" "$(sanitize "$content")"
            return 0
        fi
    done
    return 1
}

# Scan one file. Handles size, binary, dedup, and pattern matching.
scan_file() {
    local file="$1" source_label="${2:-content}"

    # Skip our own script
    [ "$file" = "$SCRIPT_PATH" ] && return

    # Per-path dedup using canonical path
    local canon
    canon=$(readlink -f -- "$file" 2>/dev/null || printf '%s' "$file")
    [ -n "${SCANNED_PATHS["$canon"]:-}" ] && return
    SCANNED_PATHS["$canon"]=1

    [ -f "$file" ] || return
    [ -r "$file" ] || { record_skip "$file" "unreadable"; return; }

    local sz
    sz=$(file_size "$file")
    [ "$sz" -le 0 ] && return
    if [ "$SKIP_LARGE" -eq 1 ] && [ "$sz" -gt $((MAX_FILE_SIZE_MB * 1024 * 1024)) ]; then
        record_skip "$file" "size>${MAX_FILE_SIZE_MB}MB"
        return
    fi
    is_binary "$file" && { record_skip "$file" "binary"; return; }

    # ── Phase 1: private-key markers ─────────────────────────────────────
    local key_entry plabel
    if grep -qE -- "$COMBINED_KEY_REGEX" "$file" 2>/dev/null; then
        for key_entry in "${KEY_PATTERNS[@]}"; do
            plabel="${key_entry%%|*}"
            local kregex="${key_entry#*|}"
            local match
            match=$(grep -nE -m1 -- "$kregex" "$file" 2>/dev/null) || continue
            [ -z "$match" ] && continue
            record_finding KEY "$plabel" "$file" "${match%%:*}" "$(sanitize "${match#*:}")"
        done
    fi

    # ── Phase 2: combined credential alternation ─────────────────────────
    # One grep call selects all candidate lines. Classification happens
    # in-bash via [[ =~ ]] with no subprocess fork per pattern.
    local matches_found=0
    while IFS= read -r match || [ -n "$match" ]; do
        [ -z "$match" ] && continue
        [ "$matches_found" -ge "$MAX_MATCHES_PER_FILE" ] && break
        local lineno="${match%%:*}"
        local content="${match#*:}"
        if classify_line "$content" "$file" "$lineno" "$source_label"; then
            matches_found=$((matches_found + 1))
        fi
    done < <(grep -niE -m "$MAX_MATCHES_PER_FILE" -- "$COMBINED_CRED_REGEX" "$file" 2>/dev/null)
}

# ============================================================================
#  Stage 1 — OS-level credential checks (targeted file lists, not recursive)
# ============================================================================

check_known_file() {
    local file="$1" label="$2"
    [ -e "$file" ] || return
    record_checked "$label" "$file"
    [ -f "$file" ] || return
    if [ ! -r "$file" ]; then
        record_skip "$file" "unreadable"
        return
    fi
    scan_file "$file" "$label"
}

check_shell_histories() {
    info "Stage 1.1 — shell / tool history files"
    local f histfiles=(
        /root/.bash_history /root/.zsh_history /root/.sh_history /root/.ash_history
        /root/.history /root/.lesshst /root/.viminfo
        /root/.mysql_history /root/.psql_history /root/.sqlite_history
        /root/.python_history /root/.node_repl_history /root/.rediscli_history
        /root/.irb_history
    )
    while IFS= read -r -d '' f; do histfiles+=("$f"); done < <(
        find /home -maxdepth 3 \( \
            -name '.bash_history' -o -name '.zsh_history' -o -name '.sh_history' \
            -o -name '.ash_history' -o -name '.history' -o -name '.lesshst' \
            -o -name '.mysql_history' -o -name '.psql_history' \
            -o -name '.sqlite_history' -o -name '.python_history' \
            -o -name '.node_repl_history' -o -name '.rediscli_history' \
            -o -name '.irb_history' -o -name '.viminfo' \
            \) -type f -print0 2>/dev/null)
    for f in "${histfiles[@]}"; do
        check_known_file "$f" "history"
    done
}

check_ssh() {
    info "Stage 1.2 — SSH keys, configs and authorized hosts"
    local f
    local sshdirs=(/root/.ssh)
    while IFS= read -r -d '' f; do sshdirs+=("$f"); done < <(
        find /home -maxdepth 3 -type d -name .ssh -print0 2>/dev/null)
    for d in "${sshdirs[@]}"; do
        [ -d "$d" ] || continue
        while IFS= read -r -d '' f; do
            record_checked "ssh" "$f"
            case "$(basename "$f")" in
                id_*|*.pem|*.key|identity)
                    if [ -r "$f" ] && grep -qE 'PRIVATE KEY|PuTTY-User-Key' "$f" 2>/dev/null; then
                        record_finding KEY "ssh_private_key" "$f" 1 "private key in $f"
                    fi
                    ;;
                config|authorized_keys|known_hosts)
                    scan_file "$f" "ssh"
                    ;;
            esac
        done < <(find "$d" -maxdepth 2 -type f -print0 2>/dev/null)
    done
    for f in /etc/ssh/sshd_config /etc/ssh/ssh_config; do
        [ -e "$f" ] && scan_file "$f" "sshd"
    done
}

check_environment_files() {
    info "Stage 1.3 — environment / profile / dotfiles"
    local f files=(
        /etc/environment /etc/profile /etc/bashrc /etc/bash.bashrc
        /etc/zshrc /etc/zsh/zshrc /etc/zsh/zprofile /etc/csh.cshrc
    )
    for f in "${files[@]}"; do
        [ -e "$f" ] && scan_file "$f" "env"
    done
    while IFS= read -r -d '' f; do scan_file "$f" "profile_d"; done < <(
        find /etc/profile.d -maxdepth 1 -type f -print0 2>/dev/null)
    while IFS= read -r -d '' f; do scan_file "$f" "user_rc"; done < <(
        find /root /home -maxdepth 3 -type f \( \
            -name '.bashrc' -o -name '.bash_profile' -o -name '.bash_login' \
            -o -name '.bash_logout' -o -name '.profile' -o -name '.zshrc' \
            -o -name '.zprofile' -o -name '.zlogin' -o -name '.envrc' \
            -o -name '.env' -o -name '.env.local' -o -name '.env.*' \
            \) -print0 2>/dev/null)
}

check_cron() {
    info "Stage 1.4 — cron / at"
    local f files=( /etc/crontab /etc/anacrontab /etc/at.allow /etc/at.deny )
    for f in "${files[@]}"; do [ -e "$f" ] && scan_file "$f" "cron"; done
    for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly \
             /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs \
             /var/spool/anacron /var/spool/at; do
        [ -d "$d" ] || continue
        while IFS= read -r -d '' f; do scan_file "$f" "cron"
        done < <(find "$d" -maxdepth 2 -type f -print0 2>/dev/null)
    done
}

check_systemd() {
    info "Stage 1.5 — systemd unit files"
    for d in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system \
             /etc/systemd/user; do
        [ -d "$d" ] || continue
        while IFS= read -r -d '' f; do scan_file "$f" "systemd"
        done < <(find "$d" -maxdepth 3 -type f \( \
            -name '*.service' -o -name '*.timer' -o -name '*.socket' \
            -o -name '*.target' -o -name '*.path' -o -name '*.mount' \
            -o -name '*.env' -o -name 'override.conf' \) -print0 2>/dev/null)
    done
    while IFS= read -r -d '' f; do scan_file "$f" "systemd_user"
    done < <(find /root /home -maxdepth 5 -type f -path '*/.config/systemd/*' -print0 2>/dev/null)
}

check_databases() {
    info "Stage 1.6 — database configs and per-user caches"
    local f files=(
        /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/mariadb.cnf
        /etc/postgresql/*/main/pg_hba.conf /etc/postgresql/*/main/postgresql.conf
        /etc/redis/redis.conf /etc/mongod.conf /etc/mongodb.conf
        /var/lib/pgsql/data/pg_hba.conf /etc/elasticsearch/elasticsearch.yml
    )
    for f in "${files[@]}"; do
        for g in $f; do
            [ -e "$g" ] && scan_file "$g" "db_config"
        done
    done
    while IFS= read -r -d '' f; do scan_file "$f" "user_db"
    done < <(find /root /home -maxdepth 3 -type f \( \
        -name '.my.cnf' -o -name '.pgpass' -o -name '.mylogin.cnf' \
        -o -name '.mongorc.js' -o -name '.dbshell' -o -name '.sqliterc' \
        -o -name '.psqlrc' -o -name '.dbeaver-credentials.json' \
        \) -print0 2>/dev/null)
}

check_web_apps() {
    info "Stage 1.7 — web-app configs"
    local d
    for d in /var/www /srv/www /srv/http /usr/share/nginx/html \
             /var/lib/nginx /var/lib/apache2 /var/lib/httpd \
             /etc/nginx /etc/apache2 /etc/httpd /etc/lighttpd; do
        [ -d "$d" ] || continue
        while IFS= read -r -d '' f; do scan_file "$f" "webapp"
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

check_home_dotfiles() {
    info "Stage 1.8 — high-value dotfiles in home dirs"
    local f
    while IFS= read -r -d '' f; do scan_file "$f" "dotfile"
    done < <(find /root /home -maxdepth 4 -type f \( \
        -name '.netrc' -o -name '_netrc' -o -name '.git-credentials' \
        -o -name '.gitconfig' -o -name '.npmrc' -o -name '.pypirc' \
        -o -path '*/.aws/credentials' -o -path '*/.aws/config' \
        -o -path '*/.azure/*' -o -path '*/.config/rclone/rclone.conf' \
        -o -path '*/.config/filezilla/sitemanager.xml' \
        -o -path '*/.config/filezilla/recentservers.xml' \
        \) -print0 2>/dev/null)

    # Browser credential stores: flag for offline decryption only
    while IFS= read -r -d '' f; do record_interest "browser_credentials" "$f"
    done < <(find /root /home -maxdepth 6 -type f \( \
        -path '*/.config/google-chrome/*/Login Data' \
        -o -path '*/.config/chromium/*/Login Data' \
        -o -path '*/.mozilla/firefox/*/key4.db' \
        -o -path '*/.mozilla/firefox/*/key3.db' \
        -o -path '*/.mozilla/firefox/*/logins.json' \
        \) -print0 2>/dev/null)
}

check_system_files() {
    info "Stage 1.9 — sensitive system files"
    local f
    for f in /etc/shadow /etc/gshadow /etc/master.passwd /etc/security/opasswd; do
        [ -e "$f" ] || continue
        record_checked "shadow" "$f"
        if [ -r "$f" ]; then
            scan_file "$f" "shadow"
        else
            record_skip "$f" "unreadable (need root)"
        fi
    done
    [ -e /etc/sudoers ] && scan_file /etc/sudoers "sudoers"
    [ -d /etc/sudoers.d ] && while IFS= read -r -d '' f; do scan_file "$f" "sudoers"
    done < <(find /etc/sudoers.d -maxdepth 1 -type f -print0 2>/dev/null)
    for f in /etc/fstab /etc/exports /etc/anaconda-ks.cfg /root/anaconda-ks.cfg \
             /root/initial-setup-ks.cfg /root/ks.cfg \
             /etc/network/interfaces /etc/dhcp/dhclient.conf \
             /etc/login.defs /etc/security/access.conf; do
        [ -e "$f" ] && scan_file "$f" "system"
    done
    # polkit rules sometimes hardcode service-account passwords
    while IFS= read -r -d '' f; do scan_file "$f" "polkit"
    done < <(find /etc/polkit-1/rules.d /etc/polkit-1/localauthority \
        -maxdepth 3 -type f 2>/dev/null -print0 2>/dev/null)
    # at-jobs + anacron spool (commands often embed creds)
    while IFS= read -r -d '' f; do scan_file "$f" "at_job"
    done < <(find /var/spool/at /var/spool/anacron -maxdepth 2 -type f -print0 2>/dev/null)
}

check_wifi() {
    info "Stage 1.10 — saved Wi-Fi connection profiles"
    local f
    for d in /etc/NetworkManager/system-connections /etc/wpa_supplicant; do
        [ -d "$d" ] || continue
        while IFS= read -r -d '' f; do
            record_checked "wifi" "$f"
            if [ -r "$f" ]; then
                scan_file "$f" "wifi"
            else
                record_skip "$f" "unreadable (need root)"
            fi
        done < <(find "$d" -maxdepth 3 -type f -print0 2>/dev/null)
    done
}

check_misc_services() {
    info "Stage 1.11 — VPN / mail / Kerberos / Samba / FTP / proxy / monitoring / CI configs"
    local f
    for f in /etc/openvpn/auth.txt /etc/openvpn/credentials \
             /etc/openvpn/server.conf /etc/openvpn/client.conf \
             /etc/wireguard/*.conf /etc/strongswan.conf \
             /etc/ipsec.secrets /etc/ppp/chap-secrets /etc/ppp/pap-secrets \
             /etc/postfix/main.cf /etc/postfix/sasl_passwd \
             /etc/dovecot/dovecot.conf /etc/mail/sendmail.cf \
             /etc/krb5.conf /var/kerberos/krb5kdc/kadm5.acl \
             /etc/freeradius/*/clients.conf /etc/raddb/clients.conf \
             /etc/proftpd/proftpd.conf /etc/proftpd/sql.conf \
             /etc/vsftpd.conf /etc/samba/smb.conf /etc/samba/smbpasswd \
             /var/lib/samba/.secrets.keytab /var/lib/samba/private/secrets.tdb \
             /etc/squid/squid.conf /etc/squid/passwords \
             /etc/snmp/snmpd.conf /etc/snmp/snmptrapd.conf \
             /etc/nagios/htpasswd.users /etc/icinga2/conf.d/*.conf \
             /etc/zabbix/zabbix_agentd.conf /etc/zabbix/zabbix_server.conf \
             /etc/proxychains.conf /etc/proxychains4.conf \
             /etc/rsyncd.conf /etc/rsyncd.secrets \
             /etc/security/opasswd /etc/sssd/sssd.conf /etc/sssd/conf.d/* \
             /etc/cifs/credentials /etc/cifs-utils/* \
             /etc/varnish/secret /etc/grafana/grafana.ini \
             /etc/gitlab/gitlab.rb /etc/gitea/conf/app.ini \
             /var/lib/jenkins/credentials.xml \
             /var/lib/jenkins/secrets/master.key \
             /var/lib/jenkins/secret.key \
             /var/lib/jenkins/secrets/hudson.util.Secret \
             /etc/jenkins/* \
             /etc/elasticsearch/elasticsearch.yml /etc/kibana/kibana.yml \
             /var/log/installer/syslog /preseed.cfg /var/log/installer/preseed.cfg; do
        for g in $f; do
            [ -e "$g" ] && scan_file "$g" "service"
        done
    done

    # Cloud-init user-data (often holds first-boot admin password)
    while IFS= read -r -d '' f; do scan_file "$f" "cloud_init"
    done < <(find /var/lib/cloud/instances -maxdepth 3 -type f \( \
        -name 'user-data.txt' -o -name 'user-data' -o -name 'cloud-config' \
        \) -print0 2>/dev/null)

    # VNC / Remmina / desktop-session creds (per user)
    while IFS= read -r -d '' f; do
        case "$(basename "$f")" in
            passwd) record_interest "vnc_passwd_d3des" "$f" ;;  # binary, d3des-encoded
            *.remmina) scan_file "$f" "remmina_session" ;;
        esac
    done < <(find /root /home -maxdepth 5 -type f \( \
        -path '*/.vnc/passwd' -o -path '*/.config/remmina/*.remmina' \
        \) -print0 2>/dev/null)

    # Per-user mail / paging clients
    while IFS= read -r -d '' f; do scan_file "$f" "mail_client"
    done < <(find /root /home -maxdepth 3 -type f \( \
        -name '.msmtprc' -o -name '.fetchmailrc' -o -name '.muttrc' \
        -o -name 'muttrc' -o -name '.netrc' \
        \) -print0 2>/dev/null)

    # Password-store / Gnome Keyring backing dirs (flag only — encrypted)
    while IFS= read -r -d '' f; do record_interest "password_store" "$f"
    done < <(find /root /home -maxdepth 5 -type f \( \
        -path '*/.password-store/*.gpg' \
        -o -path '*/.local/share/keyrings/*.keyring' \
        -o -path '*/.config/keepassxc/*' \
        \) -print0 2>/dev/null)

    # Kerberos keytabs / ticket caches (binary - flag)
    while IFS= read -r -d '' f; do record_interest "kerberos_keytab" "$f"
    done < <(find /etc /root /home /var -maxdepth 4 -type f -name '*.keytab' -print0 2>/dev/null)
    [ -e /etc/krb5.keytab ] && record_interest "kerberos_keytab" /etc/krb5.keytab
    while IFS= read -r -d '' f; do record_interest "krb5_ccache" "$f"
    done < <(find /tmp /var/run -maxdepth 2 -type f -name 'krb5cc_*' -print0 2>/dev/null)
}

check_docker_kube() {
    info "Stage 1.12 — Docker / Kubernetes configuration"
    local f files=(
        /etc/docker/daemon.json /etc/containerd/config.toml
        /var/lib/kubelet/config.yaml /etc/kubernetes/admin.conf
        /etc/kubernetes/kubelet.conf /etc/kubernetes/controller-manager.conf
        /etc/kubernetes/scheduler.conf
    )
    for f in "${files[@]}"; do [ -e "$f" ] && scan_file "$f" "container"; done
    while IFS= read -r -d '' f; do scan_file "$f" "user_container"
    done < <(find /root /home -maxdepth 4 -type f \( \
        -path '*/.docker/config.json' -o -path '*/.kube/config' \
        -o -path '*/.kube/*.yaml' \) -print0 2>/dev/null)
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
    check_home_dotfiles
    check_system_files
    check_wifi
    check_misc_services
    check_docker_kube
    ok "Stage 1 complete."
}

# ============================================================================
#  Filename / extension data + exclusion paths
# ============================================================================

# Stage 2: extensions whose presence ALONE confirms credential material.
GUARANTEED_CRED_EXTS=(
    kdbx kdb psafe3 agilekeychain opvault 1pif 1pux lpdb enpass enpassdb
    bitwarden_export ppk pfx p12 pvk jks keystore truststore bek fve keytab dpapimk
)

# Stage 3: strong signal but ambiguous (could be public cert / non-cred binary)
HIGH_VALUE_EXTS=(
    pem key priv asc gpg wallet rdp ovpn

    # Session managers / VPN profiles
    rdg rdcman rtsz remmina pcf tblk

    # VMware Workstation .vmx files (displayName.passwd, encoded.password)
    vmx

    # Outlook archives
    pst ost

    # Office docs (admins paste creds in these)
    doc docx docm dot dotx dotm xls xlsx xlsm xlsb xlt xltx xltm
    ppt pptx pptm pps ppsx odt ods odp odg pdf one onetoc2

    # Binary databases
    mdb accdb bacpac dacpac mdf ldf frm myd sqlite sqlite3 db db3

    # Registry hives & memory / process / crash dumps
    hive hiv dmp mdmp crash core
)

# Stage 4a: exact filename matches — every entry is a known credential file
EXACT_CRED_FILENAMES=(
    .bash_history .zsh_history .sh_history .ksh_history .history .ash_history
    .psql_history .mysql_history .sqlite_history .python_history
    .node_repl_history .irb_history .rediscli_history .lesshst .viminfo .wget-hsts
    .netrc .pgpass .my.cnf my.cnf .mysql.cnf .dbshell .mongorc.js
    .pypirc .npmrc .gitconfig .git-credentials .gitcredentials
    .htpasswd .htaccess shadow gshadow passwd sudoers master.passwd
    login.defs auth.log secure pam.conf smb.conf smbpasswd freerdp
    wgetrc .wgetrc curlrc .curlrc
    id_rsa id_dsa id_ecdsa id_ed25519 id_xmss
    authorized_keys authorized_keys2 known_hosts ssh_config sshd_config
    SAM SYSTEM SECURITY SOFTWARE NTUSER.DAT NTDS.dit
    SYSTEM.SAV SECURITY.SAV SAM.SAV
    unattend.xml unattended.xml autounattend.xml sysprep.xml sysprep.inf
    Groups.xml Services.xml Scheduledtasks.xml DataSources.xml Printers.xml Drives.xml
    web.config wp-config.php wp-config.bak wp-config.old
    wp-config.php.bak wp-config.php.old wp-config.php.save
    configuration.php settings.php local.xml config.inc.php config.php
    db.php database.php connect.php connection.php
    appsettings.json appsettings.Production.json appsettings.Development.json
    connection.config machine.config hibernate.cfg.xml persistence.xml
    context.xml tomcat-users.xml standalone.xml server.xml
    mgmt-users.properties application.properties application.yml application.yaml
    bootstrap.yml bootstrap.yaml
    pg_hba.conf postgresql.conf my.ini mongod.conf redis.conf
    elasticsearch.yml kibana.yml tnsnames.ora sqlnet.ora listener.ora wallet.dat
    winscp.ini WinSCP.ini putty.reg sitemanager.xml recentservers.xml
    filezilla.xml queue.xml confCons.xml mRemoteNG.xml default.rdg RDCMan.settings
    .env .env.local .env.dev .env.development .env.prod .env.production
    .env.staging .env.test .env.backup .env.bak .env.old .env.save
    .env.example .env.sample env.production env.development
    .vault_pass vault_pass.txt .ansible_vault

    # ── Research adds (HTB/THM/PG/real-engagement staples) ──────────────
    tomcat-users.xml                # HTB Tabby — Tomcat manager
    credentials.xml                 # Jenkins $JENKINS_HOME/credentials.xml
    master.key secret.key           # Jenkins secrets/master.key & secret.key
    hudson.util.Secret              # Jenkins encrypted secret
    SiteList.xml                    # McAfee Common Framework
    applicationHost.config          # IIS
    KeePass.config.xml KeePass.config.enforced.xml
    grafana.ini gitlab.rb app.ini   # Grafana / GitLab / Gitea
    accounts.xml                    # Pidgin / .purple
    secrets.tdb                     # Samba LSA secrets
    user-data.txt cloud-config      # cloud-init artefacts
    ks.cfg initial-setup-ks.cfg     # Anaconda kickstart (RHEL)
    preseed.cfg                     # Debian/Ubuntu preseed
    opasswd                         # /etc/security/opasswd (password history)
    sssd.conf                       # LDAP bind passwords
    .pcf .tblk                      # Cisco AnyConnect / Tunnelblick VPN
)

# Stage 4b: substring fragments (case-insensitive, broader)
SUSPICIOUS_NAMES=(
    password passwd pwd passphrase passcode
    credential creds vault secret
    htpasswd netrc pgpass
    db_pass database_password dbpass
    masterkey master_password masterpass sshpass
    pwdump kerberoast asreproast hashdump mimikatz lsass
    keepass
    sshkey ssh_key sshconfig ssh_config
    winscp putty filezilla mremoteng rdcman
    ansible_vault vault_pass
    smbpasswd
    autologon
    unattend sysprep autounattend
    wp_config wp-config wpconfig

    # ── Research-derived adds (Snaffler classifiers, 0xdf writeups,
    #    BHIS file-share triage, real internal-engagement loot) ─────────
    handover onboarding offboarding newhire helpdesk runbook
    "as-built"
    "build sheet" "build_sheet" buildsheet
    "new hire" new_hire
    "reset password" reset_password password_recovery password_reset
    "it master" it_master
    "domain admin" domain_admin
    "service account" service_account svc_account svcaccount svcacct
    "domain join" domain_join
    "local admin" local_admin
    "break glass" break_glass breakglass
    "default password" default_password defaultpass
    naa snmp_community
)

# Stage 5 search extensions — text formats commonly carrying passwords
SEARCH_EXTS=(
    # Configuration & structured data
    conf config cfg cnf ini env envrc
    yaml yml toml json jsonc json5 xml plist
    properties prop props settings
    tf tfvars tfstate hcl
    # Shell & scripting
    sh bash zsh ksh csh fish profile bashrc zshrc
    ps1 psm1 psd1 ps1xml bat cmd vbs vbe wsf wsh ahk
    # Source code commonly carrying hardcoded passwords
    py pl rb php phtml php3 php5 lua groovy tcl coffee
    java cs vb go rs c cpp h hpp
    js ts jsx tsx mjs cjs
    # Web app files
    aspx asp ashx asmx asax ascx cshtml vbhtml
    jsp jspx jspf cfm cfc htm html htaccess
    # Database / connection (text)
    sql ddl dump dsn udl ora tns
    # Windows-specific text formats
    reg pol rdp rdg rdcman inf unattend answerfile
    # Remote access tools
    ovpn openvpn vnc rdc tcc ica session kix
    # Plain text / notes
    txt text md markdown rtf nfo log logs readme
    # Backups / temp / cached configs
    bak backup old orig original save saved tmp temp cache
    # Data exports / directory dumps
    csv tsv ldif ldiff
    # systemd / cron
    service unit timer socket crontab cron
    # Variant config suffixes
    local shared template example sample dist
)

# Directories never to descend into (matched by basename anywhere in tree)
EXCLUDE_DIR_NAMES=(
    .git .hg .svn .bzr CVS _darcs
    node_modules .npm .pnpm-store .yarn .yarn-cache .bun
    .venv venv env .pyenv .virtualenvs __pycache__
    .mypy_cache .pytest_cache .tox .nox .ruff_cache
    site-packages dist-packages vendor bower_components
    .terraform .terragrunt-cache .gradle .m2 .ivy2 .sbt
    target dist build out coverage .next .nuxt obj
    .cache .ccache .npm-cache .composer
    .idea .vscode .vs .history
    .Trash .Spotlight-V100 .fseventsd .DocumentRevisions-V100
    WinSxS
)

# Absolute path prefixes never to descend into
EXCLUDE_PATHS=(
    /proc /sys /dev /run /run/user /run/lock
    /boot /lost+found
    /snap /var/lib/snapd /var/lib/flatpak
    /usr/share /usr/lib /usr/lib32 /usr/lib64 /usr/libexec
    /usr/include /usr/src
    /lib /lib32 /lib64 /libexec
    /var/cache /var/lib/dpkg /var/lib/rpm /var/lib/apt /var/lib/yum
    /var/lib/docker/overlay2 /var/lib/docker/aufs /var/lib/docker/btrfs
    /var/lib/docker/devicemapper /var/lib/docker/zfs /var/lib/docker/tmp
    /var/lib/docker/buildkit /var/lib/docker/image
    /var/lib/containerd /var/lib/buildah
    /var/log
    /tmp/.X11-unix /tmp/.ICE-unix /tmp/.font-unix
)

# ============================================================================
#  Stages 2-5 — recursive scanning of user-supplied paths
# ============================================================================

build_find_excludes() {
    # Compose once, reuse forever.
    [ -n "$FIND_EXCLUDES_CACHE" ] && { printf '%s' "$FIND_EXCLUDES_CACHE"; return; }
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
    if [ -n "$exprs" ]; then
        FIND_EXCLUDES_CACHE=$(printf -- '\\( %s \\) -prune -o' "$exprs")
    fi
    printf '%s' "$FIND_EXCLUDES_CACHE"
}

# Stage 2 — confirmed credential containers
find_guaranteed_credentials() {
    section "Stage 2 — Confirmed credential containers"
    local path e ext_expr="" first=1
    for e in "${GUARANTEED_CRED_EXTS[@]}"; do
        if [ "$first" -eq 1 ]; then
            ext_expr=" \( -iname '*.${e}'"; first=0
        else
            ext_expr+=" -o -iname '*.${e}'"
        fi
    done
    ext_expr+=" \)"
    local excludes; excludes=$(build_find_excludes)
    local count=0
    for path in "${SCAN_PATHS[@]}"; do
        [ -e "$path" ] || continue
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            local ext_only="${f##*.}"
            record_guaranteed "${ext_only,,}" "$f"
            count=$((count + 1))
        done < <(eval "find \"$path\" $excludes -type f $ext_expr -print" 2>/dev/null)
    done
    if [ -s "$GUARANTEED_FILE" ]; then
        sort -u "$GUARANTEED_FILE" -o "$GUARANTEED_FILE"
        count=$(wc -l <"$GUARANTEED_FILE" | tr -d ' ')
    fi
    if [ "$count" -gt 0 ]; then
        ok "Found ${R}${BOLD}${count}${NC} ${R}confirmed credential container(s)${NC}."
    else
        ok "Found ${W}0${NC} confirmed credential containers."
    fi
}

# Stage 3 — auxiliary credential-related files
find_high_value_files() {
    section "Stage 3 — Auxiliary credential-related files"
    local path e ext_expr="" first=1
    for e in "${HIGH_VALUE_EXTS[@]}"; do
        if [ "$first" -eq 1 ]; then
            ext_expr=" \( -iname '*.${e}'"; first=0
        else
            ext_expr+=" -o -iname '*.${e}'"
        fi
    done
    ext_expr+=" \)"
    local excludes; excludes=$(build_find_excludes)
    local count=0
    for path in "${SCAN_PATHS[@]}"; do
        [ -e "$path" ] || continue
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            record_interest "credential_related" "$f"
            count=$((count + 1))
        done < <(eval "find \"$path\" $excludes -type f $ext_expr -print" 2>/dev/null)
    done
    ok "Found ${W}${count}${NC} auxiliary credential-related file(s)."
}

# Stage 4 — filename detection (exact + substring, single tree walk)
find_suspicious_filenames() {
    section "Stage 4 — Filename patterns"
    local path n expr_exact="" expr_sub="" first=1 f
    for n in "${EXACT_CRED_FILENAMES[@]}"; do
        if [ "$first" -eq 1 ]; then
            expr_exact=" \( -iname '${n}'"; first=0
        else
            expr_exact+=" -o -iname '${n}'"
        fi
    done
    expr_exact+=" \)"
    first=1
    for n in "${SUSPICIOUS_NAMES[@]}"; do
        if [ "$first" -eq 1 ]; then
            expr_sub=" \( -iname '*${n}*'"; first=0
        else
            expr_sub+=" -o -iname '*${n}*'"
        fi
    done
    expr_sub+=" \)"

    local excludes; excludes=$(build_find_excludes)

    # Exact pass
    for path in "${SCAN_PATHS[@]}"; do
        [ -e "$path" ] || continue
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            record_exact "$f"
        done < <(eval "find \"$path\" -mindepth 1 $excludes $expr_exact -print" 2>/dev/null)
    done
    [ -s "$EXACT_FILE" ] && sort -u "$EXACT_FILE" -o "$EXACT_FILE"
    local exact_count=0
    [ -s "$EXACT_FILE" ] && exact_count=$(wc -l <"$EXACT_FILE" | tr -d ' ')
    if [ "$exact_count" -gt 0 ]; then
        ok "Found ${R}${BOLD}${exact_count}${NC} ${R}credential-named file(s)${NC} (exact)."
    else
        ok "Found ${W}0${NC} credential-named files (exact)."
    fi

    # Substring pass (dedup against exact)
    local raw="$TMPDIR/names.raw"
    : >"$raw"
    for path in "${SCAN_PATHS[@]}"; do
        [ -e "$path" ] || continue
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            printf '%s\n' "$f" >>"$raw"
        done < <(eval "find \"$path\" -mindepth 1 $excludes $expr_sub -print" 2>/dev/null)
    done
    sort -u "$raw" -o "$raw"
    if [ -s "$EXACT_FILE" ] && [ -s "$raw" ]; then
        comm -23 "$raw" "$EXACT_FILE" >"$NAME_FILE"
    else
        cp "$raw" "$NAME_FILE"
    fi
    local sub_count=0
    [ -s "$NAME_FILE" ] && sub_count=$(wc -l <"$NAME_FILE" | tr -d ' ')
    ok "Found ${W}${sub_count}${NC} suspicious-name pattern match(es)."
}

# Stage 5 — recursive content scan of extension-matched candidates
enumerate_candidates() {
    local path size_bytes size_filter=""
    size_bytes=$((MAX_FILE_SIZE_MB * 1024 * 1024))
    [ "$SKIP_LARGE" -eq 1 ] && size_filter="-size -${size_bytes}c"
    local excludes; excludes=$(build_find_excludes)
    for path in "${SCAN_PATHS[@]}"; do
        [ -e "$path" ] || { warn "Path does not exist: $path"; continue; }
        if [ "$ALL_MODE" -eq 1 ]; then
            # shellcheck disable=SC2046
            find "$path" $excludes -type f $size_filter -print 2>/dev/null
        else
            local ext_expr=""
            local first=1 e
            for e in "${SEARCH_EXTS[@]}"; do
                if [ "$first" -eq 1 ]; then
                    ext_expr=" \( -iname '*.${e}'"; first=0
                else
                    ext_expr+=" -o -iname '*.${e}'"
                fi
            done
            ext_expr+=" -o -iname 'Dockerfile' -o -iname 'Vagrantfile' -o -iname 'Makefile' -o -iname 'Jenkinsfile'"
            ext_expr+=" -o -iname '.env*' -o -iname '*rc' -o -iname 'authorized_keys'"
            ext_expr+=" -o -iname 'id_rsa' -o -iname 'id_dsa' -o -iname 'id_ecdsa'"
            ext_expr+=" -o -iname 'id_ed25519' -o -iname 'identity' -o -iname 'id_*'"
            ext_expr+=" -o -iname '.htpasswd' -o -iname 'htpasswd' -o -iname 'shadow'"
            ext_expr+=" -o -iname '.netrc' -o -iname '_netrc' -o -iname '.git-credentials'"
            ext_expr+=" -o -iname '.gitconfig' -o -iname '.npmrc' -o -iname '.pypirc'"
            ext_expr+=" -o -iname '.s3cfg' -o -iname '.boto' -o -iname '.viminfo'"
            ext_expr+=" -o -iname '.psqlrc' -o -iname '.mysqlrc' -o -iname '.my.cnf'"
            # Shell/tool history files frequently contain command-line creds
            # (sshpass -p, mysql -pXXX, PGPASSWORD=, curl -u, etc.)
            ext_expr+=" -o -iname '.bash_history' -o -iname '.zsh_history' -o -iname '.sh_history'"
            ext_expr+=" -o -iname '.ksh_history' -o -iname '.ash_history' -o -iname '.history'"
            ext_expr+=" -o -iname '.psql_history' -o -iname '.mysql_history' -o -iname '.sqlite_history'"
            ext_expr+=" -o -iname '.python_history' -o -iname '.node_repl_history'"
            ext_expr+=" -o -iname '.irb_history' -o -iname '.rediscli_history' -o -iname '.lesshst' \)"
            # shellcheck disable=SC2046
            eval "find \"$path\" $excludes -type f $size_filter $ext_expr -print" 2>/dev/null
        fi
    done
}

scan_user_paths_contents() {
    section "Stage 5 — File-content scan"
    [ ${#SCAN_PATHS[@]} -eq 0 ] && { warn "No paths provided; skipping."; return; }
    info "Enumerating candidate files…"
    enumerate_candidates >"$CANDIDATE_FILES" 2>/dev/null
    [ -s "$CANDIDATE_FILES" ] && sort -u "$CANDIDATE_FILES" -o "$CANDIDATE_FILES"
    local total
    total=$(wc -l <"$CANDIDATE_FILES" | tr -d ' ')
    if [ "$total" -eq 0 ]; then
        warn "No candidate files found in the supplied paths."
        return
    fi
    ok "Candidate files: ${W}${total}${NC}  (mode: $( [ "$ALL_MODE" -eq 1 ] && echo all || echo extensions ))"
    local current=0
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        current=$((current + 1))
        draw_progress "$current" "$total" "Scanning"
        scan_file "$f" "content"
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

render_findings() {
    local file="$1" tag="$2" color="$3"
    [ ! -s "$file" ] && return 0
    sort -u "$file" -o "$file"
    local label path lineno preview
    while IFS=$'\t' read -r label path lineno preview; do
        printf '  %b[%s]%b %b%s%b  %s%s:%s%s\n' \
            "$color" "$tag" "$NC" "$D" "$label" "$NC" "$Y" "$path" "$lineno" "$NC"
        printf '       %b%s%b\n' "$D" "$preview" "$NC"
        log_line "[$tag] $label $path:$lineno  $preview"
    done <"$file"
}

print_summary() {
    section "Findings"

    if [ -s "$GUARANTEED_FILE" ]; then
        print_section_header "Confirmed credential containers  ⚠"
        sort -u "$GUARANTEED_FILE" -o "$GUARANTEED_FILE"
        local ext path
        while IFS=$'\t' read -r ext path; do
            printf '  %b%b[CRITICAL]%b %b%-8s%b  %b%s%b\n' \
                "$BOLD" "$R" "$NC" "$D" "$ext" "$NC" "$W" "$path" "$NC"
            log_line "[CRITICAL] $ext  $path"
        done <"$GUARANTEED_FILE"
    fi

    if [ -s "$HIGH_FILE" ]; then
        print_section_header "Reusable credentials"
        render_findings "$HIGH_FILE" "HIGH" "$R"
    fi

    if [ -s "$KEY_FILE" ]; then
        print_section_header "Private keys & authentication material"
        render_findings "$KEY_FILE" "KEY" "$M"
    fi

    if [ -s "$INTEREST_FILE" ]; then
        print_section_header "Auxiliary credential-related files"
        sort -u "$INTEREST_FILE" -o "$INTEREST_FILE"
        local cat path
        while IFS=$'\t' read -r cat path; do
            printf '  %b[INTEREST]%b %b%s%b  %s\n' "$C" "$NC" "$D" "$cat" "$NC" "$path"
            log_line "[INTEREST] $cat  $path"
        done <"$INTEREST_FILE"
    fi

    if [ -s "$EXACT_FILE" ]; then
        print_section_header "Credential-named files (exact match)"
        local f
        while IFS= read -r f; do
            printf '  %b[CRED_FILE]%b %s\n' "$R" "$NC" "$f"
            log_line "[CRED_FILE] $f"
        done <"$EXACT_FILE"
    fi

    if [ -s "$NAME_FILE" ]; then
        print_section_header "Suspicious filenames (substring match)"
        local f
        while IFS= read -r f; do
            printf '  %b[NAME]%b %s\n' "$Y" "$NC" "$f"
            log_line "[NAME] $f"
        done <"$NAME_FILE"
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
        local n
        n=$(wc -l <"$SKIPPED_FILE" | tr -d ' ')
        printf '  %b[SKIP]%b %d file(s) skipped (binary / size / unreadable). See log.\n' \
            "$D" "$NC" "$n"
        log_line ""
        log_line "Skipped files:"
        local path reason
        while IFS=$'\t' read -r path reason; do
            log_line "[SKIP] $reason  $path"
        done <"$SKIPPED_FILE"
    fi

    # Counts
    local n_guar n_high n_key n_int n_exact n_name n_check n_skip
    n_guar=$( [ -s "$GUARANTEED_FILE" ] && wc -l <"$GUARANTEED_FILE" | tr -d ' ' || echo 0)
    n_high=$( [ -s "$HIGH_FILE" ]    && wc -l <"$HIGH_FILE"    | tr -d ' ' || echo 0)
    n_key=$(  [ -s "$KEY_FILE" ]     && wc -l <"$KEY_FILE"     | tr -d ' ' || echo 0)
    n_int=$(  [ -s "$INTEREST_FILE" ]&& wc -l <"$INTEREST_FILE"| tr -d ' ' || echo 0)
    n_exact=$([ -s "$EXACT_FILE" ]   && wc -l <"$EXACT_FILE"   | tr -d ' ' || echo 0)
    n_name=$( [ -s "$NAME_FILE" ]    && wc -l <"$NAME_FILE"    | tr -d ' ' || echo 0)
    n_check=$([ -s "$CHECKED_FILE" ] && wc -l <"$CHECKED_FILE" | tr -d ' ' || echo 0)
    n_skip=$( [ -s "$SKIPPED_FILE" ] && wc -l <"$SKIPPED_FILE" | tr -d ' ' || echo 0)

    section "Summary"
    printf '  %b%-44s %s%b\n' "$BOLD" "Category" "Count" "$NC"
    printf '  %s\n' "────────────────────────────────────────────  ─────"
    printf '  %b%b%-44s %5d%b\n' "$BOLD" "$R" "Confirmed credential containers ⚠" "$n_guar" "$NC"
    printf '  %b%-44s %5d%b\n' "$R" "Reusable credentials"                "$n_high"  "$NC"
    printf '  %b%-44s %5d%b\n' "$M" "Private keys / auth material"        "$n_key"   "$NC"
    printf '  %b%-44s %5d%b\n' "$C" "Auxiliary credential-related files"  "$n_int"   "$NC"
    printf '  %b%-44s %5d%b\n' "$R" "Credential-named files (exact)"      "$n_exact" "$NC"
    printf '  %b%-44s %5d%b\n' "$Y" "Suspicious filenames (substring)"    "$n_name"  "$NC"
    printf '  %b%-44s %5d%b\n' "$B" "OS locations checked"                "$n_check" "$NC"
    printf '  %b%-44s %5d%b\n' "$D" "Files skipped (size/binary/perm)"    "$n_skip"  "$NC"
    printf '  %s\n' "────────────────────────────────────────────  ─────"

    log_line ""
    log_line "Summary:"
    log_line "  Confirmed credential containers: $n_guar"
    log_line "  Reusable credentials:            $n_high"
    log_line "  Private keys / material:         $n_key"
    log_line "  Auxiliary credential-related:    $n_int"
    log_line "  Credential-named files (exact):  $n_exact"
    log_line "  Suspicious filenames (substring):$n_name"
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
    build_combined_regex   # build the merged alternation regex once
    print_banner

    if [ "$SKIP_LARGE" -eq 1 ]; then
        info "Size cap: skipping files larger than ${W}${MAX_FILE_SIZE_MB} MB${NC}  (use -m N or --no-size-limit)"
    else
        warn "Size cap disabled (--no-size-limit) — every readable file will be inspected."
    fi

    if [ "${#USER_EXCLUDE_PATHS[@]}" -gt 0 ]; then
        info "User exclusions (${W}${#USER_EXCLUDE_PATHS[@]}${NC}) — applied to stages 2-5 only:"
        local p
        for p in "${USER_EXCLUDE_PATHS[@]}"; do
            printf '       %b- %s%b\n' "$D" "$p" "$NC" >&2
        done
    fi

    if [ "$SKIP_SYSTEM" -eq 0 ]; then
        run_system_checks
    else
        warn "Skipping OS-level checks (per --skip-system)."
    fi

    if [ ${#SCAN_PATHS[@]} -eq 0 ]; then
        warn "No paths supplied (-p). Skipping stages 2-5."
        warn "Tip: pass -p / to scan everything under root."
    else
        find_guaranteed_credentials
        find_high_value_files
        find_suspicious_filenames
        scan_user_paths_contents
    fi

    print_summary

    if [ -s "$GUARANTEED_FILE" ] || [ -s "$HIGH_FILE" ] || \
       [ -s "$KEY_FILE" ]       || [ -s "$EXACT_FILE" ]; then
        exit 1
    fi
    exit 0
}

main "$@"
