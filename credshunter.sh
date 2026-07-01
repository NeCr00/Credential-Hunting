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
# Capture the user's real locale for glyph selection BEFORE forcing LC_ALL=C
# below -- the C override is for deterministic regex/sort only and must not
# downgrade the UI to ASCII on a UTF-8 terminal.
USER_LOCALE="${LC_ALL:-${LC_CTYPE:-${LANG:-}}}"
export LC_ALL=C   # consistent regex / sort behavior regardless of host locale

# Case-insensitive matching for bash [[ =~ ]] and `case` patterns. Our regex
# library is written in lowercase; without nocasematch, classify_line would
# miss content like "Password=..." even though grep -i finds it.
shopt -s nocasematch 2>/dev/null || true

VERSION="2.4.0"

# Pre-initialise color vars so `err()` and friends work BEFORE setup_colors
# runs (e.g. when parse_args reports a bad flag).
R='' G='' Y='' B='' M='' C='' W='' D='' BOLD='' NC=''
# Pre-initialise glyphs (ASCII) so any output before setup_glyphs is safe.
GH='-' GHV='=' GTL='+' GTR='+' GBL='+' GBR='+'
GBRANCH='+-' GBUL='>' GDOT='-' GELL='...' GWARN='!' GARROW='->'

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
STAGE1_SKIP=0
STAGE2_SKIP=0
STAGE3_SKIP=0
STAGE4_SKIP=0
STAGE5_SKIP=0
NO_COLOR_FLAG=0
SCAN_PATHS=()
USER_EXCLUDE_PATHS=()
OUTPUT_FILE=""
MAX_MATCHES_PER_FILE=20
# Findings output is NEVER truncated -- the full matched secret is always shown
# in the grouped Findings section and written to the -o log. The live per-stage
# feed caps each preview at LIVE_PREVIEW_LEN purely so a pathological multi-KB
# minified / base64 / log line cannot flood the terminal; any real credential is
# far shorter and shown whole, and the complete value is always in Findings.
LIVE_PREVIEW_LEN=2000
# Longest line classify_line will inspect. Real credential lines are short; a
# multi-KB minified/base64/log line would otherwise pin the per-pattern regex
# loop. 16 KB comfortably covers single-line GPP Groups.xml / one-line JSON
# connection strings while bounding worst-case CPU. Mirrored in the PS engine.
MAX_LINE_LEN=16384
# Upper bound on regex-matching lines fed to classify_line per file. The real
# finding cap is MAX_MATCHES_PER_FILE (post-FP); this only bounds pathological
# files where thousands of lines match the prefilter but are all false
# positives, so a genuine credential after them is still reached and reported.
PREFILTER_LINE_CAP=5000

# Stage-1 live-output state. When IN_STAGE1=1, the record_* helpers stream
# each finding to stderr as it's discovered so the operator sees results in
# real time. SUBSTAGE_FINDINGS is reset before each substage runs; if it is
# still 0 when the substage returns, a "no credentials found" line is shown.
IN_STAGE1=0
SUBSTAGE_FINDINGS=0

# ----------------------------------------------------------------------------
#  Temp workspace + per-path dedup
# ----------------------------------------------------------------------------
TMPDIR="$(mktemp -d -t credshunter.XXXXXX 2>/dev/null || mktemp -d /tmp/credshunter.XXXXXX)"
HIGH_FILE="$TMPDIR/high.tsv"
KEY_FILE="$TMPDIR/keys.tsv"
NAME_FILE="$TMPDIR/names.tsv"
INTEREST_FILE="$TMPDIR/interest.tsv"
GUARANTEED_FILE="$TMPDIR/guaranteed.tsv"
SKIPPED_FILE="$TMPDIR/skipped.tsv"
CHECKED_FILE="$TMPDIR/checked.tsv"
CANDIDATE_FILES="$TMPDIR/candidates.lst"
touch "$HIGH_FILE" "$KEY_FILE" "$NAME_FILE" \
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

# Box-drawing glyphs: Unicode when the locale advertises UTF-8, ASCII fallback
# otherwise so legacy / C-locale terminals never render mojibake. Mirrored in
# the PowerShell engine (Set-Glyphs).
setup_glyphs() {
    case "${USER_LOCALE:-}" in
        *UTF-8*|*UTF8*|*utf-8*|*utf8*) USE_UNICODE=1 ;;
        *)                             USE_UNICODE=0 ;;
    esac
    if [ "$USE_UNICODE" -eq 1 ]; then
        GH='─'; GHV='═'; GTL='╭'; GTR='╮'; GBL='╰'; GBR='╯'
        GBRANCH='└─'; GBUL='▸'; GDOT='·'; GELL='…'; GWARN='⚠'; GARROW='→'
    else
        GH='-'; GHV='='; GTL='+'; GTR='+'; GBL='+'; GBR='+'
        GBRANCH='+-'; GBUL='>'; GDOT='-'; GELL='...'; GWARN='!'; GARROW='->'
    fi
}

# Echo a horizontal rule: $1 repeated $2 times (display-column safe -- each
# glyph is one column, so counts align in either glyph set).
hbar() { local ch="$1" n="$2" s='' i; for ((i=0; i<n; i++)); do s+="$ch"; done; printf '%s' "$s"; }

# One Summary row with a dotted leader: "  Label ........... 12"
# The script runs under LC_ALL=C, so ${#label} counts BYTES; the warning glyph
# is multi-byte under Unicode (3 bytes, 1 display column). Correct its width so
# the count column stays aligned -- and byte-identical to the PowerShell engine,
# whose .Length already counts the glyph as one unit.
sum_row() {
    local color="$1" label="$2" cnt="$3" col=50 dots dispw=${#2}
    case "$label" in *"$GWARN"*) dispw=$(( dispw - ${#GWARN} + 1 )) ;; esac
    dots=$(( col - dispw - 1 )); [ "$dots" -lt 1 ] && dots=1
    printf '  %b%s %s %5s%b\n' "$color" "$label" "$(hbar '.' "$dots")" "$cnt" "$NC"
}

info()    { [ "$QUIET" -eq 0 ] && printf '%b[*]%b %b\n' "$B" "$NC" "$*" >&2; }
ok()      { [ "$QUIET" -eq 0 ] && printf '%b[+]%b %b\n' "$G" "$NC" "$*" >&2; }
warn()    { printf '%b[!]%b %b\n' "$Y" "$NC" "$*" >&2; }
err()     { printf '%b[x]%b %b\n' "$R" "$NC" "$*" >&2; }
section() {
    local title="$1" tw=66 fill
    fill=$(( tw - 6 - ${#title} )); [ "$fill" -lt 3 ] && fill=3
    printf '\n  %b%s %s %s%b\n' "${BOLD}${C}" "$(hbar "$GHV" 2)" "$title" "$(hbar "$GHV" "$fill")" "$NC" >&2
}

# Stream a single Stage-1 finding to stderr as it is recorded.
#   Args: TIER LABEL PATH [LINE]
# TIER ∈ {CRITICAL HIGH KEY INTEREST NAME}. Increments
# SUBSTAGE_FINDINGS so the wrapper knows the substage produced output.
stage1_emit() {
    [ "$QUIET" -eq 1 ] && return
    local tier="$1" label="$2" path="$3" line="${4:-0}" preview="${5:-}"
    local color="$R"
    case "$tier" in
        CRITICAL|HIGH)            color="$R" ;;
        KEY)                      color="$M" ;;
        INTEREST|NAME)            color="$Y" ;;
    esac
    if [ "${line:-0}" -gt 0 ] 2>/dev/null; then
        printf '%b   %s [%s]%b %s %s %s:%s\n' "$color" "$GBRANCH" "$tier" "$NC" "$label" "$GARROW" "$path" "$line" >&2
    else
        printf '%b   %s [%s]%b %s %s %s\n' "$color" "$GBRANCH" "$tier" "$NC" "$label" "$GARROW" "$path" >&2
    fi
    # Show the matched content/command inline (dim) so the operator can verify
    # an embedded credential live, even when the value lives in the preview.
    # Live feed only: capped (never the Findings section / log).
    if [ -n "$preview" ] && [ "$preview" != "$path" ]; then
        printf '%b        %s%b\n' "$D" "$(live_preview "$preview")" "$NC" >&2
    fi
    SUBSTAGE_FINDINGS=$((SUBSTAGE_FINDINGS + 1))
}

# Wrapper: run a Stage-1 substage and print a tidy "nothing here" line if
# the substage produced zero findings. Keeps every check_* function
# untouched — they only need to call record_finding / record_interest.
run_stage1_check() {
    SUBSTAGE_FINDINGS=0
    "$@"
    if [ "$SUBSTAGE_FINDINGS" -eq 0 ] && [ "$QUIET" -eq 0 ]; then
        printf '%b   %s no credentials found in this category%b\n' "$D" "$GBRANCH" "$NC" >&2
    fi
}

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
    local label=' credshunter ' span=62 top bot
    top="${GTL}$(hbar "$GH" 1)${label}$(hbar "$GH" $(( span - 1 - ${#label} )))${GTR}"
    bot="${GBL}$(hbar "$GH" "$span")${GBR}"
    {
        printf '\n'
        printf '  %b%s%b\n'                        "${C}${BOLD}" "$top" "$NC"
        printf '     %breusable-credential discovery %s v%s %s Linux%b\n' "$W" "$GDOT" "$VERSION" "$GDOT" "$NC"
        printf '     %bauthorized testing only %s read-only%b\n'          "$D" "$GDOT" "$NC"
        printf '  %b%s%b\n'                        "${C}${BOLD}" "$bot" "$NC"
        printf '\n'
    } >&2
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
      --no-stage1       Same as --skip-system (alias).
      --no-stage2       Skip stage 2 (confirmed credential containers).
      --no-stage3       Skip stage 3 (high-value file types).
      --no-stage4       Skip stage 4 (filename substring search).
      --no-stage5       Skip stage 5 (recursive content scan).
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
  0 = nothing sensitive found (INTEREST / NAME alone do not change the code)
  1 = at least one CRITICAL / HIGH / KEY finding
  2 = argument / I/O error
  130 = interrupted (Ctrl+C / SIGTERM)
EOF
}

# ============================================================================
#  USER-CUSTOMIZABLE PATTERN LISTS
#
#  Edit the arrays below to add or remove what each stage flags. NO OTHER
#  changes are required when you tweak these.
#
#  All matching is case-insensitive. Stage 2/3 use `find -iname`;
#  Stage 4 uses bash substring match.
# ============================================================================

# -- Stage 2 -- confirmed credential containers (match alone = [CRITICAL]) ----
STAGE2_EXTENSIONS=(
    kdbx kdb psafe3 agilekeychain opvault 1pif 1pux lpdb enpass enpassdb
    bitwarden_export ppk pfx p12 pvk jks keystore truststore bek fve keytab
    dpapimk
)

# -- Stage 3 -- high-value file types (match = [INTEREST]) -------------------
# Files matching these are surfaced but not auto-classified as credentials.
STAGE3_EXTENSIONS=(
    # SSH / TLS private key formats
    pem key priv crt cer csr
    # App-secret dotfile extensions
    env envrc
    # Kerberos (also in STAGE2_EXTENSIONS — Stage 3 runtime dedups
    # against Stage 2 findings, so this is harmless duplication kept for
    # discoverability when editing this file)
    keytab
    # Shell scripts
    sh bash
    # Backup / scratch / saved variants
    bak old orig backup swp save
    # SQLite databases (text caches dropped -- see SKIP_DB_BASENAMES filter)
    db sqlite sqlite3
    # Log files (admins sometimes paste pw into custom logs)
    log
    # Packet captures (may contain plaintext auth)
    pcap pcapng
    # Compressed archives (admin backups often contain creds)
    tar tgz gz zip 7z
)

# Exact filename matches for Stage 3 (names that cannot be expressed as
# a simple *.ext glob -- includes dotfiles like .netrc and config files
# like krb5.conf / my.cnf)
STAGE3_EXACT_NAMES=(
    krb5.conf
    .htpasswd .netrc .pgpass .my.cnf my.cnf .mysql.cnf
)

# Glob patterns for Stage 3 (used as `find -iname '<pattern>'`)
# Note: '*.tar.gz' is covered by the 'gz' entry in STAGE3_EXTENSIONS, but
# kept here so users can toggle tarball-handling independently of raw .gz.
STAGE3_GLOB_PATTERNS=(
    'krb5cc_*'
    '*.tar.gz'
    '.env.*'
)

# -- Stage 4 -- filename substring tokens (match = [NAME]) -------------------
# Any filename containing one of these tokens (case-insensitive) is flagged.
# Keep this list short: each entry is a substring, so loose entries balloon
# the false-positive rate.
STAGE4_NAME_TOKENS=(
    credential secret pass password passwd account login
)

# -- Stage 5 -- content-scan extension allow-list ----------------------------
# Recursive credential-pattern scan runs ONLY on files with one of these
# extensions (unless --all is passed).
STAGE5_EXTENSIONS=(
    # Configuration & structured data
    conf config cfg cnf ini env envrc
    yaml yml toml json jsonc json5 xml plist
    properties prop props settings
    tf tfvars tfstate hcl
    # Shell & scripting
    sh bash zsh ksh csh fish profile bashrc zshrc
    ps1 psm1 psd1 ps1xml bat cmd vbs vbe wsf wsh ahk
    # Source code commonly carrying hardcoded passwords
    py pl rb php phtml php3 php5 inc lua groovy tcl coffee
    java cs vb go rs c cpp h hpp
    js ts jsx tsx mjs cjs
    # Web app files
    aspx asp ashx asmx asax ascx cshtml vbhtml master svc
    jsp jspx jspf cfm cfc htm html htaccess
    # Database / connection (text)
    sql ddl dump dsn udl ora tns
    # Windows-specific text formats
    reg pol rdp rdg rdcman inf unattend answerfile
    # Remote access tools
    ovpn openvpn vnc rdc tcc ica session script kix
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
    # ── Secret-bearing / auth file extensions ────────────────────────────
    secret secrets creds cred passwd auth vault
    # ── Config management / IaC / templating (Ansible/Puppet/Salt/Chef) ───
    j2 erb pp sls tmpl tpl gotmpl nix dhall jsonnet libsonnet cson bicep
    # ── Additional source languages ──────────────────────────────────────
    pyw kt kts scala sbt gradle clj cljs cljc edn ex exs erl hrl dart swift
    vue svelte astro cc cxx hxx hh cgi fcgi php4 php7 phps pht
    # ── .NET / Visual Studio project & publish files (conn strings, deploy) ─
    csproj vbproj fsproj vcxproj sln resx resw pubxml publishsettings manifest
    # ── Windows scripting / app / shortcut formats ───────────────────────
    hta au3 url psc1 pssc desktop
    # ── VPN / network configuration ──────────────────────────────────────
    nmconnection network netdev link wg pcf mobileconfig
    # ── Database scripts / ORM schemas ───────────────────────────────────
    psql pgsql plsql tsql cql sqlproj prisma
    # ── Notes / documentation / mail ─────────────────────────────────────
    org rst adoc asciidoc note notes wiki eml
    # ── Backup / package-manager config remnants (old configs keep creds) ─
    dpkg-old dpkg-dist dpkg-new rpmsave rpmnew rpmorig ucf-old ucf-dist
    bk bkp bkup sav swp swo default
    # ── systemd unit types ───────────────────────────────────────────────
    path mount automount target slice scope
    # ── Tabular / structured data exports ────────────────────────────────
    tab psv jsonl ndjson
)

# ----------------------------------------------------------------------------
#  Argument parsing
# ----------------------------------------------------------------------------
parse_args() {
    # Guard: option requires a following argument. Without this, a trailing
    # `-p`/`-x`/`-m`/`-o` would hit `$2` under `set -u` and abort with an ugly
    # "unbound variable" instead of a clean, actionable error.
    _need_arg() { [ "$1" -ge 2 ] || { err "Option '$2' requires an argument."; usage; exit 2; }; }
    while [ $# -gt 0 ]; do
        case "$1" in
            -p|--path)        _need_arg "$#" "$1"; SCAN_PATHS+=("$2"); shift 2 ;;
            -x|--exclude)     _need_arg "$#" "$1"; USER_EXCLUDE_PATHS+=("$2"); shift 2 ;;
            -a|--all)         ALL_MODE=1; shift ;;
            -m|--max-size)    _need_arg "$#" "$1"; MAX_FILE_SIZE_MB="$2"; SKIP_LARGE=1; shift 2 ;;
            --no-size-limit)  SKIP_LARGE=0; shift ;;
            -o|--output)      _need_arg "$#" "$1"; OUTPUT_FILE="$2"; shift 2 ;;
            -s|--skip-system) SKIP_SYSTEM=1; STAGE1_SKIP=1; shift ;;
            --no-stage1)      STAGE1_SKIP=1; SKIP_SYSTEM=1; shift ;;
            --no-stage2)      STAGE2_SKIP=1; shift ;;
            --no-stage3)      STAGE3_SKIP=1; shift ;;
            --no-stage4)      STAGE4_SKIP=1; shift ;;
            --no-stage5)      STAGE5_SKIP=1; shift ;;
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
        # The log holds extracted plaintext credential previews, so create it
        # owner-only (umask 077) and tighten any pre-existing loose mode — never
        # leave harvested secrets world/group readable in a shared directory.
        ( umask 077; : >"$OUTPUT_FILE" ) || { err "Cannot write to $OUTPUT_FILE"; exit 2; }
        chmod 600 "$OUTPUT_FILE" 2>/dev/null || true
    fi
    # Must be a positive integer (>= 1). `-m 0` would make `find -size -0c`
    # and the Stage-1 size gate exclude every file, silently scanning nothing.
    [[ "$MAX_FILE_SIZE_MB" =~ ^[0-9]+$ ]] || { err "max-size must be a number"; exit 2; }
    [ "$MAX_FILE_SIZE_MB" -ge 1 ] || { err "max-size must be >= 1 (got '$MAX_FILE_SIZE_MB')"; exit 2; }

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
    'password_assign|(^|[^A-Za-z_])(password|passwd|passphrase|pwd)['"'"'"]?[[:space:]]*[:=][[:space:]]*['"'"'"]?[^[:space:]"#$<>{}]{3,}'

    # ── DB / service-prefixed passwords ──────────────────────────────────
    'db_password|(db|database|mysql|psql|pg|postgres|mongo|mssql|sql|sa|dba|oracle|redis|memcache|ldap|smtp|smb|ftp|sftp|imap|pop3|admin|user|service|svc|jenkins|jboss|tomcat|nexus|gitlab|jira|svn|backup|root|wp|wordpress|joomla|drupal|magento|laravel|django|proxy|vpn|sftp|cifs)[_-]?(password|passwd|passphrase|pwd|pass)['"'"'"]?[[:space:]]*[:=][[:space:]]*['"'"'"]?[^[:space:]"#$<>{}]{3,}'
    # Any OTHER identifier ending in _password/_pass/_pwd (covers OpenStack
    # keystone_password, nova_password, app_password, mail_pass, ...). The
    # value FP filter removes references/placeholders. Placed AFTER db_password
    # so the well-known prefixes keep their specific label.
    'prefixed_password|[A-Za-z][A-Za-z0-9]*_(password|passwd|passphrase|pwd|pass)['"'"'"]?[[:space:]]*[:=][[:space:]]*['"'"'"]?[^[:space:]"#$<>{}]{3,}'

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
    'mysql_cmd|(mysql|mysqladmin|mysqldump|mysqlimport)[[:space:]].*(--password=[^[:space:]"#]{2,}|[[:space:]]-p[^[:space:]"#-][^[:space:]"#]{2,})'
    'psql_cmd|psql[[:space:]].*(-W|--password=|host=[^[:space:]]+.*password=)[^[:space:]"#]{2,}'
    'mongo_cmd|(mongo|mongosh|mongodump|mongorestore)[[:space:]].*(-p|--password)[[:space:]=]+['"'"'"]?[^[:space:]'"'"'"]{2,}'
    'redis_cmd|redis-cli[[:space:]].*(-a|--pass)[[:space:]=]+['"'"'"]?[^[:space:]'"'"'"]{2,}'
    'curl_basic|(curl|wget)[[:space:]].*--?(u|user|http-user)[[:space:]=]+[^:[:space:]]+:[^[:space:]'"'"'"]{3,}'
    'wget_pass|wget[[:space:]].*--(http-password|password|ftp-password)[[:space:]=]+[^[:space:]"]{3,}'
    'smbclient_pass|smbclient[[:space:]].*-U[[:space:]]+[^%[:space:]]+%[^[:space:]]{3,}'
    'smbmount_pass|(mount(\.cifs)?[[:space:]]+(-t[[:space:]]+cifs|//)|mount\.cifs[[:space:]]+//).*(pass|password)=[^,[:space:]"]{3,}'
    'lftp_pass|lftp[[:space:]].*(-u[[:space:]]+[^,[:space:]]+,[^[:space:]]{2,}|-p[[:space:]]+['"'"'"]?[^[:space:]'"'"'"]{2,})'
    'keepalived_authpass|^[[:space:]]*auth_pass[[:space:]]+[^[:space:]#]{2,}'
    'reg_autologon|reg(\.exe)?[[:space:]]+add.*(Default|AltDefault)Password.*/d[[:space:]]+['"'"'"]?[^[:space:]'"'"'"/]{2,}'
    'freerdp_pass|(xfreerdp|freerdp|rdesktop|mstsc)[[:space:]].*(-p|/p:)[[:space:]]?['"'"'"]?[^[:space:]"]{2,}'
    'plink_pass|plink[[:space:]].*-pw[[:space:]]+['"'"'"]?[^[:space:]'"'"'"]{2,}'
    # Generic password flag in ANY command line (not coupled to a tool name):
    # catches `&('"'"'…plink.exe'"'"') -pw '"'"'SECRET'"'"'`, `--password=X`, `/p:X`
    # which the tool-anchored patterns above miss.
    'cmdline_pw_flag|(^|[[:space:]])((-pw|--pw|-pass|--password)[[:space:]=]+['"'"'"]?[^[:space:]'"'"'"]{3,}|(/p:|/pass:|/password:)['"'"'"]?[^[:space:]'"'"'"]{3,})'
    'net_use_pass|net[[:space:]]+use[[:space:]]+.*[[:space:]]/user:[^[:space:]]+[[:space:]]+[^[:space:]/"]{3,}'
    # `net user john.doe "MySecurePassword" /domain` — local/domain user creation
    # `net user <user> <password> [/add|/domain|...]` — the trailing flag is
    # OPTIONAL so a plain `net user john MyPass` set-password is also caught.
    # The 2nd/3rd tokens must NOT start with `/` (a flag), which prevents
    # matching the 2-token display form `net user john`.
    'net_user_create|net[[:space:]]+user[[:space:]]+[^[:space:]/]+[[:space:]]+["'"'"']?[^[:space:]/"'"'"']{3,}'
    # Linux user creation / password setting in scripts (HTB / OSCP staples)
    'useradd_pass|(useradd|usermod)[[:space:]].*-p[[:space:]]+["'"'"']?[^[:space:]"'"'"']{3,}'
    'chpasswd_inline|(echo|printf)[[:space:]]+["'"'"']?[^:[:space:]]+:[^[:space:]"'"'"']{3,}["'"'"']?[[:space:]]*\|[[:space:]]*chpasswd'
    'chpasswd_heredoc|chpasswd[[:space:]]*<<<?[[:space:]]*["'"'"']?[^:[:space:]]+:[^[:space:]"'"'"']{3,}'
    'passwd_stdin|(echo|printf)[[:space:]]+["'"'"'][^"'"'"']{3,}["'"'"'][[:space:]]*\|[[:space:]]*passwd[[:space:]]+[^[:space:]]+([[:space:]]+--stdin)?'
    # PowerShell local user / AD password cmdlets
    'ps_localuser|(New-LocalUser|Add-LocalUser|Set-LocalUser)[[:space:]].*-(Password|AccountPassword)[[:space:]]+["'"'"'][^"'"'"']{3,}["'"'"']'
    'ps_adsetpass|(Set-ADAccountPassword|New-ADUser)[[:space:]].*-(AccountPassword|NewPassword)[[:space:]]'
    # Robust: handles positional or -String, and -Force is optional.
    'ps_secstring_plain|ConvertTo-SecureString[[:space:]]+(-String[[:space:]]+)?["'"'"'][^"'"'"']{3,}["'"'"'][[:space:]]+(-Key[[:space:]]+\S+[[:space:]]+)?-AsPlainText'
    # Plaintext password passed to a cmdlet -Password/-AccountPassword param
    # as a quoted literal (secure-string objects use $vars -> not matched).
    'ps_password_param|-(Password|Pass|AccountPassword|AdminPassword|NewPassword|DefaultPassword)[[:space:]]+["'"'"'][^"'"'"']{3,}["'"'"']'
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

    # ── Web framework specifics ──────────────────────────────────────────
    'wp_db_password|define\([[:space:]]*['"'"'"]DB_PASSWORD['"'"'"][[:space:]]*,[[:space:]]*['"'"'"][^'"'"'"]{2,}'
    'joomla_password|public[[:space:]]+\$(password|smtppass|dbpass|secret)[[:space:]]*=[[:space:]]*['"'"'"][^'"'"'"]{2,}'
    'drupal_password|['"'"'"]password['"'"'"][[:space:]]*=>[[:space:]]*['"'"'"][^'"'"'"]{4,}'
    # Generic PHP define() for any *PASSWORD/*PASS/*PWD/*SECRET constant
    # (DB_PASS, SMTP_PASSWORD, SECRET_KEY, ...). CTF staple beyond DB_PASSWORD.
    'define_secret|define[[:space:]]*\([[:space:]]*['"'"'"][A-Za-z0-9_]*(PASSWORD|PASSWD|PWD|PASS|SECRET)['"'"'"][[:space:]]*,[[:space:]]*['"'"'"][^'"'"'"]{3,}'
    # Hardcoded password as the 3rd positional arg of a DB-connect call --
    # new mysqli("host","user","PASS"), mysqli_connect(...), new PDO(...),
    # mysql_connect(...), pg_connect(...). Classic HTB/CTF pattern (e.g. Magic:
    # new mysqli("localhost","theseus","iamkingofcrete2398","Magic")).
    'php_db_connect|(mysqli_connect|mysql_connect|pg_connect|new[[:space:]]+mysqli|new[[:space:]]+PDO|->[[:space:]]*connect)[[:space:]]*\(([^,]*,){2}[[:space:]]*['"'"'"][^'"'"'"]{3,}['"'"'"]'

    # ── Linux auth files ─────────────────────────────────────────────────
    'htpasswd_hash|^[^:[:space:]#]+:\$(apr1|2[aby]?|5|6|y)\$'
    'netrc_password|^[[:space:]]*(machine[[:space:]]+\S+[[:space:]]+)?(login|user|username)[[:space:]]+\S+[[:space:]]+password[[:space:]]+\S{2,}'
    'sudoers_nopasswd|^[[:space:]]*[^#][^[:space:]]*[[:space:]].*NOPASSWD[[:space:]]*[:=]'
    'samba_password|^[[:space:]]*(passwd|password|smb[[:space:]]+passwd)[[:space:]]*=[[:space:]]*[^[:space:]]{3,}'
    # LDAP bind password (OpenLDAP/nslcd/sssd) and IPsec pre-shared key
    'ldap_bindpw|(bindpw[[:space:]]+|ldap_default_authtok[[:space:]]*=[[:space:]]*)[^[:space:]#"]{3,}'
    'ipsec_psk|:[[:space:]]*PSK[[:space:]]+"[^"]{3,}"'
    # SNMP community strings (the real secrets live in directives, not in the
    # commented `# snmpwalk -c public` examples which are comment-skipped).
    'snmp_community|^[[:space:]]*(rocommunity6?|rwcommunity6?)[[:space:]]+[^[:space:]#]{2,}'
    'snmp_com2sec|^[[:space:]]*com2sec6?[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]#]{2,}'

    # ── Specific config-file credential formats ──────────────────────────
    # Redis ACL / standalone:  requirepass MyR3disPw
    'redis_requirepass|^[[:space:]]*requirepass[[:space:]]+[^[:space:]#]{3,}'
    # Anaconda kickstart:  rootpw --plaintext MyRootPw  |  user --password=...
    'anaconda_rootpw|^[[:space:]]*(rootpw|user)[[:space:]].*(--plaintext[[:space:]]+|--password=)[^[:space:]"#]{3,}'

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
    test tester testing
    foo bar baz qux foobar barbaz
    abc 123
    # NOTE: weak/common passwords (qwerty, letmein, password123, p@ssw0rd,
    # 123456, admin123, test123, ...) are DELIBERATELY *not* dropped here.
    # On CTF/HTB boxes and real weak-credential findings those ARE the answer,
    # so suppressing them would lose valid findings. Only unambiguous
    # template/echo/masked values stay on this list.
    changeme change_me change-me changethis change-this changeit change-it
    todo fixme tbd "n/a" na
    your_password yourpassword your-password yourpasswordhere yourpwd
    insert_password replace_me replace-me replace_this insert_here
    "<password>" "<pass>" "<secret>" "<token>" "<key>" "<value>" "<your-password>"
    "<input>" "<enter>" "<here>" "<...>"
    "..." "...." "....." "********" "*****" "***" xxxxxxxx xxxxx xxx
    redacted hidden masked sanitized
    # Clearly-non-password config values / field-name echoes (a password field
    # whose value is one of these is an echo or stray non-secret, never a cred)
    username email hostname host database value string text data
    admin administrator
    localhost 127.0.0.1 0.0.0.0 ::1 enabled disabled default auto unknown
    "yes" "no" "on" "off" optional required mandatory
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
        # Trailing marker words — values like 'changemePlaceholder', 'XYZexample'
        # explicitly self-label as placeholders. Recognise and drop.
        *placeholder|*placeholders|*_example|*_sample|*_dummy|*_mock|*_stub|*_fake|*_demo) return 0 ;;
    esac

    # ── High-confidence placeholder phrases anywhere in the value ─────────
    # These appear ONLY in templates/examples — never inside a real password
    # — so substring matching is safe and does not lose valid findings.
    case "$lower" in
        *changeme*|*change_me*|*change-me*|*changethis*|*change_this*) return 0 ;;
        *yourpassword*|*your_password*|*your-password*|*passwordhere*|*password_here*|*goeshere*) return 0 ;;
        *placeholder*|*redacted*|*replaceme*|*replace_me*|*replacethis*|*replace_this*) return 0 ;;
        *insertpassword*|*insert_password*|*enterpassword*|*enter_password*|*enteryour*) return 0 ;;
        *tobeset*|*to_be_set*|*tobedefined*|*fillme*|*fill_me*|*fillinpassword*) return 0 ;;
        *examplepassword*|*samplepassword*|*dummypassword*|*fakepassword*) return 0 ;;
        # Space-separated vendor template defaults (WordPress wp-config-sample,
        # etc.) — never appear inside a real password.
        *'put your password here'*|*'your database password here'*|*'your password here'*|*'enter your password'*) return 0 ;;
        *xxxxxx*) return 0 ;;   # 6+ masking chars
    esac

    # ── Value is a REFERENCE / lookup of a secret, not a literal ──────────
    # (env var, vault read, secrets-manager call, config getter)
    case "$lower" in
        *getenv*|*os.environ*|*process.env*|*'env['*|*'$env{'*|*'@value('*) return 0 ;;
        *keyvault*|*getsecret*|*secretsmanager*|*secretmanager*|*'vault.read'*|*hvac.*) return 0 ;;
        *configurationmanager*|*boto3*|*'ssm.get'*|*getparameter*) return 0 ;;
    esac

    # ── Bare dotted identifier reference (config.dbPassword, settings.pass) ─
    # A code reference, not a literal. ($-prefixed form handled further down.)
    [[ "$v" =~ ^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$ ]] && return 0

    # ── Function-call accessor (getPassword(), get_password(), cfg.getSecret())
    # — code that FETCHES a secret at runtime, not a hardcoded literal.
    [[ "$v" =~ ^[A-Za-z_][A-Za-z0-9_.]*\(.*\)$ ]] && return 0

    # Variable interpolation / template markers
    case "$v" in
        *'${'*|*'$('*|*'%('*|*'{{'*|*'<%'*|*'%>'*|*'#{'*) return 0 ;;
        # Placeholder tag like <password> / <your-pw> (a letter must follow '<';
        # keeps real passwords containing '<3' etc. that PS also keeps).
        *'<'[A-Za-z_]*'>'*) return 0 ;;
        *'$1'*|*'$2'*|*'$3'*|*'$$'*) return 0 ;;
        *'%'[A-Z_]*'%'*) return 0 ;;
        *'@@'*|*'__'*'__'*) return 0 ;;
    esac

    # Programming-language references that look like passwords but aren't
    # (Python `self.password`, Java `this.password`, PHP `$_POST['password']`)
    case "$v" in
        'self.'*|'this.'*|'cls.'*|'@self.'*) return 0 ;;
        '$_POST['*|'$_GET['*|'$_REQUEST['*|'$_SERVER['*|'$_ENV['*|'$_SESSION['*|'$_COOKIE['*) return 0 ;;
    esac
    # Dotted variable/field reference like $obj.field or $cred.Password
    # (matches PS Test-FalsePositive). Bare $VAR and real passwords that
    # merely start with '$' (e.g. $Pass123, $ecretP@ss) are intentionally
    # KEPT — dropping them would miss genuine credentials.
    [[ "$v" =~ ^\$[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$ ]] && return 0

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

    # Single repeating char (e.g. "xxxx", "****"). NOTE: bash's `[[ =~ ]]` is
    # POSIX ERE and does NOT support back-references, so the old `^(.)\1+$`
    # never matched (dead filter). Check character-by-character instead so this
    # matches the PowerShell Test-FalsePositive behaviour. Value length is
    # bounded (<=256) so the loop cost is negligible.
    if [ "$len" -ge 3 ]; then
        local c0="${v:0:1}" same=1 i
        for ((i = 1; i < len; i++)); do
            [ "${v:i:1}" = "$c0" ] || { same=0; break; }
        done
        [ "$same" -eq 1 ] && return 0
    fi

    # Only non-alphanumeric punctuation
    if [[ "$v" =~ ^[^A-Za-z0-9]+$ ]]; then
        return 0
    fi

    # Bare filesystem path used as a value (e.g. `pwd: /usr/local/bin`,
    # `password = /etc/secrets`) — a working-directory / path reference, not a
    # secret. Require a leading /, ./ or ../, only path-safe characters (so any
    # password with other punctuation or whitespace is untouched), and at least
    # two path separators so single-segment values like `/x` are kept.
    if [[ "$v" =~ ^(\.\.?/|/)[A-Za-z0-9._/-]+$ ]] && [[ "$v" == */*/* ]]; then
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

# Fast filename-based skip for files that match a credential-related
# extension (so they pass the candidate filter) but are well-known to be
# license / changelog / lockfile / IDE-config / docs — none of these ever
# carry reusable credentials. Skipping at the filename layer avoids one
# `stat` + one `head` + one `grep` per file → measurable speedup on
# repositories full of node_modules-style boilerplate.
should_skip_filename() {
    local b="${1##*/}"
    case "$b" in
        # License files (all common name shapes)
        LICENSE|LICENSE.*|LICENCE|LICENCE.*|UNLICENSE|UNLICENSE.*) return 0 ;;
        COPYING|COPYING.*|COPYRIGHT|COPYRIGHT.*) return 0 ;;
        # Changelogs / release notes
        CHANGELOG|CHANGELOG.*|CHANGES|CHANGES.*|HISTORY|HISTORY.*) return 0 ;;
        NEWS|NEWS.*|RELEASE_NOTES*|RELEASES.*) return 0 ;;
        # Project meta-docs
        AUTHORS|AUTHORS.*|CONTRIBUTORS|CONTRIBUTORS.*|MAINTAINERS|MAINTAINERS.*) return 0 ;;
        CONTRIBUTING|CONTRIBUTING.*|CODE_OF_CONDUCT*) return 0 ;;
        NOTICE|NOTICE.*|THIRD_PARTY*|TRADEMARKS*|ATTRIBUTION*) return 0 ;;
        INSTALL|INSTALL.*|UPGRADE|UPGRADE.*|UPGRADING*) return 0 ;;
        SECURITY.md|SUPPORT.md|GOVERNANCE.md|ROADMAP.md|FUNDING*) return 0 ;;
        README*|readme*) return 0 ;;
        # Lockfiles & manifests (npm/yarn/pnpm/bun/cargo/poetry/composer/go)
        package.json|package-lock.json|npm-shrinkwrap.json) return 0 ;;
        yarn.lock|pnpm-lock.yaml|bun.lockb|bun.lock) return 0 ;;
        Cargo.lock|Gemfile.lock|poetry.lock|composer.lock|composer.json) return 0 ;;
        go.sum|go.mod|Pipfile.lock) return 0 ;;
        # TypeScript / build configs (no creds)
        tsconfig.json|tsconfig.*.json|jsconfig.json|tslint.json|tslint*.json) return 0 ;;
        # VCS / formatter / linter dotfiles
        .gitignore|.gitattributes|.editorconfig|.gitmodules|.gitkeep|.mailmap) return 0 ;;
        .prettierrc|.prettierrc.*|.prettierignore) return 0 ;;
        .eslintrc|.eslintrc.*|.eslintignore|.stylelintrc|.stylelintrc.*) return 0 ;;
        .babelrc|.babelrc.*|.browserslistrc|.nvmrc|.node-version|.python-version) return 0 ;;
        .dockerignore|.npmignore|.ignore|.gitlab-ci.yml.dist) return 0 ;;
        # Python project meta (cred-free)
        pyproject.toml|setup.cfg|MANIFEST.in|tox.ini|noxfile.py) return 0 ;;
        # Common build / make files (cred-free)
        Makefile|GNUmakefile|CMakeLists.txt|meson.build|pom.xml) return 0 ;;
        # NOTE: build.gradle / gradle.properties are NOT skipped -- they
        # commonly hold repo / signing / nexus passwords (signing.password,
        # mavenPassword, nexusPassword, ...).
        # OS / desktop noise
        .DS_Store|Thumbs.db|desktop.ini|*.lnk) return 0 ;;
        # Minified / bundled / source-map artefacts (never carry real creds,
        # huge size, all-on-one-line content kills regex performance)
        *.min.js|*.min.css|*.bundle.js|*.bundle.css|*.chunk.js) return 0 ;;
        *.js.map|*.css.map|*.map) return 0 ;;
        # Gettext / localisation files
        *.po|*.pot|*.mo) return 0 ;;
        # .env templates / examples / dist files — by definition placeholders,
        # not real creds. They are still flagged by stage 4 (filename match).
        .env.example|.env.sample|.env.template|.env.dist) return 0 ;;
        *.env.example|*.env.sample|*.env.template|*.env.dist) return 0 ;;
    esac
    return 1
}

# Binary detection in a SINGLE fork. `grep -I` treats a file containing NUL
# bytes as binary (no match); an empty file likewise yields no match; `-m1`
# stops at the first text line so we never read more than one line of a text
# file. Replaces the old `head -c 4096 | grep` two-fork pipeline.
is_binary() {
    ! LC_ALL=C grep -qIm1 . -- "$1" 2>/dev/null
}

sanitize() {
    local v="$1"
    v="${v//$'\r'/}"
    v="${v//$'\n'/ }"
    # Drop terminal control bytes (ESC/BEL/backspace/etc.) from scanned content
    # so neither the live output nor the on-disk log can carry escape sequences;
    # then collapse remaining whitespace runs to single spaces.
    v="$(printf '%s' "$v" | LC_ALL=C tr -d '\000-\010\013\014\016-\037\177' | tr -s '[:space:]' ' ')"
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    # NO truncation here: the full secret is stored so the Findings section and
    # -o log always show it whole. The live feed caps its own copy (live_preview).
    printf '%s' "$v"
}

# Cap a preview for the LIVE feed only (never the Findings section / log). Real
# credentials are far shorter than the cap, so this only trims pathological
# multi-KB lines; the complete value still appears in Findings.
live_preview() {
    local p="$1"
    if [ "${#p}" -gt "$LIVE_PREVIEW_LEN" ]; then
        printf '%s%s(+%d more)' "${p:0:$LIVE_PREVIEW_LEN}" "$GELL" "$(( ${#p} - LIVE_PREVIEW_LEN ))"
    else
        printf '%s' "$p"
    fi
}

# Collapse TAB/CR/LF in a path so it stays a single, column-stable field in the
# TAB-separated tier files. Filenames may legally contain these bytes, and since
# enumeration is NUL-safe a newline in a path would otherwise split a TSV record
# into two phantom lines (wrong line numbers / garbled paths). Result -> REPLY
# (no subshell, so this stays cheap on the per-file record_skip/record_checked).
_clean_path() { REPLY="${1//$'\t'/ }"; REPLY="${REPLY//$'\r'/ }"; REPLY="${REPLY//$'\n'/ }"; }

record_finding() {
    # Args: BUCKET LABEL FILE LINE PREVIEW
    local bucket="$1" label="$2" file="$3" line="$4" preview="$5"
    _clean_path "$file"; file="$REPLY"
    case "$bucket" in
        HIGH) printf '%s\t%s\t%s\t%s\n' "$label" "$file" "$line" "$preview" >>"$HIGH_FILE" ;;
        KEY)  printf '%s\t%s\t%s\t%s\n' "$label" "$file" "$line" "$preview" >>"$KEY_FILE"  ;;
    esac
    [ "$IN_STAGE1" -eq 1 ] && stage1_emit "$bucket" "$label" "$file" "$line" "$preview"
}
record_interest() {
    _clean_path "$2"
    printf '%s\t%s\n' "$1" "$REPLY" >>"$INTEREST_FILE"
    [ "$IN_STAGE1" -eq 1 ] && stage1_emit INTEREST "$1" "$REPLY"
}
record_name() {
    _clean_path "$1"
    printf '%s\n' "$REPLY" >>"$NAME_FILE"
    [ "$IN_STAGE1" -eq 1 ] && stage1_emit NAME "name_match" "$REPLY"
}
record_skip()        { _clean_path "$1"; printf '%s\t%s\n' "$REPLY" "$2" >>"$SKIPPED_FILE"; }
record_checked()     { _clean_path "$2"; printf '%s\t%s\n' "$1" "$REPLY" >>"$CHECKED_FILE"; }
record_guaranteed() {
    _clean_path "$2"
    printf '%s\t%s\n' "$1" "$REPLY" >>"$GUARANTEED_FILE"
    [ "$IN_STAGE1" -eq 1 ] && stage1_emit CRITICAL "$1" "$REPLY"
}

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
#  Stage lifecycle -- per-stage timing, skip-gating, and live-results block
# ============================================================================

declare -A STAGE_BEFORE_GUARANTEED
declare -A STAGE_BEFORE_INTEREST
declare -A STAGE_BEFORE_NAME
declare -A STAGE_BEFORE_HIGH
declare -A STAGE_BEFORE_KEY
declare -A STAGE_START_TIME

# Snapshot finding-file line counts BEFORE a stage runs, so the live
# results block can print just the delta.
stage_begin() {
    local n=$1
    STAGE_BEFORE_GUARANTEED[$n]=$(wc -l <"$GUARANTEED_FILE" 2>/dev/null | tr -d ' ' || echo 0)
    STAGE_BEFORE_INTEREST[$n]=$(wc -l <"$INTEREST_FILE"   2>/dev/null | tr -d ' ' || echo 0)
    STAGE_BEFORE_NAME[$n]=$(wc -l <"$NAME_FILE"           2>/dev/null | tr -d ' ' || echo 0)
    STAGE_BEFORE_HIGH[$n]=$(wc -l <"$HIGH_FILE"           2>/dev/null | tr -d ' ' || echo 0)
    STAGE_BEFORE_KEY[$n]=$(wc -l <"$KEY_FILE"             2>/dev/null | tr -d ' ' || echo 0)
    STAGE_START_TIME[$n]=$(date +%s.%N 2>/dev/null || date +%s)
}

# Print the live results block for stage <n>. <title> is the human-readable
# stage name. Reads each tier file's delta and emits a single tier label per
# finding.
stage_end() {
    local n=$1 title="$2"
    local end
    end=$(date +%s.%N 2>/dev/null || date +%s)
    local elapsed
    elapsed=$(awk -v a="${STAGE_START_TIME[$n]:-0}" -v b="$end" \
        'BEGIN{ d=b-a; if(d<0)d=0; printf "%.2f", d }')

    local now_guar now_int now_name now_hi now_ky
    now_guar=$(wc -l <"$GUARANTEED_FILE" 2>/dev/null | tr -d ' ' || echo 0)
    now_int=$(wc -l <"$INTEREST_FILE"    2>/dev/null | tr -d ' ' || echo 0)
    now_name=$(wc -l <"$NAME_FILE"       2>/dev/null | tr -d ' ' || echo 0)
    now_hi=$(wc -l <"$HIGH_FILE"         2>/dev/null | tr -d ' ' || echo 0)
    now_ky=$(wc -l <"$KEY_FILE"          2>/dev/null | tr -d ' ' || echo 0)

    local d_guar=$(( now_guar - ${STAGE_BEFORE_GUARANTEED[$n]:-0} ))
    local d_int=$((  now_int  - ${STAGE_BEFORE_INTEREST[$n]:-0}   ))
    local d_name=$(( now_name - ${STAGE_BEFORE_NAME[$n]:-0}       ))
    local d_hi=$((   now_hi   - ${STAGE_BEFORE_HIGH[$n]:-0}       ))
    local d_ky=$((   now_ky   - ${STAGE_BEFORE_KEY[$n]:-0}        ))
    local total=$(( d_guar + d_int + d_name + d_hi + d_ky ))

    local header="Stage $n -- $title" tw=72 fill
    fill=$(( tw - 6 - ${#header} )); [ "$fill" -lt 3 ] && fill=3
    printf '\n  %b%s %b%s%b %b%s%b\n' \
        "$D$C" "$(hbar "$GH" 2)" "$BOLD" "$header" "$NC" "$D$C" "$(hbar "$GH" "$fill")" "$NC"
    printf '     %b%s found in %ss%b\n' "$D" "$total" "$elapsed" "$NC"

    if [ "$QUIET" -eq 0 ] && [ "$total" -gt 0 ]; then
        printf '\n'
        stage_print_delta CRITICAL  "$GUARANTEED_FILE" "${STAGE_BEFORE_GUARANTEED[$n]:-0}" "$d_guar"
        stage_print_delta HIGH      "$HIGH_FILE"       "${STAGE_BEFORE_HIGH[$n]:-0}"       "$d_hi"
        stage_print_delta KEY       "$KEY_FILE"        "${STAGE_BEFORE_KEY[$n]:-0}"        "$d_ky"
        stage_print_delta INTEREST  "$INTEREST_FILE"   "${STAGE_BEFORE_INTEREST[$n]:-0}"   "$d_int"
        stage_print_delta NAME      "$NAME_FILE"       "${STAGE_BEFORE_NAME[$n]:-0}"       "$d_name"
    fi
}

# Print delta lines from a tier file as: [TIER]  /path
# Args: tier-label  file  before-count  delta
stage_print_delta() {
    local tier="$1" file="$2" before="$3" delta="$4"
    [ "$delta" -le 0 ] && return
    [ ! -s "$file" ] && return
    local start=$((before + 1))
    case "$tier" in
        HIGH|KEY)
            # path line, then the FULL matched value indented beneath it (dim).
            # Only the live feed is capped (LIVE_PREVIEW_LEN); Findings show all.
            tail -n "+$start" "$file" | awk -F'\t' -v t="$tier" -v d="$D" -v nc="$NC" \
                -v cap="$LIVE_PREVIEW_LEN" -v ell="$GELL" '
                {
                    printf "  [%-8s]  %s\n", t, $2
                    if ($4 != "") {
                        p = $4
                        if (length(p) > cap) p = substr(p, 1, cap) ell "(+" (length(p) - cap) " more)"
                        printf "              %s%s%s\n", d, p, nc
                    }
                }'
            ;;
        INTEREST|NAME)
            tail -n "+$start" "$file" | awk -F'\t' -v t="$tier" '{ p=$NF; printf "  [%-8s]  %s\n", t, p }'
            ;;
        CRITICAL)
            tail -n "+$start" "$file" | awk -F'\t' '{ printf "  [%-8s]  %s\n", "CRITICAL", $2 }'
            ;;
    esac
}

# Print the SKIPPED variant of a stage block.
stage_skipped() {
    local n=$1 title="$2"
    local header="Stage $n -- $title  [SKIPPED]" tw=72 fill
    fill=$(( tw - 6 - ${#header} )); [ "$fill" -lt 3 ] && fill=3
    printf '\n  %b%s %b%s%b %b%s%b\n' \
        "$D$C" "$(hbar "$GH" 2)" "$BOLD" "$header" "$NC" "$D$C" "$(hbar "$GH" "$fill")" "$NC"
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

    # Skip pathologically long / trivially short lines before any regex work.
    # Bounds the per-pattern [[ =~ ]] loop on minified/base64/log lines (DoS
    # guard) and matches the PowerShell engine's per-line gate for parity.
    local _clen=${#content}
    [ "$_clen" -gt "$MAX_LINE_LEN" ] && return 1
    [ "$_clen" -lt 6 ] && return 1

    # ── Line-level hard-coded FPs (observed on real Windows hosts) ────────
    # MSSQL @password parameter references in stored procedures
    [[ "$content" =~ @password[[:space:]]*=[[:space:]]*(@password|N\'\'|NULL|@[A-Za-z_]+) ]] && return 1
    # Microsoft's well-known SQL-Agent signing-cert password
    [[ "$content" =~ WITH[[:space:]]+PASSWORD[[:space:]]*=[[:space:]]*\'Yukon90_\' ]] && return 1
    # Masked passwords: PASSWORD = '*******'
    [[ "$content" =~ PASSWORD[[:space:]]*=[[:space:]]*\'\*+\' ]] && return 1
    # SQL Server Telemetry / Setup-Bootstrap log noise
    [[ "$content" == *SQLTelemetry*Setting* ]] && return 1
    [[ "$content" == *SafeSqlCommand*PASSWORD*\*\*\*\*\*\*\** ]] && return 1

    local entry label regex value
    for entry in "${CRED_PATTERNS[@]}"; do
        label="${entry%%|*}"
        regex="${entry#*|}"
        if [[ "$content" =~ $regex ]]; then
            # ── Commented example skip ───────────────────────────────────
            # Stock configs ship docs like `# snmpwalk -c public` or
            # `# rocommunity public` — examples, not live creds. Skip comment
            # lines ONLY for command/directive patterns. Generic key=value
            # assignments (password_assign, db_password, ...) are tried first
            # and are NOT skipped, so a commented-out real password is still
            # reported.
            if [[ "$content" =~ ^[[:space:]]*(#|//|\;|[Rr][Ee][Mm][[:space:]]) ]]; then
                case "$label" in
                    *_cmd|*_pass|cmdline_pw_flag|impacket_cred|runas_savecred|cmdkey_add|net_user_create|chpasswd_*|passwd_stdin|ps_localuser|ps_adsetpass|ps_secstring_*|htpasswd_create|nmcli_wifi|useradd_pass|snmp_community|snmp_com2sec)
                        return 1 ;;
                esac
            fi
            # ── Smarter value extraction ─────────────────────────────────
            # The OLD code took the substring after the FIRST `:`/`=`. That
            # misfires on timestamps ("03:39:54 SVCPASSWORD: source = X")
            # where the first colon is the clock. Locate the password
            # keyword instead, then read whatever immediately follows ITS
            # operator. Falls back to the full content if no kv shape.
            value="$content"
            if [[ "$content" =~ (password|passwd|passphrase|pass|pwd|cpassword|requirepass|rootpw|cred(ential)?s?|secret)[[:space:]]*[:=]?[[:space:]]*(.+)$ ]]; then
                value="${BASH_REMATCH[3]}"
                value="${value%%#*}"
                value="${value%%;*}"
                # Cut at ", " / " -> " / "  message=" — common log noise
                value="${value%%, message*}"
                value="${value%% -> *}"
                value="${value%%, source*}"
            fi
            # PHP 'key' => 'value' / define('KEY','value') shapes: the generic
            # extractor above leaves a messy "=> 'value'" prefix, so take the
            # last quoted literal on the line as the value before FP-filtering
            # (e.g.  'password' => 'changeme'  ->  changeme).
            case "$label" in
                drupal_password|wp_db_password)
                    if [[ "$content" =~ .*[\'\"]([^\'\"]+)[\'\"][^\'\"]*$ ]]; then
                        value="${BASH_REMATCH[1]}"
                    fi
                    ;;
            esac
            # Skip the generic FP filter ONLY for findings where the FULL match
            # IS the credential (hash dumps, format-anchored markers, XML value
            # tags, free-form auth-line formats). Patterns whose value is an
            # ordinary user string (autologon/drupal/wp/htpasswd_create) are
            # NOT here — they must run through is_false_positive so placeholders
            # and variable references are dropped.
            case "$label" in
                ntlm_dump|ntds_dump|shadow_*|krb5_*|mscash_*|htpasswd_hash|gpp_cpassword) ;;
                unattend_password) ;;
                netrc_password|sudoers_nopasswd) ;;
                joomla_password) ;;
                define_secret|php_db_connect) ;;
                redis_requirepass|anaconda_rootpw) ;;
                ldap_bindpw|ipsec_psk|snmp_community|snmp_com2sec) ;;
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

    # Per-path dedup. Stage 1's targeted lists can reference the same file
    # under different names / symlinks, so it keys on the canonical path
    # (one readlink fork per Stage-1 file — a small fixed list). Stage 5's
    # candidate list is already `sort -u` unique and `find` does not follow
    # symlinks, so a literal-path key is sufficient there and avoids ~1
    # readlink fork per file across the entire tree.
    local key
    if [ "$IN_STAGE1" -eq 1 ]; then
        key=$(readlink -f -- "$file" 2>/dev/null || printf '%s' "$file")
    else
        key="$file"
    fi
    [ -n "${SCANNED_PATHS["$key"]:-}" ] && return
    SCANNED_PATHS["$key"]=1

    [ -f "$file" ] || return

    # Fast filename skip — runs before any I/O so well-known cred-free
    # files (LICENSE, package-lock.json, .gitignore, etc.) cost nothing.
    if should_skip_filename "$file"; then
        record_skip "$file" "non-credential filename"
        return
    fi

    [ -r "$file" ] || { record_skip "$file" "unreadable"; return; }

    # Size gate. In Stage 5 the candidate list was already size-filtered by
    # `find -size` (see enumerate_candidates) when a cap is active, so the
    # per-file stat is only needed for Stage 1's targeted files. Empty files
    # are caught by is_binary below (grep -I yields no match on 0 bytes).
    if [ "$IN_STAGE1" -eq 1 ]; then
        local sz
        sz=$(file_size "$file")
        [ "$sz" -le 0 ] && return
        if [ "$SKIP_LARGE" -eq 1 ] && [ "$sz" -gt $((MAX_FILE_SIZE_MB * 1024 * 1024)) ]; then
            record_skip "$file" "size>${MAX_FILE_SIZE_MB}MB"
            return
        fi
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
    done < <(grep -niE -m "$PREFILTER_LINE_CAP" -- "$COMBINED_CRED_REGEX" "$file" 2>/dev/null)

    # ── Phase 3: multi-line XML credential tags (unattend.xml / sysprep) ──
    # Real autologon blocks split <Password> and <Value> across lines, which
    # the per-line scan above cannot match. Scoped to XML/INF-type files (rare,
    # so the whole-file read stays cheap) and skipped when the single-line form
    # already matched in Phase 2 (avoids double-reporting the same finding).
    case "${file,,}" in
        *.xml|*.inf|*.unattend|*.answerfile)
            if ! grep -qiE '<(Administrator)?Password>[[:space:]]*<Value>[^[:space:]<]' "$file" 2>/dev/null; then
                local xml_content xml_val pline
                xml_content=$(LC_ALL=C tr -d '\000\r' <"$file")
                if [[ "$xml_content" =~ \<(Administrator)?Password\>[[:space:]]*\<Value\>[[:space:]]*([^\<]{2,}) ]]; then
                    xml_val="${BASH_REMATCH[2]}"
                    xml_val="${xml_val%"${xml_val##*[![:space:]]}"}"   # rtrim
                    xml_val="${xml_val#"${xml_val%%[![:space:]]*}"}"   # ltrim
                    if [ -n "$xml_val" ] && ! is_false_positive "$xml_val"; then
                        pline=$(grep -niE -m1 '<(Administrator)?Password>' "$file" 2>/dev/null)
                        pline="${pline%%:*}"; [[ "$pline" =~ ^[0-9]+$ ]] || pline=1
                        record_finding HIGH "${source_label}/unattend_password" "$file" "$pline" "$(sanitize "Password Value: $xml_val")"
                    fi
                fi
            fi
            ;;
    esac
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
    while IFS= read -r -d '' f; do
        case "$f" in
            # FileZilla stores <Pass encoding="base64">…</Pass> which the
            # content regex cannot decode — always list it for manual review.
            */filezilla/sitemanager.xml|*/filezilla/recentservers.xml|*/filezilla/filezilla.xml)
                record_interest "filezilla_session" "$f" ;;
        esac
        scan_file "$f" "dotfile"
    done < <(find /root /home -maxdepth 4 -type f \( \
        -name '.netrc' -o -name '_netrc' -o -name '.git-credentials' \
        -o -name '.gitconfig' -o -name '.npmrc' -o -name '.pypirc' \
        -o -path '*/.aws/credentials' -o -path '*/.aws/config' \
        -o -path '*/.azure/*' -o -path '*/.config/rclone/rclone.conf' \
        -o -path '*/.config/filezilla/sitemanager.xml' \
        -o -path '*/.config/filezilla/recentservers.xml' \
        -o -path '*/.config/filezilla/filezilla.xml' \
        \) -print0 2>/dev/null)

    # gcloud CLI credential stores (sqlite DB + ADC json). The DBs are binary,
    # so flag for manual review; the JSON ADC files are also content-scanned.
    while IFS= read -r -d '' f; do
        record_interest "cloud_credential_file" "$f"
        case "$f" in *.json) scan_file "$f" "gcloud" ;; esac
    done < <(find /root /home -maxdepth 6 -type f \( \
        -path '*/.config/gcloud/credentials.db' \
        -o -path '*/.config/gcloud/access_tokens.db' \
        -o -path '*/.config/gcloud/application_default_credentials.json' \
        -o -path '*/.config/gcloud/legacy_credentials/*' \
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
            *.remmina)
                # Remmina stores password=<base64/3DES> which the content regex
                # cannot decode — always list the session file for manual review.
                record_interest "remmina_session" "$f"
                scan_file "$f" "remmina_session" ;;
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
    IN_STAGE1=1
    run_stage1_check check_shell_histories
    run_stage1_check check_ssh
    run_stage1_check check_environment_files
    run_stage1_check check_cron
    run_stage1_check check_systemd
    run_stage1_check check_databases
    run_stage1_check check_web_apps
    run_stage1_check check_home_dotfiles
    run_stage1_check check_system_files
    run_stage1_check check_wifi
    run_stage1_check check_misc_services
    run_stage1_check check_docker_kube
    IN_STAGE1=0
}

# ============================================================================
#  Filename / extension data + exclusion paths
# ============================================================================

# Known MSSQL system / template database basenames — always shipped, never
# user data. Skip from Stage 3 INTEREST flagging.
SKIP_DB_BASENAMES=(
    master.mdf mastlog.ldf
    model.mdf modellog.ldf
    msdb.mdf msdbdata.mdf msdblog.ldf
    tempdb.mdf templog.ldf
    mssqlsystemresource.mdf mssqlsystemresource.ldf
    model_msdbdata.mdf model_msdblog.ldf
    model_replicatedmaster.mdf model_replicatedmaster.ldf
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
    # Kernel / runtime pseudo-filesystems
    /proc /sys /dev /run /run/user /run/lock
    # Bootloader / recovery
    /boot /lost+found
    # Snap / Flatpak
    /snap /var/lib/snapd /var/lib/flatpak
    # System binaries — executables, never credential-bearing
    /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin
    /usr/games /usr/local/games
    # System libraries / shared data — system-owned, no user creds
    /usr/share /usr/lib /usr/lib32 /usr/lib64 /usr/libexec
    /usr/include /usr/src
    /lib /lib32 /lib64 /libexec
    # Package manager state / caches
    /var/cache /var/lib/dpkg /var/lib/rpm /var/lib/apt /var/lib/yum
    /var/lib/dnf /var/lib/PackageKit /var/lib/pacman /var/lib/portage
    /var/lib/mlocate /var/lib/updatedb /var/lib/locate
    # Container runtime overlays / caches
    /var/lib/docker/overlay2 /var/lib/docker/aufs /var/lib/docker/btrfs
    /var/lib/docker/devicemapper /var/lib/docker/zfs /var/lib/docker/tmp
    /var/lib/docker/buildkit /var/lib/docker/image
    /var/lib/containerd /var/lib/buildah
    # Log dirs — noisy; opt in via -p /var/log
    /var/log
    # X11 / IPC sockets
    /tmp/.X11-unix /tmp/.ICE-unix /tmp/.font-unix
)

# ============================================================================
#  Stages 2-5 — recursive scanning of user-supplied paths
# ============================================================================

# Build the find pruning expression ONCE as an argv ARRAY (no eval, no quoting
# games, no command-injection surface from scan/exclude paths). FIND_EXCLUDE_ARGS
# expands to:  ( -type d -name X -o -path Y -o -path Y/* ... ) -prune -o
# which find reads as "prune these subtrees, otherwise fall through to the match
# expression that follows". Reused by every stage.
FIND_EXCLUDE_ARGS=()
build_find_excludes() {
    [ "${#FIND_EXCLUDE_ARGS[@]}" -gt 0 ] && return   # compose once, reuse forever
    local d inner=()
    for d in "${EXCLUDE_DIR_NAMES[@]}"; do
        inner+=( -o -type d -name "$d" )
    done
    for d in "${EXCLUDE_PATHS[@]}"; do
        inner+=( -o -path "$d" -o -path "$d/*" )
    done
    # Drop the leading "-o" (inner[@]:1) and wrap in a ( ... ) -prune -o group.
    [ "${#inner[@]}" -gt 0 ] && FIND_EXCLUDE_ARGS=( '(' "${inner[@]:1}" ')' -prune -o )
}

# Stage 2 — confirmed credential containers
find_guaranteed_credentials() {
    build_find_excludes
    local path e match=()
    for e in "${STAGE2_EXTENSIONS[@]}"; do
        match+=( -o -iname "*.${e}" )
    done
    local name_expr=( '(' "${match[@]:1}" ')' )
    for path in "${SCAN_PATHS[@]}"; do
        [ -e "$path" ] || continue
        while IFS= read -r -d '' f; do
            [ -z "$f" ] && continue
            local ext_only="${f##*.}"
            record_guaranteed "${ext_only,,}" "$f"
        done < <(find "$path" "${FIND_EXCLUDE_ARGS[@]}" -type f "${name_expr[@]}" -print0 2>/dev/null)
    done
    if [ -s "$GUARANTEED_FILE" ]; then
        sort -u "$GUARANTEED_FILE" -o "$GUARANTEED_FILE"
    fi
}

# Stage 3 -- high-value file types (NEW SPEC)
# Three sub-passes driven by the top-of-file arrays:
#   STAGE3_EXTENSIONS    -- match by extension (case-insensitive)
#   STAGE3_EXACT_NAMES   -- match by full basename
#   STAGE3_GLOB_PATTERNS -- match by find -iname glob (e.g. krb5cc_*)
#
# Files already flagged by Stage 2 (guaranteed credential containers) are
# deduped against $GUARANTEED_FILE so e.g. *.keytab doesn't double-emit.
find_high_value_files() {
    build_find_excludes
    local path

    # Build dedup set from Stage 2 outputs (TSV: ext<TAB>path -> use column 2)
    declare -A STAGE2_HITS=()
    if [ -s "$GUARANTEED_FILE" ]; then
        local g
        while IFS=$'\t' read -r _ g; do
            [ -n "$g" ] && STAGE2_HITS["$g"]=1
        done <"$GUARANTEED_FILE"
    fi

    # One combined match expression: extensions OR exact filenames OR globs.
    local match=() e n gp
    for e  in "${STAGE3_EXTENSIONS[@]}";    do match+=( -o -iname "*.${e}" ); done
    for n  in "${STAGE3_EXACT_NAMES[@]}";   do match+=( -o -iname "$n" );     done
    for gp in "${STAGE3_GLOB_PATTERNS[@]}"; do match+=( -o -iname "$gp" );    done
    local name_expr=( '(' "${match[@]:1}" ')' )

    for path in "${SCAN_PATHS[@]}"; do
        [ -e "$path" ] || continue
        while IFS= read -r -d '' f; do
            [ -z "$f" ] && continue
            # Stage 2 dedup -- skip files already flagged as guaranteed
            [ -n "${STAGE2_HITS[$f]:-}" ] && continue
            # SKIP_DB_BASENAMES filter (MS SQL Server templates)
            local bn="${f##*/}"
            local skip=0 k
            for k in "${SKIP_DB_BASENAMES[@]}"; do
                if [ "${bn,,}" = "${k,,}" ]; then skip=1; break; fi
            done
            [ "$skip" -eq 1 ] && continue
            record_interest "high_value_file" "$f"
        done < <(find "$path" "${FIND_EXCLUDE_ARGS[@]}" -type f "${name_expr[@]}" -print0 2>/dev/null)
    done
}

# Stage 4 -- filename substring search (NEW SPEC)
# Single pass: any file whose basename (case-insensitive) contains one of
# STAGE4_NAME_TOKENS is emitted as a [NAME] finding.
#
# Binary executables, libraries, and the scanner's own file are excluded.
# The exact-filename list from earlier versions is removed -- if you need
# to detect well-known credential files (.bash_history, id_rsa, shadow,
# etc.) at non-standard paths, add their identifying substring (e.g. "rsa",
# "shadow", "history") to STAGE4_NAME_TOKENS at the top of this script.
find_suspicious_filenames() {
    build_find_excludes
    local path self_name
    self_name="${SCRIPT_PATH##*/}"

    # Dedup against Stage 2: a confirmed credential container (e.g.
    # passwords.kdbx, secrets.ppk) is already reported as [CRITICAL]; do not
    # also down-tag it as a mere [NAME] substring hit.
    declare -A STAGE2_HITS=()
    if [ -s "$GUARANTEED_FILE" ]; then
        local _g
        while IFS=$'\t' read -r _ _g; do
            [ -n "$_g" ] && STAGE2_HITS["$_g"]=1
        done <"$GUARANTEED_FILE"
    fi

    for path in "${SCAN_PATHS[@]}"; do
        [ -e "$path" ] || continue
        while IFS= read -r -d '' f; do
            [ -z "$f" ] && continue
            # Skip files already flagged as confirmed containers in Stage 2
            [ -n "${STAGE2_HITS[$f]:-}" ] && continue
            local bn="${f##*/}"
            local bn_lower="${bn,,}"
            # Skip our own script
            [ "$bn" = "$self_name" ] && continue
            local t
            for t in "${STAGE4_NAME_TOKENS[@]}"; do
                if [[ "$bn_lower" == *"${t,,}"* ]]; then
                    record_name "$f"
                    break
                fi
            done
        # -mindepth 1 prevents the SCAN_PATH itself from being flagged
        # (running with -p /etc/passwd shouldn't emit /etc/passwd as a finding).
        done < <(find "$path" -mindepth 1 "${FIND_EXCLUDE_ARGS[@]}" -type f \
            ! -iname '*.dll' ! -iname '*.exe' ! -iname '*.sys' ! -iname '*.so' \
            ! -iname '*.dylib' ! -iname '*.ocx' ! -iname '*.pdb' ! -iname '*.nupkg' \
            ! -iname '*.mui' ! -iname '*.cpl' ! -iname '*.drv' \
            -print0 2>/dev/null)
    done
}

# Stage 5 — recursive content scan of extension-matched candidates
enumerate_candidates() {
    build_find_excludes
    local path
    local size_args=()
    [ "$SKIP_LARGE" -eq 1 ] && size_args=( -size "-$((MAX_FILE_SIZE_MB * 1024 * 1024))c" )

    # Build the extension/name match expression ONCE as an argv array (it is
    # identical for every -p path). Empty in --all mode, where every file under
    # the (pruned) tree is a candidate.
    local name_args=()
    if [ "$ALL_MODE" -eq 0 ]; then
        local e
        for e in "${STAGE5_EXTENSIONS[@]}"; do name_args+=( -o -iname "*.${e}" ); done
        name_args+=( -o -iname 'Dockerfile' -o -iname 'Vagrantfile' -o -iname 'Makefile' -o -iname 'Jenkinsfile' )
        name_args+=( -o -iname '.env*' -o -iname '*rc' -o -iname 'authorized_keys' )
        name_args+=( -o -iname 'id_rsa' -o -iname 'id_dsa' -o -iname 'id_ecdsa' )
        name_args+=( -o -iname 'id_ed25519' -o -iname 'identity' -o -iname 'id_*' )
        name_args+=( -o -iname '.htpasswd' -o -iname 'htpasswd' -o -iname 'shadow' )
        # Extension-less auth files (so `-p /etc` scans them without Stage 1)
        name_args+=( -o -iname 'gshadow' -o -iname 'sudoers' -o -iname 'opasswd' )
        name_args+=( -o -iname '.netrc' -o -iname '_netrc' -o -iname '.git-credentials' )
        name_args+=( -o -iname '.gitconfig' -o -iname '.npmrc' -o -iname '.pypirc' )
        name_args+=( -o -iname '.s3cfg' -o -iname '.boto' -o -iname '.viminfo' )
        name_args+=( -o -iname '.psqlrc' -o -iname '.mysqlrc' -o -iname '.my.cnf' )
        # Shell/tool history files frequently contain command-line creds
        # (sshpass -p, mysql -pXXX, PGPASSWORD=, curl -u, etc.)
        name_args+=( -o -iname '.bash_history' -o -iname '.zsh_history' -o -iname '.sh_history' )
        name_args+=( -o -iname '.ksh_history' -o -iname '.ash_history' -o -iname '.history' )
        name_args+=( -o -iname '.psql_history' -o -iname '.mysql_history' -o -iname '.sqlite_history' )
        name_args+=( -o -iname '.python_history' -o -iname '.node_repl_history' )
        name_args+=( -o -iname '.irb_history' -o -iname '.rediscli_history' -o -iname '.lesshst' )
    fi

    for path in "${SCAN_PATHS[@]}"; do
        [ -e "$path" ] || { warn "Path does not exist: $path"; continue; }
        if [ "$ALL_MODE" -eq 1 ]; then
            find "$path" "${FIND_EXCLUDE_ARGS[@]}" -type f "${size_args[@]+"${size_args[@]}"}" -print0 2>/dev/null
        else
            local name_expr=( '(' "${name_args[@]:1}" ')' )
            find "$path" "${FIND_EXCLUDE_ARGS[@]}" -type f "${size_args[@]+"${size_args[@]}"}" "${name_expr[@]}" -print0 2>/dev/null
        fi
    done
}

scan_user_paths_contents() {
    [ ${#SCAN_PATHS[@]} -eq 0 ] && { warn "No paths provided; skipping."; return; }
    info "Enumerating candidate files…"
    # NUL-delimited throughout so filenames containing spaces/newlines survive.
    enumerate_candidates >"$CANDIDATE_FILES" 2>/dev/null
    [ -s "$CANDIDATE_FILES" ] && sort -z -u "$CANDIDATE_FILES" -o "$CANDIDATE_FILES"
    local total
    total=$(tr -cd '\0' <"$CANDIDATE_FILES" | wc -c | tr -d ' ')
    if [ "$total" -eq 0 ]; then
        warn "No candidate files found in the supplied paths."
        return
    fi
    ok "Candidate files: ${W}${total}${NC}  (mode: $( [ "$ALL_MODE" -eq 1 ] && echo all || echo extensions ))"
    local current=0
    while IFS= read -r -d '' f; do
        [ -z "$f" ] && continue
        current=$((current + 1))
        draw_progress "$current" "$total" "Scanning"
        scan_file "$f" "content"
    done <"$CANDIDATE_FILES"
    draw_progress "$total" "$total" "Scanning"
    end_progress
}

# ============================================================================
#  Output / summary
# ============================================================================

print_section_header() {
    printf '\n%b%s %s%b\n' "${BOLD}${W}" "$GBUL" "$1" "$NC"
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
    local n_guar n_high n_key n_int n_name n_check n_skip
    n_guar=$( [ -s "$GUARANTEED_FILE" ] && wc -l <"$GUARANTEED_FILE" | tr -d ' ' || echo 0)
    n_high=$( [ -s "$HIGH_FILE" ]    && wc -l <"$HIGH_FILE"    | tr -d ' ' || echo 0)
    n_key=$(  [ -s "$KEY_FILE" ]     && wc -l <"$KEY_FILE"     | tr -d ' ' || echo 0)
    n_int=$(  [ -s "$INTEREST_FILE" ]&& wc -l <"$INTEREST_FILE"| tr -d ' ' || echo 0)
    n_name=$( [ -s "$NAME_FILE" ]    && wc -l <"$NAME_FILE"    | tr -d ' ' || echo 0)
    n_check=$([ -s "$CHECKED_FILE" ] && wc -l <"$CHECKED_FILE" | tr -d ' ' || echo 0)
    n_skip=$( [ -s "$SKIPPED_FILE" ] && wc -l <"$SKIPPED_FILE" | tr -d ' ' || echo 0)

    section "Summary"
    sum_row "$BOLD$R" "Confirmed credential containers $GWARN" "$n_guar"
    sum_row "$R"      "Reusable credentials"                   "$n_high"
    sum_row "$M"      "Private keys / auth material"           "$n_key"
    sum_row "$C"      "Auxiliary credential-related files"     "$n_int"
    sum_row "$Y"      "Suspicious filenames (substring)"       "$n_name"
    sum_row "$B"      "OS locations checked"                   "$n_check"
    sum_row "$D"      "Files skipped (size/binary/perm)"       "$n_skip"

    log_line ""
    log_line "Summary:"
    log_line "  Confirmed credential containers: $n_guar"
    log_line "  Reusable credentials:            $n_high"
    log_line "  Private keys / material:         $n_key"
    log_line "  Auxiliary credential-related:    $n_int"
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
    setup_glyphs
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

    if [ "$STAGE1_SKIP" -eq 0 ]; then
        stage_begin 1
        run_system_checks
        stage_end 1 "OS-level credential checks"
    else
        stage_skipped 1 "OS-level credential checks"
    fi

    if [ ${#SCAN_PATHS[@]} -eq 0 ]; then
        warn "No paths supplied (-p). Skipping stages 2-5."
        warn "Tip: pass -p / to scan everything under root."
    else
        if [ "$STAGE2_SKIP" -eq 0 ]; then
            stage_begin 2; find_guaranteed_credentials; stage_end 2 "Confirmed credential containers"
        else
            stage_skipped 2 "Confirmed credential containers"
        fi
        if [ "$STAGE3_SKIP" -eq 0 ]; then
            stage_begin 3; find_high_value_files; stage_end 3 "High-value file types"
        else
            stage_skipped 3 "High-value file types"
        fi
        if [ "$STAGE4_SKIP" -eq 0 ]; then
            stage_begin 4; find_suspicious_filenames; stage_end 4 "Filename substring search"
        else
            stage_skipped 4 "Filename substring search"
        fi
        if [ "$STAGE5_SKIP" -eq 0 ]; then
            stage_begin 5; scan_user_paths_contents; stage_end 5 "Recursive content scan"
        else
            stage_skipped 5 "Recursive content scan"
        fi
    fi

    print_summary

    if [ -s "$GUARANTEED_FILE" ] || [ -s "$HIGH_FILE" ] || [ -s "$KEY_FILE" ]; then
        exit 1
    fi
    exit 0
}

main "$@"
