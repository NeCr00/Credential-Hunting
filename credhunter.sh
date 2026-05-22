#!/usr/bin/env bash
# ============================================================
#  credhunter.sh
#
#  Linux hardcoded-credential hunter for authorized
#  penetration testing, red-team labs, CTFs, and OSCP /
#  HTB / Proving Grounds style boxes.
#
#  Focus: hardcoded passwords, tokens, API keys, secrets,
#  DB connection strings, cloud credentials, private keys.
#
#  Usage:   ./credhunter.sh [options] <path>
#  Help:    ./credhunter.sh -h
#
#  Authorized testing only.
# ============================================================

set -o pipefail

# ----- defaults ----------------------------------------------------
MAX_SIZE="10M"
MODE="smart"            # smart | all
TARGET=""
CONTEXT=0
QUIET=0

declare -i HITS=0 FILES_LISTED=0
declare -A CAT_COUNT

# ----- colours (tty-aware) ----------------------------------------
if [[ -t 1 ]]; then
    RED=$'\033[1;31m'; YEL=$'\033[1;33m'; GRN=$'\033[1;32m'
    CYA=$'\033[1;36m'; MAG=$'\033[1;35m'; BLU=$'\033[1;34m'
    WHT=$'\033[1;37m'; BLD=$'\033[1m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
    RED=""; YEL=""; GRN=""; CYA=""; MAG=""; BLU=""; WHT=""; BLD=""; DIM=""; RST=""
fi

# ----- usage -------------------------------------------------------
usage() {
cat <<EOF
${BLD}credhunter.sh${RST}  -  Linux hardcoded credential hunter

Usage:
  $0 [options] <path>

Options:
  -a, --all            Scan every readable file under <path>.
                       Binary files and files larger than max-size are
                       still skipped. Default mode targets only the file
                       types that realistically hold credentials.
  -s, --max-size SIZE  Skip files larger than SIZE (find -size syntax:
                       500K, 5M, 1G, ...). Default: 10M.
  -c, --context        Print one line of surrounding context per hit.
  -q, --quiet          Hide banner / progress; only show findings + summary.
  -h, --help           Show this help.

Examples:
  $0 /etc
  $0 --all /var/www
  $0 -c -s 5M /home
  $0 -a -c /

Authorized testing only.
EOF
}

# ----- arg parsing -------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -a|--all)       MODE="all"; shift ;;
        -s|--max-size)  [[ -z "${2:-}" ]] && { echo "Error: -s needs a value." >&2; exit 1; }
                        MAX_SIZE="$2"; shift 2 ;;
        -c|--context)   CONTEXT=1; shift ;;
        -q|--quiet)     QUIET=1; shift ;;
        -h|--help)      usage; exit 0 ;;
        --)             shift; TARGET="${1:-}"; shift || true ;;
        -*)             echo "Unknown option: $1" >&2; usage; exit 1 ;;
        *)              TARGET="$1"; shift ;;
    esac
done

[[ -z "$TARGET" ]]   && { echo "Error: target path required." >&2; usage; exit 1; }
[[ ! -e "$TARGET" ]] && { echo "Error: '$TARGET' does not exist." >&2; exit 1; }
[[ ! -r "$TARGET" ]] && { echo "Error: '$TARGET' is not readable." >&2; exit 1; }

# ----- dependency check -------------------------------------------
for c in find grep awk xargs sed mktemp wc; do
    command -v "$c" >/dev/null 2>&1 || { echo "Error: required tool '$c' not found." >&2; exit 1; }
done
if ! echo x | grep -P x >/dev/null 2>&1; then
    echo "Error: this script needs grep with PCRE support (-P)." >&2
    exit 1
fi

# ----- temp file list ---------------------------------------------
FILELIST=$(mktemp /tmp/credhunter.XXXXXX) || { echo "mktemp failed" >&2; exit 1; }
trap 'rm -f "$FILELIST"' EXIT INT TERM

# ============================================================
# File enumeration
# ============================================================

# Files commonly hosting credentials on Linux systems.
SMART_NAMES=(
    # generic configuration
    '*.conf' '*.config' '*.cfg' '*.cnf' '*.ini' '*.properties'
    '*.yaml' '*.yml' '*.json' '*.toml' '*.xml' '*.plist'

    # env / dotenv
    '.env' '.env.*' '*.env' 'env.*' 'environment'

    # source code (frequent home of hardcoded creds in dev/CTF)
    '*.php' '*.py' '*.rb' '*.pl' '*.js' '*.ts' '*.jsx' '*.tsx'
    '*.mjs' '*.cjs' '*.go' '*.java' '*.kt' '*.scala' '*.groovy'
    '*.cs' '*.vb' '*.rs' '*.c' '*.cpp' '*.cc' '*.h' '*.hpp'
    '*.swift' '*.lua' '*.r' '*.sh' '*.bash' '*.zsh' '*.ksh'
    '*.fish' '*.ps1' '*.psm1' '*.vbs' '*.bat' '*.cmd' '*.tcl'

    # well-known app config filenames
    'wp-config.php' 'wp-config-sample.php'
    'web.config' 'app.config' 'machine.config'
    'settings.py' 'local_settings.py' 'config.py' 'secret.py' 'secrets.py'
    'config.php' 'configuration.php' 'connect.php' 'db.php' 'database.php'
    'database.yml' 'database.yaml' 'secrets.yml' 'secrets.yaml'
    'application.yml' 'application.yaml' 'application.properties'
    'bootstrap.yml' 'bootstrap.properties'
    'standalone.xml' 'server.xml' 'context.xml' 'tomcat-users.xml'
    'hibernate.cfg.xml' 'persistence.xml'

    # backups / temp / examples
    '*.bak' '*.backup' '*.old' '*.orig' '*.save' '*.swp' '*~'
    '*.tmp' '*.copy' '*.dist' '*.sample' '*.example' '*.template'

    # SQL and DB dumps
    '*.sql' '*.dump' '*.psql' '*.mysqldump'

    # shell / repl history
    '.bash_history' '.zsh_history' '.ash_history' '.sh_history' '.history'
    '.mysql_history' '.psql_history' '.sqlite_history' '.lesshst'
    '.python_history' '.node_repl_history' '.rediscli_history' '.irb_history'

    # credential / auth files
    '.netrc' '_netrc' '.pgpass' '.my.cnf' '.htpasswd' '.htdigest'
    'credentials' 'credentials.csv' 'credentials.json' 'authinfo' 'authinfo.gpg'
    'passwords' 'passwords.txt' 'shadow' 'gshadow' 'master.passwd'
    'passwd-' 'shadow-' 'sssd.conf'

    # SSH keys / configs
    'id_rsa' 'id_dsa' 'id_ecdsa' 'id_ed25519' 'id_xmss'
    'authorized_keys' 'known_hosts' 'ssh_config' 'sshd_config' 'config'

    # service configs commonly with creds
    'smb.conf' 'smbpasswd' 'vsftpd.conf' 'proftpd.conf'
    'pg_hba.conf' 'postgresql.conf' 'redis.conf' 'mongod.conf'
    'php.ini' 'php-fpm.conf' 'nginx.conf' 'httpd.conf' 'apache2.conf'
    'crontab' 'anacrontab'

    # cloud / containers / IaC / CI
    'Dockerfile' 'Dockerfile.*' 'docker-compose*.yml' 'docker-compose*.yaml'
    '.dockercfg' 'config.json'
    '*.tf' '*.tfvars' 'terraform.tfstate' 'terraform.tfstate.backup'
    'Vagrantfile' 'Jenkinsfile'
    '.gitlab-ci.yml' '.travis.yml' 'azure-pipelines.yml'
    'cloudbuild.yaml' 'serverless.yml' 'sam.yaml' 'sam.yml'
    'ansible.cfg' 'hosts' 'inventory'

    # logs (size-capped)
    '*.log' '*.log.*'

    # plain text formats that frequently contain notes / creds
    '*.txt' '*.md' '*.csv' '*.rst' '*.tsv' '*.note' '*.notes'
)

# Directories pruned in both modes (build/cache/VCS noise).
EXCLUDE_DIR_NAMES=(
    '.git' '.svn' '.hg' '.bzr'
    'node_modules' 'bower_components'
    '__pycache__' '.pytest_cache' '.mypy_cache' '.ruff_cache'
    'venv' '.venv' '.tox' 'virtualenv'
    'vendor' 'site-packages' 'eggs' '.eggs'
    'dist' 'build' 'target' 'out' '.next' '.nuxt'
    '.cache' '.npm' '.yarn' '.gradle' '.m2' '.ivy2'
    '.idea' '.vscode' '.terraform'
)

# Always-pruned absolute paths (virtual / runtime FS).
EXCLUDE_FULL_PATHS=( '/proc' '/sys' '/dev' '/run' '/snap' )

enumerate_files() {
    local -a args=( "$TARGET" )
    local first

    # 1) prune virtual filesystem paths
    args+=( '(' )
    first=1
    for p in "${EXCLUDE_FULL_PATHS[@]}"; do
        if (( first )); then args+=( '-path' "$p" ); first=0
        else                  args+=( '-o' '-path' "$p" ); fi
    done
    args+=( ')' '-prune' '-o' )

    # 2) prune noisy directory names
    args+=( '(' '-type' 'd' '(' )
    first=1
    for d in "${EXCLUDE_DIR_NAMES[@]}"; do
        if (( first )); then args+=( '-name' "$d" ); first=0
        else                  args+=( '-o' '-name' "$d" ); fi
    done
    args+=( ')' ')' '-prune' '-o' )

    # 3) file matching
    if [[ "$MODE" == "all" ]]; then
        args+=( '(' '-type' 'f' '-size' "-$MAX_SIZE" '-print' ')' )
    else
        args+=( '(' '-type' 'f' '-size' "-$MAX_SIZE" '(' )
        first=1
        for n in "${SMART_NAMES[@]}"; do
            if (( first )); then args+=( '-iname' "$n" ); first=0
            else                  args+=( '-o' '-iname' "$n" ); fi
        done
        args+=( ')' '-print' ')' )
    fi

    find "${args[@]}" 2>/dev/null
}

# ============================================================
# Regex patterns
# ------------------------------------------------------------
# Tuned for high signal on hardcoded credentials. PCRE syntax.
# \x27 is a single quote (avoids shell quoting headaches).
# ============================================================

# ---- PRIVATE KEYS -----------------------------------------------------------
PAT_PRIVKEY='-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED|DH) )?PRIVATE KEY(?: BLOCK)?-----'
PAT_PUTTY='^PuTTY-User-Key-File-[0-9]+:'

# ---- PASSWORDS (primary target) ---------------------------------------------
# Key=value, with an optional snake-case prefix, optional surrounding quotes
# on the key (handles JSON/PHP-array syntax), and value of >=2 non-quote chars.
PAT_PASSWORD='(?i)(?<![A-Za-z])(?:[a-z][a-z0-9_]*_)?(?:password|passwd|passphrase|pwd)(?![A-Za-z])["\x27]?\s*(?:=>|[:=])\s*["\x27]?[^"\x27\s\r\n#;,]{2,200}'
# PHP define('KEY', 'value') with KEY containing pass/pwd
PAT_PASSWORD_DEFINE='(?i)\bdefine\s*\(\s*["\x27][a-z0-9_]*(?:password|passwd|pwd)[a-z0-9_]*["\x27]\s*,\s*["\x27][^"\x27\r\n]{1,200}["\x27]'
# .netrc style "password <value>"
PAT_PASSWORD_NETRC='(?i)(?:^|[^A-Za-z_])password\s+\S{3,}'
# bare "password" alone on a line is too noisy, but plain "user:pass" pairs
# (e.g. dumped from a SQL table) are worth flagging
PAT_PASSWORD_USERPASS='(?i)^[\s\t]*(?:user(?:name)?|login)\s*[:=]\s*\S{1,}\s*[\r\n].{0,80}(?:password|passwd|pwd)\s*[:=]\s*\S{3,}'

# ---- DB / SERVICE URLs WITH EMBEDDED CREDENTIALS ---------------------------
# protocol://user:pass@host  (catches mysql/postgres/mongo/redis/ftp/http/ssh/…)
PAT_URL_CREDS='(?i)\b(?:https?|ftp|ftps|sftp|ssh|scp|rsync|ldap|ldaps|mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|kafka|smtp|smtps|imap|imaps|pop3|pop3s)://[^:/\s@"\x27]+:[^/\s@"\x27<>]{1,}@[^\s"\x27<>]+'
# JDBC URL with explicit credentials in query string
PAT_JDBC='(?i)jdbc:[a-z0-9]+:[^"\x27\s]+[?&;](?:user|password|pwd)=[^"\x27\s&;]+'

# ---- AWS --------------------------------------------------------------------
# Access Key IDs (very high confidence)
PAT_AWS_AKID='\b(?:AKIA|ASIA|AGPA|AIDA|ANPA|AROA|ABIA|ACCA)[0-9A-Z]{16}\b'
# Generic AWS secret key declaration
PAT_AWS_SECRET='(?i)\baws[_\-]?(?:secret[_\-]?)?(?:access[_\-]?)?key(?:[_\-]?id)?\b\s*(?:=>|[:=])\s*["\x27]?[A-Za-z0-9/+=]{16,}["\x27]?'

# ---- HIGH-CONFIDENCE TOKEN FORMATS -----------------------------------------
PAT_TOKEN='\b(?:ghp_[A-Za-z0-9]{30,}|gho_[A-Za-z0-9]{30,}|ghu_[A-Za-z0-9]{30,}|ghs_[A-Za-z0-9]{30,}|ghr_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|sk-proj-[A-Za-z0-9_\-]{20,}|sk-ant-[A-Za-z0-9_\-]{20,}|AIza[0-9A-Za-z_\-]{35}|ya29\.[0-9A-Za-z_\-]{20,}|glpat-[0-9A-Za-z_\-]{20}|hf_[A-Za-z0-9]{30,}|EAAA[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{36}|dckr_pat_[A-Za-z0-9_\-]{20,}|SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}|atlassian_api_token[a-z0-9_=]*)\b'

# ---- JWTs -------------------------------------------------------------------
PAT_JWT='\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'

# ---- GENERIC API KEYS -------------------------------------------------------
PAT_API_KEY='(?i)\b(?:api[_\-]?key|apikey|x[_\-]?api[_\-]?key|client[_\-]?secret|consumer[_\-]?(?:key|secret)|access[_\-]?token|auth[_\-]?token|bearer[_\-]?token|refresh[_\-]?token|app[_\-]?key|app[_\-]?id|private[_\-]?token)\b["\x27]?\s*(?:=>|[:=])\s*["\x27]?[A-Za-z0-9_\-\.=/+]{12,}["\x27]?'

# ---- AUTHORIZATION HEADERS --------------------------------------------------
PAT_AUTH='(?i)\bauthorization\s*[:=]\s*["\x27]?(?:Bearer|Basic|Digest|Token)\s+[A-Za-z0-9_\-\.=/+]{8,}'

# ---- AZURE / GCP ------------------------------------------------------------
PAT_AZURE='(?i)(?:DefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{40,}|AccountKey=[A-Za-z0-9+/=]{60,}|SharedAccessSignature=sv=[A-Za-z0-9%&=_\-]+)'
PAT_GCP='"type"\s*:\s*"service_account"'

# ---- NETRC BLOCK ------------------------------------------------------------
PAT_NETRC_BLOCK='(?i)^\s*machine\s+\S+\s+login\s+\S+\s+password\s+\S+'

# ---- GENERIC SECRETS --------------------------------------------------------
PAT_SECRET='(?i)\b(?:secret[_\-]?key|signing[_\-]?key|encryption[_\-]?key|app[_\-]?secret|session[_\-]?secret|csrf[_\-]?secret|jwt[_\-]?secret|django[_\-]?secret|flask[_\-]?secret|rails[_\-]?secret|cookie[_\-]?secret|webhook[_\-]?secret|master[_\-]?key)\b["\x27]?\s*(?:=>|[:=])\s*["\x27]?[^"\x27\s\r\n#;,]{6,}'

# ---- PASSWORD HASHES (shadow / htpasswd / NTLM / etc.) ---------------------
PAT_HASH='\$(?:1|2[abxy]?|5|6|y|7)\$[A-Za-z0-9./]{1,}\$[A-Za-z0-9./]{8,}|\$apr1\$[A-Za-z0-9./]{1,}\$[A-Za-z0-9./]{8,}|:\$NT\$[a-fA-F0-9]{32}|\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b'

# ============================================================
# Output helpers
# ============================================================

print_context() {
    local file="$1" lineno="$2"
    [[ -r "$file" ]] || return 0
    local start end
    start=$(( lineno > 1 ? lineno - 1 : 1 ))
    end=$(( lineno + 1 ))
    sed -n "${start},${end}p" "$file" 2>/dev/null | \
        awk -v ln="$start" -v hit="$lineno" -v dim="$DIM" -v rst="$RST" '
            {
                cur = ln + NR - 1
                if (cur == hit) next
                # truncate context lines too
                line = $0
                if (length(line) > 200) line = substr(line, 1, 200) "…"
                printf "  %s│ %s%s\n", dim, line, rst
            }'
}

# scan_category CATEGORY COLOR PATTERN [PATTERN ...]
#
# GNU grep's -P (PCRE) mode only accepts a *single* pattern, so we combine
# all category patterns into one non-capturing alternation:  (?:p1)|(?:p2)|...
scan_category() {
    local cat="$1"; shift
    local color="$1"; shift
    local combined=""
    local p
    for p in "$@"; do
        if [[ -z "$combined" ]]; then
            combined="(?:${p})"
        else
            combined="${combined}|(?:${p})"
        fi
    done

    # Process substitution keeps the while loop in the parent shell so the
    # counter variables actually update.
    while IFS= read -r entry; do
        # entry format from grep -H -n  =>  file:lineno:content
        local file="${entry%%:*}"
        local rest="${entry#*:}"
        local lineno="${rest%%:*}"
        local content="${rest#*:}"
        # trim leading whitespace from content
        content="${content#"${content%%[![:space:]]*}"}"
        [[ -z "$content" ]] && continue
        # truncate very long lines (minified JS, dumps, etc.)
        if (( ${#content} > 240 )); then
            content="${content:0:240}…"
        fi
        printf "%s[%-11s]%s %s%s%s:%s%s%s  %s\n" \
            "$color" "$cat" "$RST" \
            "$CYA" "$file" "$RST" \
            "$YEL" "$lineno" "$RST" \
            "$content"
        (( CONTEXT )) && print_context "$file" "$lineno"
        ((HITS++))
        CAT_COUNT[$cat]=$(( ${CAT_COUNT[$cat]:-0} + 1 ))
    done < <(xargs -a "$FILELIST" -d '\n' -r \
                 grep -P -H -n -I --color=never \
                      -e "$combined" 2>/dev/null)
}

banner() {
    printf "%s┌──────────────────────────────────────────────────┐%s\n" "$BLD" "$RST"
    printf "%s│%s  %scredhunter%s  ·  Linux credential discovery       %s│%s\n" \
           "$BLD" "$RST" "$GRN" "$RST" "$BLD" "$RST"
    printf "%s└──────────────────────────────────────────────────┘%s\n" "$BLD" "$RST"
    printf "%starget:%s    %s\n"      "$DIM" "$RST" "$TARGET"
    printf "%smode:%s      %s    %smax-size:%s %s    %scontext:%s %s\n\n" \
        "$DIM" "$RST" "$MODE" \
        "$DIM" "$RST" "$MAX_SIZE" \
        "$DIM" "$RST" "$( ((CONTEXT)) && echo on || echo off )"
}

print_summary() {
    echo
    printf "%s──────────────  summary  ──────────────%s\n" "$BLD" "$RST"
    if (( HITS == 0 )); then
        printf "%sNo credential indicators found.%s\n" "$DIM" "$RST"
        printf "%sFiles scanned: %d%s\n" "$DIM" "$FILES_LISTED" "$RST"
        return
    fi
    printf "%sTotal hits:%s %d   %sFiles scanned:%s %d\n\n" \
        "$BLD" "$RST" "$HITS" "$DIM" "$RST" "$FILES_LISTED"
    # sort categories by count desc
    {
        for cat in "${!CAT_COUNT[@]}"; do
            printf "%d\t%s\n" "${CAT_COUNT[$cat]}" "$cat"
        done
    } | sort -k1,1 -nr | while IFS=$'\t' read -r count cat; do
        printf "  %s%-12s%s %d\n" "${BLD}" "$cat" "${RST}" "$count"
    done
}

# ============================================================
# Main
# ============================================================

(( QUIET )) || banner

# Enumerate target files
enumerate_files > "$FILELIST"
FILES_LISTED=$(wc -l < "$FILELIST")

if (( FILES_LISTED == 0 )); then
    (( QUIET )) || printf "%s[!]%s No matching files under '%s'.\n" "$YEL" "$RST" "$TARGET"
    print_summary
    exit 0
fi

(( QUIET )) || printf "%s[i]%s scanning %d file(s)…\n\n" "$BLU" "$RST" "$FILES_LISTED"

# Order: highest-signal first so the most important hits stream out early.
scan_category "PRIVATE_KEY" "$RED" "$PAT_PRIVKEY" "$PAT_PUTTY"
scan_category "PASSWORD"    "$RED" "$PAT_PASSWORD" "$PAT_PASSWORD_DEFINE" \
                                   "$PAT_PASSWORD_NETRC" "$PAT_PASSWORD_USERPASS"
scan_category "URL_CREDS"   "$RED" "$PAT_URL_CREDS" "$PAT_JDBC"
scan_category "AWS"         "$RED" "$PAT_AWS_AKID" "$PAT_AWS_SECRET"
scan_category "TOKEN"       "$MAG" "$PAT_TOKEN"
scan_category "JWT"         "$MAG" "$PAT_JWT"
scan_category "API_KEY"     "$YEL" "$PAT_API_KEY"
scan_category "AUTH_HEADER" "$YEL" "$PAT_AUTH"
scan_category "AZURE"       "$YEL" "$PAT_AZURE"
scan_category "GCP"         "$YEL" "$PAT_GCP"
scan_category "NETRC"       "$YEL" "$PAT_NETRC_BLOCK"
scan_category "SECRET"      "$YEL" "$PAT_SECRET"
scan_category "HASH"        "$BLU" "$PAT_HASH"

print_summary
