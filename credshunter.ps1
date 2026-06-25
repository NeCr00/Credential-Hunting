<#
.SYNOPSIS
    credshunter - Reusable-credential discovery for authorized Windows
    post-exploitation (read-only).

.DESCRIPTION
    Hunts for material a pentester can actually re-use to move laterally or
    escalate privileges: plaintext passwords, DB connection strings, GPP
    cpassword, unattend autologon, SSH / PuTTY private keys, NTLM / Kerberos
    / shadow hashes, command-line credentials in PowerShell history,
    sudoers NOPASSWD analogues, htpasswd / netrc / smb.conf, etc.

    Deliberately ignores cloud / SaaS access tokens (JWT, AWS keys, GitHub
    tokens, Slack tokens, generic API keys) - those rarely help with
    lateral movement inside a network and produce most of the noise on
    real hosts.

    Read-only. Never modifies the system. Never transmits data.
    Built for authorized internal pentests, red-team engagements, CTFs.

.PARAMETER Path
    One or more directories to scan recursively (stages 2-5).

.PARAMETER ExcludePath
    Directories to skip during stages 2-5. Stage 1 (OS-level credential
    checks) always uses its own hardcoded list and is unaffected.

.PARAMETER All
    Stage 5 scans every readable text file in -Path, not just
    credential-related extensions. Binary files still skipped.

.PARAMETER MaxFileSizeMB
    Skip files larger than this many megabytes. Default 5.

.PARAMETER NoSizeLimit
    Disable the file-size cap.

.PARAMETER OutputFile
    Append a plain-text log of all findings.

.PARAMETER SkipSystem
    Skip stage 1 (OS-level credential checks). Alias for -NoStage1.

.PARAMETER NoStage1
    Skip stage 1 (OS-level credential checks).

.PARAMETER NoStage2
    Skip stage 2 (confirmed credential containers).

.PARAMETER NoStage3
    Skip stage 3 (high-value file types).

.PARAMETER NoStage4
    Skip stage 4 (filename substring search).

.PARAMETER NoStage5
    Skip stage 5 (recursive content scan).

.PARAMETER Quiet
    Reduce status noise. Findings still printed.

.PARAMETER NoColor
    Strip ANSI colour codes.

.PARAMETER IncludeData
    Opt-in: also content-scan large data / SQL files in stage 5
    (.sql/.ddl/.dump/.psql/.pgsql/.plsql/.tsql/.csv/.tsv). These follow the
    normal -MaxFileSizeMB size cap. Off by default because such files are
    routinely huge and rarely hold hardcoded credentials.

.PARAMETER NoDefaultExclude
    Disable the built-in system / vendor directory excludes (Windows Defender,
    SDKs, Visual Studio, driver vendors, upgrade-staging dirs, etc.) that keep a
    C:\ scan fast. Stage 1's targeted OS checks are unaffected either way.

.EXAMPLE
    .\credshunter.ps1 -Path C:\Users, C:\inetpub -OutputFile loot.txt

.EXAMPLE
    .\credshunter.ps1 -Path C:\ -MaxFileSizeMB 10

.EXAMPLE
    .\credshunter.ps1 -SkipSystem -Path .\app -Quiet

.NOTES
    Requires PowerShell 5.1+. Elevated session recommended for SAM /
    SYSTEM hives, vault directories, and Wi-Fi key-clear dumps.
#>
#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string[]] $Path = @(),

    [string[]] $ExcludePath = @(),

    [switch] $All,

    [switch] $IncludeData,   # opt-in: re-enable scanning of large data/SQL files
                             # (.sql/.ddl/.dump/.psql/.pgsql/.plsql/.tsql/.csv/.tsv)

    [switch] $NoDefaultExclude,   # disable the built-in system/vendor path excludes

    [ValidateRange(1, 10240)]
    [int] $MaxFileSizeMB = 5,

    [switch] $NoSizeLimit,

    [string] $OutputFile,

    [switch] $SkipSystem,
    [switch] $NoStage1,
    [switch] $NoStage2,
    [switch] $NoStage3,
    [switch] $NoStage4,
    [switch] $NoStage5,

    [switch] $Quiet,

    [switch] $NoColor,

    [Alias('h','?')]
    [switch] $Help
)

$script:Version = '2.3.0'

# Minimalistic, Linux-style usage. Shown for -Help / -h and when the script is
# run with no parameters at all. (Get-Help .\credshunter.ps1 still gives the full
# comment-based reference.)
function Show-Usage {
    @"
credshunter v$($script:Version) - reusable-credential discovery (read-only, Windows)

Usage: .\credshunter.ps1 -Path <dir>[,<dir>] [options]

  -Path <dir>          Directories to scan (stages 2-5)
  -ExcludePath <dir>   Directories to skip (stages 2-5)
  -NoDefaultExclude    Don't skip built-in system / vendor dirs
  -All                 Stage 5 scans every readable file
  -IncludeData         Also scan large SQL / CSV / data files
  -MaxFileSizeMB <n>   Skip files larger than n MB (default 5)
  -NoSizeLimit         Disable the file-size cap
  -OutputFile <file>   Append a findings log
  -SkipSystem          Skip stage 1 (OS checks); alias -NoStage1
  -NoStage1..5         Skip an individual stage
  -Quiet               Reduce status noise
  -NoColor             Strip colour codes
  -Help                Show this help (-h)

Examples:
  .\credshunter.ps1 -Path C:\ -OutputFile loot.txt
  .\credshunter.ps1 -Path C:\Users,C:\inetpub -SkipSystem
"@
}

if ($Help -or $PSBoundParameters.Count -eq 0) {
    Show-Usage
    exit 0
}

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'Continue'

# Stage-skip booleans: -SkipSystem is the legacy alias for -NoStage1.
$script:Stage1Skip = $SkipSystem.IsPresent -or $NoStage1.IsPresent
$script:Stage2Skip = $NoStage2.IsPresent
$script:Stage3Skip = $NoStage3.IsPresent
$script:Stage4Skip = $NoStage4.IsPresent
$script:Stage5Skip = $NoStage5.IsPresent

# Resolve our own path so we never scan ourselves
$script:SelfPath = $null
try { $script:SelfPath = $PSCommandPath } catch {}
if ([string]::IsNullOrEmpty($script:SelfPath)) {
    try { $script:SelfPath = $MyInvocation.MyCommand.Path } catch {}
}

# ----------------------------------------------------------------------------
#  Configuration
# ----------------------------------------------------------------------------
$script:MaxFileSizeBytes  = $MaxFileSizeMB * 1MB
$script:SkipLarge         = -not $NoSizeLimit.IsPresent
$script:MaxMatchesPerFile = 20
$script:MaxPreviewLen     = 140
# Longest line scanned per file. 16 KB covers single-line GPP Groups.xml /
# one-line JSON connection strings while bounding .NET regex backtracking on
# minified/base64/log lines. Mirrored in the bash engine (MAX_LINE_LEN).
$script:MaxLineLen        = 16384

# Normalise user exclusions to absolute paths (no symlink resolution)
$script:UserExcludePaths = @()
foreach ($p in $ExcludePath) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    try { $abs = [System.IO.Path]::GetFullPath($p) } catch { $abs = $p }
    $abs = $abs.TrimEnd('\','/')
    if ($abs.Length -gt 0) { $script:UserExcludePaths += $abs }
}

# ----------------------------------------------------------------------------
#  Colours (ASCII only - no Unicode glyphs so PS 5.1 reads the file
#  correctly regardless of host code page)
# ----------------------------------------------------------------------------
# Disable colour when stdout is redirected to a file/pipe (parity with the
# bash `[ ! -t 2 ]` check) so `> out.txt` and CI captures stay free of ANSI.
$script:OutputRedirected = $false
try { $script:OutputRedirected = [System.Console]::IsOutputRedirected } catch {}
$script:UseColor = -not $NoColor `
    -and -not (Test-Path Env:NO_COLOR) `
    -and -not $script:OutputRedirected `
    -and ($Host.Name -ne 'Default Host')

if ($script:UseColor) {
    $ESC = [char]27
    $script:CR    = "$ESC[1;31m"; $script:CG = "$ESC[1;32m"
    $script:CY    = "$ESC[1;33m"; $script:CB = "$ESC[1;34m"
    $script:CM    = "$ESC[1;35m"; $script:CC = "$ESC[1;36m"
    $script:CW    = "$ESC[1;37m"; $script:CD = "$ESC[2m"
    $script:CBold = "$ESC[1m";    $script:CNC = "$ESC[0m"
} else {
    $script:CR=''; $script:CG=''; $script:CY=''; $script:CB=''
    $script:CM=''; $script:CC=''; $script:CW=''; $script:CD=''
    $script:CBold=''; $script:CNC=''
}

# ----------------------------------------------------------------------------
#  Finding storage
# ----------------------------------------------------------------------------
$script:HighFindings     = [System.Collections.Generic.List[object]]::new()
$script:KeyFindings      = [System.Collections.Generic.List[object]]::new()
$script:Interesting      = [System.Collections.Generic.List[object]]::new()
$script:Guaranteed       = [System.Collections.Generic.List[object]]::new()
$script:GuaranteedHashes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:SuspiciousNamesFound = [System.Collections.Generic.List[string]]::new()
$script:NameHashes       = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:LocationsChecked = [System.Collections.Generic.List[object]]::new()
$script:CheckedHashes    = [System.Collections.Generic.HashSet[string]]::new()
$script:SkippedFiles     = [System.Collections.Generic.List[object]]::new()
$script:FindingHashes    = [System.Collections.Generic.HashSet[string]]::new()
$script:InterestingHashes = [System.Collections.Generic.HashSet[string]]::new()
$script:ScannedPaths     = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# Stage-1 live-output state. When InStage1 is true, the Add-* helpers stream
# each finding to the host as it is recorded so the operator sees results in
# real time. SubstageFindings is reset before each substage runs; if it is
# still 0 when the substage returns, a "no credentials found" line is shown.
$script:InStage1         = $false
$script:SubstageFindings = 0

# ============================================================================
#  Pattern data - PASSWORD-FOCUSED for lateral movement / priv-esc
# ============================================================================
#
# One unified list. Each entry has a label and a regex compiled once at
# startup. No cloud / SaaS access tokens (JWT, AWS, GitHub, Slack, generic
# API keys) - they dominate noise on real hosts and rarely help in-network.

$script:RawPatterns = @(
    # ---- Direct password assignments ---------------------------------------
    @{ Label = 'password_assign';
       Regex = '(?im)(^|[^A-Za-z_])(password|passwd|passphrase|pwd)["'']?\s*[:=]\s*["'']?[^\s"#<>{}]{3,}' }

    # ---- DB / service-prefixed passwords ------------------------------------
    @{ Label = 'db_password';
       Regex = '(?im)(db|database|mysql|psql|pg|postgres|mongo|mssql|sql|sa|dba|oracle|redis|memcache|ldap|smtp|smb|ftp|sftp|imap|pop3|admin|user|service|svc|jenkins|jboss|tomcat|nexus|gitlab|jira|svn|backup|root|wp|wordpress|joomla|drupal|magento|laravel|django|proxy|vpn|cifs)[_-]?(password|passwd|passphrase|pwd|pass)["'']?\s*[:=]\s*["'']?[^\s"#<>{}]{3,}' }
    # Any identifier ending in _password/_pass/_pwd (OpenStack keystone_password,
    # nova_password, app_password, mail_pass, ...). Value FP filter prunes refs.
    @{ Label = 'prefixed_password';
       Regex = '(?im)[A-Za-z][A-Za-z0-9]*_(password|passwd|passphrase|pwd|pass)["'']?\s*[:=]\s*["'']?[^\s"#<>{}]{3,}' }

    # ---- Connection-string passwords (.NET / JDBC / ODBC) -------------------
    @{ Label = 'connection_string';
       Regex = '(?im)(server|host|data[ _-]?source)\s*=.{1,200}(password|pwd)\s*=\s*["'']?[^;&\s"]{3,}' }
    @{ Label = 'jdbc_url';
       Regex = '(?i)jdbc:[a-z]+://[^\s"]*[?&;]password=[^;&\s"]{3,}' }

    # ---- URL-embedded credentials ------------------------------------------
    @{ Label = 'url_credentials';
       Regex = '(?i)(mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|rabbitmq|ftp|ftps|sftp|ssh|smb|cifs|ldap[s]?|imap[s]?|smtp[s]?|https?)://[^\s/:@]+:[^\s/@]{2,}@' }

    # ---- Windows-specific high-value ---------------------------------------
    @{ Label = 'gpp_cpassword';
       Regex = '(?i)cpassword\s*=\s*"([A-Za-z0-9+/=]{20,})"' }
    @{ Label = 'unattend_password';
       Regex = '(?is)<(?:Administrator)?Password>\s*<Value>([^<]{2,})(?:</Value>)?' }
    # `["']?` before the operator so the canonical .reg export form
    # "DefaultPassword"="value" is matched (now that UTF-16 .reg files are read).
    @{ Label = 'autologon_password';
       Regex = '(?i)(DefaultPassword|AltDefaultPassword)["'']?\s*[:=]\s*["'']?[^\s"#]{2,}' }

    # ---- Environment-variable credentials ----------------------------------
    @{ Label = 'env_password';
       Regex = '(?im)(^|\s)(set\s+|export\s+|setx\s+)?[A-Z][A-Z0-9_]*(PASSWORD|PASSWD|PASSPHRASE)[A-Z0-9_]*\s*=\s*["'']?[^\s"<>]{3,}' }
    @{ Label = 'pgpassword_env';
       Regex = '(?im)\bPGPASSWORD\s*=\s*["'']?[^\s"#]{3,}' }
    @{ Label = 'mysql_pwd_env';
       Regex = '(?im)\bMYSQL_PWD\s*=\s*["'']?[^\s"#]{3,}' }

    # ---- Shell-history / command-line credentials --------------------------
    @{ Label = 'sshpass_cmd';
       Regex = '(?i)sshpass\s+(-p|--password)\s*["'']?[^\s''"]{2,}' }
    @{ Label = 'mysql_cmd';
       Regex = '(?i)(mysql|mysqladmin|mysqldump|mysqlimport)\s.*(--password=[^\s"#]{2,}|\s-p[^\s"#-][^\s"#]{2,})' }
    @{ Label = 'psql_cmd';
       Regex = '(?i)psql\s.*(-W\s|--password=|host=\S+.*password=)[^\s"#]{2,}' }
    @{ Label = 'mongo_cmd';
       Regex = '(?i)(mongo|mongosh|mongodump|mongorestore)\s.*(-p|--password)[\s=]+["'']?[^\s''"]{2,}' }
    @{ Label = 'redis_cmd';
       Regex = '(?i)redis-cli\s.*(-a|--pass)[\s=]+["'']?[^\s''"]{2,}' }
    @{ Label = 'curl_basic';
       Regex = '(?i)(curl|wget)\s.*--?(u|user|http-user)[\s=]+[^:\s]+:[^\s''"]{3,}' }
    @{ Label = 'wget_pass';
       Regex = '(?i)wget\s.*--(http-password|password|ftp-password)[\s=]+[^\s"]{3,}' }
    @{ Label = 'smbclient_pass';
       Regex = '(?i)smbclient\s.*-U\s+[^%\s]+%[^\s]{3,}' }
    @{ Label = 'cifs_mount_pass';
       Regex = '(?i)mount(\.cifs)?\s+(-t\s+cifs|//\S+)\s+.*\b(pass|password)=[^,\s"]{3,}' }
    @{ Label = 'lftp_pass';
       Regex = '(?i)lftp\s.*(-u\s+[^,\s]+,[^\s]{2,}|-p\s+["'']?[^\s''"]{2,})' }
    @{ Label = 'keepalived_authpass';
       Regex = '(?im)^\s*auth_pass\s+[^\s#]{2,}' }
    @{ Label = 'reg_autologon';
       Regex = '(?i)reg(\.exe)?\s+add.*(Default|AltDefault)Password.*/d\s+["'']?[^\s''"/]{2,}' }
    @{ Label = 'freerdp_pass';
       Regex = '(?i)(xfreerdp|freerdp|rdesktop|mstsc)\s.*(-p|/p:)\s?["'']?[^\s"]{2,}' }
    @{ Label = 'plink_pass';
       Regex = '(?i)plink(\.exe)?\s.*-pw\s+["'']?[^\s''"]{2,}' }
    # Generic password flag in ANY command line (not coupled to a tool name):
    # catches &(''...plink.exe'') -pw ''SECRET'', --password=X, /p:X which the
    # tool-anchored patterns above miss (e.g. PuTTY ProxyCommand using the
    # PowerShell call-operator syntax).
    @{ Label = 'cmdline_pw_flag';
       Regex = '(?i)(^|\s)((-pw|--pw|-pass|--password)[\s=]+["'']?[^\s"'']{3,}|(/p:|/pass:|/password:)["'']?[^\s"'']{3,})' }
    # `net use \\srv\share /user:DOMAIN\user PASSWORD` OR
    # `net use \\srv\share PASSWORD /user:DOMAIN\user` -- the password can come
    # before OR after the /user: token, so match both orderings.
    @{ Label = 'net_use_pass';
       Regex = '(?i)net\s+use\s+\S+(\s+/user:\S+\s+[^\s/"]{3,}|\s+[^\s/"]{3,}\s+/user:\S+)' }
    # `net user <user> <password> [/add|/domain|...]` -- trailing flag is
    # OPTIONAL so a plain `net user john MyPass` set-password is also caught;
    # tokens must not start with `/`, so the 2-token display form is ignored.
    @{ Label = 'net_user_create';
       Regex = '(?i)net\s+user\s+[^\s/]+\s+["'']?[^\s/"'']{3,}' }
    # PowerShell local-user / AD password cmdlets -- common in deploy scripts
    @{ Label = 'ps_localuser_pass';
       Regex = '(?i)(New-LocalUser|Add-LocalUser|Set-LocalUser)\s.*-(Password|AccountPassword)\s+["''][^"'']{3,}["'']' }
    @{ Label = 'ps_ad_password';
       Regex = '(?i)(Set-ADAccountPassword|New-ADUser)\s.*-(AccountPassword|NewPassword)\s' }
    # Robust: positional or -String, and -Force optional.
    @{ Label = 'ps_secstring_plain';
       Regex = '(?i)ConvertTo-SecureString\s+(-String\s+)?["''][^"'']{3,}["'']\s+(-Key\s+\S+\s+)?-AsPlainText' }
    # Plaintext password passed to a cmdlet -Password/-AccountPassword param as
    # a quoted literal (secure-string objects use $vars and are not matched).
    @{ Label = 'ps_password_param';
       Regex = '(?i)-(Password|Pass|AccountPassword|AdminPassword|NewPassword|DefaultPassword)\s+["''][^"'']{3,}["'']' }
    # Linux user-creation in shell scripts (HTB / OSCP staples)
    @{ Label = 'useradd_pass';
       Regex = '(?i)(useradd|usermod)\s.*-p\s+["'']?[^\s"'']{3,}' }
    @{ Label = 'chpasswd_inline';
       Regex = '(?i)(echo|printf)\s+["'']?[^:\s]+:[^\s"'']{3,}["'']?\s*\|\s*chpasswd' }
    @{ Label = 'chpasswd_heredoc';
       Regex = '(?i)chpasswd\s*<<<?\s*["'']?[^:\s]+:[^\s"'']{3,}' }
    @{ Label = 'passwd_stdin';
       Regex = '(?i)(echo|printf)\s+["''][^"'']{3,}["'']\s*\|\s*passwd\s+\S+(\s+--stdin)?' }
    @{ Label = 'ldap_pass';
       Regex = '(?i)(ldapsearch|ldapadd|ldapmodify|ldapdelete|ldapcompare)\s.*-w\s+["'']?[^\s''"]{2,}' }
    # Parity with bash: kinit (cred read from a pw file), htpasswd -b creation,
    # nmcli Wi-Fi connect with an inline key. Previously bash-only.
    @{ Label = 'kinit_pass';
       Regex = '(?i)kinit\s.*<\s*\S+' }
    @{ Label = 'htpasswd_create';
       Regex = '(?i)htpasswd(\.exe)?\s+(-nb?|-b)\s+\S+\s+[^\s"]{2,}' }
    @{ Label = 'nmcli_wifi';
       Regex = '(?i)nmcli\s.*wifi\s+(connect|hotspot)\s.*(password|key)\s+[^\s"]{2,}' }
    @{ Label = 'rsync_pass';
       Regex = '(?i)rsync\s.*--password-file=\S+' }
    @{ Label = 'snmp_cmd';
       Regex = '(?i)snmpwalk\s.*(-A|-X|-c)\s+["'']?[^\s''"]{3,}' }
    @{ Label = 'mosquitto_pass';
       Regex = '(?i)mosquitto_(pub|sub)\s.*(-P|--pw)\s+["'']?[^\s''"]{2,}' }
    @{ Label = 'archive_pass';
       Regex = '(?i)(7z|zip|unzip|gpg)\s.*(-P|-p|--passphrase)[\s=]+["'']?[^\s''"]{2,}' }
    @{ Label = 'openssl_pass';
       Regex = '(?i)openssl\s.*(-(pass(in|out)?|passphrase|k))\s+(pass:|file:|env:)[^\s"]{2,}' }
    @{ Label = 'sqlcmd_pass';
       Regex = '(?i)(sqlcmd|osql|bcp)(\.exe)?\s.*-P\s+["'']?[^\s''"]{2,}' }
    @{ Label = 'runas_savecred';
       Regex = '(?i)runas\s+/(user|savecred)[\s:]\S+' }
    @{ Label = 'wmic_pass';
       Regex = '(?i)wmic\s.*/password:[^\s"]{2,}' }
    @{ Label = 'psexec_pass';
       Regex = '(?i)psexec(\.exe|64)?\s.*-p\s+["'']?[^\s''"]{2,}' }
    @{ Label = 'cmdkey_add';
       Regex = '(?i)cmdkey\s+/(add|generic):\S+.*(/pass:|/p:)[^\s"]{2,}' }
    @{ Label = 'sc_config_pass';
       Regex = '(?i)sc(\.exe)?\s+config\s+\S+\s.*password=\s*[^\s"]{2,}' }
    @{ Label = 'schtasks_pass';
       Regex = '(?i)schtasks(\.exe)?\s.*/rp\s+["'']?[^\s''"]{2,}' }
    @{ Label = 'evilwinrm_cmd';
       Regex = '(?i)evil-winrm\s.*-p\s+["'']?[^\s''"]{2,}' }
    @{ Label = 'impacket_cred';
       Regex = '(?i)(psexec|wmiexec|smbexec|secretsdump|GetUserSPNs|GetNPUsers)\.py\s.*[^\s/]+/[^:\s]+:[^@\s]{3,}@' }
    @{ Label = 'invoke_credential';
       Regex = '(?i)(New-Object\s+(System\.Management\.Automation\.)?PSCredential|ConvertTo-SecureString)\s*[\(\s].*["''][^''"]{3,}' }
    @{ Label = 'pscredential_inline';
       Regex = '(?i)New-Object\s+System\.Net\.NetworkCredential\(\s*["''][^''"]+["'']\s*,\s*["''][^''"]+["'']' }
    # (pssecure_plain removed in 2.3.0 -- it was a strict subset of
    #  ps_secstring_plain, which already covers ConvertTo-SecureString ... -AsPlainText.)

    # ---- Web framework specifics -------------------------------------------
    @{ Label = 'wp_db_password';
       Regex = "(?i)define\(\s*['""]DB_PASSWORD['""]\s*,\s*['""][^'""]{2,}" }
    @{ Label = 'joomla_password';
       Regex = '(?i)public\s+\$(password|smtppass|dbpass|secret)\s*=\s*[''"][^''"]{2,}' }
    @{ Label = 'drupal_password';
       Regex = "(?i)['""]password['""][ \t]*=>\s*['""][^'""]{4,}" }
    # Generic PHP define() for any *PASSWORD/*PASS/*PWD/*SECRET constant.
    @{ Label = 'define_secret';
       Regex = '(?i)define\s*\(\s*["''][A-Za-z0-9_]*(PASSWORD|PASSWD|PWD|PASS|SECRET)["'']\s*,\s*["''][^"'']{3,}' }
    # Hardcoded password as the 3rd positional arg of a DB-connect call:
    # new mysqli("host","user","PASS"), mysqli_connect(...), new PDO(...),
    # mysql_connect(...), pg_connect(...). Classic HTB/CTF pattern.
    @{ Label = 'php_db_connect';
       Regex = '(?i)(mysqli_connect|mysql_connect|pg_connect|new\s+mysqli|new\s+PDO|->\s*connect)\s*\(([^,]*,){2}\s*["''][^"'']{3,}["'']' }

    # ---- Linux auth files (likely on cross-mounted drives) -----------------
    @{ Label = 'htpasswd_hash';
       Regex = '(?m)^[^:\s#]+:\$(apr1|2[aby]?|5|6|y)\$' }
    @{ Label = 'netrc_password';
       Regex = '(?im)^\s*(machine\s+\S+\s+)?(login|user|username)\s+\S+\s+password\s+\S{2,}' }
    @{ Label = 'samba_password';
       Regex = '(?im)^\s*(passwd|password|smb\s+passwd)\s*=\s*\S{3,}' }
    # sudoers NOPASSWD entry (referenced by NoFPCheck; previously had no
    # pattern, so PS silently missed it on cross-mounted Linux drives).
    @{ Label = 'sudoers_nopasswd';
       Regex = '(?im)^\s*[^#]\S*\s.*NOPASSWD\s*[:=]' }
    # LDAP bind password (OpenLDAP / nslcd / sssd) and IPsec pre-shared key.
    @{ Label = 'ldap_bindpw';
       Regex = '(?im)(bindpw\s+|ldap_default_authtok\s*=\s*)[^\s#"]{3,}' }
    @{ Label = 'ipsec_psk';
       Regex = '(?i):\s*PSK\s+"[^"]{3,}"' }
    # SNMP community strings (real secrets are in directives; the commented
    # `# snmpwalk -c public` examples are comment-skipped at scan time).
    @{ Label = 'snmp_community';
       Regex = '(?im)^\s*(rocommunity6?|rwcommunity6?)\s+[^\s#]{2,}' }
    @{ Label = 'snmp_com2sec';
       Regex = '(?im)^\s*com2sec6?\s+\S+\s+\S+\s+[^\s#]{2,}' }

    # ---- Specific config-file credential formats ---------------------------
    @{ Label = 'redis_requirepass';
       Regex = '(?im)^\s*requirepass\s+\S{3,}' }
    @{ Label = 'anaconda_rootpw';
       Regex = '(?im)^\s*(rootpw|user)\s.*(--plaintext\s+|--password=)[^\s"#]{3,}' }

    # ---- Hash dumps (pass-the-hash / cracking) -----------------------------
    @{ Label = 'ntlm_dump';
       Regex = '(?m)^[^:\s#]+:[0-9]+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:::' }
    @{ Label = 'ntds_dump';
       Regex = '(?m)^[^:\s#]+\\[^:]+:[0-9]+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:::' }

    # ---- Linux shadow / hash formats ---------------------------------------
    @{ Label = 'shadow_md5';     Regex = '\$1\$[A-Za-z0-9./]{1,8}\$[A-Za-z0-9./]{22}' }
    @{ Label = 'shadow_sha256';  Regex = '\$5\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{40,}' }
    @{ Label = 'shadow_sha512';  Regex = '\$6\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{40,}' }
    @{ Label = 'shadow_yescrypt';Regex = '\$y\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+' }
    @{ Label = 'shadow_bcrypt';  Regex = '\$2[aby]?\$[0-9]{2}\$[A-Za-z0-9./]{53}' }
    @{ Label = 'shadow_argon2';  Regex = '\$argon2(id|i|d)\$' }

    # ---- Kerberos roasting output ------------------------------------------
    @{ Label = 'krb5_tgs';       Regex = '\$krb5tgs\$[0-9]' }
    @{ Label = 'krb5_asrep';     Regex = '\$krb5asrep\$[0-9]' }
    @{ Label = 'mscash_v1';      Regex = '(?i)M\$[A-Za-z0-9._-]+#[a-fA-F0-9]{32}' }
    @{ Label = 'mscash_v2';      Regex = '\$DCC2\$[0-9]+#' }
)

# Private-key markers (separate bucket - always reported under [KEY])
$script:KeyPatternsRaw = @(
    @{ Label = 'rsa_private';        Regex = '-----BEGIN RSA PRIVATE KEY-----' }
    @{ Label = 'dsa_private';        Regex = '-----BEGIN DSA PRIVATE KEY-----' }
    @{ Label = 'ec_private';         Regex = '-----BEGIN EC PRIVATE KEY-----' }
    @{ Label = 'openssh_private';    Regex = '-----BEGIN OPENSSH PRIVATE KEY-----' }
    @{ Label = 'pkcs8_private';      Regex = '-----BEGIN PRIVATE KEY-----' }
    @{ Label = 'encrypted_private';  Regex = '-----BEGIN ENCRYPTED PRIVATE KEY-----' }
    @{ Label = 'pgp_private';        Regex = '-----BEGIN PGP PRIVATE KEY BLOCK-----' }
    @{ Label = 'putty_private';      Regex = 'PuTTY-User-Key-File-' }
)

# Compile each regex once. Hot-path code reuses the [Regex] instance.
$script:CredPatterns = foreach ($p in $script:RawPatterns) {
    [PSCustomObject]@{
        Label = $p.Label
        Regex = [regex]::new($p.Regex, [System.Text.RegularExpressions.RegexOptions]::Compiled)
    }
}
$script:KeyPatterns = foreach ($p in $script:KeyPatternsRaw) {
    [PSCustomObject]@{
        Label = $p.Label
        Regex = [regex]::new($p.Regex, [System.Text.RegularExpressions.RegexOptions]::Compiled)
    }
}

# Whole-file (?is) regex for multi-line unattend / sysprep <Password><Value>
# autologon blocks that the per-line scan cannot match (parity with the bash
# Phase-3 pass in Invoke-ScanFile).
$script:UnattendRegex = [regex]::new(
    '(?is)<(?:Administrator)?Password>\s*<Value>\s*([^<]{2,})',
    [System.Text.RegularExpressions.RegexOptions]::Compiled)

# Labels for which we skip the value-based FP check (the entire match IS
# the finding - hash dumps, key markers, etc.)
$script:NoFPCheck = @(
    'ntlm_dump','ntds_dump','gpp_cpassword',
    'htpasswd_hash','shadow_md5','shadow_sha256','shadow_sha512',
    'shadow_yescrypt','shadow_bcrypt','shadow_argon2',
    'krb5_tgs','krb5_asrep','mscash_v1','mscash_v2',
    # Format-anchored patterns where the matched line IS the credential.
    # NOTE: autologon_password / drupal_password / wp_db_password / joomla_password
    # / define_secret / php_db_connect are deliberately NOT here — their value is
    # an ordinary user string that may be a placeholder or variable reference, so
    # it must run through Test-FalsePositive (the last-quoted-literal extraction
    # below isolates the value for these PHP/Joomla quoted shapes first).
    'unattend_password',
    'netrc_password','sudoers_nopasswd',
    'redis_requirepass','anaconda_rootpw',
    'ldap_bindpw','ipsec_psk','snmp_community','snmp_com2sec'
)

# Fast keyword pre-filter. Run as a single compiled-regex IsMatch() against
# the whole file (line 1090) and again per line (line 1102) before the
# expensive per-pattern pass. If a line contains NONE of these anchors, no
# credential pattern can fire, so we skip the ~60-pattern loop for it.
#
# CRITICAL: this MUST be a strict SUPERSET of every CredPattern, or matching
# files are silently dropped. The previous version anchored only 4 URL
# schemes and omitted ntlm/ntds dumps, mscash, requirepass, rootpw,
# ConvertTo-SecureString, and most command-line tools -- so those creds were
# missed entirely. The anchors below were derived by checking ALL patterns:
#   * keyword forms      -> pass / pwd / rootpw / secret / credential /
#                           securestring / bindpw
#   * URL creds (any scheme) -> ://user:pass@
#   * hash dumps / shadow / kerberos / mscash -> hex32::: , $..$ , M$..#hex32
#   * command-line tools that carry no 'pass' keyword -> explicit tool names
$script:KeywordPrefilter = [regex]::new(
    '(?i)pass|pwd|rootpw|secret|credential|securestring|bindpw|://[^\s/:@]+:[^\s/@]+@|[A-Fa-f0-9]{32}:::|\$(?:apr1|1|2[aby]?|5|6|y|argon2|krb5tgs|krb5asrep|dcc2)\$|M\$[A-Za-z0-9._-]+#[A-Fa-f0-9]{32}|jdbc:|:\s*PSK\s|wp-config|configuration\.php|appsettings|web\.config|tomcat-users|cmdkey|runas|psexec|smbclient|net\s+use|net\s+user|wmic|schtasks|evil-winrm|new-localuser|set-localuser|add-localuser|set-adaccountpassword|new-aduser|-pw\b|/p:|mysql|psql|mongo|redis-cli|xfreerdp|freerdp|rdesktop|mstsc|plink|ldap|snmpwalk|mosquitto_|sqlcmd|osql|\bbcp\b|impacket|\.py\b|kinit|useradd|usermod|lftp|nmcli|openssl|curl|wget|gpg|\b7z\b|\bzip\b|unzip|rocommunity|rwcommunity|com2sec|\bpdo\b|pg_connect|new\s+mysqli|define\s*\(|->\s*connect',
    [System.Text.RegularExpressions.RegexOptions]::Compiled)

# ============================================================================
#  False-positive filter
# ============================================================================

$script:FalsePositives = @(
    '','password','passwd','pwd','pass','passphrase','secret','token',
    'null','none','nil','undefined','empty','void','true','false',
    'example','sample','demo','placeholder','dummy','fake','stub','mock','lorem','ipsum',
    'test','tester','testing',
    'foo','bar','baz','qux','foobar','barbaz',
    'abc','123',
    # NOTE: weak/common passwords (qwerty, letmein, password123, p@ssw0rd,
    # 123456, admin123, test123, ...) are DELIBERATELY *not* dropped here --
    # on CTF/HTB boxes and real weak-credential findings those ARE the answer,
    # so suppressing them would lose valid findings.
    'changeme','change_me','change-me','changethis','change-this','changeit','change-it',
    'todo','fixme','tbd','n/a','na',
    'your_password','yourpassword','your-password','yourpasswordhere','yourpwd',
    'insert_password','replace_me','replace-me','replace_this','insert_here',
    '<password>','<pass>','<secret>','<token>','<key>','<value>','<your-password>',
    '<input>','<enter>','<here>','<...>',
    '...','....','.....','********','*****','***','xxxxxxxx','xxxxx','xxx',
    'redacted','hidden','masked','sanitized',
    # Clearly-non-password config values / field-name echoes
    'username','email','hostname','host','database','value','string','text','data',
    'admin','administrator',
    'localhost','127.0.0.1','0.0.0.0','::1','enabled','disabled','default','auto','unknown',
    'yes','no','on','off','optional','required','mandatory',
    'uabhahmacwbvahiazaa==',          # MS sysprep default base64 UTF-16LE "Password"
    '*sensitive*data*deleted*'        # sysprep-cleaned NetSetup.log
)

function Test-FalsePositive { param([string]$Value)
    if ($null -eq $Value) { return $true }
    $v = $Value.Trim().Trim('"', "'", ' ', ';')
    $len = $v.Length
    if ($len -lt 3 -or $len -gt 256) { return $true }

    $lower = $v.ToLowerInvariant()
    if ($script:FalsePositives -contains $lower) { return $true }

    # Suffix-based template placeholders (e.g. MY_DB_PASSWORD as var name)
    if ($lower -match '_(password|secret|token|key|pass|pwd|passwordhere)$') { return $true }
    if ($lower -match '^(your|insert|replace|example|sample|test|my|fake)_')  { return $true }
    # Trailing marker words -- values that self-label as placeholders
    if ($lower -match '(placeholder|placeholders)$')                          { return $true }
    if ($lower -match '_(example|sample|dummy|mock|stub|fake|demo)$')         { return $true }

    # High-confidence placeholder phrases ANYWHERE in the value (substring) --
    # these appear only in templates/examples, never in a real password.
    if ($lower -match 'changeme|change_me|change-me|changethis|change_this') { return $true }
    if ($lower -match 'yourpassword|your_password|your-password|passwordhere|password_here|goeshere') { return $true }
    if ($lower -match 'placeholder|redacted|replaceme|replace_me|replacethis|replace_this') { return $true }
    if ($lower -match 'insertpassword|insert_password|enterpassword|enter_password|enteryour') { return $true }
    if ($lower -match 'tobeset|to_be_set|tobedefined|fillme|fill_me|fillinpassword')          { return $true }
    if ($lower -match 'examplepassword|samplepassword|dummypassword|fakepassword')            { return $true }
    # Space-separated vendor template defaults (WordPress wp-config-sample, etc.)
    if ($lower -match 'put your password here|your database password here|your password here|enter your password') { return $true }
    if ($lower -match 'x{6,}')                                                                { return $true }

    # Value is a REFERENCE / lookup of a secret, not a hardcoded literal
    # (env var, vault read, secrets-manager call, config getter).
    if ($lower -match 'getenv|os\.environ|process\.env|\benv\[|\$env\{|@value\(') { return $true }
    if ($lower -match 'keyvault|getsecret|secretsmanager|secretmanager|vault\.read|hvac\.') { return $true }
    if ($lower -match 'configurationmanager|boto3|ssm\.get|getparameter')        { return $true }
    # Bare dotted identifier reference (config.dbPassword, settings.password).
    if ($v -match '^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$')         { return $true }
    # Function-call accessor (getPassword(), get_password(), cfg.getSecret()) --
    # code that fetches a secret at runtime, not a hardcoded literal.
    if ($v -match '^[A-Za-z_][A-Za-z0-9_.]*\(.*\)$')                             { return $true }

    # Template / interpolation markers
    if ($v -match '\$\{[^}]+\}')                  { return $true }
    if ($v -match '\$\([^)]+\)')                  { return $true }
    if ($v -match '\{\{[^}]+\}\}')                { return $true }
    if ($v -match '<%.*?%>')                      { return $true }
    if ($v -match '#\{[^}]+\}')                   { return $true }
    if ($v -match '<[A-Za-z_][^>]*>')             { return $true }
    if ($v -match '%[A-Z_]+%')                    { return $true }
    # Value that IS a sed/awk positional backref ($1/$2/$3) or shell PID ($$) /
    # ${1}. Anchored to the WHOLE value so a real password merely CONTAINING $$
    # (e.g. P@$$w0rd!) is kept -- supports the "allow $ in passwords" change
    # (#3). The ${...} template ref above still removes interpolation markers.
    if ($v -match '^\$(\$|[0-9]+|\{[0-9]+\})$')    { return $true }

    # Programming-language references that look like passwords but aren't.
    # Catches Python `self.password`, Java `this.password`, PowerShell var
    # references `$cred.GetNetworkCredential().Password`, PHP `$_POST['password']`.
    if ($v -match '^(self|this|cls|@self)\.\w+')                    { return $true }
    if ($v -match '^\$_(POST|GET|REQUEST|SERVER|ENV|SESSION|COOKIE)\[') { return $true }
    if ($v -match '^\$[A-Za-z_]\w*(\.\w+)+$')                       { return $true }

    # Already-encrypted / vaulted markers -- secret is protected at rest.
    if ($v -match '^ENC\(.+\)$')                  { return $true }  # Jasypt
    if ($v -match '^\{cipher\}')                  { return $true }  # Spring Cloud
    if ($v -match '^vault:v\d+:')                 { return $true }  # HashiCorp Vault
    if ($v -match '^\$ANSIBLE_VAULT;')            { return $true }  # Ansible Vault
    if ($v -match '^pbkdf2_sha\d+\$')             { return $true }  # Django hash

    # SQL Server / .NET trusted connection strings have no password to extract
    if ($lower -match 'integrated security=(true|sspi)') { return $true }
    if ($lower -match 'trusted_connection=(yes|true)')   { return $true }

    # Single repeating char (e.g. xxxx)
    if ($len -ge 3 -and $v -match "^(.)\1+$")     { return $true }

    # Only non-alphanumeric punctuation
    if ($v -match '^[^A-Za-z0-9]+$')              { return $true }

    # Bare filesystem path used as a value (e.g. `pwd: /usr/local/bin`,
    # `password = /etc/secrets`) -- a path reference, not a secret. Require a
    # leading /, ./ or ../, only path-safe characters, and at least two path
    # separators so single-segment values are kept. Parity with bash.
    if ($v -match '^(\.{1,2}/|/)[A-Za-z0-9._/-]+$' -and
        ($v.Length - $v.Replace('/','').Length) -ge 2) { return $true }

    return $false
}

# ============================================================================
#  USER-CUSTOMIZABLE PATTERN LISTS
#
#  Edit the arrays below to add or remove what each stage flags. NO OTHER
#  changes are required when you tweak these.
#
#  All matching is case-insensitive. Stage 2/3 match extensions / names;
#  Stage 4 uses substring match on the basename.
# ============================================================================

# -- Stage 2 -- confirmed credential containers (match alone = [CRITICAL]) ----
$script:Stage2Extensions = @(
    '.kdbx','.kdb','.psafe3'
    '.agilekeychain','.opvault','.1pif','.1pux'
    '.lpdb','.enpass','.enpassdb','.bitwarden_export'
    '.ppk','.pfx','.p12','.pvk'
    '.jks','.keystore','.truststore'
    '.bek','.fve','.keytab','.dpapimk'
)

# -- Stage 3 -- high-value file types (match = [INTEREST]) -------------------
# Three sub-arrays drive the Stage 3 detector: extensions, exact filenames,
# and globs. A file matched by ANY of the three is flagged.
$script:Stage3Extensions = @(
    # SSH / TLS private key formats
    '.pem','.key','.priv','.crt','.cer','.csr'
    # App-secret dotfile extensions
    '.env','.envrc'
    # Kerberos (also in $script:Stage2Extensions -- Stage 3 runtime dedups
    # against Stage 2 findings, harmless duplication kept for discoverability)
    '.keytab'
    # Shell scripts
    '.sh','.bash'
    # Backup / scratch / saved variants
    '.bak','.old','.orig','.backup','.swp','.save'
    # SQLite databases (system DB basenames filtered separately, see SkipDbFilenames)
    '.db','.sqlite','.sqlite3'
    # Logs (admins sometimes paste pw into custom logs)
    '.log'
    # Packet captures (may contain plaintext auth)
    '.pcap','.pcapng'
    # Compressed archives (admin backups often contain creds)
    '.tar','.tgz','.gz','.zip','.7z'
)

# Exact filename matches (names that cannot be expressed as a simple *.ext glob)
$script:Stage3ExactNames = @(
    'krb5.conf'
    '.htpasswd','.netrc','.pgpass','.my.cnf','my.cnf','.mysql.cnf'
)
$script:Stage3ExactNamesSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]$script:Stage3ExactNames, [System.StringComparer]::OrdinalIgnoreCase)

# Glob patterns (PowerShell -like syntax). Note: '*.tar.gz' is covered by
# the '.gz' entry above, but kept here so users can toggle tarball handling
# independently of raw .gz.
$script:Stage3GlobPatterns = @(
    'krb5cc_*'
    '*.tar.gz'
    '.env.*'
)

# Known SQL Server SYSTEM / TEMPLATE database basenames -- always shipped, never
# user data. Filtered at Stage 3 [INTEREST] flagging.
$script:SkipDbFilenames = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@(
        'master.mdf','mastlog.ldf'
        'model.mdf','modellog.ldf'
        'msdb.mdf','msdbdata.mdf','msdblog.ldf'
        'tempdb.mdf','templog.ldf'
        'mssqlsystemresource.mdf','mssqlsystemresource.ldf'
        'model_msdbdata.mdf','model_msdblog.ldf'
        'model_replicatedmaster.mdf','model_replicatedmaster.ldf'
    ),
    [System.StringComparer]::OrdinalIgnoreCase)

# -- Stage 4 -- filename substring tokens (match = [NAME]) -------------------
# Any filename containing one of these tokens (case-insensitive) is flagged.
# Keep this list short: each entry is a substring, so loose entries balloon
# the false-positive rate.
$script:Stage4NameTokens = @(
    'credential','secret','password','passwd'
)

# -- Stage 5 -- content-scan extension allow-list ----------------------------
# Recursive credential-pattern scan runs ONLY on files with one of these
# extensions (unless -All is passed).
$script:Stage5Extensions = @(
    '.conf','.config','.cfg','.cnf','.ini','.env','.envrc'
    '.yaml','.yml','.toml','.json','.jsonc','.json5'
    '.xml'
    '.properties','.prop','.props','.settings'
    '.tf','.tfvars','.tfstate','.hcl'
    '.sh','.bash','.zsh','.ksh','.csh','.fish','.bashrc','.profile','.zshrc'
    '.ps1','.psm1','.psd1'
    '.bat','.cmd','.vbs','.vbe','.wsf','.ahk'
    '.py','.pl','.rb','.php','.phtml','.php3','.php5','.inc'
    '.lua','.groovy','.tcl'
    '.java','.cs','.vb','.go','.rs'
    '.js','.ts','.jsx','.tsx','.mjs','.cjs'
    '.aspx','.asp','.ashx','.asmx','.asax','.ascx','.cshtml','.vbhtml','.master','.svc'
    '.jsp','.jspx','.jspf','.cfm','.cfc'
    '.htaccess'
    '.dsn','.udl','.ora','.tns'
    '.reg','.rdp','.rdg','.rdcman','.inf','.unattend','.answerfile'
    '.ovpn','.openvpn','.vnc','.rdc','.tcc','.ica','.session','.kix'
    '.txt','.text','.log','.logs'
    '.bak','.backup','.old','.orig','.original','.save','.saved','.tmp','.temp'
    '.ldif','.ldiff'
    '.service','.unit','.crontab','.cron'
    '.local','.shared'
    # Secret-bearing / auth file extensions
    '.secret','.secrets','.creds','.cred','.passwd','.auth','.vault'
    # Config management / IaC / templating (Ansible/Puppet/Salt/Chef)
    '.j2','.erb','.pp','.sls','.tmpl','.tpl','.gotmpl','.bicep'
    # Additional source languages
    '.pyw','.kt','.kts','.scala','.sbt','.gradle','.clj','.cljs','.cljc','.ex','.exs','.erl','.hrl','.dart','.swift'
    '.vue','.svelte','.astro','.cgi','.fcgi','.php4','.php7','.phps','.pht'
    # .NET / Visual Studio project & publish files (conn strings, deploy creds)
    '.resx','.resw','.pubxml','.publishsettings'
    # Windows scripting / app / shortcut formats
    '.hta','.au3','.url'
    # VPN / network configuration
    '.nmconnection','.wg','.pcf','.mobileconfig'
    # Database scripts / ORM schemas
    '.cql','.prisma'
    # Notes / documentation / mail
    '.note','.notes','.eml'
    # Backup / package-manager config remnants (old configs keep old creds)
    '.dpkg-old','.dpkg-dist','.dpkg-new','.rpmsave','.rpmnew','.rpmorig','.ucf-old','.ucf-dist'
    '.bk','.bkp','.bkup','.sav','.default'
)
$script:Stage5ExtensionsSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]$script:Stage5Extensions, [System.StringComparer]::OrdinalIgnoreCase)
# -IncludeData re-enables the heavy data/SQL extensions that are off by default
# (large files, near-zero hardcoded-credential yield). They follow the normal
# size cap; only .log/.logs get the always-on cap applied at Stage 5 selection.
if ($IncludeData) {
    foreach ($e in '.sql','.ddl','.dump','.psql','.pgsql','.plsql','.tsql','.csv','.tsv') {
        [void]$script:Stage5ExtensionsSet.Add($e)
    }
}

# O(1) extension lookups for Stage 2 / Stage 3 (replaces per-file `-contains`
# linear array scans across the whole tree), and globs pre-lowered once so the
# Stage-3 hot loop doesn't ToLowerInvariant() a constant on every file.
$script:Stage2ExtensionsSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]$script:Stage2Extensions, [System.StringComparer]::OrdinalIgnoreCase)
$script:Stage3ExtensionsSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]$script:Stage3Extensions, [System.StringComparer]::OrdinalIgnoreCase)
$script:Stage3GlobPatternsLower = @($script:Stage3GlobPatterns | ForEach-Object { $_.ToLowerInvariant() })

# Fast filename-based skip for cred-free files that match a credential
# extension (LICENSE.md / package-lock.json / .gitignore / etc.). Skipping
# at the filename layer avoids per-file stat/grep work on common dev noise.
$script:SkipFilenames = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@(
        # License files
        'LICENSE','LICENSE.txt','LICENSE.md','LICENSE.rst'
        'LICENCE','LICENCE.txt','LICENCE.md'
        'UNLICENSE','UNLICENSE.txt'
        'COPYING','COPYING.txt','COPYRIGHT','COPYRIGHT.txt'
        # Changelogs
        'CHANGELOG','CHANGELOG.md','CHANGELOG.txt','CHANGELOG.rst'
        'CHANGES','CHANGES.md','HISTORY','HISTORY.md'
        'NEWS','NEWS.md','RELEASE_NOTES','RELEASE_NOTES.md','RELEASES.md'
        # Project meta docs
        'AUTHORS','AUTHORS.txt','AUTHORS.md','CONTRIBUTORS','CONTRIBUTORS.md'
        'MAINTAINERS','MAINTAINERS.md'
        'CONTRIBUTING','CONTRIBUTING.md','CODE_OF_CONDUCT.md'
        'NOTICE','NOTICE.txt','NOTICE.md','THIRD_PARTY_NOTICES.txt'
        'TRADEMARKS.md','ATTRIBUTION.txt'
        'INSTALL','INSTALL.md','INSTALL.txt','UPGRADE','UPGRADE.md','UPGRADING.md'
        'SECURITY.md','SUPPORT.md','GOVERNANCE.md','ROADMAP.md'
        'FUNDING','FUNDING.yml','FUNDING.md'
        'README','README.md','README.txt','README.rst'
        # Lockfiles / manifests (no creds)
        'package.json','package-lock.json','npm-shrinkwrap.json'
        'yarn.lock','pnpm-lock.yaml','bun.lockb','bun.lock'
        'Cargo.lock','Gemfile.lock','poetry.lock','composer.lock','composer.json'
        'go.sum','go.mod','Pipfile.lock'
        # Build / TS configs
        'tsconfig.json','jsconfig.json','tslint.json'
        'Makefile','GNUmakefile','CMakeLists.txt','meson.build','pom.xml'
        # NOTE: build.gradle / gradle.properties are NOT skipped -- they
        # commonly hold repo / signing / nexus passwords.
        'pyproject.toml','setup.cfg','MANIFEST.in','tox.ini','noxfile.py'
        # VCS / formatter / linter dotfiles
        '.gitignore','.gitattributes','.editorconfig','.gitmodules','.gitkeep','.mailmap'
        '.prettierrc','.prettierignore','.prettierrc.json','.prettierrc.yml'
        '.eslintrc','.eslintignore','.eslintrc.json','.eslintrc.yml','.eslintrc.js'
        '.stylelintrc','.stylelintrc.json'
        '.babelrc','.babelrc.json','.browserslistrc','.nvmrc','.node-version','.python-version'
        '.dockerignore','.npmignore','.ignore'
        # OS / desktop noise
        '.DS_Store','Thumbs.db','desktop.ini'
    ), [System.StringComparer]::OrdinalIgnoreCase)

# Special-cased filenames (no standard extension) we still want to scan in stage 5
$script:ExtraScanNames = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@(
        'dockerfile','vagrantfile','makefile','jenkinsfile'
        'authorized_keys','known_hosts','identity'
        # Extension-less Linux auth files (cross-mounted drives / -Path scans)
        'shadow','gshadow','sudoers','opasswd','.htpasswd','htpasswd'
        '.bashrc','.zshrc','.kshrc','.cshrc','.tcshrc','.bash_profile'
        '.zprofile','.profile','.bash_login','.zlogin','.bash_logout'
        '.envrc','.env','.npmrc','.pypirc','.netrc','_netrc'
        '.gitconfig','.git-credentials','.s3cfg','.boto','.viminfo'
        '.psqlrc','.mysqlrc','.my.cnf'
        '.bash_history','.zsh_history','.sh_history','.ksh_history','.ash_history'
        '.history','.psql_history','.mysql_history','.sqlite_history'
        '.python_history','.node_repl_history','.irb_history','.rediscli_history','.lesshst'
    ),
    [System.StringComparer]::OrdinalIgnoreCase)

# Exclude these directory names anywhere in the tree
$script:ExcludeDirNames = @(
    '.hg','.svn','.bzr','CVS','_darcs'
    'node_modules','.npm','.pnpm-store','.yarn','.yarn-cache','.bun'
    '.venv','venv','env','.pyenv','.virtualenvs','__pycache__'
    '.mypy_cache','.pytest_cache','.tox','.nox','.ruff_cache'
    'site-packages','dist-packages','vendor','bower_components'
    '.terraform','.terragrunt-cache','.gradle','.m2','.ivy2','.sbt'
    'target','dist','build','out','coverage','.next','.nuxt','obj'
    # Cross-platform dev/tool caches (parity with bash EXCLUDE_DIR_NAMES)
    '.cache','.ccache','.npm-cache','.composer'
    '.idea','.vscode','.vs','.history'
    'WinSxS','Installer','SoftwareDistribution','CrashDumps'
    'LiveKernelReports','servicing','AppPatch','assembly'
    'Fonts','Help','IME','Media','PolicyDefinitions'
    '.Trash','.Spotlight-V100','.fseventsd'
)
$script:ExcludeDirSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]$script:ExcludeDirNames, [System.StringComparer]::OrdinalIgnoreCase)

# Absolute-path prefixes never to descend into during stages 2-5.
#
# IMPORTANT: Stage 1 (OS-level checks) uses hardcoded paths and bypasses
# this list -- excluding $env:SystemRoot does NOT prevent Sysprep / GPP /
# SAM / AutoLogon / IIS / Scheduled Tasks checks from working. It just
# keeps the stage-5 recursive scanner from burning cycles on the 100k+
# system files under C:\Windows that never carry credentials.
$script:ExcludePathPrefixes = @(
    # Entire C:\Windows tree -- system DLLs, drivers, components, fonts.
    $env:SystemRoot
    # AppX / MSIX package store
    (Join-Path ${env:ProgramFiles} 'WindowsApps')
    (Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps')
    (Join-Path $env:LOCALAPPDATA 'Packages')
    # Recycle / restore / perf data
    "$env:SystemDrive\`$Recycle.Bin"
    "$env:SystemDrive\System Volume Information"
    "$env:SystemDrive\PerfLogs"
    # -- Microsoft SQL Server install trees (binaries + system DBs + install
    #    scripts + setup logs). User databases live in custom dirs like
    #    D:\Data, not under Program Files. Skipping the product dir cuts
    #    huge noise from instmsdb.sql / msdb110_upgrade.sql / Setup Bootstrap
    #    logs which contain SQL-parameter-reference noise.
    (Join-Path ${env:ProgramFiles} 'Microsoft SQL Server')
    (Join-Path ${env:ProgramFiles(x86)} 'Microsoft SQL Server')
    # -- ProgramData noise (Windows update cache, identity CRL, breadcrumbs)
    (Join-Path $env:ProgramData 'Microsoft\Windows\Caches')
    (Join-Path $env:ProgramData 'USOPrivate')
    (Join-Path $env:ProgramData 'USOShared')
    (Join-Path $env:ProgramData 'Microsoft\IdentityCRL')
    (Join-Path $env:ProgramData 'Microsoft\Device Stage')
    (Join-Path $env:ProgramData 'Microsoft\NetFramework\BreadcrumbStore')
    (Join-Path $env:ProgramData 'Vmware')
    (Join-Path $env:ProgramData 'Microsoft\')
) | Where-Object { $_ -and $_.Trim() -ne '' }

# Well-known system / vendor directories that never hold hardcoded credentials.
# Excluded from the shared stage 2-5 walk by default to keep a C:\ scan fast.
# Stage 1's targeted OS checks use hardcoded paths and bypass this list, so
# Jenkins / Tomcat / IIS / SAM / GPP / etc. detection is unaffected. These are
# directories OUTSIDE C:\Windows (which $env:SystemRoot already excludes).
# Disable the whole set with -NoDefaultExclude.
$script:DefaultSystemExcludePrefixes = @(
    foreach ($pf in @(${env:ProgramFiles}, ${env:ProgramFiles(x86)})) {
        if (-not $pf) { continue }
        Join-Path $pf 'Windows Defender'
        Join-Path $pf 'Windows Defender Advanced Threat Protection'
        Join-Path $pf 'Windows Kits'                      # Windows SDK headers (.h monster)
        Join-Path $pf 'Microsoft SDKs'
        Join-Path $pf 'Microsoft Visual Studio'           # IDE install; user projects live elsewhere
        Join-Path $pf 'dotnet'
        Join-Path $pf 'MSBuild'
        Join-Path $pf 'Reference Assemblies'
        Join-Path $pf 'Microsoft Office'
        Join-Path $pf 'Common Files\Microsoft Shared'
        Join-Path $pf 'NVIDIA Corporation'
        Join-Path $pf 'Intel'
        Join-Path $pf 'AMD'
        Join-Path $pf 'Realtek'
        Join-Path $pf 'Windows Photo Viewer'
        Join-Path $pf 'Windows Media Player'
        Join-Path $pf 'Windows NT'
        Join-Path $pf 'Windows Mail'
        Join-Path $pf 'dotnet'
        Join-Path $pf 'VMware'
        Join-Path $pf 'Amazon'
        Join-Path $pf 'AWS Tools'      
        Join-Path $pf 'AWS SDK for .NET'
        Join-Path $pf 'AWS Tools for Windows PowerShell'
        Join-Path $pf 'WindowsPowerShell\Modules'
        Join-Path $pf 'Windows Defender Advanced Threat Protection'
        Join-Path $pf 'Reference Assemblies'
        Join-Path $pf 'Microsoft.NET'
        
    }
    Join-Path $env:ProgramData 'Microsoft'
    Join-Path $env:ProgramData 'Amazon'
    Join-Path $env:ProgramData 'Vmware'
    Join-Path $env:ProgramData 'Package Cache'                     # VS / installer MSI cache
    Join-Path $env:ProgramData 'NVIDIA'
    Join-Path $env:ProgramData 'NVIDIA Corporation'
    Join-Path $env:ProgramData 'Intel'
    Join-Path $env:SystemDrive 'MSOCache'
    Join-Path $env:SystemDrive 'Recovery'
    Join-Path $env:SystemDrive 'Config.Msi'
    Join-Path $env:SystemDrive '$WinREAgent'
    Join-Path $env:SystemDrive '$SysReset'
    Join-Path $env:SystemDrive '$GetCurrent'
    Join-Path $env:SystemDrive '$Windows.~BT'                      # upgrade staging
    Join-Path $env:SystemDrive '$Windows.~WS'
    Join-Path $env:SystemDrive 'OneDriveTemp'
    Join-Path $env:SystemDrive 'Intel'
    Join-Path $env:SystemDrive 'AMD'
    Join-Path $env:SystemDrive 'NVIDIA'
) | Where-Object { $_ -and $_.Trim() -ne '' }

if (-not $NoDefaultExclude) {
    $script:ExcludePathPrefixes = @($script:ExcludePathPrefixes) + $script:DefaultSystemExcludePrefixes
}

# Path-substring exclusions -- used when the noisy directory lives at a
# per-user path that can't be expressed as a single absolute prefix
# (e.g. C:\Users\<every-user>\AppData\Local\Microsoft\Windows\Caches).
# Compared case-insensitively against the full directory path via Contains.
$script:ExcludePathContains = @(
    '\AppData\Local\Microsoft\Windows\Caches'
    '\AppData\Local\Microsoft\Windows\Explorer'      # iconcache / thumbcache
    '\AppData\Local\Microsoft\Windows\Notifications' # wpndatabase
    '\AppData\Local\ConnectedDevicesPlatform'        # ActivitiesCache
    '\AppData\Local\Microsoft\Edge\User Data\Default\Cache'
    '\AppData\Local\Microsoft\Edge\User Data\Default\Code Cache'
    '\AppData\Local\Microsoft\Edge\User Data\Default\GPUCache'
    '\AppData\Local\Microsoft\Edge\User Data\Default\ShaderCache'
    '\AppData\Local\Microsoft\Edge\User Data\Default\Service Worker'
    '\AppData\Local\Microsoft\Edge\User Data\BrowserMetrics'
    '\AppData\Local\Microsoft\Edge\User Data\Crashpad'
    '\AppData\Local\Microsoft\Edge\User Data\ShaderCache'
    '\AppData\Local\Google\Chrome\User Data\Default\Cache'
    '\AppData\Local\Google\Chrome\User Data\Default\Code Cache'
    '\AppData\Roaming\Microsoft\NetFramework\BreadcrumbStore'
)

if ($script:UserExcludePaths.Count -gt 0) {
    $script:ExcludePathPrefixes = @($script:ExcludePathPrefixes) + $script:UserExcludePaths
}

# ============================================================================
#  Output helpers
# ============================================================================

function Write-Banner {
    if ($Quiet) { return }
    Write-Host ""
    Write-Host "$($script:CC)$($script:CBold)  +-------------------------------------------------------------+$($script:CNC)"
    Write-Host "$($script:CC)$($script:CBold)  |  credshunter  *  Windows reusable-credential discovery     |$($script:CNC)"
    Write-Host "$($script:CC)$($script:CBold)  |  v$($script:Version)  *  $($script:CD)authorized testing only * read-only$($script:CNC)$($script:CC)$($script:CBold)             |$($script:CNC)"
    Write-Host "$($script:CC)$($script:CBold)  +-------------------------------------------------------------+$($script:CNC)"
    Write-Host ""
}
function Write-Section { param([string]$Title)
    Write-Host ""
    Write-Host "$($script:CBold)$($script:CC)=== $Title ===$($script:CNC)"
}
function Write-Info { param([string]$Msg) if (-not $Quiet) { Write-Host "$($script:CB)[*]$($script:CNC) $Msg" } }
function Write-Ok   { param([string]$Msg) if (-not $Quiet) { Write-Host "$($script:CG)[+]$($script:CNC) $Msg" } }
function Write-Warn { param([string]$Msg) Write-Host "$($script:CY)[!]$($script:CNC) $Msg" }
function Write-Err  { param([string]$Msg) Write-Host "$($script:CR)[x]$($script:CNC) $Msg" }

# Stream a single Stage-1 finding to the host as it is recorded.
function Write-Stage1Finding {
    param(
        [string]$Tier,
        [string]$Label,
        [string]$Path,
        [int]   $LineNumber = 0,
        [string]$Preview = ''
    )
    if ($Quiet) { return }
    switch ($Tier) {
        'Critical' { $color = $script:CR; $tag = 'CRITICAL' }
        'High'     { $color = $script:CR; $tag = 'HIGH' }
        'Key'      { $color = $script:CM; $tag = 'KEY' }
        'Interest' { $color = $script:CY; $tag = 'INTEREST' }
        'Name'     { $color = $script:CY; $tag = 'NAME' }
        default    { $color = $script:CR; $tag = $Tier.ToUpper() }
    }
    if ($LineNumber -gt 0) {
        Write-Host ("{0}   +- [{1}]{2} {3} -> {4}:{5}" -f $color, $tag, $script:CNC, $Label, $Path, $LineNumber)
    } else {
        Write-Host ("{0}   +- [{1}]{2} {3} -> {4}" -f $color, $tag, $script:CNC, $Label, $Path)
    }
    # Show the matched content/command inline (dim) so the operator can verify
    # an embedded credential live -- e.g. a session command holding -pw '...'
    # that the regex flagged but whose value lives only in the preview.
    if ($Preview -ne '' -and $Preview -ne $Path) {
        Write-Host ("{0}        {1}{2}" -f $script:CD, $Preview, $script:CNC)
    }
    $script:SubstageFindings++
}

# Wrapper: run a Stage-1 substage and print a tidy "nothing here" line if
# the substage produced zero findings. Keeps every Test-* function
# untouched -- they only need to call Add-Finding / Add-Interesting / etc.
function Invoke-Stage1Check {
    param([scriptblock]$Block)
    $script:SubstageFindings = 0
    # Isolate each substage: an unexpected terminating error in one check
    # (odd registry ACL, malformed value, null env var, etc.) must NOT abort
    # the remaining Stage-1 checks. Log it and carry on.
    try {
        & $Block
    } catch {
        Write-Warn ("substage error (continuing): " + $_.Exception.Message)
    }
    if ($script:SubstageFindings -eq 0 -and -not $Quiet) {
        Write-Host ("{0}   +- no credentials found in this category{1}" -f $script:CD, $script:CNC)
    }
}

function Write-LogLine { param([string]$Line)
    if ([string]::IsNullOrEmpty($script:LogPath)) { return }
    # Strip ANSI escapes for the on-disk log. NOTE: the `e escape sequence was
    # only introduced in PowerShell 6 — on Windows PowerShell 5.1 it is a
    # literal 'e', so a "`e\[..." regex leaves the real ESC (char 27) bytes in
    # the log. Build the regex from [char]27 so stripping works on 5.1 too.
    $clean = $Line -replace ([char]27 + '\[[0-9;]*m'), ''
    Add-Content -Path $script:LogPath -Value $clean -Encoding UTF8
}

# ============================================================================
#  Stage lifecycle -- per-stage timing, skip-gating, and live-results block
# ============================================================================

$script:StageBeforeCounts = @{}
$script:StageStartTime    = @{}

function Begin-Stage { param([int]$N)
    $script:StageBeforeCounts[$N] = @{
        Guaranteed = $script:Guaranteed.Count
        High       = $script:HighFindings.Count
        Key        = $script:KeyFindings.Count
        Interest   = $script:Interesting.Count
        Name       = $script:SuspiciousNamesFound.Count
    }
    $script:StageStartTime[$N] = [DateTime]::UtcNow
}

function End-Stage { param([int]$N, [string]$Title)
    $before = $script:StageBeforeCounts[$N]
    $elapsed = ([DateTime]::UtcNow - $script:StageStartTime[$N]).TotalSeconds
    $dGuar = $script:Guaranteed.Count           - $before.Guaranteed
    $dHigh = $script:HighFindings.Count         - $before.High
    $dKey  = $script:KeyFindings.Count          - $before.Key
    $dInt  = $script:Interesting.Count          - $before.Interest
    $dName = $script:SuspiciousNamesFound.Count - $before.Name
    $total = $dGuar + $dHigh + $dKey + $dInt + $dName

    Write-Host ""
    Write-Host "$($script:CC)======================================================================$($script:CNC)"
    Write-Host "$($script:CBold)  Stage $N -- $Title$($script:CNC)"
    Write-Host "$($script:CC)----------------------------------------------------------------------$($script:CNC)"
    # Invariant culture so the decimal separator is always '.' (matches the
    # bash output) regardless of the host's regional settings.
    $elapsedStr = $elapsed.ToString('0.00', [System.Globalization.CultureInfo]::InvariantCulture)
    Write-Host ("  Found: $($script:CW)$($script:CBold){0}$($script:CNC) file(s)   ({1}s)" -f $total, $elapsedStr)

    if (-not $Quiet -and $total -gt 0) {
        Write-Host ""
        if ($dGuar -gt 0) {
            $script:Guaranteed | Select-Object -Last $dGuar | ForEach-Object {
                Write-Host ("  [{0,-9}]  {1}" -f 'CRITICAL', $_.Path)
            }
        }
        if ($dHigh -gt 0) {
            $script:HighFindings | Select-Object -Last $dHigh | ForEach-Object {
                Write-Host ("  [{0,-9}]  {1}" -f 'HIGH', $_.Path)
                if ($_.Preview) { Write-Host ("             $($script:CD){0}$($script:CNC)" -f $_.Preview) }
            }
        }
        if ($dKey -gt 0) {
            $script:KeyFindings | Select-Object -Last $dKey | ForEach-Object {
                Write-Host ("  [{0,-9}]  {1}" -f 'KEY', $_.Path)
                if ($_.Preview) { Write-Host ("             $($script:CD){0}$($script:CNC)" -f $_.Preview) }
            }
        }
        if ($dInt -gt 0) {
            $script:Interesting | Select-Object -Last $dInt | ForEach-Object {
                Write-Host ("  [{0,-9}]  {1}" -f 'INTEREST', $_.Path)
            }
        }
        if ($dName -gt 0) {
            $script:SuspiciousNamesFound | Select-Object -Last $dName | ForEach-Object {
                Write-Host ("  [{0,-9}]  {1}" -f 'NAME', $_)
            }
        }
    }
    Write-Host "$($script:CC)======================================================================$($script:CNC)"
}

function Stage-Skipped { param([int]$N, [string]$Title)
    Write-Host ""
    Write-Host "$($script:CC)======================================================================$($script:CNC)"
    Write-Host "$($script:CBold)  Stage $N -- $Title  [SKIPPED]$($script:CNC)"
    Write-Host "$($script:CC)======================================================================$($script:CNC)"
}

# ============================================================================
#  Helper functions
# ============================================================================

function Get-FileSizeSafe { param([string]$FullPath)
    try { return (New-Object System.IO.FileInfo $FullPath).Length } catch { return -1 }
}

# Encoding-aware reader. Probes the first 4 KB for a BOM, then for a UTF-16/32
# NUL-stride pattern, and decodes with the detected encoding. Returns $null only
# when the bytes look genuinely binary (NULs that are not a UTF-16/32 stride).
# This replaces the old NUL-means-binary test, which wrongly skipped UTF-16 .reg
# exports, Scheduled-Task XML, and any Unicode-saved config/log.
function Read-TextFileSmart {
    # Returns decoded text, or $null if the file looks binary. Opens the file ONCE:
    # probes the first ProbeBytes for a BOM / UTF-16/32 NUL-stride, rejects genuine
    # binaries WITHOUT reading the body, then seeks back and streams the rest.
    param([string]$FullPath, [int]$ProbeBytes = 4096)
    $fs = $null
    try {
        # Read-only, share ReadWrite so we never lock a log that's being appended to.
        $fs    = [System.IO.File]::Open($FullPath, 'Open', 'Read', 'ReadWrite')
        $probe = New-Object byte[] $ProbeBytes
        $read  = $fs.Read($probe, 0, $probe.Length)
        if ($read -le 0) { $fs.Dispose(); return '' }

        $enc = $null
        if ($read -ge 3 -and $probe[0] -eq 0xEF -and $probe[1] -eq 0xBB -and $probe[2] -eq 0xBF) {
            $enc = [System.Text.Encoding]::UTF8
        } elseif ($read -ge 4 -and $probe[0] -eq 0xFF -and $probe[1] -eq 0xFE -and $probe[2] -eq 0 -and $probe[3] -eq 0) {
            $enc = [System.Text.Encoding]::UTF32
        } elseif ($read -ge 4 -and $probe[0] -eq 0 -and $probe[1] -eq 0 -and $probe[2] -eq 0xFE -and $probe[3] -eq 0xFF) {
            $enc = New-Object System.Text.UTF32Encoding($true, $true)
        } elseif ($read -ge 2 -and $probe[0] -eq 0xFF -and $probe[1] -eq 0xFE) {
            $enc = [System.Text.Encoding]::Unicode
        } elseif ($read -ge 2 -and $probe[0] -eq 0xFE -and $probe[1] -eq 0xFF) {
            $enc = [System.Text.Encoding]::BigEndianUnicode
        }
        if (-not $enc) {
            $nul = 0; $nulEven = 0; $nulOdd = 0
            for ($i = 0; $i -lt $read; $i++) {
                if ($probe[$i] -eq 0) { $nul++; if ($i % 2) { $nulOdd++ } else { $nulEven++ } }
            }
            if ($nul -eq 0) {
                $enc = [System.Text.Encoding]::UTF8
            } elseif ($nulOdd -ge ($read / 4) -and $nulEven -lt ($read / 16)) {
                $enc = [System.Text.Encoding]::Unicode
            } elseif ($nulEven -ge ($read / 4) -and $nulOdd -lt ($read / 16)) {
                $enc = [System.Text.Encoding]::BigEndianUnicode
            } else {
                $fs.Dispose(); return $null   # genuine binary -- reject without reading the body
            }
        }

        $fs.Position = 0
        $sr = New-Object System.IO.StreamReader($fs, $enc, $true)  # takes ownership of $fs
        $fs = $null                                                # prevent double-dispose
        try { return $sr.ReadToEnd() } finally { $sr.Dispose() }
    } catch {
        return $null
    } finally {
        if ($fs) { try { $fs.Dispose() } catch {} }
    }
}

function Test-DirectoryExcluded { param([string]$DirectoryPath)
    # Never descend into reparse points (directory junctions / symlinks).
    # [System.IO.Directory]::EnumerateDirectories returns them as ordinary
    # directories, so without this guard a self-referential junction loops
    # forever and a junction targeting C:\ lets the scan escape -Path. GNU find
    # on the bash side never follows symlinks (no -L), so this restores parity.
    try {
        $attr = [System.IO.File]::GetAttributes($DirectoryPath)
        if (($attr -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { return $true }
    } catch { return $true }   # unreadable attributes -> safest to skip
    try {
        $dname = [System.IO.Path]::GetFileName($DirectoryPath)
        if ($script:ExcludeDirSet.Contains($dname)) { return $true }
        $sep = [System.IO.Path]::DirectorySeparatorChar
        foreach ($prefix in $script:ExcludePathPrefixes) {
            if (-not $prefix) { continue }
            # Exact match OR a real path-separated child. Bare StartsWith would
            # over-exclude siblings (C:\foo also matching C:\foobar); this mirrors
            # the bash `-path '$d' -o -path '$d/*'` semantics.
            if ($DirectoryPath.Equals($prefix, [System.StringComparison]::OrdinalIgnoreCase) -or
                $DirectoryPath.StartsWith($prefix + $sep, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
        # Path-substring patterns (per-user paths can't use simple prefixes)
        foreach ($needle in $script:ExcludePathContains) {
            if ($DirectoryPath.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $true
            }
        }
    } catch {}
    return $false
}

function Format-Preview { param([string]$Text)
    if (-not $Text) { return '' }
    $t = $Text -replace '[\r\n]+', ' '
    # Drop terminal control bytes (ESC/BEL/backspace/etc.) from scanned content
    # so neither live output nor the on-disk log can carry escape sequences.
    $t = $t -replace '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', ''
    $t = $t -replace '\s+', ' '
    $t = $t.Trim()
    if ($t.Length -gt $script:MaxPreviewLen) {
        $t = $t.Substring(0, $script:MaxPreviewLen) + '...'
    }
    return $t
}

function Get-LineNumber { param([string]$Content, [int]$Index)
    if ($Index -le 0) { return 1 }
    $stop = [Math]::Min($Index, $Content.Length)
    $count = 1
    for ($i = 0; $i -lt $stop; $i++) {
        if ($Content[$i] -eq "`n") { $count++ }
    }
    return $count
}

function Add-Finding {
    param(
        [ValidateSet('High','Key')] [string]$Bucket,
        [string]$Label,
        [string]$Path,
        [int]   $LineNumber,
        [string]$Preview
    )
    $key = "$Bucket|$Label|$Path|$LineNumber"
    if (-not $script:FindingHashes.Add($key)) { return }
    $obj = [PSCustomObject]@{
        Label = $Label; Path = $Path; LineNumber = $LineNumber; Preview = $Preview
    }
    switch ($Bucket) {
        'High' { $script:HighFindings.Add($obj) }
        'Key'  { $script:KeyFindings.Add($obj)  }
    }
    if ($script:InStage1) {
        Write-Stage1Finding -Tier $Bucket -Label $Label -Path $Path -LineNumber $LineNumber -Preview $Preview
    }
}

function Add-Interesting { param([string]$Category, [string]$Path)
    $k = "$Category|$Path"
    if ($script:InterestingHashes.Add($k)) {
        $script:Interesting.Add([PSCustomObject]@{ Category = $Category; Path = $Path })
        if ($script:InStage1) {
            Write-Stage1Finding -Tier 'Interest' -Label $Category -Path $Path
        }
    }
}
function Add-Guaranteed { param([string]$Extension, [string]$Path)
    if ($script:GuaranteedHashes.Add($Path)) {
        $script:Guaranteed.Add([PSCustomObject]@{ Extension = $Extension; Path = $Path })
        if ($script:InStage1) {
            Write-Stage1Finding -Tier 'Critical' -Label $Extension -Path $Path
        }
    }
}
function Add-SuspiciousName { param([string]$Path)
    if ($script:NameHashes.Add($Path)) {
        $script:SuspiciousNamesFound.Add($Path) | Out-Null
        if ($script:InStage1) {
            Write-Stage1Finding -Tier 'Name' -Label 'name_match' -Path $Path
        }
    }
}
function Add-Checked { param([string]$Label, [string]$Path)
    $k = "$Label|$Path"
    if ($script:CheckedHashes.Add($k)) {
        $script:LocationsChecked.Add([PSCustomObject]@{ Label = $Label; Path = $Path })
    }
}
function Add-Skipped { param([string]$Path, [string]$Reason)
    $script:SkippedFiles.Add([PSCustomObject]@{ Path = $Path; Reason = $Reason })
}

# ============================================================================
#  Content scanning core
# ============================================================================

# Single file scan. Used by both stage 1 (OS checks) and stage 5 (recursive).
#
# Performance design:
#   1. Cheap I/O + binary + size gate.
#   2. ONE compiled-regex pre-filter on the whole file. If no credential
#      anchor keyword appears anywhere, only the (always-cheap) private-key
#      header check runs. This kills 80-95% of files instantly and is what
#      makes scanning C:\ feasible -- license/doc/boilerplate text files
#      otherwise burn minutes on backtracking.
#   3. LINE-BY-LINE pattern evaluation for files that pass the pre-filter.
#      Each pattern runs against a single bounded-length line, so
#      catastrophic backtracking is impossible.
#   4. First pattern that matches a line wins (one finding per line).
#   5. Skip pathologically long lines (> MaxLineLen, 16 KB) -- minified JS,
#      base64 blobs, or log rotations, never credential assignments.
function Invoke-ScanFile { param([string]$FullPath, [string]$SourceLabel = 'content', [long]$KnownSize = -1)
    if ($script:SelfPath -and $FullPath -eq $script:SelfPath) { return }
    if (-not $script:ScannedPaths.Add($FullPath)) { return }

    # Cheap filename-based skip BEFORE any I/O: LICENSE, CHANGELOG, package-lock,
    # README, .gitignore, etc. all match credential extensions but never contain
    # reusable credentials. Skipping here saves a stat, a binary check, and a
    # regex pass per file on every dev-style repo.
    $bn = [System.IO.Path]::GetFileName($FullPath)
    if ($script:SkipFilenames.Contains($bn)) {
        Add-Skipped -Path $FullPath -Reason 'non-credential filename'
        return
    }
    # Glob-style doc/meta name skips (parity with bash should_skip_filename's
    # README*/LICENSE.*/CHANGELOG.* etc. patterns, which the exact-name HashSet
    # above does not cover for arbitrary suffixes).
    if ($bn -match '(?i)^README' -or
        $bn -match '(?i)^(LICEN[CS]E|UNLICENSE|COPYING|COPYRIGHT|CHANGELOG|CHANGES|HISTORY|NEWS|RELEASE_NOTES|RELEASES|AUTHORS|CONTRIBUTORS|MAINTAINERS|CONTRIBUTING|INSTALL|UPGRADE|UPGRADING)(\..*)?$' -or
        $bn -match '(?i)^tsconfig\..*\.json$' -or $bn -match '(?i)^tslint.*\.json$') {
        Add-Skipped -Path $FullPath -Reason 'non-credential filename'; return
    }
    if ($bn -match '(?i)\.lnk$') { Add-Skipped -Path $FullPath -Reason 'shortcut'; return }
    # Pattern-based skips: minified / bundled / code-split / translation / maps
    if ($bn -match '\.(min|bundle)\.(js|css)$' -or $bn -match '\.chunk\.js$') {
        Add-Skipped -Path $FullPath -Reason 'minified asset'; return
    }
    if ($bn -match '\.(po|pot|mo)$')  { Add-Skipped -Path $FullPath -Reason 'gettext translation'; return }
    if ($bn -match '\.map$')          { Add-Skipped -Path $FullPath -Reason 'source map'; return }
    # .env templates are placeholders by definition -- flagged by stage 4 but
    # we skip their content to avoid <YOUR_PASSWORD>-style false positives.
    if ($bn -match '\.env\.(example|sample|template|dist)$') { Add-Skipped -Path $FullPath -Reason 'env template'; return }

    # Reuse the size Stage 5 already captured from directory find-data (passed via
    # -KnownSize) instead of forcing a second stat. Stage 1 call sites omit it and
    # fall back to Get-FileSizeSafe.
    $size = if ($KnownSize -ge 0) { $KnownSize } else { Get-FileSizeSafe -FullPath $FullPath }
    if ($size -lt 0) { Add-Skipped -Path $FullPath -Reason 'unreadable'; return }
    if ($size -eq 0) { return }
    # Hard memory ceiling enforced even under -NoSizeLimit: never read a file
    # larger than 512 MB whole (it would balloon RSS). One warning, then skip.
    if ($size -gt 512MB) {
        Write-Warn ("Skipping very large file (> 512 MB hard cap): {0}" -f $FullPath)
        Add-Skipped -Path $FullPath -Reason 'size>512MB (hard cap)'; return
    }
    if ($script:SkipLarge -and $size -gt $script:MaxFileSizeBytes) {
        Add-Skipped -Path $FullPath -Reason ("size>{0}MB" -f $MaxFileSizeMB); return
    }
    # Encoding-aware read (handles UTF-16/32 .reg exports, Scheduled-Task XML,
    # Unicode-saved configs); $null means the bytes look genuinely binary.
    $content = Read-TextFileSmart -FullPath $FullPath
    if ($null -eq $content) { Add-Skipped -Path $FullPath -Reason 'binary'; return }
    if ([string]::IsNullOrEmpty($content)) { return }

    # ---- Private-key markers (format-anchored) ------------------------------
    # ~99% of files contain no key header, so gate the 8 whole-file regex passes
    # behind a cheap Ordinal substring check. This canNOT run after the keyword
    # prefilter: key headers (-----BEGIN ... / PuTTY-User-Key-File-) match no
    # prefilter anchor, so prefiltering would drop real keys. These two literals
    # cover every $script:KeyPatternsRaw entry (all 7 PEM "-----BEGIN ..." markers
    # plus the PuTTY marker).
    if ($content.IndexOf('-----BEGIN', [System.StringComparison]::Ordinal) -ge 0 -or
        $content.IndexOf('PuTTY-User-Key-File', [System.StringComparison]::Ordinal) -ge 0) {
        foreach ($p in $script:KeyPatterns) {
            $m = $p.Regex.Match($content)
            if ($m.Success) {
                $lineNo = Get-LineNumber -Content $content -Index $m.Index
                Add-Finding -Bucket Key -Label $p.Label -Path $FullPath -LineNumber $lineNo -Preview $m.Value
            }
        }
    }

    # ---- Multi-line XML credential tags (unattend.xml / sysprep autologon) ---
    # <Password> and <Value> frequently span separate lines, which the per-line
    # loop below cannot match. Do one whole-file (?is) match here; the cheap
    # IndexOf gate keeps it off the hot path for non-XML files. Single-line hits
    # are de-duplicated by Add-Finding (same label+path+line as the per-line scan).
    if ($content.IndexOf('Password>', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        $um = $script:UnattendRegex.Match($content)
        if ($um.Success) {
            $uval = $um.Groups[1].Value.Trim()
            if ($uval -and -not (Test-FalsePositive -Value $uval)) {
                $uLine = Get-LineNumber -Content $content -Index $um.Index
                Add-Finding -Bucket High -Label "$SourceLabel/unattend_password" `
                    -Path $FullPath -LineNumber $uLine -Preview ("Password Value: " + $uval)
            }
        }
    }

    # ---- Pre-filter: if no anchor keyword, skip the expensive pass ----------
    if (-not $script:KeywordPrefilter.IsMatch($content)) { return }

    # ---- Line-by-line credential-pattern scan -------------------------------
    $matchesFound = 0
    # Stream lines with a StringReader instead of -split, which would allocate the
    # whole file as a string[] -- doubling memory and GC pressure on exactly the
    # large files that are slowest. $i is 1-based (incremented before use), so
    # findings use -LineNumber $i. StringReader.ReadLine() treats \r\n, \r and \n
    # as terminators, matching the old split semantics.
    $reader = New-Object System.IO.StringReader($content)
    try {
        $i = 0
        while ($null -ne ($line = $reader.ReadLine())) {
            $i++
            if ($matchesFound -ge $script:MaxMatchesPerFile) { break }
            $llen = $line.Length
            if ($llen -lt 6 -or $llen -gt $script:MaxLineLen) { continue }

            # Cheap per-line keyword check (regex IsMatch on a short string is fast)
            if (-not $script:KeywordPrefilter.IsMatch($line)) { continue }

        foreach ($p in $script:CredPatterns) {
            $m = $p.Regex.Match($line)
            if (-not $m.Success) { continue }

            # Commented example skip: stock configs ship docs like
            # `# snmpwalk -c public`. Skip comment lines ONLY for
            # command/directive patterns; generic key=value assignments are
            # tried first and are NOT skipped (a commented-out real password
            # is still reported).
            # NOTE: `break`, not `continue` — once the first matching pattern is
            # ruled noise, the whole line yields nothing (parity with the bash
            # classify_line `return 1` first-match-wins semantics). Using
            # `continue` here let a later, broader pattern (e.g. define_secret in
            # NoFPCheck) re-report a line an earlier pattern had already dropped.
            if ($line -match '^\s*(#|//|;|[Rr][Ee][Mm]\s)' -and
                $p.Label -match '(_cmd$|_pass$|^cmdline_pw_flag$|^impacket_cred$|^runas_savecred$|^cmdkey_add$|^net_user_create$|^chpasswd_|^passwd_stdin$|^ps_localuser|^ps_ad_password$|^ps_secstring|^htpasswd_create$|^nmcli_wifi$|^useradd_pass$|^snmp_community$|^snmp_com2sec$)') {
                break
            }

            # -- Smarter value extraction --
            # The OLD code grabbed the substring after the FIRST `:` or `=` on
            # the line. That misfires on timestamps ("03:39:54 SVCPASSWORD:
            # source = Default") where the first `:` is the clock, not the
            # password operator. Find the password-keyword position first,
            # then take whatever immediately follows ITS operator.
            # Anchor the keyword on a non-letter boundary (NOT \b — underscore is
            # a word char, which would break db_password) and list longest-first so
            # the value is taken after the real keyword, never after a pass-like
            # substring inside "bypass" / "compass" / "passenger".
            $value = $line
            $kwMatch = [regex]::Match($line,
                '(?i)(?<![A-Za-z])(?:cpassword|passphrase|password|passwd|requirepass|rootpw|credentials?|cred|secret|pass|pwd)\s*[:=]?\s*',
                [System.Text.RegularExpressions.RegexOptions]::None)
            if ($kwMatch.Success) {
                $value = $line.Substring($kwMatch.Index + $kwMatch.Length)
                $value = $value.Trim().Trim('"', "'", ' ', ';')
                $value = ($value -split '[#;]')[0]
                # Cut at the next `, ` or `->` boundary -- common log noise
                # like "key = value, message = ..." would otherwise capture
                # the whole tail.
                $value = ($value -split ',\s+|\s+->\s+|\s+message\s*=', 2)[0]
            }

            # PHP 'key' => 'value' / define('KEY','value') / new mysqli(...,'pw')
            # shapes: the generic extractor leaves a messy "=> 'value'" prefix, so
            # take the LAST quoted literal on the line as the value before
            # FP-filtering (e.g.  'password' => 'changeme'  ->  changeme).
            # autologon_password included so the canonical .reg form
            # "DefaultPassword"="value" yields the real value (the boundary-anchored
            # keyword extractor above skips "password" inside the compound key
            # "DefaultPassword" and would otherwise latch onto a keyword in the value).
            if ($p.Label -eq 'drupal_password' -or $p.Label -eq 'wp_db_password' -or
                $p.Label -eq 'joomla_password' -or $p.Label -eq 'define_secret' -or
                $p.Label -eq 'php_db_connect' -or $p.Label -eq 'autologon_password') {
                $mq = [regex]::Match($line, '["'']([^"'']+)["''][^"'']*$')
                if ($mq.Success) { $value = $mq.Groups[1].Value }
            }

            # -- Hard-coded line-level FP filter (real-host noise) --
            # SQL parameter references / masked passwords / SQL Telemetry
            # logs / Microsoft's published Yukon90_ certificate-signing pw.
            # `break` (not `continue`): a line ruled noise / false-positive by
            # its first matching pattern yields nothing — matching the bash
            # classify_line `return 1` semantics. (Otherwise a later broad
            # pattern in NoFPCheck, e.g. define_secret, would re-report a
            # placeholder a more specific pattern had already suppressed.)
            if ($line -match '@password\s*=\s*(@password|N''''|NULL|@\w+\b)') { break }
            if ($line -match 'WITH\s+PASSWORD\s*=\s*''Yukon90_''')           { break }
            if ($line -match 'PASSWORD\s*=\s*''\*+''')                       { break }
            if ($line -match 'SQLTelemetry\s*:\s*Setting')                   { break }
            if ($line -match 'SafeSqlCommand.*PASSWORD\s*=\s*''\*+''')       { break }

            if (-not ($script:NoFPCheck -contains $p.Label)) {
                if (Test-FalsePositive -Value $value) { break }
            }

            Add-Finding -Bucket High -Label "$SourceLabel/$($p.Label)" `
                -Path $FullPath -LineNumber $i -Preview (Format-Preview $line)
            $matchesFound++
            break    # one classification per line is enough
        }
        }
    } finally { $reader.Dispose() }
}

function Test-KnownFile { param([string]$Path, [string]$Label)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Add-Checked -Label $Label -Path $Path
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    Invoke-ScanFile -FullPath $Path -SourceLabel $Label
}

# Enumerate a registry "Sessions"-style container and surface EVERY saved
# session for manual review -- regardless of whether a credential regex or the
# FP filter would match. Saved sessions (PuTTY/KiTTY/WinSCP/RDP) are rare and
# high-value; a silent miss (dropping a session that stores a password the
# regex never recognised) is far worse than listing a handful of entries the
# operator can eyeball. For each subkey we dump the host/user identity plus the
# RAW value of any property whose NAME looks credential-bearing
# (Password/Passphrase/Pwd/Secret/Cred/ProxyPassword/...). A stored secret field
# -> [HIGH] with the raw value; an identity-only session -> [INTEREST] review.
function Write-RegistrySessionReview { param([string]$Root, [string]$Tool)
    if (-not (Test-Path $Root)) { return }
    Add-Checked -Label "${Tool}_sessions" -Path $Root
    try {
        Get-ChildItem -LiteralPath $Root -ErrorAction SilentlyContinue | ForEach-Object {
            $sess = $_.PSChildName
            try { $sess = [System.Uri]::UnescapeDataString($sess) } catch {}
            $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            if (-not $p) { return }
            $ident = @()
            foreach ($f in 'HostName','UserName','UsernameHint','PortNumber',
                           'ProxyHost','ProxyUsername','PublicKeyFile','PortForwardings') {
                if ($p.PSObject.Properties.Match($f).Count -gt 0 -and "$($p.$f)" -ne '') {
                    $ident += "$f=$($p.$f)"
                }
            }
            # A credential can hide in (a) a value whose NAME looks secret-like
            # (Password/ProxyPassword/...), OR (b) the value DATA itself -- e.g.
            # a ProxyCommand / RemoteCommand value holding
            #   &('C:\...\plink.exe') -pw 'Th3R@tC@tch3r' user@host 'df -h'
            # where the value name ("zachary") gives no hint. We therefore
            # inspect BOTH the name and the data, and ALWAYS log the full string
            # so the operator can verify manually even when the regex misses it.
            $secretInData = '(?i)(-pw\b|--pw\b|-pass\b|--password|/p:|/pass:|/password:|password\s*[:=]|passwd\s*[:=]|\bpwd\s*[:=]|sshpass\s|://[^\s/:@]+:[^\s/@]+@)'
            $cmdInData    = '(?i)(\bplink\b|\bpscp\b|\bpsftp\b|\bputty\b|\bnet\s+use\b|\brunas\b|\bcmdkey\b|\bpsexec\b|\bwmic\b|\bschtasks\b|\.exe\b|-i\s+\S+\.ppk)'
            $secrets = @()
            $review  = @()
            foreach ($prop in $p.PSObject.Properties) {
                if ($prop.Name -like 'PS*') { continue }   # skip PSPath/PSProvider/etc.
                $data = if ($prop.Value -is [byte[]]) { [BitConverter]::ToString($prop.Value) } else { "$($prop.Value)" }
                if ($data -eq '') { continue }
                # Light sanitise + generous cap so the WHOLE command is visible
                # (well past the 140-char preview cap) without flooding on a
                # pathological multi-KB value.
                $show = ($data -replace '[\r\n\t]+', ' ')
                if ($show.Length -gt 600) { $show = $show.Substring(0, 600) + '...(truncated)' }
                if ($prop.Name -match '(?i)(password|passwd|pwd|passphrase|secret|cred)') {
                    $secrets += "$($prop.Name)=$show"            # name looks secret
                } elseif ($data -match $secretInData) {
                    $secrets += "$($prop.Name)=$show"            # password embedded in data
                } elseif ($data -match $cmdInData) {
                    $review  += "$($prop.Name)=$show"            # stored command -> manual review
                }
            }
            $base = (@("${Tool}[$sess]") + $ident) -join '  '
            if ($secrets.Count -gt 0) {
                # Bypass regex/FP filter entirely -- dump the raw stored value(s).
                Add-Finding -Bucket High -Label "$Tool/stored_session_secret" `
                    -Path $_.PSPath -LineNumber 0 -Preview (($base + '  ' + ($secrets -join '  ')).Trim())
            }
            if ($review.Count -gt 0) {
                # Command stored in the session -- log the full string so the
                # operator can manually check for embedded credentials.
                Add-Finding -Bucket High -Label "$Tool/session_command_review" `
                    -Path $_.PSPath -LineNumber 0 -Preview (($base + '  ' + ($review -join '  ')).Trim())
            }
            if ($secrets.Count -eq 0 -and $review.Count -eq 0) {
                Add-Interesting -Category "${Tool}_session_review" -Path $base
            }
        }
    } catch {}
}

# ============================================================================
#  Stage 1 - OS-level credential checks (targeted Windows locations)
# ============================================================================

function Test-RegistryAutoLogon {
    Write-Info "Stage 1.1 - AutoLogon registry"
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon'
    )
    foreach ($k in $keys) {
        if (-not (Test-Path $k)) { continue }
        Add-Checked -Label 'autologon_registry' -Path $k
        try {
            $p = Get-ItemProperty -Path $k -ErrorAction Stop
            foreach ($prop in 'DefaultPassword','AltDefaultPassword') {
                if ($p.PSObject.Properties.Match($prop).Count -gt 0) {
                    $v = $p.$prop
                    if (-not [string]::IsNullOrEmpty($v) -and -not (Test-FalsePositive -Value $v)) {
                        Add-Finding -Bucket High -Label "registry/autologon_$($prop.ToLower())" -Path $k -LineNumber 0 -Preview ("{0} = {1}" -f $prop, $v)
                    }
                }
            }
        } catch {}
    }
}

function Test-GPPCPassword {
    Write-Info "Stage 1.2 - Group Policy Preferences cpassword"
    $roots = @(
        Join-Path $env:SystemRoot 'SYSVOL'
        Join-Path $env:ProgramData 'Microsoft\Group Policy\History'
        Join-Path $env:SystemRoot 'System32\GroupPolicy'
    )
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Add-Checked -Label 'gpp_root' -Path $root
        try {
            $xmls = Get-ChildItem -LiteralPath $root -Recurse -Include 'Groups.xml','Services.xml','ScheduledTasks.xml','DataSources.xml','Drives.xml','Printers.xml' -ErrorAction SilentlyContinue
            foreach ($x in $xmls) {
                Add-Checked -Label 'gpp_xml' -Path $x.FullName
                try {
                    $c = [System.IO.File]::ReadAllText($x.FullName)
                    if ($c -match 'cpassword\s*=\s*"([A-Za-z0-9+/=]{20,})"') {
                        Add-Finding -Bucket High -Label 'gpp/gpp_cpassword' -Path $x.FullName -LineNumber 0 -Preview "cpassword=$($Matches[1])"
                    }
                } catch {}
            }
        } catch {}
    }
}

function Test-UnattendedInstall {
    Write-Info "Stage 1.3 - unattended install / sysprep files"
    $files = @(
        Join-Path $env:SystemRoot 'Panther\Unattend.xml'
        Join-Path $env:SystemRoot 'Panther\Unattended.xml'
        Join-Path $env:SystemRoot 'Panther\Unattend\Unattend.xml'
        Join-Path $env:SystemRoot 'Panther\Unattend\Unattended.xml'
        Join-Path $env:SystemRoot 'System32\Sysprep\unattend.xml'
        Join-Path $env:SystemRoot 'System32\Sysprep\sysprep.xml'
        Join-Path $env:SystemRoot 'System32\Sysprep\Panther\unattend.xml'
        Join-Path $env:SystemDrive '\unattend.xml'
        Join-Path $env:SystemDrive '\autounattend.xml'
        Join-Path $env:SystemDrive '\sysprep.inf'
        Join-Path $env:SystemRoot 'debug\NetSetup.log'
    )
    foreach ($f in $files) { Test-KnownFile -Path $f -Label 'unattend' }
}

function Test-PowerShellHistory {
    Write-Info "Stage 1.4 - PowerShell history"
    $hist = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    Test-KnownFile -Path $hist -Label 'powershell_history'
    try {
        Get-ChildItem -LiteralPath (Join-Path $env:SystemDrive '\Users') -Directory -ErrorAction SilentlyContinue |
            ForEach-Object {
                $p = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
                if (Test-Path -LiteralPath $p) { Test-KnownFile -Path $p -Label 'powershell_history' }
            }
    } catch {}
}

function Test-CmdkeyVault {
    Write-Info "Stage 1.5 - Windows credential vault / cmdkey"
    # NOTE: this parse of `cmdkey /list` is LOCALE-DEPENDENT -- the "Target:" /
    # "User:" / "Type:" labels are localized, so on non-English hosts the block
    # split and User capture can miss. The robust, locale-independent alternative
    # is to P/Invoke CredEnumerate (advapi32) and read the CREDENTIAL structs
    # directly; left as a TODO to avoid adding Add-Type/native interop here.
    try {
        $out = & cmdkey.exe /list 2>$null
        if ($out) {
            $joined = ($out -join "`n")
            Add-Checked -Label 'cmdkey_list' -Path 'cmdkey /list'
            $blocks = ($joined -split '(?m)^\s*Target:' )
            foreach ($b in $blocks) {
                if ($b -match 'User:\s*(.+)' -or $b -match 'Type:') {
                    $tgt = ($b -split "`r?`n" | Where-Object { $_ -match '\S' } | Select-Object -First 3) -join ' | '
                    if ($tgt) {
                        Add-Finding -Bucket High -Label 'cmdkey/saved_credential' -Path 'cmdkey:list' -LineNumber 0 -Preview (Format-Preview $tgt)
                    }
                }
            }
        }
    } catch {}
    foreach ($p in @(
        (Join-Path $env:USERPROFILE 'AppData\Roaming\Microsoft\Credentials')
        (Join-Path $env:USERPROFILE 'AppData\Local\Microsoft\Credentials')
        (Join-Path $env:USERPROFILE 'AppData\Local\Microsoft\Vault')
        (Join-Path $env:USERPROFILE 'AppData\Roaming\Microsoft\Vault')
    )) {
        if (Test-Path -LiteralPath $p) {
            Add-Checked -Label 'vault_dir' -Path $p
            try {
                Get-ChildItem -LiteralPath $p -Force -File -ErrorAction SilentlyContinue | ForEach-Object {
                    Add-Interesting -Category 'windows_vault_file' -Path $_.FullName
                }
            } catch {}
        }
    }
}

function Test-PuTTYSessions {
    Write-Info "Stage 1.6 - PuTTY / KiTTY saved sessions"
    # Every saved session is listed for manual review (host/user + any
    # credential-named field, raw). PuTTY stores ProxyPassword in cleartext;
    # KiTTY (a PuTTY fork sharing the same layout) additionally stores a
    # cleartext/obfuscated Password field -- both are dumped regardless of the
    # FP filter so a session can never be silently dropped.
    Write-RegistrySessionReview -Root 'HKCU:\Software\SimonTatham\PuTTY\Sessions' -Tool 'putty'
    Write-RegistrySessionReview -Root 'HKCU:\Software\9bis.com\KiTTY\Sessions'    -Tool 'kitty'
}

function Test-WinSCPSessions {
    Write-Info "Stage 1.7 - WinSCP saved sessions"
    # Every saved session listed for manual review; the (encrypted) Password
    # field is dumped raw so it can be decrypted offline (winscppasswd, etc.).
    Write-RegistrySessionReview -Root 'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions' -Tool 'winscp'
    foreach ($d in @($env:APPDATA, $env:LOCALAPPDATA, $env:USERPROFILE)) {
        if (-not $d) { continue }
        try {
            Get-ChildItem -LiteralPath $d -Recurse -Force -Filter 'WinSCP.ini' -ErrorAction SilentlyContinue |
                Select-Object -First 5 |
                ForEach-Object {
                    Add-Interesting -Category 'winscp_ini' -Path $_.FullName
                    Invoke-ScanFile -FullPath $_.FullName -SourceLabel 'winscp_ini'
                }
        } catch {}
    }
}

function Test-VNCRegistry {
    Write-Info "Stage 1.8 - VNC registry (TightVNC / RealVNC / UltraVNC / TigerVNC)"
    $keys = @(
        'HKLM:\SOFTWARE\TightVNC\Server'
        'HKLM:\SOFTWARE\WOW6432Node\TightVNC\Server'
        'HKLM:\SOFTWARE\RealVNC\WinVNC4'
        'HKLM:\SOFTWARE\WOW6432Node\RealVNC\WinVNC4'
        'HKLM:\SOFTWARE\RealVNC\vncserver'
        'HKLM:\SOFTWARE\ORL\WinVNC3'
        'HKLM:\SOFTWARE\WOW6432Node\ORL\WinVNC3'
        'HKLM:\SOFTWARE\TigerVNC\WinVNC4'
        'HKCU:\Software\TightVNC\Server'
        'HKCU:\Software\ORL\WinVNC3'
        'HKCU:\Software\RealVNC\WinVNC4'
        'HKCU:\Software\TigerVNC\vncserver'
    )
    foreach ($k in $keys) {
        if (-not (Test-Path $k)) { continue }
        Add-Checked -Label 'vnc_registry' -Path $k
        try {
            $p = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
            $found = $false
            # Dump EVERY credential-named value (Password, PasswordViewOnly,
            # ControlPassword, UltraVNC Passwd/Passwd2, etc.) raw -- bypassing
            # the FP filter -- so no VNC variant's stored (DES-obfuscated)
            # password is silently dropped.
            foreach ($prop in $p.PSObject.Properties) {
                if ($prop.Name -match '(?i)(password|passwd|pwd|secret|cred)' -and "$($prop.Value)" -ne '') {
                    $val = if ($prop.Value -is [byte[]]) { [BitConverter]::ToString($prop.Value) } else { "$($prop.Value)" }
                    Add-Finding -Bucket High -Label 'vnc/stored_password' -Path $k -LineNumber 0 -Preview (Format-Preview ("{0} = {1}" -f $prop.Name, $val))
                    $found = $true
                }
            }
            # VNC configured but no password value found in this key -- list it
            # for manual review (auth may be external / in another key).
            if (-not $found) { Add-Interesting -Category 'vnc_registry_review' -Path $k }
        } catch {}
    }
}

function Test-SNMPRegistry {
    Write-Info "Stage 1.9 - SNMP community strings"
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'
    if (-not (Test-Path $key)) { return }
    Add-Checked -Label 'snmp_communities' -Path $key
    try {
        $p = Get-Item -LiteralPath $key -ErrorAction SilentlyContinue
        foreach ($name in $p.GetValueNames()) {
            if ($name) {
                Add-Finding -Bucket High -Label 'snmp/community' -Path $key -LineNumber 0 -Preview ("community = {0}" -f $name)
            }
        }
    } catch {}
}

function Test-SAMHives {
    Write-Info "Stage 1.10 - SAM/SYSTEM/SECURITY hive files"
    $hives = @(
        (Join-Path $env:SystemRoot 'System32\config\SAM')
        (Join-Path $env:SystemRoot 'System32\config\SYSTEM')
        (Join-Path $env:SystemRoot 'System32\config\SECURITY')
        (Join-Path $env:SystemRoot 'repair\SAM')
        (Join-Path $env:SystemRoot 'repair\SYSTEM')
        (Join-Path $env:SystemRoot 'repair\SECURITY')
        (Join-Path $env:SystemRoot 'System32\config\RegBack\SAM')
        (Join-Path $env:SystemRoot 'System32\config\RegBack\SYSTEM')
        (Join-Path $env:SystemRoot 'System32\config\RegBack\SECURITY')
    )
    foreach ($h in $hives) {
        if (-not (Test-Path -LiteralPath $h)) { continue }
        Add-Checked -Label 'sam_hive' -Path $h
        try {
            $fs = [System.IO.File]::OpenRead($h)
            $fs.Close()
            Add-Interesting -Category 'readable_hive' -Path $h
            Add-Finding -Bucket Key -Label 'readable_sam_hive' -Path $h -LineNumber 0 -Preview "Hive readable - extract with secretsdump.py / impacket-secretsdump"
        } catch {}
    }
}

function Test-IISConfigs {
    Write-Info "Stage 1.11 - IIS web.config / applicationHost.config"
    foreach ($f in @(
        (Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config')
        (Join-Path $env:SystemRoot 'System32\inetsrv\config\administration.config')
    )) { Test-KnownFile -Path $f -Label 'iis_config' }
    # .NET machine.config — machine-wide connection strings + machineKey
    foreach ($f in @(
        (Join-Path $env:SystemRoot 'Microsoft.NET\Framework\v4.0.30319\Config\machine.config')
        (Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\Config\machine.config')
        (Join-Path $env:SystemRoot 'Microsoft.NET\Framework\v2.0.50727\Config\machine.config')
        (Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v2.0.50727\Config\machine.config')
    )) { Test-KnownFile -Path $f -Label 'dotnet_machine_config' }
    $inetpub = Join-Path $env:SystemDrive '\inetpub'
    if (Test-Path -LiteralPath $inetpub) {
        try {
            Get-ChildItem -LiteralPath $inetpub -Recurse -Force -Filter 'web.config' -ErrorAction SilentlyContinue |
                Select-Object -First 200 |
                ForEach-Object { Test-KnownFile -Path $_.FullName -Label 'iis_webconfig' }
        } catch {}
        # ASP.NET Core appsettings*.json (connection strings, secrets in plaintext)
        try {
            Get-ChildItem -LiteralPath $inetpub -Recurse -Force -Filter 'appsettings*.json' -ErrorAction SilentlyContinue |
                Select-Object -First 200 |
                ForEach-Object { Test-KnownFile -Path $_.FullName -Label 'aspnet_appsettings' }
        } catch {}
    }
}

function Test-ScheduledTasks {
    Write-Info "Stage 1.12 - scheduled task XML"
    $tasks = Join-Path $env:SystemRoot 'System32\Tasks'
    if (-not (Test-Path -LiteralPath $tasks)) { return }
    try {
        Get-ChildItem -LiteralPath $tasks -Recurse -Force -File -ErrorAction SilentlyContinue |
            Select-Object -First 500 |
            ForEach-Object {
                try {
                    $c = [System.IO.File]::ReadAllText($_.FullName)
                    if ($c -match '(?i)<LogonType>Password</LogonType>' -or
                        $c -match '(?i)<UserId>([^<]+)</UserId>') {
                        Invoke-ScanFile -FullPath $_.FullName -SourceLabel 'scheduled_task'
                    }
                } catch {}
            }
    } catch {}
}

function Test-WiFiProfiles {
    Write-Info "Stage 1.13 - saved Wi-Fi profiles"
    # Export profiles (key=clear) to a temp folder and parse the NON-localized XML
    # schema (<name> / <keyMaterial>) instead of scraping the localized
    # "Key Content :" text, which only matched on English-language hosts. The
    # exported XML holds cleartext keys, so the temp folder is deleted in finally.
    $tmp = $null
    try {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('cs_wifi_' + [System.IO.Path]::GetRandomFileName())
        New-Item -ItemType Directory -Path $tmp -Force -ErrorAction SilentlyContinue | Out-Null
        & netsh.exe wlan export profile key=clear folder="$tmp" 2>$null | Out-Null
        Get-ChildItem -LiteralPath $tmp -Filter '*.xml' -File -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $xml  = [System.IO.File]::ReadAllText($_.FullName)
                # First <name> in a WLANProfile is the profile/SSID name.
                $ssid = if ($xml -match '(?is)<name>\s*(.*?)\s*</name>') { $Matches[1] } else { $_.BaseName }
                Add-Checked -Label 'wifi_profile' -Path $ssid
                $km = [regex]::Match($xml, '(?is)<keyMaterial>\s*(.*?)\s*</keyMaterial>')
                if ($km.Success) {
                    $key = $km.Groups[1].Value.Trim()
                    if ($key -and -not (Test-FalsePositive -Value $key)) {
                        Add-Finding -Bucket High -Label 'wifi/key_clear' -Path ('wifi:' + $ssid) -LineNumber 0 -Preview ("SSID `"$ssid`": $key")
                    }
                }
            } catch {}
        }
    } catch {} finally {
        if ($tmp -and (Test-Path -LiteralPath $tmp)) {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-McAfeeSiteList {
    Write-Info "Stage 1.14 - McAfee SiteList"
    foreach ($f in @(
        (Join-Path ${env:ProgramFiles} 'McAfee\Common Framework\SiteList.xml')
        (Join-Path ${env:ProgramFiles(x86)} 'McAfee\Common Framework\SiteList.xml')
        (Join-Path $env:ALLUSERSPROFILE 'McAfee\Common Framework\SiteList.xml')
        (Join-Path $env:ALLUSERSPROFILE 'McAfee\Common Framework\SiteMgr.xml')
    )) {
        if (Test-Path -LiteralPath $f) {
            Add-Interesting -Category 'mcafee_sitelist' -Path $f
            Test-KnownFile -Path $f -Label 'mcafee_sitelist'
        }
    }
}

function Test-BrowserCredFiles {
    Write-Info "Stage 1.15 - browser credential databases"
    try {
        Get-ChildItem -LiteralPath (Join-Path $env:SystemDrive '\Users') -Directory -ErrorAction SilentlyContinue |
            ForEach-Object {
                $u = $_.FullName
                foreach ($c in @(
                    "$u\AppData\Local\Google\Chrome\User Data\Default\Login Data"
                    "$u\AppData\Local\Microsoft\Edge\User Data\Default\Login Data"
                    "$u\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Login Data"
                    "$u\AppData\Local\Google\Chrome\User Data\Local State"
                    "$u\AppData\Local\Microsoft\Edge\User Data\Local State"
                    "$u\AppData\Roaming\Opera Software\Opera Stable\Login Data"
                )) {
                    if (Test-Path -LiteralPath $c) {
                        Add-Interesting -Category 'browser_credentials' -Path $c
                    }
                }
                $fxProfiles = Join-Path $u 'AppData\Roaming\Mozilla\Firefox\Profiles'
                if (Test-Path -LiteralPath $fxProfiles) {
                    Add-Interesting -Category 'firefox_profiles' -Path $fxProfiles
                }
            }
    } catch {}
}

function Test-CloudCliCredentials {
    Write-Info "Stage 1.16 - cloud CLI credential stores"
    try {
        Get-ChildItem -LiteralPath (Join-Path $env:SystemDrive '\Users') -Directory -ErrorAction SilentlyContinue |
            ForEach-Object {
                $u = $_.FullName
                foreach ($c in @(
                    "$u\.aws\credentials","$u\.aws\config"
                    "$u\.azure\accessTokens.json","$u\.azure\azureProfile.json"
                    "$u\.kube\config","$u\.docker\config.json"
                    "$u\.netrc","$u\_netrc","$u\.git-credentials"
                    "$u\.npmrc","$u\.pypirc","$u\.s3cfg"
                    "$u\AppData\Roaming\rclone\rclone.conf"
                    # gcloud CLI credential stores (Windows %APPDATA%\gcloud and
                    # the cross-platform ~/.config/gcloud layout)
                    "$u\AppData\Roaming\gcloud\credentials.db"
                    "$u\AppData\Roaming\gcloud\access_tokens.db"
                    "$u\AppData\Roaming\gcloud\application_default_credentials.json"
                    "$u\.config\gcloud\credentials.db"
                    "$u\.config\gcloud\application_default_credentials.json"
                )) {
                    if (Test-Path -LiteralPath $c) {
                        Add-Interesting -Category 'cloud_credential_file' -Path $c
                        Test-KnownFile -Path $c -Label 'cloud_cli'
                    }
                }
            }
    } catch {}
}

function Test-SSHKeysWindows {
    Write-Info "Stage 1.17 - SSH keys in user profiles"
    try {
        Get-ChildItem -LiteralPath (Join-Path $env:SystemDrive '\Users') -Directory -ErrorAction SilentlyContinue |
            ForEach-Object {
                $ssh = Join-Path $_.FullName '.ssh'
                if (-not (Test-Path -LiteralPath $ssh)) { return }
                Add-Checked -Label 'ssh_dir' -Path $ssh
                try {
                    Get-ChildItem -LiteralPath $ssh -Force -File -ErrorAction SilentlyContinue | ForEach-Object {
                        $name = $_.Name
                        if ($name -match '^id_[a-z0-9]+$' -or $name -match '\.(pem|key|priv)$' -or $name -eq 'identity' -or
                            $name -in 'config','authorized_keys','known_hosts') {
                            Invoke-ScanFile -FullPath $_.FullName -SourceLabel 'ssh'
                        }
                    }
                } catch {}
            }
    } catch {}
}

function Test-RDPSavedSessions {
    Write-Info "Stage 1.18 - saved RDP sessions"
    # Per-server subkeys carry a UsernameHint (the saved password itself lives
    # in Credential Manager / DPAPI). List every saved RDP target + its username
    # for manual review so none is silently dropped.
    Write-RegistrySessionReview -Root 'HKCU:\Software\Microsoft\Terminal Server Client\Servers' -Tool 'rdp'
    # Recent-server MRU list (values, not subkeys).
    $rdpDefault = 'HKCU:\Software\Microsoft\Terminal Server Client\Default'
    if (Test-Path $rdpDefault) {
        Add-Checked -Label 'rdp_registry' -Path $rdpDefault
        try {
            $p = Get-ItemProperty -LiteralPath $rdpDefault -ErrorAction SilentlyContinue
            foreach ($prop in $p.PSObject.Properties) {
                if ($prop.Name -match '^MRU' -and "$($prop.Value)" -ne '') {
                    Add-Interesting -Category 'rdp_recent_target' -Path ("rdp_mru  $($prop.Name)=$($prop.Value)")
                }
            }
        } catch {}
    }
    foreach ($d in @($env:USERPROFILE, $env:PUBLIC, "$env:SystemDrive\Users")) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        try {
            # NOTE: -LiteralPath silently ignores -Include in PowerShell. We
            # MUST filter explicitly via Where-Object to avoid returning every
            # file and directory under $d.
            # -Depth bounds traversal so a directory-junction cycle under a user
            # profile cannot hang the scan (PS 5.1 -Recurse follows junctions).
            Get-ChildItem -LiteralPath $d -Recurse -Depth 12 -Force -ErrorAction SilentlyContinue |
                Where-Object { -not $_.PSIsContainer -and $_.Extension -in '.rdp','.rdg' } |
                Select-Object -First 200 |
                ForEach-Object {
                    Add-Interesting -Category 'saved_rdp_file' -Path $_.FullName
                    Invoke-ScanFile -FullPath $_.FullName -SourceLabel 'rdp_file'
                }
        } catch {}
    }
    # RDCMan main settings file (DPAPI-encrypted creds for stored hosts)
    foreach ($f in @(
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Remote Desktop Connection Manager\RDCMan.settings')
    )) {
        if (Test-Path -LiteralPath $f) {
            Add-Interesting -Category 'rdcman_settings' -Path $f
            Invoke-ScanFile -FullPath $f -SourceLabel 'rdcman'
        }
    }
}

function Test-RemoteAccessManagers {
    Write-Info "Stage 1.19 - mRemoteNG / Devolutions / Royal TS / KiTTY / Pidgin"
    # mRemoteNG (default master key 'mR3m', AES -- flag the file)
    foreach ($f in @(
        (Join-Path $env:APPDATA 'mRemoteNG\confCons.xml')
        (Join-Path $env:APPDATA 'mRemoteNG\confCons.xml.bak')
    )) {
        if (Test-Path -LiteralPath $f) {
            Add-Interesting -Category 'mremoteng_session' -Path $f
            Invoke-ScanFile -FullPath $f -SourceLabel 'mremoteng'
        }
    }
    # Devolutions Remote Desktop Manager
    foreach ($f in @(
        (Join-Path $env:APPDATA 'Devolutions\RemoteDesktopManager\Connections.xml')
        (Join-Path $env:LOCALAPPDATA 'Devolutions\RemoteDesktopManager\Connections.xml')
    )) {
        if (Test-Path -LiteralPath $f) {
            Add-Interesting -Category 'devolutions_rdm' -Path $f
            Invoke-ScanFile -FullPath $f -SourceLabel 'devolutions_rdm'
        }
    }
    # Royal TS -- same -LiteralPath + -Include bug fix as above
    try {
        # -Depth bounds traversal so a directory-junction cycle cannot hang the
        # scan (PS 5.1 -Recurse follows junctions).
        Get-ChildItem -LiteralPath $env:APPDATA -Recurse -Depth 12 -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer -and $_.Extension -in '.rtsz','.rtsg' } |
            Select-Object -First 50 |
            ForEach-Object {
                Add-Interesting -Category 'royal_ts_session' -Path $_.FullName
                Invoke-ScanFile -FullPath $_.FullName -SourceLabel 'royal_ts'
            }
    } catch {}
    # Pidgin (cleartext accounts.xml)
    foreach ($f in @(
        (Join-Path $env:APPDATA '.purple\accounts.xml')
        (Join-Path $env:APPDATA 'Pidgin\accounts.xml')
    )) {
        if (Test-Path -LiteralPath $f) {
            Invoke-ScanFile -FullPath $f -SourceLabel 'pidgin'
        }
    }
    # KiTTY sessions (PuTTY fork with a stored Password field) are enumerated
    # in Stage 1.6 (Test-PuTTYSessions) via Write-RegistrySessionReview.
}

function Test-WiFiProfileXmls {
    Write-Info "Stage 1.20 - Wlansvc profile XML files (DPAPI-protected keys)"
    $root = Join-Path $env:ProgramData 'Microsoft\Wlansvc\Profiles\Interfaces'
    if (-not (Test-Path -LiteralPath $root)) { return }
    try {
        Get-ChildItem -LiteralPath $root -Recurse -Force -Filter '*.xml' -ErrorAction SilentlyContinue |
            ForEach-Object {
                Add-Interesting -Category 'wlansvc_profile_xml' -Path $_.FullName
            }
    } catch {}
}

function Test-AutopilotProvisioning {
    Write-Info "Stage 1.21 - Autopilot / provisioning packages"
    $root = Join-Path $env:SystemRoot 'Provisioning\Autopilot'
    if (-not (Test-Path -LiteralPath $root)) { return }
    try {
        Get-ChildItem -LiteralPath $root -Force -Filter '*.json' -ErrorAction SilentlyContinue |
            ForEach-Object { Invoke-ScanFile -FullPath $_.FullName -SourceLabel 'autopilot' }
    } catch {}
}

function Test-StickyNotes {
    Write-Info "Stage 1.22 - Sticky Notes (admins often paste creds here)"
    try {
        Get-ChildItem -LiteralPath (Join-Path $env:SystemDrive '\Users') -Directory -ErrorAction SilentlyContinue |
            ForEach-Object {
                $u = $_.FullName
                foreach ($f in @(
                    "$u\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite"
                    "$u\AppData\Roaming\Microsoft\Sticky Notes\StickyNotes.snt"
                )) {
                    if (Test-Path -LiteralPath $f) {
                        Add-Interesting -Category 'sticky_notes' -Path $f
                    }
                }
            }
    } catch {}
}

function Test-IISConfigHistory {
    Write-Info "Stage 1.23 - IIS config history (applicationHost.config backups)"
    $hist = Join-Path $env:SystemDrive 'inetpub\history'
    if (-not (Test-Path -LiteralPath $hist)) { return }
    try {
        Get-ChildItem -LiteralPath $hist -Recurse -Force `
            -Filter 'applicationHost.config' -ErrorAction SilentlyContinue |
            Select-Object -First 50 |
            ForEach-Object { Invoke-ScanFile -FullPath $_.FullName -SourceLabel 'iis_config_history' }
    } catch {}
}

function Test-FileZilla {
    Write-Info "Stage 1.24 - FileZilla saved sites"
    # FileZilla stores passwords as <Pass encoding="base64">...</Pass> (and,
    # in some builds, key files). Base64 is trivially decoded, so always list
    # the files for manual review in addition to content-scanning them.
    foreach ($f in @(
        (Join-Path $env:APPDATA 'FileZilla\sitemanager.xml')
        (Join-Path $env:APPDATA 'FileZilla\recentservers.xml')
        (Join-Path $env:APPDATA 'FileZilla\filezilla.xml')
        (Join-Path $env:APPDATA 'FileZilla\queue.xml')
    )) {
        if (Test-Path -LiteralPath $f) {
            Add-Interesting -Category 'filezilla_session' -Path $f
            Invoke-ScanFile -FullPath $f -SourceLabel 'filezilla'
        }
    }
}

function Test-OpenSSHServer {
    Write-Info "Stage 1.25 - OpenSSH server (host keys / config)"
    $sshDir = Join-Path $env:ProgramData 'ssh'
    if (-not (Test-Path -LiteralPath $sshDir)) { return }
    Add-Checked -Label 'openssh_server' -Path $sshDir
    try {
        Get-ChildItem -LiteralPath $sshDir -Force -File -ErrorAction SilentlyContinue | ForEach-Object {
            $n = $_.Name
            if ($n -like 'ssh_host_*_key' -and $n -notlike '*.pub') {
                Add-Interesting -Category 'sshd_host_key' -Path $_.FullName
                Invoke-ScanFile -FullPath $_.FullName -SourceLabel 'sshd_host_key'
            } elseif ($n -eq 'administrators_authorized_keys' -or $n -eq 'sshd_config') {
                Invoke-ScanFile -FullPath $_.FullName -SourceLabel 'openssh_server'
            }
        }
    } catch {}
}

function Test-MobaXterm {
    Write-Info "Stage 1.26 - MobaXterm sessions"
    $ini = Join-Path $env:APPDATA 'MobaXterm\MobaXterm.ini'
    if (Test-Path -LiteralPath $ini) {
        Add-Interesting -Category 'mobaxterm_ini' -Path $ini
        Invoke-ScanFile -FullPath $ini -SourceLabel 'mobaxterm'
    }
    $root = 'HKCU:\Software\Mobatek\MobaXterm'
    if (Test-Path $root) {
        $sessions = Join-Path $root 'Sessions'
        if (Test-Path $sessions) {
            Write-RegistrySessionReview -Root $sessions -Tool 'mobaxterm'
        } else {
            Add-Interesting -Category 'mobaxterm_registry' -Path $root
        }
    }
}

function Test-DBClients {
    Write-Info "Stage 1.27 - DB GUI clients (DBeaver / HeidiSQL)"
    # DBeaver: credentials-config.json (DPAPI/AES) + data-sources.json (hosts/users)
    foreach ($dbRoot in @(
        (Join-Path $env:APPDATA 'DBeaverData')
        (Join-Path $env:APPDATA 'DBeaver')
    )) {
        if (-not (Test-Path -LiteralPath $dbRoot)) { continue }
        try {
            Get-ChildItem -LiteralPath $dbRoot -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { -not $_.PSIsContainer -and ($_.Name -eq 'credentials-config.json' -or $_.Name -eq 'data-sources.json') } |
                Select-Object -First 20 |
                ForEach-Object { Add-Interesting -Category 'dbeaver_credentials' -Path $_.FullName }
        } catch {}
    }
    # HeidiSQL: stored servers (passwords are reversibly obfuscated in the registry)
    $heidi = 'HKCU:\Software\HeidiSQL\Servers'
    if (Test-Path $heidi) {
        Add-Checked -Label 'heidisql_servers' -Path $heidi
        try {
            Get-ChildItem -LiteralPath $heidi -ErrorAction SilentlyContinue |
                ForEach-Object { Add-Interesting -Category 'heidisql_server' -Path $_.PSPath }
        } catch {}
    }
}

function Test-AppServers {
    Write-Info "Stage 1.28 - app servers (Jenkins / Tomcat)"
    # Jenkins: credentials.xml + the DPAPI-independent secret keys used to decrypt it
    $jenkinsRoots = @()
    if ($env:JENKINS_HOME) { $jenkinsRoots += $env:JENKINS_HOME }
    $jenkinsRoots += (Join-Path $env:SystemDrive '\Jenkins')
    $jenkinsRoots += (Join-Path $env:ProgramData 'Jenkins\.jenkins')
    $jenkinsRoots += (Join-Path ${env:ProgramFiles} 'Jenkins')
    foreach ($jr in ($jenkinsRoots | Select-Object -Unique)) {
        if (-not $jr -or -not (Test-Path -LiteralPath $jr)) { continue }
        foreach ($rel in @('credentials.xml','secrets\master.key','secrets\hudson.util.Secret')) {
            $f = Join-Path $jr $rel
            if (Test-Path -LiteralPath $f) {
                Add-Interesting -Category 'jenkins_secret' -Path $f
                if ($rel -eq 'credentials.xml') { Invoke-ScanFile -FullPath $f -SourceLabel 'jenkins' }
            }
        }
    }
    # Tomcat: conf\tomcat-users.xml (cleartext manager creds)
    $tomcatRoots = @()
    if ($env:CATALINA_HOME) { $tomcatRoots += $env:CATALINA_HOME }
    foreach ($pf in @(${env:ProgramFiles}, ${env:ProgramFiles(x86)})) {
        if (-not $pf) { continue }
        $asf = Join-Path $pf 'Apache Software Foundation'
        if (-not (Test-Path -LiteralPath $asf)) { continue }
        try {
            Get-ChildItem -LiteralPath $asf -Directory -Filter 'Tomcat*' -ErrorAction SilentlyContinue |
                ForEach-Object { $tomcatRoots += $_.FullName }
        } catch {}
    }
    foreach ($tr in ($tomcatRoots | Select-Object -Unique)) {
        if (-not $tr) { continue }
        $tu = Join-Path $tr 'conf\tomcat-users.xml'
        if (Test-Path -LiteralPath $tu) {
            Add-Interesting -Category 'tomcat_users' -Path $tu
            Invoke-ScanFile -FullPath $tu -SourceLabel 'tomcat'
        }
    }
}

function Test-DotNetUserSecrets {
    Write-Info "Stage 1.29 - .NET user-secrets"
    $root = Join-Path $env:APPDATA 'Microsoft\UserSecrets'
    if (-not (Test-Path -LiteralPath $root)) { return }
    Add-Checked -Label 'dotnet_user_secrets' -Path $root
    try {
        Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $sf = Join-Path $_.FullName 'secrets.json'
            if (Test-Path -LiteralPath $sf) {
                Add-Interesting -Category 'dotnet_user_secrets' -Path $sf
                Invoke-ScanFile -FullPath $sf -SourceLabel 'user_secrets'
            }
        }
    } catch {}
}

function Invoke-SystemChecks {
    $script:InStage1 = $true
    Invoke-Stage1Check { Test-RegistryAutoLogon }
    Invoke-Stage1Check { Test-GPPCPassword }
    Invoke-Stage1Check { Test-UnattendedInstall }
    Invoke-Stage1Check { Test-PowerShellHistory }
    Invoke-Stage1Check { Test-CmdkeyVault }
    Invoke-Stage1Check { Test-PuTTYSessions }
    Invoke-Stage1Check { Test-WinSCPSessions }
    Invoke-Stage1Check { Test-VNCRegistry }
    Invoke-Stage1Check { Test-SNMPRegistry }
    Invoke-Stage1Check { Test-SAMHives }
    Invoke-Stage1Check { Test-IISConfigs }
    Invoke-Stage1Check { Test-ScheduledTasks }
    Invoke-Stage1Check { Test-WiFiProfiles }
    Invoke-Stage1Check { Test-McAfeeSiteList }
    Invoke-Stage1Check { Test-BrowserCredFiles }
    Invoke-Stage1Check { Test-CloudCliCredentials }
    Invoke-Stage1Check { Test-SSHKeysWindows }
    Invoke-Stage1Check { Test-RDPSavedSessions }
    Invoke-Stage1Check { Test-RemoteAccessManagers }
    Invoke-Stage1Check { Test-WiFiProfileXmls }
    Invoke-Stage1Check { Test-AutopilotProvisioning }
    Invoke-Stage1Check { Test-StickyNotes }
    Invoke-Stage1Check { Test-IISConfigHistory }
    Invoke-Stage1Check { Test-FileZilla }
    Invoke-Stage1Check { Test-OpenSSHServer }
    Invoke-Stage1Check { Test-MobaXterm }
    Invoke-Stage1Check { Test-DBClients }
    Invoke-Stage1Check { Test-AppServers }
    Invoke-Stage1Check { Test-DotNetUserSecrets }
    $script:InStage1 = $false
}

# ============================================================================
#  Recursive scanning of user-supplied paths (stages 2-5)
# ============================================================================

# Single shared tree walk for stages 2-5, with the directory-exclusion check applied.
function Get-WalkedFiles { param([string[]]$Paths)
    # Walk each -Path subtree ONCE (reparse-guarded, Test-DirectoryExcluded
    # applied) and return a List of file descriptors { Path, Name (lc), Ext (lc),
    # Size } that stages 2-5 share, instead of each stage re-walking the tree.
    # No size filtering here -- stages 2-4 never read content; Stage 5 applies the
    # size cap itself when it selects candidates. One EnumerateFileSystemInfos pass
    # yields files AND subdirectories together; the FileInfo .Length comes from the
    # directory find-data (no extra stat), so Size is populated essentially for free.
    $result = [System.Collections.Generic.List[object]]::new()
    $stack  = [System.Collections.Generic.Stack[string]]::new()
    foreach ($r in $Paths) {
        try { $abs = [System.IO.Path]::GetFullPath($r) } catch { Write-Warn "Invalid path: $r"; continue }
        if (-not (Test-Path -LiteralPath $abs)) { Write-Warn "Path does not exist: $abs"; continue }
        $it = Get-Item -LiteralPath $abs -ErrorAction SilentlyContinue
        if ($null -eq $it) {
            # Stat failed though Test-Path passed (transient I/O / odd ACL):
            # treat as a directory so it still gets walked rather than dropped.
            Write-Warn "Cannot stat path (treating as directory): $abs"; $stack.Push($abs); continue
        }
        if (-not $it.PSIsContainer) {
            # A single file passed directly as -Path.
            try {
                $fi = New-Object System.IO.FileInfo $abs
                $result.Add([PSCustomObject]@{
                    Path = $fi.FullName; Name = $fi.Name.ToLowerInvariant()
                    Ext  = $fi.Extension.ToLowerInvariant(); Size = $fi.Length })
            } catch {}
            continue
        }
        $stack.Push($abs)
    }
    $walkCount = 0
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        try {
            foreach ($info in (New-Object System.IO.DirectoryInfo $current).EnumerateFileSystemInfos()) {
                if ($info -is [System.IO.DirectoryInfo]) {
                    if (-not (Test-DirectoryExcluded -DirectoryPath $info.FullName)) { $stack.Push($info.FullName) }
                } else {
                    $result.Add([PSCustomObject]@{
                        Path = $info.FullName; Name = $info.Name.ToLowerInvariant()
                        Ext  = $info.Extension.ToLowerInvariant(); Size = $info.Length })
                    $walkCount++
                    if (-not $Quiet -and ($walkCount % 20000) -eq 0) {
                        Write-Host ("  $($script:CD)[*] enumerated $walkCount files...$($script:CNC)")
                    }
                }
            }
        } catch {}
    }
    return ,$result
}

# Stage 2 - confirmed credential containers (extension == proof)
function Find-GuaranteedCredentials { param($Files)
    foreach ($f in $Files) {
        if ($script:Stage2ExtensionsSet.Contains($f.Ext)) {
            Add-Guaranteed -Extension $f.Ext.TrimStart('.') -Path $f.Path
        }
    }
}

# Stage 3 - high-value file types (NEW SPEC)
# Three passes driven by top-of-file arrays:
#   $script:Stage3Extensions    -- extension match
#   $script:Stage3ExactNamesSet -- exact-basename match (HashSet)
#   $script:Stage3GlobPatterns  -- wildcard match (PowerShell -like)
# Files already flagged by Stage 2 are deduped via $script:GuaranteedHashes.
function Find-HighValueFiles { param($Files)
    foreach ($f in $Files) {
        # Stage 2 dedup
        if ($script:GuaranteedHashes.Contains($f.Path)) { continue }
        # SQL Server system-DB filter (always skip). SkipDbFilenames /
        # Stage3ExactNamesSet are OrdinalIgnoreCase, so the lowercased Name works.
        if ($script:SkipDbFilenames.Contains($f.Name)) { continue }

        $matched = $false
        # Pass 1: extension
        if ($script:Stage3ExtensionsSet.Contains($f.Ext)) { $matched = $true }
        # Pass 2: exact filename
        if (-not $matched -and $script:Stage3ExactNamesSet.Contains($f.Name)) { $matched = $true }
        # Pass 3: glob (e.g. krb5cc_*, *.tar.gz) -- pre-lowered patterns
        if (-not $matched) {
            foreach ($g in $script:Stage3GlobPatternsLower) {
                if ($f.Name -like $g) { $matched = $true; break }
            }
        }
        if ($matched) { Add-Interesting -Category 'high_value_file' -Path $f.Path }
    }
}

# Stage 4 - filename substring search (NEW SPEC)
# Single pass: any file whose basename contains a token from
# $script:Stage4NameTokens (case-insensitive) is emitted as a [NAME] finding.
# Binary executables, libraries, and the scanner's own script are excluded.
# The exact-filename list from earlier versions is removed -- if you need to
# detect well-known credential files at non-standard paths, add their
# identifying substring (e.g. 'rsa', 'shadow', 'history') to
# $script:Stage4NameTokens at the top of this script.
function Find-SuspiciousNames { param($Files)
    $binaryExts = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@('.dll','.exe','.sys','.ocx','.com','.scr','.drv','.cpl',
                    '.ax','.efi','.mui','.so','.dylib','.lib','.bin',
                    '.tlb','.olb','.tlh','.pdb','.ilk','.nupkg'),
        [System.StringComparer]::OrdinalIgnoreCase)
    $selfName = if ($script:SelfPath) { [System.IO.Path]::GetFileName($script:SelfPath).ToLowerInvariant() } else { '' }
    $tokens = @($script:Stage4NameTokens | ForEach-Object { $_.ToLowerInvariant() })

    foreach ($e in $Files) {
        # Dedup against Stage 2: a confirmed container (passwords.kdbx,
        # secrets.ppk, ...) is already [CRITICAL]; don't also down-tag it to a
        # mere [NAME] substring hit.
        if ($script:GuaranteedHashes.Contains($e.Path)) { continue }
        if ($selfName -and $e.Name -eq $selfName) { continue }
        if ($binaryExts.Contains($e.Ext)) { continue }
        foreach ($t in $tokens) {
            if ($e.Name.Contains($t)) { Add-SuspiciousName -Path $e.Path; break }
        }
    }
}

# Stage 5 - recursive file-content scan. Selects content-scan candidates from
# the shared walked list (no re-walk); the size cap is applied HERE since stages
# 2-4 didn't need it.
function Invoke-UserPathScan { param($Files)
    if (-not $Files -or $Files.Count -eq 0) {
        Write-Warn "No candidate files found in the supplied paths."
        return
    }
    Write-Info "Enumerating candidate files..."
    $allMode = $All.IsPresent
    # Keep the descriptor objects (not bare paths) so the size captured during the
    # walk can be threaded into Invoke-ScanFile, avoiding a second per-file stat.
    $cands = [System.Collections.Generic.List[object]]::new()
    foreach ($d in $Files) {
        $include = $false
        if ($allMode) {
            $include = $true
        } elseif ($script:Stage5ExtensionsSet.Contains($d.Ext)) {
            $include = $true
        } elseif ($script:ExtraScanNames.Contains($d.Name)) {
            $include = $true
        } elseif ($d.Name -like 'id_*' -and $d.Name -notlike '*.pub') {
            $include = $true
        } elseif ($d.Name -like '.env*' -or $d.Name -like '*rc') {
            # Parity with bash enumerate_candidates globs (-iname '.env*' / '*rc'):
            # .env.production, .env.local, arbitrary *rc dotfiles carry app secrets.
            $include = $true
        } elseif ($d.Name -like 'sitemanager.xml' -or $d.Name -like 'recentservers.xml' -or $d.Name -like 'winscp.ini') {
            $include = $true
        }
        if (-not $include) { continue }
        # .log / .logs are kept in the content scan (admins sometimes paste passwords,
        # connection strings, or tokens into custom logs) but are ALWAYS bounded by the
        # MaxFileSizeMB cap -- even under -NoSizeLimit and -All -- because verbose/rotating
        # logs are the known size-blowup vector for Stage 5. Raise -MaxFileSizeMB to scan
        # larger logs (this guard tracks $script:MaxFileSizeBytes).
        if (($d.Ext -eq '.log' -or $d.Ext -eq '.logs') -and
            ($d.Size -lt 0 -or $d.Size -gt $script:MaxFileSizeBytes)) { continue }
        # Size cap at Stage-5 selection time (Size < 0 = stat failed -> exclude).
        if ($script:SkipLarge -and ($d.Size -lt 0 -or $d.Size -gt $script:MaxFileSizeBytes)) { continue }
        $cands.Add($d)
    }
    $total = $cands.Count
    if ($total -eq 0) {
        Write-Warn "No candidate files found in the supplied paths."
        return
    }
    $mode = if ($All) { 'all' } else { 'extensions' }
    Write-Ok "Candidate files: $($script:CW)$total$($script:CNC)  (mode: $mode)"
    $i = 0
    foreach ($f in $cands) {
        $i++
        # Throttled progress. Truncate long paths so the progress bar doesn't
        # blow out terminal width with deep SQL Server / WindowsApps paths.
        if (($i % 25) -eq 0 -or $i -eq $total) {
            $cur = $f.Path
            if ($cur.Length -gt 70) { $cur = '...' + $cur.Substring($cur.Length - 67) }
            Write-Progress -Activity "Scanning files for credentials" `
                           -Status ("{0} / {1}" -f $i, $total) `
                           -CurrentOperation $cur `
                           -PercentComplete ([Math]::Min(100, ($i * 100 / $total)))
        }
        Invoke-ScanFile -FullPath $f.Path -SourceLabel 'content' -KnownSize $f.Size
    }
    Write-Progress -Activity "Scanning files for credentials" -Completed
}

# ============================================================================
#  Output / summary
# ============================================================================

function Write-FindingsSection {
    param([string]$Title, [System.Collections.Generic.List[object]]$List, [string]$Tag, [string]$Color)
    if ($List.Count -eq 0) { return }
    Write-Host ""
    Write-Host "$($script:CBold)$($script:CW)> $Title$($script:CNC)"
    Write-LogLine ""
    Write-LogLine "=== $Title ==="
    foreach ($f in $List | Sort-Object Label, Path, LineNumber) {
        Write-Host ("  $Color[$Tag]$($script:CNC) $($script:CD)$($f.Label)$($script:CNC)  $($script:CY)$($f.Path):$($f.LineNumber)$($script:CNC)")
        Write-Host ("       $($script:CD)$($f.Preview)$($script:CNC)")
        Write-LogLine ("[$Tag] $($f.Label) $($f.Path):$($f.LineNumber)  $($f.Preview)")
    }
}

function Write-FullSummary {
    Write-Section "Findings"

    try {
    if ($script:Guaranteed.Count -gt 0) {
        Write-Host ""
        Write-Host "$($script:CBold)$($script:CW)> Confirmed credential containers  !$($script:CNC)"
        Write-LogLine ""
        Write-LogLine "=== Confirmed credential containers ==="
        foreach ($g in $script:Guaranteed | Sort-Object Extension, Path) {
            Write-Host ("  $($script:CBold)$($script:CR)[CRITICAL]$($script:CNC) $($script:CD)$($g.Extension.PadRight(8))$($script:CNC)  $($script:CW)$($g.Path)$($script:CNC)")
            Write-LogLine ("[CRITICAL] $($g.Extension)  $($g.Path)")
        }
    }
    } catch { Write-Warn ("summary section error (Confirmed credential containers): " + $_.Exception.Message) }

    try { Write-FindingsSection -Title "Reusable credentials" -List $script:HighFindings -Tag "HIGH" -Color $script:CR }
    catch { Write-Warn ("summary section error (Reusable credentials): " + $_.Exception.Message) }
    try { Write-FindingsSection -Title "Private keys & authentication material" -List $script:KeyFindings -Tag "KEY" -Color $script:CM }
    catch { Write-Warn ("summary section error (Private keys): " + $_.Exception.Message) }

    try {
    if ($script:Interesting.Count -gt 0) {
        Write-Host ""
        Write-Host "$($script:CBold)$($script:CW)> Auxiliary credential-related files$($script:CNC)"
        Write-LogLine ""
        Write-LogLine "=== Auxiliary credential-related files ==="
        foreach ($i in $script:Interesting | Sort-Object Category, Path) {
            Write-Host ("  $($script:CC)[INTEREST]$($script:CNC) $($script:CD)$($i.Category)$($script:CNC)  $($i.Path)")
            Write-LogLine ("[INTEREST] $($i.Category)  $($i.Path)")
        }
    }
    } catch { Write-Warn ("summary section error (Auxiliary credential-related files): " + $_.Exception.Message) }

    try {
    if ($script:SuspiciousNamesFound.Count -gt 0) {
        Write-Host ""
        Write-Host "$($script:CBold)$($script:CW)> Suspicious filenames (substring match)$($script:CNC)"
        Write-LogLine ""
        Write-LogLine "=== Suspicious filenames (substring match) ==="
        foreach ($n in $script:SuspiciousNamesFound | Sort-Object -Unique) {
            Write-Host ("  $($script:CY)[NAME]$($script:CNC) $n")
            Write-LogLine ("[NAME] $n")
        }
    }
    } catch { Write-Warn ("summary section error (Suspicious filenames): " + $_.Exception.Message) }

    try {
    if ($script:LocationsChecked.Count -gt 0) {
        Write-Host ""
        Write-Host "$($script:CBold)$($script:CW)> OS locations checked$($script:CNC)"
        Write-LogLine ""
        Write-LogLine "=== OS locations checked ==="
        foreach ($c in $script:LocationsChecked | Sort-Object Label, Path) {
            Write-Host ("  $($script:CB)[CHECK]$($script:CNC) $($script:CD)$($c.Label)$($script:CNC)  $($c.Path)")
            Write-LogLine ("[CHECK] $($c.Label)  $($c.Path)")
        }
    }
    } catch { Write-Warn ("summary section error (OS locations checked): " + $_.Exception.Message) }

    try {
    if ($script:SkippedFiles.Count -gt 0) {
        Write-Host ""
        Write-Host "$($script:CBold)$($script:CW)> Skipped files$($script:CNC)"
        Write-Host ("  $($script:CD)[SKIP]$($script:CNC) {0} file(s) skipped (binary / size / unreadable). See log." -f $script:SkippedFiles.Count)
        Write-LogLine ""
        Write-LogLine "=== Skipped files ==="
        foreach ($s in $script:SkippedFiles) {
            Write-LogLine ("[SKIP] $($s.Reason)  $($s.Path)")
        }
    }
    } catch { Write-Warn ("summary section error (Skipped files): " + $_.Exception.Message) }

    try {
    Write-Section "Summary"
    $nGuar  = $script:Guaranteed.Count
    $nHigh  = $script:HighFindings.Count
    $nKey   = $script:KeyFindings.Count
    $nInt   = $script:Interesting.Count
    $nName  = $script:SuspiciousNamesFound.Count
    $nCheck = $script:LocationsChecked.Count
    $nSkip  = $script:SkippedFiles.Count
    $fmt = "  {0,-44} {1,5}"
    Write-Host ("$($script:CBold)" + ($fmt -f 'Category','Count') + "$($script:CNC)")
    Write-Host ('  ' + ('-' * 44) + '  ' + ('-' * 5))
    Write-Host ("$($script:CBold)$($script:CR)" + ($fmt -f 'Confirmed credential containers !',  $nGuar)  + "$($script:CNC)")
    Write-Host ("$($script:CR)" + ($fmt -f 'Reusable credentials',                 $nHigh)  + "$($script:CNC)")
    Write-Host ("$($script:CM)" + ($fmt -f 'Private keys / auth material',         $nKey)   + "$($script:CNC)")
    Write-Host ("$($script:CC)" + ($fmt -f 'Auxiliary credential-related files',   $nInt)   + "$($script:CNC)")
    Write-Host ("$($script:CY)" + ($fmt -f 'Suspicious filenames (substring)',     $nName)  + "$($script:CNC)")
    Write-Host ("$($script:CB)" + ($fmt -f 'OS locations checked',                 $nCheck) + "$($script:CNC)")
    Write-Host ("$($script:CD)" + ($fmt -f 'Files skipped (size/binary/perm)',     $nSkip)  + "$($script:CNC)")
    Write-Host ('  ' + ('-' * 44) + '  ' + ('-' * 5))

    Write-LogLine ""
    Write-LogLine "Summary:"
    Write-LogLine "  Confirmed credential containers: $nGuar"
    Write-LogLine "  Reusable credentials:            $nHigh"
    Write-LogLine "  Private keys / material:         $nKey"
    Write-LogLine "  Auxiliary credential-related:    $nInt"
    Write-LogLine "  Suspicious filenames (substring):$nName"
    Write-LogLine "  OS locations checked:            $nCheck"
    Write-LogLine "  Files skipped:                   $nSkip"
    } catch { Write-Warn ("summary section error (Summary table): " + $_.Exception.Message) }

    if ($script:LogPath) {
        Write-Host ""
        Write-Host "$($script:CB)[*]$($script:CNC) Full log written to $($script:CW)$($script:LogPath)$($script:CNC)"
    }
}

# ============================================================================
#  Entry point
# ============================================================================

function Invoke-Main {
    $script:LogPath = $null
    if ($OutputFile) {
        try {
            New-Item -ItemType File -Path $OutputFile -Force | Out-Null
            $script:LogPath = (Resolve-Path -LiteralPath $OutputFile).Path
            # The log holds extracted plaintext credential previews. Restrict its
            # ACL to the current user only (break inheritance) so harvested
            # secrets are not readable by other local accounts. Best-effort:
            # silently skip on filesystems that do not support ACLs.
            try {
                $me  = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                $acl = Get-Acl -LiteralPath $script:LogPath
                $acl.SetAccessRuleProtection($true, $false)   # break inheritance, drop inherited ACEs
                $acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }
                $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $me, 'FullControl', 'Allow')))
                Set-Acl -LiteralPath $script:LogPath -AclObject $acl
            } catch {}
        } catch {
            Write-Err "Cannot write to $OutputFile : $_"
            exit 2
        }
    }

    Write-Banner

    if ($script:SkipLarge) {
        Write-Info ("Size cap: skipping files larger than $($script:CW){0} MB$($script:CNC)  (use -MaxFileSizeMB N or -NoSizeLimit)" -f $MaxFileSizeMB)
    } else {
        Write-Warn "Size cap disabled (-NoSizeLimit) - every readable file will be inspected."
    }

    if ($script:UserExcludePaths.Count -gt 0) {
        Write-Info ("User exclusions ($($script:CW){0}$($script:CNC)) - applied to stages 2-5 only:" -f $script:UserExcludePaths.Count)
        foreach ($p in $script:UserExcludePaths) {
            Write-Host ("       $($script:CD)- {0}$($script:CNC)" -f $p)
        }
    }

    # Run all stages inside try/finally so the consolidated summary ALWAYS prints
    # even if a stage throws -- the exception still propagates to the outer catch
    # ("Fatal:" + exit 2) afterwards. If nothing throws, behaviour is unchanged.
    try {
    if (-not $script:Stage1Skip) {
        Begin-Stage 1
        Invoke-SystemChecks
        End-Stage 1 "OS-level credential checks"
    } else {
        Stage-Skipped 1 "OS-level credential checks"
    }

    if ($Path.Count -eq 0) {
        Write-Warn "No -Path supplied. Skipping stages 2-5."
        Write-Warn "Tip: pass -Path C:\ to scan everywhere."
    } else {
        # Walk the -Path tree ONCE and share the file list across stages 2-5
        # (unless every one of them is skipped). Each stage keeps its own
        # predicate; only the enumeration is de-duplicated.
        $walked = $null
        if (-not ($script:Stage2Skip -and $script:Stage3Skip -and $script:Stage4Skip -and $script:Stage5Skip)) {
            $walked = Get-WalkedFiles -Paths $Path
        }
        if (-not $script:Stage2Skip) {
            Begin-Stage 2; Find-GuaranteedCredentials -Files $walked; End-Stage 2 "Confirmed credential containers"
        } else {
            Stage-Skipped 2 "Confirmed credential containers"
        }
        if (-not $script:Stage3Skip) {
            Begin-Stage 3; Find-HighValueFiles -Files $walked; End-Stage 3 "High-value file types"
        } else {
            Stage-Skipped 3 "High-value file types"
        }
        if (-not $script:Stage4Skip) {
            Begin-Stage 4; Find-SuspiciousNames -Files $walked; End-Stage 4 "Filename substring search"
        } else {
            Stage-Skipped 4 "Filename substring search"
        }
        if (-not $script:Stage5Skip) {
            Begin-Stage 5; Invoke-UserPathScan -Files $walked; End-Stage 5 "Recursive content scan"
        } else {
            Stage-Skipped 5 "Recursive content scan"
        }
    }
    } finally {
        Write-FullSummary
    }

    if ($script:Guaranteed.Count -gt 0 -or
        $script:HighFindings.Count -gt 0 -or
        $script:KeyFindings.Count -gt 0) {
        exit 1
    } else {
        exit 0
    }
}

# Ctrl+C / pipeline-stop exits cleanly with 130.
try {
    Invoke-Main
} catch [System.Management.Automation.PipelineStoppedException] {
    try { Write-Progress -Activity '*' -Completed } catch {}
    Write-Host ""
    Write-Warn "Interrupted by user. Exiting."
    exit 130
} catch {
    try { Write-Progress -Activity '*' -Completed } catch {}
    if ($_.Exception.GetType().FullName -match 'Stopped|Cancel|Interrupt') {
        Write-Host ""
        Write-Warn "Interrupted by user. Exiting."
        exit 130
    }
    Write-Err ("Fatal: " + $_.Exception.Message)
    exit 2
}
