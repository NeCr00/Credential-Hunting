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

if ($Help) {
    if ($PSCommandPath) { Get-Help $PSCommandPath -Full } else { Get-Help $MyInvocation.MyCommand.Path -Full }
    exit 0
}

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'Continue'
$script:Version        = '2.0.0'

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
$script:UseColor = -not $NoColor `
    -and -not $env:NO_COLOR `
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
$script:CredFiles        = [System.Collections.Generic.List[string]]::new()
$script:CredFileHashes   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
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
       Regex = '(?im)(^|[^A-Za-z_])(password|passwd|passphrase)\s*[:=]\s*["'']?[^\s"#$<>{}]{3,}' }

    # ---- DB / service-prefixed passwords ------------------------------------
    @{ Label = 'db_password';
       Regex = '(?im)(db|database|mysql|psql|pg|postgres|mongo|mssql|sql|oracle|redis|memcache|ldap|smtp|smb|ftp|sftp|imap|pop3|admin|user|service|svc|jenkins|jboss|tomcat|nexus|gitlab|jira|svn|backup|root|wp|wordpress|joomla|drupal|magento|laravel|django|proxy|vpn|cifs)[_-]?(password|passwd|passphrase|pwd|pass)\s*[:=]\s*["'']?[^\s"#$<>{}]{3,}' }

    # ---- Connection-string passwords (.NET / JDBC / ODBC) -------------------
    @{ Label = 'connection_string';
       Regex = '(?im)(server|host|data\s*source)\s*=.{1,200}(password|pwd)\s*=\s*["'']?[^;&\s"]{3,}' }
    @{ Label = 'jdbc_url';
       Regex = '(?i)jdbc:[a-z]+://[^\s"]*[?&;]password=[^;&\s"]{3,}' }

    # ---- URL-embedded credentials ------------------------------------------
    @{ Label = 'url_credentials';
       Regex = '(?i)(mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|rabbitmq|ftp|ftps|sftp|ssh|smb|cifs|ldap[s]?|imap[s]?|smtp[s]?|https?)://[^\s/:@]+:[^\s/@]{2,}@' }

    # ---- Windows-specific high-value ---------------------------------------
    @{ Label = 'gpp_cpassword';
       Regex = '(?i)cpassword\s*=\s*"([A-Za-z0-9+/=]{20,})"' }
    @{ Label = 'unattend_password';
       Regex = '(?is)<(?:Administrator)?Password>\s*<Value>([^<]{2,})</Value>' }
    @{ Label = 'autologon_password';
       Regex = '(?i)(DefaultPassword|AltDefaultPassword)\s*[:=]\s*["'']?[^\s"#]{2,}' }

    # ---- Environment-variable credentials ----------------------------------
    @{ Label = 'env_password';
       Regex = '(?im)(^|\s)(set\s+|export\s+|setx\s+)?[A-Z][A-Z0-9_]*(PASSWORD|PASSWD|PASSPHRASE)[A-Z0-9_]*\s*=\s*["'']?[^\s"$<>]{3,}' }
    @{ Label = 'pgpassword_env';
       Regex = '(?im)\bPGPASSWORD\s*=\s*["'']?[^\s"#]{3,}' }
    @{ Label = 'mysql_pwd_env';
       Regex = '(?im)\bMYSQL_PWD\s*=\s*["'']?[^\s"#]{3,}' }

    # ---- Shell-history / command-line credentials --------------------------
    @{ Label = 'sshpass_cmd';
       Regex = '(?i)sshpass\s+(-p|--password)\s*["'']?[^\s''"]{2,}' }
    @{ Label = 'mysql_cmd';
       Regex = '(?i)(mysql|mysqladmin|mysqldump|mysqlimport)\s.*\s-p[^\s"#-][^\s"#]{2,}' }
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
       Regex = '(?i)mount\s+(-t\s+cifs|//\S+)\s+.*-o\s.*\b(pass|password)=[^,\s"]{3,}' }
    @{ Label = 'freerdp_pass';
       Regex = '(?i)(xfreerdp|freerdp|rdesktop|mstsc)\s.*(-p|/p:)\s?["'']?[^\s"]{2,}' }
    @{ Label = 'plink_pass';
       Regex = '(?i)plink(\.exe)?\s.*-pw\s+["'']?[^\s''"]{2,}' }
    @{ Label = 'net_use_pass';
       Regex = '(?i)net\s+use\s+\\\\\S+\s+\S+\s+/user:\S+' }
    # `net user john.doe "MySecurePassword" /domain` — the classic Windows
    # admin-paste-into-script pattern (HTB writeups, real engagements).
    @{ Label = 'net_user_create';
       Regex = '(?i)net\s+user\s+\S+\s+["'']?[^\s"'']{3,}["'']?\s+(/add|/domain|/passwordreq|/active|/expires)' }
    # PowerShell local-user / AD password cmdlets — common in deploy scripts
    @{ Label = 'ps_localuser_pass';
       Regex = '(?i)(New-LocalUser|Add-LocalUser|Set-LocalUser)\s.*-(Password|AccountPassword)\s+["''][^"'']{3,}["'']' }
    @{ Label = 'ps_ad_password';
       Regex = '(?i)(Set-ADAccountPassword|New-ADUser)\s.*-(AccountPassword|NewPassword)\s' }
    @{ Label = 'ps_secstring_plain';
       Regex = '(?i)ConvertTo-SecureString\s+["''][^"'']{3,}["'']\s+-AsPlainText\s+-Force' }
    @{ Label = 'net_user_create';
       Regex = '(?i)net\s+user\s+\S+\s+["'']?[^\s"'']{3,}["'']?\s+(/add|/domain|/passwordreq|/active|/expires)' }
    # Linux user-creation in shell scripts (HTB / OSCP staples)
    @{ Label = 'useradd_pass';
       Regex = '(?i)useradd\s.*-p\s+["'']?[^\s"'']{3,}' }
    @{ Label = 'chpasswd_inline';
       Regex = '(?i)(echo|printf)\s+["'']?[^:\s]+:[^\s"'']{3,}["'']?\s*\|\s*chpasswd' }
    @{ Label = 'chpasswd_heredoc';
       Regex = '(?i)chpasswd\s*<<<?\s*["'']?[^:\s]+:[^\s"'']{3,}' }
    @{ Label = 'passwd_stdin';
       Regex = '(?i)(echo|printf)\s+["''][^"'']{3,}["'']\s*\|\s*passwd\s+\S+(\s+--stdin)?' }
    @{ Label = 'ldap_pass';
       Regex = '(?i)(ldapsearch|ldapadd|ldapmodify|ldapdelete|ldapcompare)\s.*-w\s+["'']?[^\s''"]{2,}' }
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
    @{ Label = 'pssecure_plain';
       Regex = '(?i)ConvertTo-SecureString\s+["''][^''"]+["'']\s+-AsPlainText' }

    # ---- Web framework specifics -------------------------------------------
    @{ Label = 'wp_db_password';
       Regex = "(?i)define\(\s*['""]DB_PASSWORD['""]\s*,\s*['""][^'""]{2,}" }
    @{ Label = 'joomla_password';
       Regex = '(?i)public\s+\$(password|smtppass|dbpass|secret)\s*=\s*[''"][^''"]{2,}' }
    @{ Label = 'drupal_password';
       Regex = "(?i)['""]password['""][ \t]*=>\s*['""][^'""]{4,}" }

    # ---- Linux auth files (likely on cross-mounted drives) -----------------
    @{ Label = 'htpasswd_hash';
       Regex = '(?m)^[^:\s#]+:\$(apr1|2[aby]?|5|6|y)\$' }
    @{ Label = 'netrc_password';
       Regex = '(?im)^\s*(machine\s+\S+\s+)?(login|user|username)\s+\S+\s+password\s+\S{2,}' }
    @{ Label = 'samba_password';
       Regex = '(?im)^\s*(passwd|password|smb\s+passwd)\s*=\s*\S{3,}' }

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

# Labels for which we skip the value-based FP check (the entire match IS
# the finding - hash dumps, key markers, etc.)
$script:NoFPCheck = @(
    'ntlm_dump','ntds_dump','gpp_cpassword',
    'htpasswd_hash','shadow_md5','shadow_sha256','shadow_sha512',
    'shadow_yescrypt','shadow_bcrypt','shadow_argon2',
    'krb5_tgs','krb5_asrep','mscash_v1','mscash_v2',
    # Format-anchored patterns where the matched line IS the credential
    'unattend_password','autologon_password',
    'netrc_password','sudoers_nopasswd','samba_password',
    'wp_db_password','joomla_password','drupal_password',
    'redis_requirepass','anaconda_rootpw'
)

# Fast keyword pre-filter. Run as a single compiled-regex IsMatch() against
# the whole file content before the expensive per-pattern pass. If the file
# contains NONE of these anchor keywords, no credential pattern can fire
# (except KEY patterns, which we always check). This single-pass filter
# eliminates 80-95% of files instantly and is the single biggest perf win
# on large trees with lots of license/doc/boilerplate text files.
$script:KeywordPrefilter = [regex]::new(
    '(?i)password|passwd|passphrase|pwd|cpassword|sshpass|kerberos|krb5(tgs|asrep)|\$DCC2\$|\$apr1\$|\$1\$[A-Za-z0-9./]{8}\$|\$2[aby]?\$|\$5\$[A-Za-z0-9./]{1,16}\$|\$6\$[A-Za-z0-9./]{1,16}\$|\$y\$|\$argon2|mongodb://|mysql://|postgres(?:ql)?://|redis://|jdbc:|PGPASSWORD|MYSQL_PWD|\bsudoers\b|NOPASSWD|wp-config|configuration\.php|appsettings\.json|web\.config|tomcat-users|cmdkey|runas\s+/|psexec|smbclient\s|net\s+use\s|wmic\s|/p:|/pass:|/password:',
    [System.Text.RegularExpressions.RegexOptions]::Compiled)

# ============================================================================
#  False-positive filter
# ============================================================================

$script:FalsePositives = @(
    '','password','passwd','pwd','pass','passphrase','secret','token',
    'null','none','nil','undefined','empty','void','true','false',
    'example','sample','demo','placeholder','dummy','fake','stub','mock','lorem','ipsum',
    'test','tester','testing','testpassword','testpass','test123','testing123',
    'foo','bar','baz','qux','foobar','barbaz',
    'abc','123','abc123','12345','123456','1234567','12345678','123456789',
    'qwerty','letmein','iloveyou','monkey','dragon','hunter2','correct horse',
    'p@ssw0rd','password123','password1','admin1','admin123',
    'changeme','change_me','change-me','changethis','change-this','changeit','change-it',
    'todo','fixme','tbd','n/a','na',
    'your_password','yourpassword','your-password','yourpasswordhere','yourpwd',
    'insert_password','replace_me','replace-me','replace_this','insert_here',
    '<password>','<pass>','<secret>','<token>','<key>','<value>','<your-password>',
    '<input>','<enter>','<here>','<...>',
    '...','....','.....','********','*****','***','xxxxxxxx','xxxxx','xxx',
    'redacted','hidden','masked','sanitized',
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
    # Trailing marker words — values that self-label as placeholders
    if ($lower -match '(placeholder|placeholders)$')                          { return $true }
    if ($lower -match '_(example|sample|dummy|mock|stub|fake|demo)$')         { return $true }

    # Template / interpolation markers
    if ($v -match '\$\{[^}]+\}')                  { return $true }
    if ($v -match '\$\([^)]+\)')                  { return $true }
    if ($v -match '\{\{[^}]+\}\}')                { return $true }
    if ($v -match '<%.*?%>')                      { return $true }
    if ($v -match '#\{[^}]+\}')                   { return $true }
    if ($v -match '<[A-Za-z_][^>]*>')             { return $true }
    if ($v -match '%[A-Z_]+%')                    { return $true }
    if ($v -match '\$\d+|\$\$')                   { return $true }

    # Programming-language references that look like passwords but aren't.
    # Catches Python `self.password`, Java `this.password`, PowerShell var
    # references `$cred.GetNetworkCredential().Password`, PHP `$_POST['password']`.
    if ($v -match '^(self|this|cls|@self)\.\w+')                    { return $true }
    if ($v -match '^\$_(POST|GET|REQUEST|SERVER|ENV|SESSION|COOKIE)\[') { return $true }
    if ($v -match '^\$[A-Za-z_]\w*(\.\w+)+$')                       { return $true }

    # Already-encrypted / vaulted markers — secret is protected at rest.
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
    'credential','secret','pass','password','passwd','account','login'
)

# -- Stage 5 -- content-scan extension allow-list ----------------------------
# Recursive credential-pattern scan runs ONLY on files with one of these
# extensions (unless -All is passed).
$script:Stage5Extensions = @(
    '.conf','.config','.cfg','.cnf','.ini','.env','.envrc'
    '.yaml','.yml','.toml','.json','.jsonc','.json5'
    '.xml','.plist'
    '.properties','.prop','.props','.settings'
    '.tf','.tfvars','.tfstate','.hcl'
    '.sh','.bash','.zsh','.ksh','.csh','.fish'
    '.ps1','.psm1','.psd1','.ps1xml'
    '.bat','.cmd','.vbs','.vbe','.wsh','.wsf','.ahk'
    '.py','.pl','.rb','.php','.phtml','.php3','.php5'
    '.lua','.groovy','.tcl','.coffee'
    '.java','.cs','.vb','.go','.rs','.c','.cpp','.h','.hpp'
    '.js','.ts','.jsx','.tsx','.mjs','.cjs'
    '.aspx','.asp','.ashx','.asmx','.asax','.ascx','.cshtml','.vbhtml','.master','.svc'
    '.jsp','.jspx','.jspf','.cfm','.cfc'
    '.htm','.html','.htaccess'
    '.sql','.ddl','.dump','.dsn','.udl','.ora','.tns'
    '.reg','.pol','.rdp','.rdg','.rdcman','.inf','.unattend','.answerfile'
    '.ovpn','.openvpn','.vnc','.rdc','.tcc','.ica','.session','.kix'
    '.txt','.text','.md','.markdown','.rtf','.nfo','.log','.logs','.readme'
    '.bak','.backup','.old','.orig','.original','.save','.saved','.tmp','.temp','.cache'
    '.csv','.tsv','.ldif','.ldiff'
    '.service','.unit','.timer','.socket','.crontab','.cron'
    '.local','.shared','.template','.example','.sample','.dist'
)
$script:Stage5ExtensionsSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]$script:Stage5Extensions, [System.StringComparer]::OrdinalIgnoreCase)

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
        'Makefile','GNUmakefile','CMakeLists.txt','meson.build'
        'build.gradle','gradle.properties','pom.xml'
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
    '.git','.hg','.svn','.bzr','CVS','_darcs'
    'node_modules','.npm','.pnpm-store','.yarn','.yarn-cache','.bun'
    '.venv','venv','env','.pyenv','.virtualenvs','__pycache__'
    '.mypy_cache','.pytest_cache','.tox','.nox','.ruff_cache'
    'site-packages','dist-packages','vendor','bower_components'
    '.terraform','.terragrunt-cache','.gradle','.m2','.ivy2','.sbt'
    'target','dist','build','out','coverage','.next','.nuxt','obj'
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
# this list — excluding $env:SystemRoot does NOT prevent Sysprep / GPP /
# SAM / AutoLogon / IIS / Scheduled Tasks checks from working. It just
# keeps the stage-5 recursive scanner from burning cycles on the 100k+
# system files under C:\Windows that never carry credentials.
$script:ExcludePathPrefixes = @(
    # Entire C:\Windows tree — system DLLs, drivers, components, fonts.
    $env:SystemRoot
    # AppX / MSIX package store
    (Join-Path ${env:ProgramFiles} 'WindowsApps')
    (Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps')
    (Join-Path $env:LOCALAPPDATA 'Packages')
    # Recycle / restore / perf data
    "$env:SystemDrive\`$Recycle.Bin"
    "$env:SystemDrive\System Volume Information"
    "$env:SystemDrive\PerfLogs"
    # ── Microsoft SQL Server install trees (binaries + system DBs + install
    #    scripts + setup logs). User databases live in custom dirs like
    #    D:\Data, not under Program Files. Skipping the product dir cuts
    #    huge noise from instmsdb.sql / msdb110_upgrade.sql / Setup Bootstrap
    #    logs which contain SQL-parameter-reference noise.
    (Join-Path ${env:ProgramFiles} 'Microsoft SQL Server')
    (Join-Path ${env:ProgramFiles(x86)} 'Microsoft SQL Server')
    # ── ProgramData noise (Windows update cache, identity CRL, breadcrumbs)
    (Join-Path $env:ProgramData 'Microsoft\Windows\Caches')
    (Join-Path $env:ProgramData 'USOPrivate')
    (Join-Path $env:ProgramData 'USOShared')
    (Join-Path $env:ProgramData 'Microsoft\IdentityCRL')
    (Join-Path $env:ProgramData 'Microsoft\Device Stage')
    (Join-Path $env:ProgramData 'Microsoft\NetFramework\BreadcrumbStore')
    (Join-Path $env:ProgramData 'Microsoft\EdgeUpdate\Log')
) | Where-Object { $_ -and $_.Trim() -ne '' }

# Path-substring exclusions — used when the noisy directory lives at a
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
        [int]   $LineNumber = 0
    )
    if ($Quiet) { return }
    switch ($Tier) {
        'Critical' { $color = $script:CR; $tag = 'CRITICAL' }
        'High'     { $color = $script:CR; $tag = 'HIGH' }
        'Key'      { $color = $script:CM; $tag = 'KEY' }
        'Interest' { $color = $script:CY; $tag = 'INTEREST' }
        'CredFile' { $color = $script:CY; $tag = 'CRED_FILE' }
        'Name'     { $color = $script:CY; $tag = 'NAME' }
        default    { $color = $script:CR; $tag = $Tier.ToUpper() }
    }
    if ($LineNumber -gt 0) {
        Write-Host ("{0}   └─ [{1}]{2} {3} → {4}:{5}" -f $color, $tag, $script:CNC, $Label, $Path, $LineNumber)
    } else {
        Write-Host ("{0}   └─ [{1}]{2} {3} → {4}" -f $color, $tag, $script:CNC, $Label, $Path)
    }
    $script:SubstageFindings++
}

# Wrapper: run a Stage-1 substage and print a tidy "nothing here" line if
# the substage produced zero findings. Keeps every Test-* function
# untouched — they only need to call Add-Finding / Add-Interesting / etc.
function Invoke-Stage1Check {
    param([scriptblock]$Block)
    $script:SubstageFindings = 0
    & $Block
    if ($script:SubstageFindings -eq 0 -and -not $Quiet) {
        Write-Host ("{0}   └─ no credentials found in this category{1}" -f $script:CD, $script:CNC)
    }
}

function Write-LogLine { param([string]$Line)
    if ([string]::IsNullOrEmpty($script:LogPath)) { return }
    $clean = $Line -replace "`e\[[0-9;]*m", ''
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
        Cred       = $script:CredFiles.Count
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
    $dCred = $script:CredFiles.Count            - $before.Cred
    $dName = $script:SuspiciousNamesFound.Count - $before.Name
    $total = $dGuar + $dHigh + $dKey + $dInt + $dCred + $dName

    Write-Host ""
    Write-Host "$($script:CC)======================================================================$($script:CNC)"
    Write-Host "$($script:CBold)  Stage $N - $Title$($script:CNC)"
    Write-Host "$($script:CC)----------------------------------------------------------------------$($script:CNC)"
    Write-Host ("  Found: $($script:CW)$($script:CBold){0}$($script:CNC) file(s)   ({1:N2}s)" -f $total, $elapsed)

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
            }
        }
        if ($dKey -gt 0) {
            $script:KeyFindings | Select-Object -Last $dKey | ForEach-Object {
                Write-Host ("  [{0,-9}]  {1}" -f 'KEY', $_.Path)
            }
        }
        if ($dInt -gt 0) {
            $script:Interesting | Select-Object -Last $dInt | ForEach-Object {
                Write-Host ("  [{0,-9}]  {1}" -f 'INTEREST', $_.Path)
            }
        }
        if ($dCred -gt 0) {
            $script:CredFiles | Select-Object -Last $dCred | ForEach-Object {
                Write-Host ("  [{0,-9}]  {1}" -f 'CRED_FILE', $_)
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
    Write-Host "$($script:CBold)  Stage $N - $Title  [SKIPPED]$($script:CNC)"
    Write-Host "$($script:CC)======================================================================$($script:CNC)"
}

# ============================================================================
#  Helper functions
# ============================================================================

function Get-FileSizeSafe { param([string]$FullPath)
    try { return (New-Object System.IO.FileInfo $FullPath).Length } catch { return -1 }
}

# Cap at first 4 KB; treat empty as binary (nothing to scan).
function Test-IsBinary { param([string]$FullPath)
    try {
        $fs = [System.IO.File]::OpenRead($FullPath)
        try {
            $buf = New-Object byte[] 4096
            $read = $fs.Read($buf, 0, $buf.Length)
            if ($read -le 0) { return $true }
            for ($i = 0; $i -lt $read; $i++) {
                if ($buf[$i] -eq 0) { return $true }
            }
            return $false
        } finally { $fs.Dispose() }
    } catch { return $true }
}

function Test-DirectoryExcluded { param([string]$DirectoryPath)
    try {
        $dname = [System.IO.Path]::GetFileName($DirectoryPath)
        if ($script:ExcludeDirSet.Contains($dname)) { return $true }
        foreach ($prefix in $script:ExcludePathPrefixes) {
            if (-not $prefix) { continue }
            if ($DirectoryPath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
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
        Write-Stage1Finding -Tier $Bucket -Label $Label -Path $Path -LineNumber $LineNumber
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
function Add-CredFile { param([string]$Path)
    if ($script:CredFileHashes.Add($Path)) {
        $script:CredFiles.Add($Path) | Out-Null
        if ($script:InStage1) {
            Write-Stage1Finding -Tier 'CredFile' -Label 'exact_name' -Path $Path
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
#   5. Skip pathologically long lines (>2 KB) -- they're minified JS,
#      base64 blobs, or log rotations, never credential assignments.
function Invoke-ScanFile { param([string]$FullPath, [string]$SourceLabel = 'content')
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
    # Pattern-based skips: minified / bundled / translation / source maps
    if ($bn -match '\.(min|bundle)\.(js|css)$') {
        Add-Skipped -Path $FullPath -Reason 'minified asset'; return
    }
    if ($bn -match '\.(po|pot|mo)$')  { Add-Skipped -Path $FullPath -Reason 'gettext translation'; return }
    if ($bn -match '\.map$')          { Add-Skipped -Path $FullPath -Reason 'source map'; return }
    # .env templates are placeholders by definition — flagged by stage 4 but
    # we skip their content to avoid <YOUR_PASSWORD>-style false positives.
    if ($bn -match '\.env\.(example|sample|template|dist)$') { Add-Skipped -Path $FullPath -Reason 'env template'; return }

    $size = Get-FileSizeSafe -FullPath $FullPath
    if ($size -lt 0) { Add-Skipped -Path $FullPath -Reason 'unreadable'; return }
    if ($size -eq 0) { return }
    if ($script:SkipLarge -and $size -gt $script:MaxFileSizeBytes) {
        Add-Skipped -Path $FullPath -Reason ("size>{0}MB" -f $MaxFileSizeMB); return
    }
    if (Test-IsBinary -FullPath $FullPath) {
        Add-Skipped -Path $FullPath -Reason 'binary'; return
    }
    try { $content = [System.IO.File]::ReadAllText($FullPath) }
    catch { Add-Skipped -Path $FullPath -Reason 'read_error'; return }
    if ([string]::IsNullOrEmpty($content)) { return }

    # ---- Always-on: private-key markers (very fast, format-anchored) --------
    foreach ($p in $script:KeyPatterns) {
        $m = $p.Regex.Match($content)
        if ($m.Success) {
            $lineNo = Get-LineNumber -Content $content -Index $m.Index
            Add-Finding -Bucket Key -Label $p.Label -Path $FullPath -LineNumber $lineNo -Preview $m.Value
        }
    }

    # ---- Pre-filter: if no anchor keyword, skip the expensive pass ----------
    if (-not $script:KeywordPrefilter.IsMatch($content)) { return }

    # ---- Line-by-line credential-pattern scan -------------------------------
    $matchesFound = 0
    $lines = $content -split "`r?`n"
    for ($i = 0; $i -lt $lines.Length; $i++) {
        if ($matchesFound -ge $script:MaxMatchesPerFile) { break }
        $line = $lines[$i]
        $llen = $line.Length
        if ($llen -lt 6 -or $llen -gt 2048) { continue }

        # Cheap per-line keyword check (regex IsMatch on a short string is fast)
        if (-not $script:KeywordPrefilter.IsMatch($line)) { continue }

        foreach ($p in $script:CredPatterns) {
            $m = $p.Regex.Match($line)
            if (-not $m.Success) { continue }

            # ── Smarter value extraction ──────────────────────────────────
            # The OLD code grabbed the substring after the FIRST `:` or `=` on
            # the line. That misfires on timestamps ("03:39:54 SVCPASSWORD:
            # source = Default") where the first `:` is the clock, not the
            # password operator. Find the password-keyword position first,
            # then take whatever immediately follows ITS operator.
            $value = $line
            $kwMatch = [regex]::Match($line,
                '(?i)(?:password|passwd|passphrase|pwd|cpassword|requirepass|rootpw|cred(?:ential)?s?|secret)\s*[:=]?\s*',
                [System.Text.RegularExpressions.RegexOptions]::None)
            if ($kwMatch.Success) {
                $value = $line.Substring($kwMatch.Index + $kwMatch.Length)
                $value = $value.Trim().Trim('"', "'", ' ', ';')
                $value = ($value -split '[#;]')[0]
                # Cut at the next `, ` or `->` boundary — common log noise
                # like "key = value, message = ..." would otherwise capture
                # the whole tail.
                $value = ($value -split ',\s+|\s+->\s+|\s+message\s*=', 2)[0]
            }

            # ── Hard-coded line-level FP filter (real-host noise) ─────────
            # SQL parameter references / masked passwords / SQL Telemetry
            # logs / Microsoft's published Yukon90_ certificate-signing pw.
            if ($line -match '@password\s*=\s*(@password|N''''|NULL|@\w+\b)') { continue }
            if ($line -match 'WITH\s+PASSWORD\s*=\s*''Yukon90_''')           { continue }
            if ($line -match 'PASSWORD\s*=\s*''\*+''')                       { continue }
            if ($line -match 'SQLTelemetry\s*:\s*Setting')                   { continue }
            if ($line -match 'SafeSqlCommand.*PASSWORD\s*=\s*''\*+''')       { continue }

            if (-not ($script:NoFPCheck -contains $p.Label)) {
                if (Test-FalsePositive -Value $value) { continue }
            }

            Add-Finding -Bucket High -Label "$SourceLabel/$($p.Label)" `
                -Path $FullPath -LineNumber ($i + 1) -Preview (Format-Preview $line)
            $matchesFound++
            break    # one classification per line is enough
        }
    }
}

function Test-KnownFile { param([string]$Path, [string]$Label)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Add-Checked -Label $Label -Path $Path
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    Invoke-ScanFile -FullPath $Path -SourceLabel $Label
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
                    if ($c -match 'cpassword\s*=\s*"([A-Za-z0-9+/=]{16,})"') {
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
    Write-Info "Stage 1.6 - PuTTY saved sessions"
    $root = 'HKCU:\Software\SimonTatham\PuTTY\Sessions'
    if (-not (Test-Path $root)) { return }
    Add-Checked -Label 'putty_sessions' -Path $root
    try {
        Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            $entries = @()
            foreach ($prop in 'HostName','UserName','PortForwardings','ProxyHost','ProxyUsername','ProxyPassword','PublicKeyFile') {
                if ($p.$prop) { $entries += "$prop=$($p.$prop)" }
            }
            if ($p.ProxyPassword -and -not (Test-FalsePositive -Value $p.ProxyPassword)) {
                Add-Finding -Bucket High -Label 'putty/proxy_password' -Path $_.PSPath -LineNumber 0 -Preview "ProxyPassword=$($p.ProxyPassword)"
            }
            if ($entries) {
                Add-Interesting -Category 'putty_session' -Path $_.PSPath
            }
        }
    } catch {}
}

function Test-WinSCPSessions {
    Write-Info "Stage 1.7 - WinSCP saved sessions"
    $root = 'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions'
    if (Test-Path $root) {
        Add-Checked -Label 'winscp_sessions' -Path $root
        try {
            Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {
                $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                if ($p.Password) {
                    Add-Finding -Bucket High -Label 'winscp/saved_password' -Path $_.PSPath -LineNumber 0 -Preview "WinSCP saved password ($($p.HostName) / $($p.UserName))"
                }
            }
        } catch {}
    }
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
    Write-Info "Stage 1.8 - VNC registry"
    $keys = @(
        'HKLM:\SOFTWARE\TightVNC\Server'
        'HKLM:\SOFTWARE\WOW6432Node\TightVNC\Server'
        'HKLM:\SOFTWARE\RealVNC\WinVNC4'
        'HKLM:\SOFTWARE\WOW6432Node\RealVNC\WinVNC4'
        'HKCU:\Software\TightVNC\Server'
        'HKCU:\Software\ORL\WinVNC3'
        'HKCU:\Software\RealVNC\WinVNC4'
    )
    foreach ($k in $keys) {
        if (Test-Path $k) {
            Add-Checked -Label 'vnc_registry' -Path $k
            try {
                $p = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
                foreach ($prop in 'Password','PasswordViewOnly','ControlPassword') {
                    if ($p.$prop) {
                        $val = if ($p.$prop -is [byte[]]) { [BitConverter]::ToString($p.$prop) } else { "$($p.$prop)" }
                        Add-Finding -Bucket High -Label 'vnc/password' -Path $k -LineNumber 0 -Preview ("{0} = {1}" -f $prop, $val)
                    }
                }
            } catch {}
        }
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
    $inetpub = Join-Path $env:SystemDrive '\inetpub'
    if (Test-Path -LiteralPath $inetpub) {
        try {
            Get-ChildItem -LiteralPath $inetpub -Recurse -Force -Filter 'web.config' -ErrorAction SilentlyContinue |
                Select-Object -First 200 |
                ForEach-Object { Test-KnownFile -Path $_.FullName -Label 'iis_webconfig' }
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
    try {
        $profilesOut = & netsh.exe wlan show profiles 2>$null
        if ($profilesOut) {
            $names = @()
            foreach ($l in $profilesOut) {
                if ($l -match 'All User Profile\s*:\s*(.+)$' -or $l -match 'Profile\s+\(.*\)\s*:\s*(.+)$') {
                    $names += $Matches[1].Trim()
                }
            }
            foreach ($n in $names) {
                Add-Checked -Label 'wifi_profile' -Path $n
                try {
                    $detail = & netsh.exe wlan show profile name="$n" key=clear 2>$null
                    $blob = ($detail -join "`n")
                    if ($blob -match '(?i)Key Content\s*:\s*(.+)') {
                        $key = $Matches[1].Trim()
                        if (-not (Test-FalsePositive -Value $key)) {
                            Add-Finding -Bucket High -Label 'wifi/key_clear' -Path ('wifi:' + $n) -LineNumber 0 -Preview ("SSID `"$n`": $key")
                        }
                    }
                } catch {}
            }
        }
    } catch {}
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
    foreach ($k in @(
        'HKCU:\Software\Microsoft\Terminal Server Client\Servers'
        'HKCU:\Software\Microsoft\Terminal Server Client\Default'
    )) {
        if (Test-Path $k) { Add-Checked -Label 'rdp_registry' -Path $k }
    }
    foreach ($d in @($env:USERPROFILE, $env:PUBLIC, "$env:SystemDrive\Users")) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        try {
            # NOTE: -LiteralPath silently ignores -Include in PowerShell. We
            # MUST filter explicitly via Where-Object to avoid returning every
            # file and directory under $d.
            Get-ChildItem -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue |
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
    # mRemoteNG (default master key 'mR3m', AES — flag the file)
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
    # Royal TS — same -LiteralPath + -Include bug fix as above
    try {
        Get-ChildItem -LiteralPath $env:APPDATA -Recurse -Force -ErrorAction SilentlyContinue |
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
    # KiTTY (PuTTY fork with stored Password field)
    $kitty = 'HKCU:\Software\9bis.com\KiTTY\Sessions'
    if (Test-Path $kitty) {
        Add-Checked -Label 'kitty_sessions' -Path $kitty
    }
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
    $script:InStage1 = $false
}

# ============================================================================
#  Recursive scanning of user-supplied paths (stages 2-5)
# ============================================================================

# Single tree walk per stage with the directory-exclusion check applied.
function Get-CandidateFiles { param([string[]]$Paths, [bool]$AllMode)
    $result = [System.Collections.Generic.List[string]]::new()
    $stack  = [System.Collections.Generic.Stack[string]]::new()
    foreach ($r in $Paths) {
        try { $abs = [System.IO.Path]::GetFullPath($r) } catch { Write-Warn "Invalid path: $r"; continue }
        if (-not (Test-Path -LiteralPath $abs)) { Write-Warn "Path does not exist: $abs"; continue }
        if (-not (Get-Item -LiteralPath $abs -ErrorAction SilentlyContinue).PSIsContainer) {
            $result.Add($abs); continue
        }
        $stack.Push($abs)
    }
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($current)) {
                try {
                    $ext  = [System.IO.Path]::GetExtension($f).ToLowerInvariant()
                    $name = [System.IO.Path]::GetFileName($f).ToLowerInvariant()
                    $include = $false
                    if ($AllMode) {
                        $include = $true
                    } elseif ($script:Stage5ExtensionsSet.Contains($ext)) {
                        $include = $true
                    } elseif ($script:ExtraScanNames.Contains($name)) {
                        $include = $true
                    } elseif ($name -like 'id_*' -and $name -notlike '*.pub') {
                        $include = $true
                    } elseif ($name -like 'sitemanager.xml' -or $name -like 'recentservers.xml' -or $name -like 'winscp.ini') {
                        $include = $true
                    }
                    if (-not $include) { continue }
                    if ($script:SkipLarge) {
                        try {
                            $fi = New-Object System.IO.FileInfo $f
                            if ($fi.Length -gt $script:MaxFileSizeBytes) { continue }
                        } catch { continue }
                    }
                    $result.Add($f)
                } catch {}
            }
        } catch {}
        try {
            foreach ($d in [System.IO.Directory]::EnumerateDirectories($current)) {
                if (Test-DirectoryExcluded -DirectoryPath $d) { continue }
                $stack.Push($d)
            }
        } catch {}
    }
    return $result
}

# Stage 2 - confirmed credential containers (extension == proof)
function Find-GuaranteedCredentials { param([string[]]$Paths)
    $count = 0
    $stack = [System.Collections.Generic.Stack[string]]::new()
    foreach ($r in $Paths) { if (Test-Path -LiteralPath $r) { $stack.Push($r) } }
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($current)) {
                $ext = [System.IO.Path]::GetExtension($f).ToLowerInvariant()
                if ($script:Stage2Extensions -contains $ext) {
                    Add-Guaranteed -Extension $ext.TrimStart('.') -Path $f
                    $count++
                }
            }
        } catch {}
        try {
            foreach ($d in [System.IO.Directory]::EnumerateDirectories($current)) {
                if (Test-DirectoryExcluded -DirectoryPath $d) { continue }
                $stack.Push($d)
            }
        } catch {}
    }
}

# Stage 3 - high-value file types (NEW SPEC)
# Three passes driven by top-of-file arrays:
#   $script:Stage3Extensions    -- extension match
#   $script:Stage3ExactNamesSet -- exact-basename match (HashSet)
#   $script:Stage3GlobPatterns  -- wildcard match (PowerShell -like)
# Files already flagged by Stage 2 are deduped via $script:GuaranteedHashes.
function Find-HighValueFiles { param([string[]]$Paths)
    $count = 0
    $stack = [System.Collections.Generic.Stack[string]]::new()
    foreach ($r in $Paths) { if (Test-Path -LiteralPath $r) { $stack.Push($r) } }
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($current)) {
                # Stage 2 dedup
                if ($script:GuaranteedHashes.Contains($f)) { continue }

                $name = [System.IO.Path]::GetFileName($f)
                $nameLc = $name.ToLowerInvariant()
                $ext = [System.IO.Path]::GetExtension($f).ToLowerInvariant()

                # SQL Server system-DB filter (always skip)
                if ($script:SkipDbFilenames.Contains($name)) { continue }

                $matched = $false

                # Pass 1: extension
                if ($script:Stage3Extensions -contains $ext) { $matched = $true }

                # Pass 2: exact filename
                if (-not $matched -and $script:Stage3ExactNamesSet.Contains($name)) {
                    $matched = $true
                }

                # Pass 3: glob (e.g. krb5cc_*, *.tar.gz)
                if (-not $matched) {
                    foreach ($g in $script:Stage3GlobPatterns) {
                        if ($nameLc -like $g.ToLowerInvariant()) { $matched = $true; break }
                    }
                }

                if ($matched) {
                    Add-Interesting -Category 'high_value_file' -Path $f
                    $count++
                }
            }
        } catch {}
        try {
            foreach ($d in [System.IO.Directory]::EnumerateDirectories($current)) {
                if (Test-DirectoryExcluded -DirectoryPath $d) { continue }
                $stack.Push($d)
            }
        } catch {}
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
function Find-SuspiciousNames { param([string[]]$Paths)

    $binaryExts = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@('.dll','.exe','.sys','.ocx','.com','.scr','.drv','.cpl',
                    '.ax','.efi','.mui','.so','.dylib','.lib','.bin',
                    '.tlb','.olb','.tlh','.pdb','.ilk','.nupkg'),
        [System.StringComparer]::OrdinalIgnoreCase)
    $selfName = if ($script:SelfPath) { [System.IO.Path]::GetFileName($script:SelfPath).ToLowerInvariant() } else { '' }

    $tokens = @($script:Stage4NameTokens | ForEach-Object { $_.ToLowerInvariant() })

    $count = 0
    $stack = [System.Collections.Generic.Stack[string]]::new()
    foreach ($r in $Paths) { if (Test-Path -LiteralPath $r) { $stack.Push($r) } }
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        try {
            foreach ($e in [System.IO.Directory]::EnumerateFiles($current)) {
                $name = [System.IO.Path]::GetFileName($e).ToLowerInvariant()
                if ($selfName -and $name -eq $selfName) { continue }
                $ext = [System.IO.Path]::GetExtension($e).ToLowerInvariant()
                if ($binaryExts.Contains($ext)) { continue }

                foreach ($t in $tokens) {
                    if ($name.Contains($t)) {
                        Add-SuspiciousName -Path $e
                        $count++
                        break
                    }
                }
            }
        } catch {}
        try {
            foreach ($d in [System.IO.Directory]::EnumerateDirectories($current)) {
                if (Test-DirectoryExcluded -DirectoryPath $d) { continue }
                $stack.Push($d)
            }
        } catch {}
    }
}

# Stage 5 - recursive file-content scan
function Invoke-UserPathScan { param([string[]]$Paths)
    if (-not $Paths -or $Paths.Count -eq 0) {
        Write-Warn "No paths provided; skipping content scan."
        return
    }
    Write-Info "Enumerating candidate files..."
    $files = Get-CandidateFiles -Paths $Paths -AllMode $All.IsPresent
    $total = $files.Count
    if ($total -eq 0) {
        Write-Warn "No candidate files found in the supplied paths."
        return
    }
    $mode = if ($All) { 'all' } else { 'extensions' }
    Write-Ok "Candidate files: $($script:CW)$total$($script:CNC)  (mode: $mode)"
    $i = 0
    foreach ($f in $files) {
        $i++
        # Throttled progress. Truncate long paths so the progress bar doesn't
        # blow out terminal width with deep SQL Server / WindowsApps paths.
        if (($i % 25) -eq 0 -or $i -eq $total) {
            $cur = $f
            if ($cur.Length -gt 70) { $cur = '...' + $cur.Substring($cur.Length - 67) }
            Write-Progress -Activity "Scanning files for credentials" `
                           -Status ("{0} / {1}" -f $i, $total) `
                           -CurrentOperation $cur `
                           -PercentComplete ([Math]::Min(100, ($i * 100 / $total)))
        }
        Invoke-ScanFile -FullPath $f -SourceLabel 'content'
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

    Write-FindingsSection -Title "Reusable credentials" -List $script:HighFindings -Tag "HIGH" -Color $script:CR
    Write-FindingsSection -Title "Private keys & authentication material" -List $script:KeyFindings -Tag "KEY" -Color $script:CM

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

    if ($script:CredFiles.Count -gt 0) {
        Write-Host ""
        Write-Host "$($script:CBold)$($script:CW)> Credential-named files (exact match)$($script:CNC)"
        Write-LogLine ""
        Write-LogLine "=== Credential-named files (exact match) ==="
        foreach ($n in $script:CredFiles | Sort-Object -Unique) {
            Write-Host ("  $($script:CR)[CRED_FILE]$($script:CNC) $n")
            Write-LogLine ("[CRED_FILE] $n")
        }
    }

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

    Write-Section "Summary"
    $nGuar  = $script:Guaranteed.Count
    $nHigh  = $script:HighFindings.Count
    $nKey   = $script:KeyFindings.Count
    $nInt   = $script:Interesting.Count
    $nExact = $script:CredFiles.Count
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
    Write-Host ("$($script:CR)" + ($fmt -f 'Credential-named files (exact)',       $nExact) + "$($script:CNC)")
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
    Write-LogLine "  Credential-named files (exact):  $nExact"
    Write-LogLine "  Suspicious filenames (substring):$nName"
    Write-LogLine "  OS locations checked:            $nCheck"
    Write-LogLine "  Files skipped:                   $nSkip"

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
        if (-not $script:Stage2Skip) {
            Begin-Stage 2; Find-GuaranteedCredentials -Paths $Path; End-Stage 2 "Confirmed credential containers"
        } else {
            Stage-Skipped 2 "Confirmed credential containers"
        }
        if (-not $script:Stage3Skip) {
            Begin-Stage 3; Find-HighValueFiles -Paths $Path; End-Stage 3 "High-value file types"
        } else {
            Stage-Skipped 3 "High-value file types"
        }
        if (-not $script:Stage4Skip) {
            Begin-Stage 4; Find-SuspiciousNames -Paths $Path; End-Stage 4 "Filename substring search"
        } else {
            Stage-Skipped 4 "Filename substring search"
        }
        if (-not $script:Stage5Skip) {
            Begin-Stage 5; Invoke-UserPathScan -Paths $Path; End-Stage 5 "Recursive content scan"
        } else {
            Stage-Skipped 5 "Recursive content scan"
        }
    }

    Write-FullSummary

    if ($script:Guaranteed.Count -gt 0 -or
        $script:HighFindings.Count -gt 0 -or
        $script:KeyFindings.Count -gt 0 -or
        $script:CredFiles.Count -gt 0) {
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
