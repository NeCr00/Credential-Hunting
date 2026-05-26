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
    Skip stage 1 (OS-level credential checks).

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

    [switch] $Quiet,

    [switch] $NoColor
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'Continue'
$script:Version        = '2.0.0'

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
    @{ Label = 'net_user_add';
       Regex = '(?i)net\s+user\s+\S+\s+[^\s/]{4,}\s+(/add|/domain)' }
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
    'krb5_tgs','krb5_asrep','mscash_v1','mscash_v2'
)

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
#  Filename / extension data
# ============================================================================

# Stage 2: confirmed credential containers
$script:GuaranteedCredExtensions = @(
    '.kdbx','.kdb','.psafe3'
    '.agilekeychain','.opvault','.1pif','.1pux'
    '.lpdb','.enpass','.enpassdb','.bitwarden_export'
    '.ppk','.pfx','.p12','.pvk'
    '.jks','.keystore','.truststore'
    '.bek','.fve','.keytab','.dpapimk'
)

# Stage 3: auxiliary / ambiguous credential-related files
$script:HighValueExtensions = @(
    '.pem','.key','.priv','.asc','.gpg','.wallet'
    '.rdp','.ovpn'
    # Session managers / VPN profiles (DPAPI-encrypted but worth flagging)
    '.rdg','.rdcman','.rtsz','.rtsg','.remmina','.pcf','.tblk'
    # VMware Workstation .vmx files have `displayName.passwd`, `encoded.password`
    '.vmx'
    # Outlook archives — admin pw emails archived here
    '.pst','.ost'
    # Office docs
    '.doc','.docx','.docm','.dot','.dotx','.dotm'
    '.xls','.xlsx','.xlsm','.xlsb','.xlt','.xltx','.xltm'
    '.ppt','.pptx','.pptm','.pps','.ppsx'
    '.odt','.ods','.odp','.odg','.pdf'
    '.one','.onetoc2'
    # Binary databases
    '.mdb','.accdb','.bacpac','.dacpac'
    '.mdf','.ldf','.frm','.myd'
    '.sqlite','.sqlite3','.db','.db3'
    # Registry hives & memory dumps
    '.hive','.hiv','.dmp','.mdmp','.crash','.core'
)

# Stage 4a: exact filename matches
$script:CredFileNames = @(
    '.bash_history','.zsh_history','.sh_history','.ksh_history','.history','.ash_history'
    '.psql_history','.mysql_history','.sqlite_history','.python_history'
    '.node_repl_history','.irb_history','.rediscli_history','.lesshst','.viminfo'
    '.wget-hsts'
    '.netrc','.pgpass','.my.cnf','my.cnf','.mysql.cnf','.dbshell','.mongorc.js'
    '.pypirc','.npmrc','.gitconfig','.git-credentials','.gitcredentials'
    '.htpasswd','.htaccess','shadow','gshadow','passwd','sudoers','master.passwd'
    'login.defs','auth.log','secure','pam.conf','smb.conf','smbpasswd','freerdp'
    'wgetrc','.wgetrc','curlrc','.curlrc'
    'id_rsa','id_dsa','id_ecdsa','id_ed25519','id_xmss'
    'authorized_keys','authorized_keys2','known_hosts','ssh_config','sshd_config'
    'sam','system','security','software','ntuser.dat','ntds.dit'
    'system.sav','security.sav','sam.sav'
    'unattend.xml','unattended.xml','autounattend.xml','sysprep.xml','sysprep.inf'
    'groups.xml','services.xml','scheduledtasks.xml','datasources.xml','printers.xml','drives.xml'
    'web.config','wp-config.php','wp-config.bak','wp-config.old'
    'wp-config.php.bak','wp-config.php.old','wp-config.php.save'
    'configuration.php','settings.php','local.xml','config.inc.php','config.php'
    'db.php','database.php','connect.php','connection.php'
    'appsettings.json','appsettings.production.json','appsettings.development.json'
    'connection.config','machine.config','hibernate.cfg.xml','persistence.xml'
    'context.xml','tomcat-users.xml','standalone.xml','server.xml'
    'mgmt-users.properties','application.properties','application.yml','application.yaml'
    'bootstrap.yml','bootstrap.yaml'
    'pg_hba.conf','postgresql.conf','my.ini','mongod.conf','redis.conf'
    'elasticsearch.yml','kibana.yml','tnsnames.ora','sqlnet.ora','listener.ora','wallet.dat'
    'winscp.ini','putty.reg','sitemanager.xml','recentservers.xml'
    'filezilla.xml','queue.xml','confcons.xml','mremoteng.xml','default.rdg','rdcman.settings'
    '.env','.env.local','.env.dev','.env.development','.env.prod','.env.production'
    '.env.staging','.env.test','.env.backup','.env.bak','.env.old','.env.save'
    '.env.example','.env.sample','env.production','env.development'
    '.vault_pass','vault_pass.txt','.ansible_vault'

    # Research adds (HTB/THM/PG + real-engagement staples)
    'tomcat-users.xml'              # Tomcat manager
    'credentials.xml'               # Jenkins $JENKINS_HOME
    'master.key','secret.key'       # Jenkins secrets/
    'hudson.util.secret'            # Jenkins encrypted secret
    'sitelist.xml'                  # McAfee
    'applicationhost.config'        # IIS
    'keepass.config.xml','keepass.config.enforced.xml'
    'grafana.ini','gitlab.rb','app.ini'
    'accounts.xml'                  # Pidgin
    'secrets.tdb'                   # Samba
    'user-data.txt','cloud-config'
    'ks.cfg','initial-setup-ks.cfg','preseed.cfg'
    'opasswd','sssd.conf'
    'confcons.xml','rdcman.settings'
    'wp-config.php~','wp-config.php.swp'   # editor scratch
)
$script:CredFileNamesSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]$script:CredFileNames, [System.StringComparer]::OrdinalIgnoreCase)

# Stage 4b: substring patterns (case-insensitive)
$script:SuspiciousNamePatterns = @(
    'password','passwd','pwd','passphrase','passcode'
    'credential','creds','vault','secret'
    'htpasswd','netrc','pgpass'
    'db_pass','database_password','dbpass'
    'masterkey','master_password','masterpass','sshpass'
    'pwdump','kerberoast','asreproast','hashdump','mimikatz','lsass'
    'keepass'
    'sshkey','ssh_key','sshconfig','ssh_config'
    'winscp','putty','filezilla','mremoteng','rdcman'
    'ansible_vault','vault_pass'
    'smbpasswd','autologon'
    'unattend','sysprep','autounattend'
    'wp_config','wp-config','wpconfig'

    # ── Research-derived adds (Snaffler classifiers, 0xdf writeups,
    #    BHIS file-share triage) ───────────────────────────────────
    'handover','onboarding','offboarding','newhire','helpdesk','runbook'
    'as-built','build sheet','buildsheet'
    'new hire','new_hire'
    'reset_password','reset password','password_recovery','password_reset'
    'it_master','it master'
    'domain_admin','domain admin'
    'service_account','service account','svc_account','svcaccount','svcacct'
    'domain_join','local_admin','break_glass','breakglass'
    'default_password','defaultpass'
    'snmp_community'
)

# Stage 5: content-search extensions
$script:SearchExtensions = @(
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
$script:SearchExtensionsSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]$script:SearchExtensions, [System.StringComparer]::OrdinalIgnoreCase)

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

# Absolute path prefixes
$script:ExcludePathPrefixes = @(
    (Join-Path $env:SystemRoot 'WinSxS')
    (Join-Path $env:SystemRoot 'Installer')
    (Join-Path $env:SystemRoot 'SoftwareDistribution')
    (Join-Path $env:SystemRoot 'Logs')
    (Join-Path $env:SystemRoot 'LiveKernelReports')
    (Join-Path $env:SystemRoot 'servicing')
    (Join-Path $env:SystemRoot 'assembly')
    (Join-Path $env:SystemRoot 'Microsoft.NET\assembly')
    (Join-Path $env:SystemRoot 'Fonts')
    (Join-Path $env:SystemRoot 'Help')
    (Join-Path $env:SystemRoot 'Microsoft.NET\Framework\v2.0.50727')
    (Join-Path $env:SystemRoot 'PolicyDefinitions')
    (Join-Path ${env:ProgramFiles} 'WindowsApps')
    (Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps')
    (Join-Path $env:LOCALAPPDATA 'Packages')
    "$env:SystemDrive\`$Recycle.Bin"
    "$env:SystemDrive\System Volume Information"
) | Where-Object { $_ -and $_.Trim() -ne '' }

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

function Write-LogLine { param([string]$Line)
    if ([string]::IsNullOrEmpty($script:LogPath)) { return }
    $clean = $Line -replace "`e\[[0-9;]*m", ''
    Add-Content -Path $script:LogPath -Value $clean -Encoding UTF8
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
}

function Add-Interesting { param([string]$Category, [string]$Path)
    $k = "$Category|$Path"
    if ($script:InterestingHashes.Add($k)) {
        $script:Interesting.Add([PSCustomObject]@{ Category = $Category; Path = $Path })
    }
}
function Add-Guaranteed { param([string]$Extension, [string]$Path)
    if ($script:GuaranteedHashes.Add($Path)) {
        $script:Guaranteed.Add([PSCustomObject]@{ Extension = $Extension; Path = $Path })
    }
}
function Add-CredFile { param([string]$Path)
    if ($script:CredFileHashes.Add($Path)) { $script:CredFiles.Add($Path) | Out-Null }
}
function Add-SuspiciousName { param([string]$Path)
    if ($script:NameHashes.Add($Path)) { $script:SuspiciousNamesFound.Add($Path) | Out-Null }
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
# Each path is processed at most once via $ScannedPaths.
function Invoke-ScanFile { param([string]$FullPath, [string]$SourceLabel = 'content')
    # Never scan ourselves
    if ($script:SelfPath -and $FullPath -eq $script:SelfPath) { return }

    # Dedup
    if (-not $script:ScannedPaths.Add($FullPath)) { return }

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

    # ---- Phase 1: private-key markers ---------------------------------------
    foreach ($p in $script:KeyPatterns) {
        $m = $p.Regex.Match($content)
        if ($m.Success) {
            $lineNo = Get-LineNumber -Content $content -Index $m.Index
            Add-Finding -Bucket Key -Label $p.Label -Path $FullPath -LineNumber $lineNo -Preview $m.Value
        }
    }

    # ---- Phase 2: credential patterns ---------------------------------------
    $matchesFound = 0
    foreach ($p in $script:CredPatterns) {
        if ($matchesFound -ge $script:MaxMatchesPerFile) { break }
        foreach ($m in $p.Regex.Matches($content)) {
            if ($matchesFound -ge $script:MaxMatchesPerFile) { break }
            $line  = $m.Value
            $value = $line
            $eq = $line.IndexOfAny(@(':','='))
            if ($eq -ge 0 -and $eq -lt $line.Length - 1) {
                $value = $line.Substring($eq + 1).Trim().Trim('"',"'",' ',';')
                $value = ($value -split '[#;]')[0]
            }
            if (-not ($script:NoFPCheck -contains $p.Label)) {
                if (Test-FalsePositive -Value $value) { continue }
            }
            $lineNo = Get-LineNumber -Content $content -Index $m.Index
            Add-Finding -Bucket High -Label "$SourceLabel/$($p.Label)" -Path $FullPath -LineNumber $lineNo -Preview (Format-Preview $line)
            $matchesFound++
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
            Get-ChildItem -LiteralPath $d -Recurse -Force -Include '*.rdp','*.rdg' -ErrorAction SilentlyContinue |
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
    # Royal TS
    try {
        Get-ChildItem -LiteralPath $env:APPDATA -Recurse -Force `
            -Include '*.rtsz','*.rtsg' -ErrorAction SilentlyContinue |
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
    Write-Section "Stage 1 - OS-level credential locations"
    Test-RegistryAutoLogon
    Test-GPPCPassword
    Test-UnattendedInstall
    Test-PowerShellHistory
    Test-CmdkeyVault
    Test-PuTTYSessions
    Test-WinSCPSessions
    Test-VNCRegistry
    Test-SNMPRegistry
    Test-SAMHives
    Test-IISConfigs
    Test-ScheduledTasks
    Test-WiFiProfiles
    Test-McAfeeSiteList
    Test-BrowserCredFiles
    Test-CloudCliCredentials
    Test-SSHKeysWindows
    Test-RDPSavedSessions
    Test-RemoteAccessManagers
    Test-WiFiProfileXmls
    Test-AutopilotProvisioning
    Test-StickyNotes
    Test-IISConfigHistory
    Write-Ok "Stage 1 complete."
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
                    } elseif ($script:SearchExtensionsSet.Contains($ext)) {
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
    Write-Section "Stage 2 - Confirmed credential containers"
    $count = 0
    $stack = [System.Collections.Generic.Stack[string]]::new()
    foreach ($r in $Paths) { if (Test-Path -LiteralPath $r) { $stack.Push($r) } }
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($current)) {
                $ext = [System.IO.Path]::GetExtension($f).ToLowerInvariant()
                if ($script:GuaranteedCredExtensions -contains $ext) {
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
    if ($count -gt 0) {
        Write-Ok "Found $($script:CR)$($script:CBold)$count$($script:CNC) $($script:CR)confirmed credential container(s)$($script:CNC)."
    } else {
        Write-Ok "Found $($script:CW)0$($script:CNC) confirmed credential containers."
    }
}

# Stage 3 - auxiliary credential-related files
function Find-HighValueFiles { param([string[]]$Paths)
    Write-Section "Stage 3 - Auxiliary credential-related files"
    $count = 0
    $stack = [System.Collections.Generic.Stack[string]]::new()
    foreach ($r in $Paths) { if (Test-Path -LiteralPath $r) { $stack.Push($r) } }
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($current)) {
                $ext = [System.IO.Path]::GetExtension($f).ToLowerInvariant()
                if ($script:HighValueExtensions -contains $ext) {
                    Add-Interesting -Category 'credential_related' -Path $f
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
    Write-Ok "Found $($script:CW)$count$($script:CNC) auxiliary credential-related file(s)."
}

# Stage 4 - filename detection (exact + substring, single tree walk)
function Find-SuspiciousNames { param([string[]]$Paths)
    Write-Section "Stage 4 - Filename patterns"
    $stack = [System.Collections.Generic.Stack[string]]::new()
    foreach ($r in $Paths) { if (Test-Path -LiteralPath $r) { $stack.Push($r) } }
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        try {
            foreach ($e in [System.IO.Directory]::EnumerateFileSystemEntries($current)) {
                $name = [System.IO.Path]::GetFileName($e).ToLowerInvariant()
                if ($script:CredFileNamesSet.Contains($name)) {
                    Add-CredFile -Path $e
                    continue
                }
                foreach ($pat in $script:SuspiciousNamePatterns) {
                    if ($pat.Contains('*')) {
                        if ($name -like "*$pat*") { Add-SuspiciousName -Path $e; break }
                    } elseif ($name.Contains($pat)) {
                        Add-SuspiciousName -Path $e; break
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
    if ($script:CredFiles.Count -gt 0) {
        Write-Ok "Found $($script:CR)$($script:CBold)$($script:CredFiles.Count)$($script:CNC) $($script:CR)credential-named file(s)$($script:CNC) (exact)."
    } else {
        Write-Ok "Found $($script:CW)0$($script:CNC) credential-named files (exact)."
    }
    Write-Ok "Found $($script:CW)$($script:SuspiciousNamesFound.Count)$($script:CNC) suspicious-name pattern match(es)."
}

# Stage 5 - recursive file-content scan
function Invoke-UserPathScan { param([string[]]$Paths)
    Write-Section "Stage 5 - File-content scan"
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
        if (($i % 25) -eq 0 -or $i -eq $total) {
            Write-Progress -Activity "Scanning files for credentials" `
                           -Status ("{0} / {1}" -f $i, $total) `
                           -CurrentOperation $f `
                           -PercentComplete ([Math]::Min(100, ($i * 100 / $total)))
        }
        Invoke-ScanFile -FullPath $f -SourceLabel 'content'
    }
    Write-Progress -Activity "Scanning files for credentials" -Completed
    Write-Ok "Scanned $($script:CW)$total$($script:CNC) files."
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

    if (-not $SkipSystem) {
        Invoke-SystemChecks
    } else {
        Write-Warn "Skipping OS-level checks (per -SkipSystem)."
    }

    if ($Path.Count -eq 0) {
        Write-Warn "No -Path supplied. Skipping stages 2-5."
        Write-Warn "Tip: pass -Path C:\ to scan everywhere."
    } else {
        Find-GuaranteedCredentials -Paths $Path
        Find-HighValueFiles -Paths $Path
        Find-SuspiciousNames -Paths $Path
        Invoke-UserPathScan -Paths $Path
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
