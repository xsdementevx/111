#Requires -Version 5.1
<#
    TLS/SSL диагностика для лоадера RF4
    ===================================
    Запуск: правый клик -> Run with PowerShell
    Результат: tls-diag-report.txt на Рабочем столе
    Отправь этот файл разработчику.
#>

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

$script:Report = [System.Collections.Generic.List[string]]::new()

function Write-Section {
    param([string]$Title)
    $line = "=" * 70
    $script:Report.Add("")
    $script:Report.Add($line)
    $script:Report.Add("  $Title")
    $script:Report.Add($line)
    Write-Host ""
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor DarkGray
}

function Write-Item {
    param([string]$Key, $Value)
    $line = "  {0,-30} : {1}" -f $Key, ($Value | Out-String).Trim()
    $script:Report.Add($line)
    Write-Host $line
}

function Write-Raw {
    param([string]$Text)
    $script:Report.Add($Text)
    Write-Host $Text
}

function Save-Report {
    if (-not $script:OutPath) { return }
    try {
        $script:Report -join "`r`n" | Out-File -FilePath $script:OutPath -Encoding UTF8 -ErrorAction Stop
    } catch {}
}

# ================================================================
# 1. Идентификация системы
# ================================================================
function Collect-SystemInfo {
    Write-Section "SYSTEM"
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        Write-Item "OS Caption"       $os.Caption
        Write-Item "OS Version"       $os.Version
        Write-Item "OS BuildNumber"   $os.BuildNumber
        Write-Item "OS Architecture"  $os.OSArchitecture
        Write-Item "Install Date"     $os.InstallDate
        Write-Item "Last Boot"        $os.LastBootUpTime
        Write-Item "LocaleID"         $os.Locale
    } catch { Write-Item "OS query" "FAILED: $($_.Exception.Message)" }

    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        Write-Item "Manufacturer"     $cs.Manufacturer
        Write-Item "Model"            $cs.Model
        Write-Item "Domain"           $cs.Domain
    } catch {}

    Write-Item "PowerShell"           $PSVersionTable.PSVersion
    Write-Item "CLR"                  $PSVersionTable.CLRVersion
    Write-Item "Current User"         $env:USERNAME
    Write-Item "Computer Name"        $env:COMPUTERNAME
    Write-Item "Timezone"             ([TimeZoneInfo]::Local.Id)

    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Item "Run as Admin"         $isAdmin
}

# ================================================================
# 2. Schannel / TLS registry
# ================================================================
function Collect-SchannelInfo {
    Write-Section "SCHANNEL (TLS in registry)"
    $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    foreach ($proto in @("TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3", "SSL 3.0")) {
        foreach ($side in @("Client", "Server")) {
            $path = Join-Path $base "$proto\$side"
            if (Test-Path $path) {
                $p = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                $enabled = if ($null -ne $p.Enabled)            { $p.Enabled }           else { "default" }
                $disBy   = if ($null -ne $p.DisabledByDefault)  { $p.DisabledByDefault } else { "default" }
                Write-Item "$proto $side" "Enabled=$enabled DisabledByDefault=$disBy"
            }
        }
    }

    # .NET strong crypto
    foreach ($k in @(
        "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
    )) {
        if (Test-Path $k) {
            $p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
            if ($null -ne $p.SchUseStrongCrypto) {
                Write-Item ".NET StrongCrypto ($k)" $p.SchUseStrongCrypto
            }
        }
    }
}

# ================================================================
# 3. Системное время vs NTP
# ================================================================
function Collect-TimeDiag {
    Write-Section "SYSTEM TIME"
    Write-Item "Local Time (UTC)"    ([DateTime]::UtcNow.ToString("o"))
    Write-Item "Local Time"          ((Get-Date).ToString("o"))

    foreach ($ntp in @("time.windows.com", "pool.ntp.org", "time.nist.gov")) {
        try {
            $ntpData = New-Object byte[] 48
            $ntpData[0] = 0x1B
            $udp = New-Object Net.Sockets.UdpClient
            $udp.Client.ReceiveTimeout = 3000
            $udp.Connect($ntp, 123)
            [void]$udp.Send($ntpData, $ntpData.Length)
            $ntpData = $udp.Receive([ref]$null)
            $udp.Close()

            $sec  = [BitConverter]::ToUInt32($ntpData[43..40], 0)
            $frac = [BitConverter]::ToUInt32($ntpData[47..44], 0)
            $epoch = New-Object DateTime(1900, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
            $ntpTime = $epoch.AddSeconds($sec).AddSeconds($frac / [Math]::Pow(2, 32))
            $skew = [Math]::Round(($ntpTime - [DateTime]::UtcNow).TotalSeconds, 2)
            Write-Item "$ntp skew (sec)" $skew
        } catch {
            Write-Item "$ntp" "FAILED: $($_.Exception.Message)"
        }
    }
}

# ================================================================
# 4. DNS
# ================================================================
function Collect-DnsDiag {
    Write-Section "DNS"

    # Активные DNS-серверы
    try {
        $servers = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                   Where-Object { $_.ServerAddresses -and $_.InterfaceAlias -notmatch "Loopback|isatap" }
        foreach ($s in $servers) {
            Write-Item "DNS on $($s.InterfaceAlias)" ($s.ServerAddresses -join ", ")
        }
    } catch { Write-Item "DNS server query" "FAILED: $($_.Exception.Message)" }

    # Hosts file
    $hosts = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue |
             Where-Object { $_ -notmatch "^\s*(#|$)" }
    if ($hosts) {
        Write-Raw "  [hosts non-empty entries]"
        foreach ($line in $hosts) { Write-Raw "    $line" }
    } else {
        Write-Item "hosts file" "only defaults/comments"
    }

    # Resolve через разные DNS
    $hostname = "keyauth.win"
    Write-Raw ""
    Write-Raw "  [Resolve $hostname through different DNS]"
    try {
        $sys = [Net.Dns]::GetHostAddresses($hostname) | ForEach-Object { $_.IPAddressToString }
        Write-Item "system resolver" ($sys -join ", ")
    } catch {
        Write-Item "system resolver" "FAILED: $($_.Exception.Message)"
    }

    foreach ($srv in @("1.1.1.1", "8.8.8.8", "9.9.9.9")) {
        try {
            $r = Resolve-DnsName -Name $hostname -Server $srv -Type A -DnsOnly -QuickTimeout -ErrorAction Stop
            Write-Item "via $srv" ($r.IPAddress -join ", ")
        } catch {
            Write-Item "via $srv" "FAILED: $($_.Exception.Message)"
        }
    }
}

# ================================================================
# 5. Root Certificate Store
# ================================================================
function Collect-RootStore {
    Write-Section "ROOT CERTIFICATE STORE"

    $critical = @{
        "ISRG Root X1"                       = "CABD2A79A1076A31F21D253635CB039D4329A5E8"
        "ISRG Root X2"                       = "BDB1B93CD5978D45C6261455F8DB95C75AD153AF"
        "DST Root CA X3 (EXPIRED 2021-09)"   = "DAC9024F54D8F6DF94935FB1732638CA6AD77C13"
        "DigiCert Global Root CA"            = "A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436"
        "DigiCert Global Root G2"            = "DF3C24F9BFD666761B268073FE06D1CC8D4F82A4"
        "Baltimore CyberTrust Root"          = "D4DE20D05E66FC53FE1A50882C78DB2852CAE474"
        "USERTrust RSA CA"                   = "2B8F1B57330DBBA2D07A6C51F70EE90DDAB9AD8E"
        "GTS Root R1"                        = "E1C950E6EF22F84C5645728B922060D7D5A7A3E8"
        "MS RSA Root CA 2017"                = "73A5E64A3BFF8316FF0EDCCC618A906E4EAE4D74"
    }

    foreach ($name in $critical.Keys) {
        $thumb   = $critical[$name]
        $machine = Test-Path "Cert:\LocalMachine\Root\$thumb"
        $user    = Test-Path "Cert:\CurrentUser\Root\$thumb"
        $status  = if ($machine) { "machine" } elseif ($user) { "user-only" } else { "MISSING" }
        Write-Item $name "$status (machine=$machine, user=$user)"
    }

    # AV / MITM root signature detection
    Write-Raw ""
    Write-Raw "  [SSL-inspection AV roots in store]"
    $avPatterns = @(
        "Kaspersky", "AVAST", "ESET", "Bitdefender", "Avira", "AVG",
        "Sophos", "McAfee", "Norton", "Symantec Endpoint"
    )
    $found = @()
    foreach ($store in @("Cert:\LocalMachine\Root", "Cert:\CurrentUser\Root")) {
        Get-ChildItem $store -ErrorAction SilentlyContinue | ForEach-Object {
            foreach ($p in $avPatterns) {
                if ($_.Subject -match $p -or $_.Issuer -match $p) {
                    $found += "  $store : $($_.Subject) [thumb=$($_.Thumbprint)]"
                }
            }
        }
    }
    if ($found) { $found | ForEach-Object { Write-Raw $_ } }
    else        { Write-Item "AV MITM roots" "none detected" }
}

# ================================================================
# 6. Proxy
# ================================================================
function Collect-ProxyConfig {
    Write-Section "PROXY"
    try {
        $ieKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        $p = Get-ItemProperty $ieKey -ErrorAction SilentlyContinue
        Write-Item "ProxyEnable"    $p.ProxyEnable
        Write-Item "ProxyServer"    $p.ProxyServer
        Write-Item "AutoConfigURL"  $p.AutoConfigURL
        Write-Item "ProxyOverride"  $p.ProxyOverride
    } catch {}

    try {
        $wp = [Net.WebRequest]::DefaultWebProxy.GetProxy("https://keyauth.win")
        Write-Item ".NET proxy for keyauth.win" $wp.ToString()
    } catch {}

    try {
        $r = netsh winhttp show proxy 2>&1 | Out-String
        Write-Raw "  [netsh winhttp show proxy]"
        Write-Raw $r.Trim()
    } catch {}

    foreach ($var in @("HTTP_PROXY","HTTPS_PROXY","NO_PROXY")) {
        $v = [Environment]::GetEnvironmentVariable($var)
        if ($v) { Write-Item "env:$var" $v }
    }
}

# ================================================================
# 7. Антивирусы / Firewall
# ================================================================
function Collect-AVInfo {
    Write-Section "SECURITY SOFTWARE"
    try {
        Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
            ForEach-Object { Write-Item "AntiVirus"   $_.displayName }
    } catch { Write-Item "AV query" "unavailable" }

    try {
        Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct -ErrorAction Stop |
            ForEach-Object { Write-Item "Firewall"    $_.displayName }
    } catch {}

    # Сетевой firewall Windows
    try {
        $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        foreach ($f in $fw) {
            Write-Item "Windows FW $($f.Name)" "Enabled=$($f.Enabled)"
        }
    } catch {}
}

# ================================================================
# 8. TLS probe с полным chain
# ================================================================
function Test-TlsEndpoint {
    param([string]$TargetHost, [int]$Port = 443, [int]$TimeoutMs = 7000)

    $out = [ordered]@{
        host         = $TargetHost
        ok           = $false
        negotiated   = $null
        cipher       = $null
        chain_errors = $null
        error        = $null
        chain        = @()
    }

    $tcp = $null; $ssl = $null; $ns = $null

    try {
        $tcp = New-Object Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            throw "TCP connect timeout"
        }
        $tcp.EndConnect($iar)
        $tcp.ReceiveTimeout = $TimeoutMs
        $tcp.SendTimeout    = $TimeoutMs

        # Синхронный handshake: callback не нужен — шифр и сертификат
        # достанем из SslStream/RemoteCertificate, а ошибки цепочки пересоберём
        # вручную через X509Chain.Build после успешного TLS.
        # (Async + script-block callback ломается под `iex`: на ThreadPool потоке
        #  нет DefaultRunspace и PowerShell не может выполнить script-block.)
        $ns = $tcp.GetStream()
        $ns.ReadTimeout  = $TimeoutMs
        $ns.WriteTimeout = $TimeoutMs
        # Принимаем любой сертификат на этапе handshake — всё валидируем потом
        $acceptAll = [Net.Security.RemoteCertificateValidationCallback]{ param($a,$b,$c,$d) return $true }
        $ssl = New-Object Net.Security.SslStream($ns, $false, $acceptAll)

        $protocols = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        $ssl.AuthenticateAsClient($TargetHost, $null, $protocols, $false)

        $out.ok           = $true
        $out.negotiated   = $ssl.SslProtocol.ToString()
        $out.cipher       = "$($ssl.CipherAlgorithm)/$($ssl.HashAlgorithm)/$($ssl.KeyExchangeAlgorithm)"

        # Собираем цепочку и ошибки независимо, через X509Chain
        $remote = $ssl.RemoteCertificate
        if ($remote) {
            $leaf  = New-Object Security.Cryptography.X509Certificates.X509Certificate2 $remote
            $bChain = New-Object Security.Cryptography.X509Certificates.X509Chain
            $bChain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            [void]$bChain.Build($leaf)
            $errs = ($bChain.ChainStatus | ForEach-Object { $_.Status.ToString() }) -join ","
            if (-not $errs) { $errs = "NoError" }
            $out.chain_errors = $errs

            foreach ($el in $bChain.ChainElements) {
                $status = ($el.ChainElementStatus | ForEach-Object { $_.Status.ToString() }) -join ","
                $out.chain += [ordered]@{
                    subject    = $el.Certificate.Subject
                    issuer     = $el.Certificate.Issuer
                    thumbprint = $el.Certificate.Thumbprint
                    not_before = $el.Certificate.NotBefore.ToString("o")
                    not_after  = $el.Certificate.NotAfter.ToString("o")
                    status     = $status
                }
            }
        }
    } catch {
        $ex = $_.Exception
        $msg = $ex.Message
        while ($ex.InnerException) { $ex = $ex.InnerException; $msg += " -> $($ex.Message)" }
        $out.error = $msg
    } finally {
        if ($ssl) { try { $ssl.Dispose() } catch {} }
        if ($tcp) { try { $tcp.Dispose() } catch {} }
    }

    return $out
}

function Invoke-AllProbes {
    Write-Section "TLS PROBES"

    $targets = @(
        @{ host = "www.microsoft.com";              role = "baseline (MS Root CA)"        },
        @{ host = "valid-isrgrootx1.letsencrypt.org"; role = "ISRG Root X1 trust"         },
        @{ host = "sha256.badssl.com";              role = "modern TLS baseline"          },
        @{ host = "ctldl.windowsupdate.com";        role = "Windows Root Update endpoint" },
        @{ host = "cloudflare.com";                 role = "Cloudflare baseline"          },
        @{ host = "rf4-game.com";                   role = "our domain"                   },
        @{ host = "fishing-hack.com";               role = "our domain 2"                 },
        @{ host = "keyauth.win";                    role = "target"                       }
    )

    foreach ($t in $targets) {
        Write-Raw ""
        Write-Raw "  ----- [$($t.role)] $($t.host) -----"
        $r = Test-TlsEndpoint -TargetHost $t.host
        Write-Item "  ok"            $r.ok
        Write-Item "  negotiated"    $r.negotiated
        Write-Item "  cipher"        $r.cipher
        Write-Item "  chain_errors"  $r.chain_errors
        if ($r.error) { Write-Item "  ERROR"      $r.error }
        for ($i = 0; $i -lt $r.chain.Count; $i++) {
            $c = $r.chain[$i]
            Write-Raw "    [cert $i]"
            Write-Raw "      Subject    : $($c.subject)"
            Write-Raw "      Issuer     : $($c.issuer)"
            Write-Raw "      Thumbprint : $($c.thumbprint)"
            Write-Raw "      NotAfter   : $($c.not_after)"
            if ($c.status -and $c.status -ne "NoError") {
                Write-Raw "      Status     : $($c.status)"
            }
        }
    }
}

# ================================================================
# 9. WinHTTP / WinINET sanity
# ================================================================
function Collect-WinHttpProbe {
    Write-Section 'WinHTTP (Invoke-WebRequest via default stack)'
    $urls = @(
        "https://keyauth.win/",
        "https://rf4-game.com/",
        "https://www.microsoft.com/"
    )
    foreach ($u in $urls) {
        try {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $resp = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
            $sw.Stop()
            Write-Item $u "OK status=$($resp.StatusCode) bytes=$($resp.RawContentLength) elapsed=$($sw.ElapsedMilliseconds)ms"
        } catch {
            $ex = $_.Exception
            $msg = $ex.Message
            while ($ex.InnerException) { $ex = $ex.InnerException; $msg += " -> $($ex.Message)" }
            Write-Item $u "FAIL: $msg"
        }
    }
}

# ================================================================
# Main
# ================================================================
Clear-Host
Write-Host ""
Write-Host "  RF4 Loader TLS/SSL Diagnostics" -ForegroundColor Green
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
Write-Host ""
Write-Host "  Сбор диагностики занимает 30-60 секунд, пожалуйста подождите..."

$script:Report.Add("RF4 Loader TLS/SSL Diagnostics")
$script:Report.Add("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')")

try { Collect-SystemInfo }    catch { Write-Raw "  [SystemInfo ERROR] $($_.Exception.Message)" }
try { Collect-SchannelInfo }  catch { Write-Raw "  [Schannel ERROR] $($_.Exception.Message)" }
try { Collect-TimeDiag }      catch { Write-Raw "  [TimeDiag ERROR] $($_.Exception.Message)" }
try { Collect-DnsDiag }       catch { Write-Raw "  [DnsDiag ERROR] $($_.Exception.Message)" }
try { Collect-RootStore }     catch { Write-Raw "  [RootStore ERROR] $($_.Exception.Message)" }
try { Collect-ProxyConfig }   catch { Write-Raw "  [Proxy ERROR] $($_.Exception.Message)" }
try { Collect-AVInfo }        catch { Write-Raw "  [AV ERROR] $($_.Exception.Message)" }
try { Invoke-AllProbes }      catch { Write-Raw "  [TlsProbes ERROR] $($_.Exception.Message)" }
try { Collect-WinHttpProbe }  catch { Write-Raw "  [WinHTTP ERROR] $($_.Exception.Message)" }

$desktop = [Environment]::GetFolderPath("Desktop")
$outPath = Join-Path $desktop "tls-diag-report.txt"
try {
    $script:Report -join "`r`n" | Out-File -FilePath $outPath -Encoding UTF8
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Отчёт сохранён: " -NoNewline
    Write-Host $outPath -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Отправь этот файл разработчику." -ForegroundColor Green
    Write-Host ""
    try {
        $selectArg = '/select,"{0}"' -f $outPath
        Start-Process -FilePath 'explorer.exe' -ArgumentList $selectArg -ErrorAction SilentlyContinue
    } catch {}
} catch {
    Write-Host ""
    Write-Host "  Не удалось сохранить файл: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Скопируй весь вывод выше и отправь разработчику." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Нажми любую клавишу чтобы закрыть окно..."
try {
    if ($Host.Name -eq 'ConsoleHost' -and -not [Console]::IsInputRedirected) {
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
} catch {}
