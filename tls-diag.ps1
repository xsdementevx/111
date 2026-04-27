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

# UTF-8 для консоли — иначе кириллица литералов скрипта и вывод нативных
# утилит (netsh) превращается в "?" или "╨в╨╡╨║" при запуске через `iwr | iex`
try {
    $null = & chcp.com 65001 2>&1
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    [Console]::InputEncoding  = [System.Text.UTF8Encoding]::new($false)
    $OutputEncoding = [System.Text.UTF8Encoding]::new($false)
} catch {}

# OEM кодировка для нативных команд, которые игнорируют chcp 65001
# (используется только для прицельного декодирования netsh)
try {
    $script:OemEncoding = [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
} catch {
    $script:OemEncoding = [System.Text.Encoding]::GetEncoding(866)
}

$script:Report = [System.Collections.Generic.List[string]]::new()
$script:Issues = [System.Collections.Generic.List[string]]::new()

# Цели, по которым реально ходит лоадер — фильтруем hosts только по ним
$script:OurDomains = @('keyauth.win', 'rf4-game.com', 'fishing-hack.com')

function Add-Issue {
    param([string]$Text)
    $script:Issues.Add($Text)
}

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
        Write-Item "OS"               "$($os.Caption) $($os.OSArchitecture) build $($os.BuildNumber)"
    } catch {}
    Write-Item "PowerShell"           $PSVersionTable.PSVersion.ToString()
    Write-Item "Locale"               ([System.Globalization.CultureInfo]::CurrentCulture.Name)
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Item "Admin"                $isAdmin
}

# ================================================================
# 2. Schannel / TLS registry
# ================================================================
function Collect-SchannelInfo {
    Write-Section "SCHANNEL (TLS in registry)"
    $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    $anomalies = 0
    foreach ($proto in @("TLS 1.2", "TLS 1.3")) {
        $path = Join-Path $base "$proto\Client"
        if (Test-Path $path) {
            $p = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            $enabled = $p.Enabled
            $disBy   = $p.DisabledByDefault
            # Аномалия: TLS 1.2/1.3 явно выключен
            if (($null -ne $enabled -and $enabled -eq 0) -or ($null -ne $disBy -and $disBy -eq 1)) {
                Write-Item "$proto Client" "DISABLED (Enabled=$enabled DisabledByDefault=$disBy)"
                Add-Issue "$proto disabled in registry — TLS handshake к keyauth.win не пойдёт"
                $anomalies++
            }
        }
    }
    if ($anomalies -eq 0) { Write-Item "TLS 1.2/1.3 client" "default (OK)" }
}

# ================================================================
# 3. Системное время vs NTP
# ================================================================
function Collect-TimeDiag {
    Write-Section "SYSTEM TIME"
    Write-Item "Local Time"           ((Get-Date).ToString("yyyy-MM-dd HH:mm:ss zzz"))

    $skews = @()
    foreach ($ntp in @("pool.ntp.org", "time.nist.gov")) {
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
            $skews += $skew
            # Только если рассинхрон критичен (>5 минут TLS уже ломается)
            if ([Math]::Abs($skew) -gt 60) {
                Write-Item "$ntp skew (sec)" "$skew (CRITICAL)"
                Add-Issue "Часы рассинхронизированы на $skew сек (NTP=$ntp). TLS-сертификаты будут считаться невалидными"
            }
        } catch {}
    }
    if ($skews.Count -gt 0 -and -not ($skews | Where-Object { [Math]::Abs($_) -gt 60 })) {
        Write-Item "Clock skew" "OK (max $([Math]::Round(($skews | ForEach-Object { [Math]::Abs($_) } | Measure-Object -Maximum).Maximum, 2)) sec)"
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
    } catch {}

    # Hosts file: показываем ТОЛЬКО строки, которые трогают наши домены
    # (полный hosts с 200+ записями discord/telegram нам ни о чём не говорит)
    $hostsLines = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue |
                  Where-Object { $_ -notmatch "^\s*(#|$)" }
    $relevantHosts = @()
    foreach ($line in $hostsLines) {
        foreach ($d in $script:OurDomains) {
            if ($line -match [regex]::Escape($d)) {
                $relevantHosts += $line.Trim()
                Add-Issue "Hosts-файл переопределяет наш домен: $($line.Trim())"
                break
            }
        }
    }
    if ($relevantHosts.Count -gt 0) {
        Write-Raw "  [hosts entries для наших доменов — ПОДОЗРИТЕЛЬНО]"
        foreach ($l in $relevantHosts) { Write-Raw "    $l" }
    } else {
        Write-Item "hosts наши домены" "не трогает (OK)"
    }

    # Resolve наших доменов через разные DNS — сравниваем результаты
    foreach ($hostname in $script:OurDomains) {
        $sysIps = $null
        try {
            $sysIps = [Net.Dns]::GetHostAddresses($hostname) | ForEach-Object { $_.IPAddressToString } | Sort-Object
        } catch {
            Write-Item "$hostname (system)" "FAILED: $($_.Exception.Message)"
            Add-Issue "Системный резолвер не находит $hostname"
            continue
        }

        $extResults = @{}
        foreach ($srv in @("1.1.1.1", "8.8.8.8")) {
            try {
                $r = Resolve-DnsName -Name $hostname -Server $srv -Type A -DnsOnly -QuickTimeout -ErrorAction Stop
                $extResults[$srv] = ($r | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress } | Sort-Object)
            } catch {}
        }

        # Сравниваем системный резолвер с публичным DNS — расхождение = подозрение на DNS-hijack
        $sysJoined = ($sysIps -join ",")
        $hijack = $false
        foreach ($srv in $extResults.Keys) {
            $extJoined = ($extResults[$srv] -join ",")
            if ($extJoined -and $sysJoined -ne $extJoined) {
                $hijack = $true
                Write-Item "$hostname" "system=$sysJoined  via $srv=$extJoined  (РАСХОЖДЕНИЕ)"
                Add-Issue "DNS hijack: $hostname резолвится в $sysJoined локально, но в $extJoined через $srv"
            }
        }
        if (-not $hijack) {
            Write-Item "$hostname" "$sysJoined (DNS совпадает с публичным)"
        }
    }
}

# ================================================================
# 5. Root Certificate Store
# ================================================================
function Collect-RootStore {
    Write-Section "ROOT CERTIFICATE STORE"

    # Корни, которые реально нужны лоадеру:
    # - ISRG Root X1 — keyauth.win и большинство Let's Encrypt
    # - GlobalSign Root R3 (rf4-game.com, fishing-hack.com)
    # - DigiCert Global Root G2 / Microsoft TLS RSA Root G2 — на всякий случай
    $critical = @{
        "ISRG Root X1 (Let's Encrypt → keyauth.win)" = "CABD2A79A1076A31F21D253635CB039D4329A5E8"
        "GlobalSign Root R3 (rf4-game.com)"          = "D69B561148F01C77C54578C10926DF5B856976AD"
        "DigiCert Global Root G2"                    = "DF3C24F9BFD666761B268073FE06D1CC8D4F82A4"
    }

    $missing = @()
    foreach ($name in $critical.Keys) {
        $thumb   = $critical[$name]
        $machine = Test-Path "Cert:\LocalMachine\Root\$thumb"
        $user    = Test-Path "Cert:\CurrentUser\Root\$thumb"
        if (-not $machine -and -not $user) {
            Write-Item $name "MISSING"
            Add-Issue "Корневой сертификат отсутствует в хранилище: $name"
            $missing += $name
        }
    }
    if ($missing.Count -eq 0) { Write-Item "Critical roots" "all present (OK)" }

    # AV / MITM корни — только если найдены
    $avPatterns = @(
        "Kaspersky", "AVAST", "ESET", "Bitdefender", "Avira", "AVG",
        "Sophos", "McAfee", "Norton", "Symantec Endpoint", "DrWeb", "Dr.Web"
    )
    $found = @()
    foreach ($store in @("Cert:\LocalMachine\Root", "Cert:\CurrentUser\Root")) {
        Get-ChildItem $store -ErrorAction SilentlyContinue | ForEach-Object {
            foreach ($p in $avPatterns) {
                if ($_.Subject -match $p -or $_.Issuer -match $p) {
                    $found += "$store : $($_.Subject)"
                    Add-Issue "AV/MITM-корень в хранилище: $($_.Subject) — антивирус подменяет TLS"
                }
            }
        }
    }
    if ($found) {
        Write-Raw "  [SSL-inspection AV roots — могут ломать TLS]"
        foreach ($f in $found) { Write-Raw "    $f" }
    }
}

# ================================================================
# 6. Proxy
# ================================================================
function Collect-ProxyConfig {
    Write-Section "PROXY"
    $anyProxy = $false

    try {
        $ieKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        $p = Get-ItemProperty $ieKey -ErrorAction SilentlyContinue
        if ($p.ProxyEnable -eq 1) {
            Write-Item "WinINET ProxyEnable" "1 (АКТИВЕН)"
            Write-Item "WinINET ProxyServer" $p.ProxyServer
            Add-Issue "Активный системный прокси WinINET: $($p.ProxyServer) — может перехватывать TLS"
            $anyProxy = $true
        }
        if ($p.AutoConfigURL) {
            Write-Item "WinINET AutoConfigURL" $p.AutoConfigURL
            Add-Issue "PAC-скрипт настроен: $($p.AutoConfigURL)"
            $anyProxy = $true
        }
    } catch {}

    # .NET DefaultWebProxy — что увидит лоадер на C#/.NET
    try {
        $u = [Uri]'https://keyauth.win/'
        $wp = [Net.WebRequest]::DefaultWebProxy
        if ($wp -and -not $wp.IsBypassed($u)) {
            $proxied = $wp.GetProxy($u)
            if ($proxied -and "$proxied" -ne "$u") {
                Write-Item ".NET proxy → keyauth.win" $proxied
                Add-Issue ".NET DefaultWebProxy направляет keyauth.win через $proxied"
                $anyProxy = $true
            }
        }
    } catch {}

    # netsh winhttp — пробуем разные кодировки. После chcp 65001 (см. начало
    # скрипта) netsh обычно пишет в UTF-8, но если chcp не успел — будет OEM.
    # Берём ту кодировку, при которой удалось распознать текст.
    $netshOut = $null
    foreach ($enc in @([System.Text.UTF8Encoding]::new($false), $script:OemEncoding)) {
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "netsh.exe"
            $psi.Arguments = "winhttp show proxy"
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.CreateNoWindow = $true
            $psi.StandardOutputEncoding = $enc
            $proc = [System.Diagnostics.Process]::Start($psi)
            $candidate = $proc.StandardOutput.ReadToEnd()
            $proc.WaitForExit(3000) | Out-Null
            # Признаки распознанного текста: ASCII "Direct"/"WinHTTP" или
            # корректные русские слова. Мохибейк "╨╡╨║" отбрасываем.
            if ($candidate -match 'Direct\s+access|Прямой\s+доступ|WinHTTP') {
                $netshOut = $candidate
                break
            }
            if (-not $netshOut) { $netshOut = $candidate }
        } catch {}
    }

    if ($netshOut -and $netshOut -notmatch 'Direct\s+access|Прямой\s+доступ') {
        Write-Raw "  [netsh winhttp show proxy]"
        foreach ($line in ($netshOut -split "`r?`n" | Where-Object { $_.Trim() })) {
            Write-Raw "    $line"
        }
        Add-Issue "WinHTTP-прокси настроен (см. netsh winhttp show proxy)"
        $anyProxy = $true
    }

    foreach ($var in @("HTTP_PROXY","HTTPS_PROXY","NO_PROXY")) {
        $v = [Environment]::GetEnvironmentVariable($var)
        if ($v) {
            Write-Item "env:$var" $v
            Add-Issue "Переменная окружения $var=$v"
            $anyProxy = $true
        }
    }

    if (-not $anyProxy) { Write-Item "Proxy" "не настроен (OK)" }
}

# ================================================================
# 7. Антивирусы / Firewall
# ================================================================
function Collect-AVInfo {
    Write-Section "SECURITY SOFTWARE"
    $printed = 0
    try {
        $avs = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
        foreach ($av in $avs) {
            $name = $av.displayName
            # Defender сам по себе TLS не ломает — пропускаем, чтоб не флудить
            if ($name -match 'Windows\s+Defender|Microsoft\s+Defender') { continue }
            Write-Item "AntiVirus" $name
            $printed++
            if ($name -match 'Kaspersky|ESET|Bitdefender|Avast|AVG|Sophos|McAfee|Norton|Symantec|Dr\.?Web') {
                Add-Issue "Установлен AV ($name) — может делать SSL-инспекцию и подменять сертификаты"
            }
        }
    } catch {}
    if ($printed -eq 0) { Write-Item "AntiVirus" "Defender / нет сторонних (OK)" }
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

    # Только домены, по которым реально ходит лоадер.
    # Microsoft/Cloudflare/badssl убраны — они не отвечают на вопрос "что сломано".
    $targets = @(
        @{ host = "keyauth.win";      role = "auth target"  },
        @{ host = "rf4-game.com";     role = "site"         },
        @{ host = "fishing-hack.com"; role = "site"         }
    )

    foreach ($t in $targets) {
        $r = Test-TlsEndpoint -TargetHost $t.host
        $hasIssue = (-not $r.ok) -or ($r.chain_errors -and $r.chain_errors -ne "NoError") -or $r.error

        if ($hasIssue) {
            Write-Raw ""
            Write-Raw "  [$($t.role)] $($t.host) — ПРОБЛЕМА"
            Write-Item "  ok"            $r.ok
            if ($r.negotiated)   { Write-Item "  negotiated"    $r.negotiated }
            if ($r.chain_errors) { Write-Item "  chain_errors"  $r.chain_errors }
            if ($r.error)        { Write-Item "  ERROR"         $r.error }

            # Подробная цепочка только при проблеме — чтобы понять, чьим Issuer подписан leaf
            for ($i = 0; $i -lt $r.chain.Count; $i++) {
                $c = $r.chain[$i]
                Write-Raw "    [cert $i] $($c.subject)"
                Write-Raw "             issued by $($c.issuer)"
                if ($c.status -and $c.status -ne "NoError") {
                    Write-Raw "             status: $($c.status)"
                }
            }

            if ($r.error)        { Add-Issue "TLS handshake к $($t.host) упал: $($r.error)" }
            elseif ($r.chain_errors -and $r.chain_errors -ne "NoError") {
                Add-Issue "TLS-цепочка $($t.host) невалидна: $($r.chain_errors)"
            }
        } else {
            Write-Item $t.host "OK ($($r.negotiated))"
        }
    }
}

# ================================================================
# 9. WinHTTP / WinINET sanity
# ================================================================
function Collect-WinHttpProbe {
    Write-Section 'HTTPS REACHABILITY'
    $urls = @(
        "https://keyauth.win/",
        "https://rf4-game.com/"
    )
    foreach ($u in $urls) {
        try {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $resp = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
            $sw.Stop()
            Write-Item $u "OK ($($resp.StatusCode), $($sw.ElapsedMilliseconds)ms)"
        } catch {
            $ex = $_.Exception
            $msg = $ex.Message
            while ($ex.InnerException) { $ex = $ex.InnerException; $msg += " -> $($ex.Message)" }
            Write-Item $u "FAIL: $msg"
            Add-Issue "HTTPS-запрос к $u падает: $msg"
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
Write-Host "  Сбор диагностики занимает 20-40 секунд, пожалуйста подождите..."

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

# Сводка проблем — печатаем в самом конце (видно при прокрутке вверх),
# и дублируем в начало текстового отчёта, чтобы разработчик увидел сразу
$summary = [System.Collections.Generic.List[string]]::new()
$summary.Add("")
$summary.Add("=" * 70)
$summary.Add("  ИТОГ")
$summary.Add("=" * 70)
if ($script:Issues.Count -eq 0) {
    $summary.Add("  Проблем, мешающих TLS/HTTPS-запуску, не обнаружено.")
} else {
    $summary.Add("  Найдено проблем: $($script:Issues.Count)")
    $i = 1
    foreach ($issue in $script:Issues) {
        $summary.Add("    $i. $issue")
        $i++
    }
}

# В консоль — в конце
Write-Host ""
foreach ($l in $summary) {
    if ($l -match '^=+$' -or $l -match 'ИТОГ') {
        Write-Host $l -ForegroundColor Cyan
    } elseif ($script:Issues.Count -eq 0) {
        Write-Host $l -ForegroundColor Green
    } else {
        Write-Host $l -ForegroundColor Yellow
    }
}

# В файл — сводка идёт первой, потом полный отчёт
$desktop = [Environment]::GetFolderPath("Desktop")
$outPath = Join-Path $desktop "tls-diag-report.txt"
try {
    $finalReport = ($summary -join "`r`n") + "`r`n" + ($script:Report -join "`r`n")
    [System.IO.File]::WriteAllText($outPath, $finalReport, [System.Text.UTF8Encoding]::new($true))
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
