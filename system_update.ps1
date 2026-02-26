#Requires -Version 7.0
<#
.SYNOPSIS  System Update PowerShell CLI — port of system_update.js (requires PowerShell 7+)
.EXAMPLE   .\system_update.ps1
           .\system_update.ps1 -UpdateAll -Yes
           .\system_update.ps1 -Source npm -NoCache
           .\system_update.ps1 -Package git -Source chocolatey
           .\system_update.ps1 -Export json -Output report.json
#>
[CmdletBinding()]
param(
    [switch]$UpdateAll,
    [switch]$DryRun,
    [switch]$NoCache,
    [switch]$ClearCache,
    [string]$Export,
    [string]$Output,
    [string]$Package,
    [string]$Version,
    [string]$Source,
    [string]$UpdateSource,
    [string]$Include,
    [switch]$Yes,
    [switch]$Help
)
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

# ── Constants ──────────────────────────────────────────────────────────────────
$VER = '1.0.1'
$DATA_DIR = if ($env:SYSTEM_UPDATE_HOME) { $env:SYSTEM_UPDATE_HOME } else { Join-Path $env:USERPROFILE '.system_update' }
$CACHE_FILE = Join-Path $DATA_DIR 'cache.json'
$LOG_FILE = Join-Path $DATA_DIR 'system.log'

$S_OK = 'up_to_date'
$S_UPD = 'update_available'
$S_UNK = 'unknown'
$S_VULN = 'vulnerable'
$S_SEC = 'security_update_available'
$S_ERR = 'error'

$CFG_CACHE_HOURS = 2
$CFG_TIMEOUT = 45
$CFG_SECURITY = $true
$CFG_SEVERITY = 'medium'

# ── ANSI ───────────────────────────────────────────────────────────────────────
$COLOR = $Host.UI.SupportsVirtualTerminal
function c([string]$code, [string]$t) { if ($COLOR) { "$([char]27)[$($code)m$t$([char]27)[0m" }else { $t } }
function bold   ([string]$t) { c '1'    $t }
function dim    ([string]$t) { c '2'    $t }
function red    ([string]$t) { c '31'   $t }
function green  ([string]$t) { c '32'   $t }
function yellow ([string]$t) { c '33'   $t }
function blue   ([string]$t) { c '34'   $t }
function magenta([string]$t) { c '35'   $t }
function cyan   ([string]$t) { c '36'   $t }
function gray   ([string]$t) { c '90'   $t }

# ── Emoji ──────────────────────────────────────────────────────────────────────
# Using [char]::ConvertFromUtf32 for surrogate-pair emoji — safe on all PS versions
function E([string]$n) {
    switch ($n) {
        'rocket' { [char]::ConvertFromUtf32(0x1F680) }
        'package' { [char]::ConvertFromUtf32(0x1F4E6) }
        'scan' { [char]::ConvertFromUtf32(0x1F50E) }
        'update' { "$([char]::ConvertFromUtf32(0x2B06))$([char]0xFE0F)" }
        'ok' { "$([char]::ConvertFromUtf32(0x2705))" }
        'warn' { "$([char]::ConvertFromUtf32(0x26A0))$([char]0xFE0F)" }
        'fail' { [char]::ConvertFromUtf32(0x274C) }
        'gear' { "$([char]::ConvertFromUtf32(0x2699))$([char]0xFE0F)" }
        'sparkle' { [char]::ConvertFromUtf32(0x2728) }
        'chart' { [char]::ConvertFromUtf32(0x1F4CA) }
        'disk' { [char]::ConvertFromUtf32(0x1F4BE) }
        'hourglass' { "$([char]::ConvertFromUtf32(0x23F1))$([char]0xFE0F)" }
        'export' { [char]::ConvertFromUtf32(0x1F4C4) }
        'lock' { [char]::ConvertFromUtf32(0x1F512) }
        'fire' { [char]::ConvertFromUtf32(0x1F525) }
        'shield' { "$([char]::ConvertFromUtf32(0x1F6E1))$([char]0xFE0F)" }
        'unknown' { '❔' }
        default { '' }
    }
}

function statusBadge([string]$s) {
    switch ($s) {
        $S_UPD { c '33;1' "$(E 'update') update" }
        $S_OK { green "$(E 'ok') up-to-date" }
        $S_ERR { red "$(E 'fail') error" }
        $S_VULN { c '31;1' "$(E 'fire') vulnerable" }
        $S_SEC { c '35;1' "$(E 'lock') security update" }
        default { gray "$(E 'unknown') unknown" }
    }
}

function srcBadge([string]$s) {
    switch ($s.Trim().ToLower()) {
        'winget' { c '34;1' $s }
        'chocolatey' { c '33;1' $s }
        'npm' { c '31;1' $s }
        'pnpm' { c '35;1' $s }
        'bun' { c '35;1' $s }
        'yarn' { c '34;1' $s }
        'pip' { c '36;1' $s }
        'path' { c '32;1' $s }
        'registry' { c '90;1' $s }
        default { gray $s }
    }
}

# ── Progress ───────────────────────────────────────────────────────────────────
function New-Progress([int]$Total, [string]$Label) {
    $p = [PSCustomObject]@{N = 0; T = $Total; L = $Label; S = [datetime]::Now }
    $p | Add-Member ScriptMethod Render { param([string]$X = '')
        $r = if ($this.T -eq 0) { 1.0 }else { [Math]::Min(1.0, $this.N / $this.T) }
        $f = [Math]::Round(26 * $r)
        $bar = ('█' * $f) + ('░' * (26 - $f))
        $pct = "$([Math]::Round($r*100))%".PadLeft(4)
        $el = ([datetime]::Now - $this.S).TotalSeconds.ToString('0.0')
        $msg = "$($this.L) $bar $pct ($($this.N)/$($this.T)) $(E 'hourglass') ${el}s $X"
        Write-Host "`r$([char]27)[2K$msg" -NoNewline
    }
    $p | Add-Member ScriptMethod Tick { param([string]$X = ''); $this.N++; $this.Render($X) }
    $p | Add-Member ScriptMethod Done { param([string]$X = ''); $this.N = $this.T; $this.Render($X); Write-Host '' }
    $p.Render(); return $p
}

# ── Header ─────────────────────────────────────────────────────────────────────
function Show-Header([string]$Title, [string]$Sub) {
    Write-Host (cyan "┌$('─'*70)┐")
    Write-Host (c '1;36' "│ $($Title.PadRight(69))│")
    Write-Host (c '2;36' "│ $($Sub.PadRight(69))│")
    Write-Host (cyan "└$('─'*70)┘")
}

# ── Log ────────────────────────────────────────────────────────────────────────
function Write-Log([string]$Msg) {
    try { "$(Get-Date -f 'o') $Msg" | Add-Content $LOG_FILE -Encoding UTF8 -EA SilentlyContinue }catch {}
}

# ── Invoke-Cmd ────────────────────────────────────────────────────────────────
# Handles all Windows executable types:
#   .ps1 (ExternalScript like npm from nvm) → pwsh -NonInteractive -File ...
#   .cmd/.bat                                → cmd.exe /d /c ...
#   .exe / AppX alias                        → ProcessStartInfo directly
function Invoke-Cmd {
    param([string]$Cmd, [string[]]$CmdArgs = @(), [int]$TimeoutSec = $CFG_TIMEOUT, [switch]$AllowFail, [switch]$Stderr)
    try {
        $exe = Get-Command $Cmd -ErrorAction SilentlyContinue
        # Use Source only for real file-system commands (Application, ExternalScript)
        $exePath = if ($exe -and $exe.Source) { $exe.Source } else { $Cmd }

        $psi = New-Object System.Diagnostics.ProcessStartInfo

        if ($exePath -match '\.ps1$') {
            # ExternalScript — run through pwsh
            $psi.FileName = (Get-Command 'pwsh' -EA SilentlyContinue)?.Source ?? 'pwsh'
            [void]$psi.ArgumentList.Add('-NonInteractive')
            [void]$psi.ArgumentList.Add('-NoProfile')
            [void]$psi.ArgumentList.Add('-File')
            [void]$psi.ArgumentList.Add($exePath)
            foreach ($arg in $CmdArgs) { [void]$psi.ArgumentList.Add($arg) }
        }
        elseif ($exePath -match '\.(cmd|bat)$') {
            # Batch script — run through cmd.exe
            $psi.FileName = $env:COMSPEC
            $quotedPath = if ($exePath -match '\s') { "`"$exePath`"" } else { $exePath }
            $quotedArgs = ($CmdArgs | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }) -join ' '
            $psi.Arguments = "/d /c $quotedPath $quotedArgs"
        }
        else {
            # Native exe / AppX alias
            $psi.FileName = $exePath
            foreach ($arg in $CmdArgs) { [void]$psi.ArgumentList.Add($arg) }
        }

        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8

        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        $proc.Start() | Out-Null

        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()
        $done = $proc.WaitForExit($TimeoutSec * 1000)

        if (-not $done) { try { $proc.Kill() } catch {}; return [PSCustomObject]@{Ok = $false; Stdout = ''; Stderr = 'timeout'; Code = $null } }

        $outStr = $outTask.GetAwaiter().GetResult().Trim()
        $errStr = $errTask.GetAwaiter().GetResult().Trim()
        $code = $proc.ExitCode
        $ok = if ($AllowFail) { $true } else { $code -eq 0 }
        $out = if ($Stderr) { "$outStr`n$errStr".Trim() } else { $outStr }
        return [PSCustomObject]@{Ok = $ok; Stdout = $out; Stderr = $errStr; Code = $code }
    }
    catch {
        Write-Log "Invoke-Cmd $Cmd $($CmdArgs -join ' '): $_"
        return [PSCustomObject]@{Ok = $false; Stdout = ''; Stderr = "$_"; Code = $null }
    }
}

function cmd-ok([string]$Cmd) {
    # Use 'where.exe' explicitly — 'where' alone is a PowerShell alias for Where-Object
    $r = Invoke-Cmd 'where.exe' @($Cmd) -AllowFail -TimeoutSec 10
    return ($r.Ok -and $r.Stdout)
}

function gh-release([string]$Url) {
    try { return Invoke-RestMethod -Uri $Url -Headers @{'User-Agent' = 'SystemUpdateCLI' } -TimeoutSec 10 } catch { return $null }
}

# Invoke-NativeCmd: runs a command via PS job (handles encoding-sensitive tools like winget)
function Invoke-NativeCmd {
    param([string]$Cmd, [string[]]$CmdArgs = @(), [int]$TimeoutSec = $CFG_TIMEOUT, [switch]$AllowFail, [switch]$Stderr)
    $job = Start-Job -ScriptBlock {
        param($c, $a, $se)
        $ErrorActionPreference = 'SilentlyContinue'
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
        try {
            if ($se) {
                $out = & $c @a 2>&1 | Out-String
            }
            else {
                $out = & $c @a 2>$null | Out-String
            }
            @{ Out = $out.Trim(); Code = $LASTEXITCODE }
        }
        catch {
            @{ Out = ''; Code = 1 }
        }
    } -ArgumentList $Cmd, $CmdArgs, $Stderr.IsPresent

    if (-not (Wait-Job $job -Timeout $TimeoutSec)) {
        Stop-Job $job; Remove-Job $job -Force
        return [PSCustomObject]@{Ok = $false; Stdout = ''; Stderr = 'timeout'; Code = $null }
    }
    $r = Receive-Job $job -ErrorAction SilentlyContinue
    Remove-Job $job -Force
    $rOut = if ($r -and $r.Out) { $r.Out }  else { '' }
    $rCode = if ($r -and $null -ne $r.Code) { $r.Code } else { $null }
    $ok = if ($AllowFail) { $true } else { $rCode -eq 0 }
    return [PSCustomObject]@{Ok = $ok; Stdout = $rOut; Stderr = ''; Code = $rCode }
}

# ── Winget Table Parser ────────────────────────────────────────────────────────
function Parse-Winget([string]$Out, [switch]$Avail) {
    $apps = @(); if (-not $Out) { return $apps }
    $lines = $Out -split "`r?`n"
    $hi = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match 'Name' -and $lines[$i] -match 'Id' -and $lines[$i] -match 'Version') { $hi = $i; break } }
    if ($hi -lt 0) { return $apps }
    $h = $lines[$hi]
    $pos = @{id = $h.IndexOf('Id'); ver = $h.IndexOf('Version'); avail = $h.IndexOf('Available'); src = $h.IndexOf('Source') }
    foreach ($line in $lines[($hi + 2)..($lines.Count - 1)]) {
        if (-not $line.Trim()) { continue }
        try {
            $name = $line.Substring(0, [Math]::Max($pos.id, 0)).Trim()
            $appId = if ($pos.ver -gt 0) { $line.Substring($pos.id, $pos.ver - $pos.id).Trim() }else { '' }
            $vEnd = if ($pos.avail -gt -1) { $pos.avail }elseif ($pos.src -gt -1) { $pos.src }else { $line.Length }
            $ver = if ($pos.ver -gt -1) { $line.Substring($pos.ver, $vEnd - $pos.ver).Trim() }else { '' }
            $latest = ''
            if ($Avail -and $pos.avail -gt -1) { $aEnd = if ($pos.src -gt -1) { $pos.src }else { $line.Length }; $latest = $line.Substring($pos.avail, $aEnd - $pos.avail).Trim() }
            if ($name -and $appId -and $ver) {
                $apps += [PSCustomObject]@{Name = $name; Source = 'winget'; Version = $ver; LatestVersion = $latest; AppId = $appId; Status = if ($latest) { $S_UPD }else { $S_UNK } }
            }
        }
        catch {}
    }
    return $apps
}

# ── Scanners ───────────────────────────────────────────────────────────────────
function Scan-Winget {
    # Use Invoke-NativeCmd: winget outputs UTF-16LE which ProcessStartInfo misreads with UTF8 encoding
    $r = Invoke-NativeCmd 'winget' @('list', '--accept-source-agreements') -AllowFail
    Parse-Winget $r.Stdout
}

function Scan-Chocolatey {
    $r = Invoke-Cmd 'choco' @('list', '--local-only', '--limit-output') -AllowFail
    @($r.Stdout -split "`r?`n" | ForEach-Object {
            $p = $_ -split '\|'
            if ($p.Count -ge 2 -and $p[0] -and $p[1]) {
                [PSCustomObject]@{Name = $p[0].Trim(); Source = 'chocolatey'; Version = $p[1].Trim(); LatestVersion = ''; AppId = $p[0].Trim(); Status = $S_UNK }
            }
        } | Where-Object { $_ })
}

function Scan-Npm {
    # Use Invoke-NativeCmd: npm may be a .ps1 ExternalScript (nvm for Windows) that ProcessStartInfo handles incorrectly
    $r = Invoke-NativeCmd 'npm' @('list', '-g', '--depth=0', '--json', '--silent') -AllowFail
    $apps = @()
    if (-not $r.Stdout) { return $apps }
    try {
        $j = $r.Stdout | ConvertFrom-Json
        if ($j.dependencies) {
            $j.dependencies.PSObject.Properties | ForEach-Object {
                $ver = if ($_.Value.version) { $_.Value.version } else { 'N/A' }
                $apps += [PSCustomObject]@{Name = $_.Name; Source = 'npm'; Version = $ver; LatestVersion = ''; AppId = $_.Name; Status = $S_UNK }
            }
        }
    }
    catch { Write-Log "npm list: $_" }
    return $apps
}

function Scan-Pnpm {
    $r = Invoke-NativeCmd 'pnpm' @('list', '-g', '--depth=0', '--json') -AllowFail
    $apps = @()
    if (-not $r.Stdout) { return $apps }
    try {
        $j = $r.Stdout | ConvertFrom-Json
        $root = if ($j -is [array]) { $j[0] } else { $j }
        if ($root -and $root.dependencies) {
            $root.dependencies.PSObject.Properties | ForEach-Object {
                $ver = if ($_.Value.version) { $_.Value.version } else { 'N/A' }
                $apps += [PSCustomObject]@{Name = $_.Name; Source = 'pnpm'; Version = $ver; LatestVersion = ''; AppId = $_.Name; Status = $S_UNK }
            }
        }
    }
    catch { Write-Log "pnpm list: $_" }
    return $apps
}

function Scan-Bun {
    $r = Invoke-Cmd 'bun' @('pm', 'ls', '-g') -AllowFail
    @($r.Stdout -split "`r?`n" | ForEach-Object {
            if ($_ -match '^\s*([^\s@]+)@([^\s]+)') {
                [PSCustomObject]@{Name = $Matches[1]; Source = 'bun'; Version = $Matches[2]; LatestVersion = ''; AppId = $Matches[1]; Status = $S_UNK }
            }
        } | Where-Object { $_ })
}

function Scan-Yarn {
    $r = Invoke-Cmd 'yarn' @('global', 'list') -AllowFail
    @($r.Stdout -split "`r?`n" | ForEach-Object {
            if ($_ -match '^info "([^@]+)@([^"]+)"') {
                [PSCustomObject]@{Name = $Matches[1]; Source = 'yarn'; Version = $Matches[2]; LatestVersion = ''; AppId = $Matches[1]; Status = $S_UNK }
            }
        } | Where-Object { $_ })
}

function Scan-Pip {
    $apps = @()
    foreach ($run in @('py', 'python', 'python3', 'pip')) {
        $a = if ($run -ne 'pip') { @('-m', 'pip', 'list', '--format=json') }else { @('list', '--format=json') }
        $r = Invoke-Cmd $run $a -AllowFail
        if ($r.Stdout) {
            try {
                ($r.Stdout | ConvertFrom-Json) | ForEach-Object {
                    $apps += [PSCustomObject]@{Name = $_.name; Source = 'pip'; Version = $_.version; LatestVersion = ''; AppId = $_.name; Status = $S_UNK }
                }
                break
            }
            catch { Write-Log "pip list: $_" }
        }
    }
    return $apps
}

function Scan-Path {
    $tools = @('node', 'npm', 'pnpm', 'yarn', 'python', 'git', 'go', 'bun', 'deno', 'rustc', 'cargo', 'dotnet', 'java', 'pwsh')
    $apps = @()
    foreach ($tool in $tools) {
        if (-not (cmd-ok $tool)) { continue }
        $va = if ($tool -eq 'java') { @('-version') }else { @('--version') }
        $r = Invoke-Cmd $tool $va -AllowFail -Stderr -TimeoutSec 10
        $first = ($r.Stdout -split "`r?`n")[0]
        if (-not $first) { $first = 'installed' }
        $ver = if ($first -match '(\d+\.\d+(?:\.\d+)*)') { $Matches[1] }else { $first.Substring(0, [Math]::Min(80, $first.Length)) }
        $apps += [PSCustomObject]@{Name = $tool; Source = 'path'; Version = $ver; LatestVersion = ''; AppId = $tool; Status = $S_UNK }
    }
    return $apps
}

function Scan-Registry {
    $seen = @{}
    $paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($path in $paths) {
        try {
            $regItems = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if (-not $regItems) { continue }
            foreach ($item in @($regItems)) {
                try {
                    if (-not $item.DisplayName -or -not $item.DisplayVersion) { continue }
                    # PSObject.Properties avoids StrictMode error when SystemComponent prop is missing
                    $sysCmp = $item.PSObject.Properties['SystemComponent']
                    if ($sysCmp -and $sysCmp.Value) { continue }
                    $key = "$($item.DisplayName)|$($item.DisplayVersion)"
                    if ($seen.ContainsKey($key)) { continue }
                    $seen[$key] = $true
                    $list.Add([PSCustomObject]@{
                            Name = $item.DisplayName.Trim(); Source = 'registry'
                            Version = $item.DisplayVersion.Trim(); LatestVersion = ''
                            AppId = $item.PSChildName; Status = $S_UNK
                        })
                }
                catch { }
            }
        }
        catch { }
    }
    return [array]@($list | Sort-Object Name)
}

function Get-Unique([array]$Apps) {
    $map = @{}
    foreach ($a in $Apps) { $k = "$($a.Source)|$($a.Name)|$($a.Version)".ToLower(); $map[$k] = $a }
    return [array]@($map.Values | Sort-Object { $_.Source + $_.Name })
}

# ── Cache ──────────────────────────────────────────────────────────────────────
function Load-Cache {
    if (-not(Test-Path $CACHE_FILE)) { return $null }
    try {
        $j = Get-Content $CACHE_FILE -Raw -Encoding UTF8 | ConvertFrom-Json
        if (([datetime]::UtcNow - [datetime]::Parse($j.timestamp)).TotalHours -gt $CFG_CACHE_HOURS) { return $null }
        return $j.apps
    }
    catch { return $null }
}
function Save-Cache([array]$Apps) {
    if (-not(Test-Path $DATA_DIR)) { New-Item -ItemType Directory $DATA_DIR -Force | Out-Null }
    @{timestamp = (Get-Date -f 'o'); version = $VER; totalApps = $Apps.Count; apps = $Apps } | ConvertTo-Json -Depth 10 | Set-Content $CACHE_FILE -Encoding UTF8
}
function Clear-AppCache { if (Test-Path $CACHE_FILE) { Remove-Item $CACHE_FILE -Force } }

# ── Update Checkers ────────────────────────────────────────────────────────────
function Check-Winget([array]$Apps) {
    $t = @($Apps | Where-Object { $_.Source -eq 'winget' }); if (-not $t) { return 0 }
    $upd = Parse-Winget (Invoke-NativeCmd 'winget' @('upgrade', '--accept-source-agreements') -AllowFail).Stdout -Avail
    $n = 0
    foreach ($u in $upd) {
        $a = $t | Where-Object { $_.AppId -and $u.AppId -and $_.AppId.ToLower() -eq $u.AppId.ToLower() } | Select-Object -First 1
        if (-not $a) { continue }; $a.LatestVersion = $u.LatestVersion; $a.Status = $S_UPD; $n++
    }
    return $n
}

function Check-Registry([array]$Apps) {
    $t = @($Apps | Where-Object { $_.Source -eq 'registry' }); if (-not $t) { return 0 }
    $upd = Parse-Winget (Invoke-NativeCmd 'winget' @('upgrade', '--accept-source-agreements') -AllowFail).Stdout -Avail
    $map = @{}; foreach ($u in $upd) { $map[$u.Name.ToLower()] = $u }
    $n = 0
    foreach ($a in $t) {
        $m = $map[$a.Name.ToLower()]
        if ($m -and $m.LatestVersion) { $a.LatestVersion = $m.LatestVersion; $a.Status = $S_UPD; $n++ } else { $a.Status = $S_OK }
    }
    return $n
}

function Check-Choco([array]$Apps) {
    $t = @($Apps | Where-Object { $_.Source -eq 'chocolatey' }); if (-not $t) { return 0 }
    $r = Invoke-Cmd 'choco' @('outdated', '--limit-output') -AllowFail; $n = 0
    foreach ($line in ($r.Stdout -split "`r?`n")) {
        $p = $line -split '\|'; if ($p.Count -lt 3 -or -not $p[0] -or -not $p[2]) { continue }
        $a = $t | Where-Object { $_.Name.ToLower() -eq $p[0].Trim().ToLower() } | Select-Object -First 1
        if (-not $a) { continue }; $a.LatestVersion = $p[2].Trim(); $a.Status = $S_UPD; $n++
    }
    return $n
}

function Check-Npm([array]$Apps) {
    $t = @($Apps | Where-Object { $_.Source -eq 'npm' }); if (-not $t) { return 0 }
    $r = Invoke-NativeCmd 'npm' @('outdated', '-g', '--json') -AllowFail; if (-not $r.Stdout) { return 0 }
    $n = 0
    try {
        $j = $r.Stdout | ConvertFrom-Json
        foreach ($prop in $j.PSObject.Properties) {
            $nm = $prop.Name
            $app = $t | Where-Object { $_.Name -eq $nm } | Select-Object -First 1
            if (-not $app) { continue }
            $lat = $j.$nm.latest ?? ''
            if ($lat) { $app.LatestVersion = $lat; $app.Status = $S_UPD; $n++ }
        }
    }
    catch { Write-Log "npm outdated: $_" }
    return $n
}

function Check-Pnpm([array]$Apps) {
    $t = @($Apps | Where-Object { $_.Source -eq 'pnpm' }); if (-not $t) { return 0 }
    $r = Invoke-NativeCmd 'pnpm' @('outdated', '-g', '--json') -AllowFail; if (-not $r.Stdout) { return 0 }
    $n = 0
    try {
        $j = $r.Stdout | ConvertFrom-Json
        $entries = if ($j -is [array]) { $j | ForEach-Object { [PSCustomObject]@{N = $_.name; L = $_.latest ?? $_.wanted ?? '' } } }
        else { $j.PSObject.Properties | ForEach-Object { $v = $j.$($_.Name); [PSCustomObject]@{N = $_.Name; L = $v.latest ?? $v.wanted ?? '' } } }
        foreach ($e in $entries) {
            $a = $t | Where-Object { $_.Name -eq $e.N } | Select-Object -First 1
            if (-not $a -or -not $e.L) { continue }; $a.LatestVersion = $e.L; $a.Status = $S_UPD; $n++
        }
    }
    catch { Write-Log "pnpm outdated: $_" }
    return $n
}

function Check-Bun([array]$Apps) {
    $t = @($Apps | Where-Object { $_.Source -eq 'bun' }); $n = 0
    foreach ($a in $t) {
        $r = Invoke-NativeCmd 'npm' @('info', $a.Name, 'version') -AllowFail
        $l = $r.Stdout.Trim()
        if ($l -and $l -ne $a.Version -and $l -notmatch 'ERR') { $a.LatestVersion = $l; $a.Status = $S_UPD; $n++ }
    }; return $n
}

function Check-Yarn([array]$Apps) {
    $t = @($Apps | Where-Object { $_.Source -eq 'yarn' }); $n = 0
    foreach ($a in $t) {
        $r = Invoke-NativeCmd 'npm' @('info', $a.Name, 'version') -AllowFail
        $l = $r.Stdout.Trim()
        if ($l -and $l -ne $a.Version -and $l -notmatch 'ERR') { $a.LatestVersion = $l; $a.Status = $S_UPD; $n++ }
    }; return $n
}

function Check-Pip([array]$Apps) {
    $t = @($Apps | Where-Object { $_.Source -eq 'pip' }); if (-not $t) { return 0 }; $n = 0
    foreach ($run in @('py', 'python', 'python3', 'pip')) {
        $a2 = if ($run -ne 'pip') { @('-m', 'pip', 'list', '--outdated', '--format=json') } else { @('list', '--outdated', '--format=json') }
        $r = Invoke-Cmd $run $a2 -AllowFail
        if ($r.Stdout) {
            try {
                ($r.Stdout | ConvertFrom-Json) | ForEach-Object {
                    $nm = $_.name; $app = $t | Where-Object { $_.Name.ToLower() -eq $nm.ToLower() } | Select-Object -First 1
                    if ($app -and $_.latest_version) { $app.LatestVersion = $_.latest_version; $app.Status = $S_UPD; $n++ }
                }
                break
            }
            catch { Write-Log "pip outdated: $_" }
        }
    }; return $n
}

function Check-PathUpdates([array]$Apps) {
    $t = @($Apps | Where-Object { $_.Source -eq 'path' }); $n = 0
    foreach ($app in $t) {
        $latest = ''
        try {
            switch ($app.Name) {
                'bun' {
                    $r = Invoke-Cmd 'bun' @('upgrade', '--dry-run') -AllowFail -Stderr
                    if ($r.Stdout -match 'Bun v([0-9.]+) is out!') { $latest = $Matches[1] } else { $latest = $app.Version }
                }
                'deno' {
                    $r = Invoke-Cmd 'deno' @('upgrade', '--dry-run') -AllowFail -Stderr
                    if ($r.Stdout -match '(?i)Found latest stable version\s+v?([0-9.]+)') { $latest = $Matches[1] } else { $latest = $app.Version }
                }
                { $_ -in @('yarn', 'npm', 'pnpm', 'node') } {
                    $r = Invoke-NativeCmd 'npm' @('view', $app.Name, 'version') -AllowFail
                    $v = $r.Stdout.Trim(); if ($v -and $v -notmatch 'ERR') { $latest = $v }
                }
                'python' {
                    $d = gh-release 'https://api.github.com/repos/python/cpython/releases/latest'
                    if ($d -and $d.tag_name -match 'v?([0-9.]+)') { $latest = $Matches[1] }
                    if (-not $latest) { $latest = $app.Version }
                }
                'git' {
                    $d = gh-release 'https://api.github.com/repos/git-for-windows/git/releases/latest'
                    if ($d -and $d.tag_name -match 'v?([0-9.]+?)(?:\.windows)') { $latest = $Matches[1] }
                    elseif ($d -and $d.tag_name) { $latest = $d.tag_name -replace '^v', '' }
                }
                'pwsh' {
                    $d = gh-release 'https://api.github.com/repos/PowerShell/PowerShell/releases/latest'
                    if ($d -and $d.tag_name) { $latest = $d.tag_name -replace '^v', '' }
                }
                'dotnet' {
                    $r = Invoke-NativeCmd 'winget' @('show', 'Microsoft.DotNet.SDK.9', '--accept-source-agreements') -AllowFail
                    if ($r.Stdout -match 'Version:\s+([0-9.]+)') { $latest = $Matches[1] }
                }
            }
        }
        catch {}
        if ($latest) {
            $cv = $app.Version -replace '^[^\d]+', ''; $cl = $latest -replace '^[^\d]+', ''
            $app.LatestVersion = $cl
            if ($cl -ne $cv -and -not $app.Version.Contains($cl)) { $app.Status = $S_UPD; $n++ } else { $app.Status = $S_OK }
        }
    }
    return $n
}

function Finalize([array]$Apps) {
    $managed = @('winget', 'chocolatey', 'npm', 'pnpm', 'bun', 'yarn', 'pip', 'registry')
    foreach ($a in $Apps) {
        if ($a.Status -in @($S_UPD, $S_OK)) { continue }
        if ($a.LatestVersion -or $a.Source -in $managed) { $a.Status = $S_OK } else { $a.Status = $S_UNK }
    }
}

# ── Security ───────────────────────────────────────────────────────────────────
function Check-NpmVulns([array]$Apps) {
    $t = @($Apps | Where-Object { $_.Source -eq 'npm' }); if (-not $t) { return @() }
    $r = Invoke-NativeCmd 'npm' @('audit', '--json', '--silent') -AllowFail; if (-not $r.Stdout) { return @() }
    $vulns = @()
    try {
        $j = $r.Stdout | ConvertFrom-Json
        if ($j.vulnerabilities) {
            $j.vulnerabilities.PSObject.Properties | ForEach-Object {
                $nm = $_.Name; $v = $j.vulnerabilities.$nm
                $a = $t | Where-Object { $_.Name.ToLower() -eq $nm.ToLower() } | Select-Object -First 1
                if (-not $a) { return }
                $sev = if ($v.severity) { $v.severity } else { 'low' }
                $cve = if ($v.cves -and $v.cves.Count -gt 0) { $v.cves[0] } else { 'N/A' }
                $desc = if ($v.title) { $v.title } else { 'Vulnerability found' }
                $vulns += [PSCustomObject]@{Pkg = $nm; Sev = $sev; CVE = $cve; Desc = $desc }
            }
        }
    }
    catch {}
    return $vulns
}

function Check-PipVulns([array]$Apps) {
    $t = @($Apps | Where-Object { $_.Source -eq 'pip' }); if (-not $t) { return @() }; $vulns = @()
    foreach ($run in @('py', 'python', 'pip')) {
        $a = if ($run -ne 'pip') { @('-m', 'pip', 'check', '--format=json') } else { @('check', '--format=json') }
        $r = Invoke-Cmd $run $a -AllowFail
        if ($r.Stdout) {
            try {
                ($r.Stdout | ConvertFrom-Json) | ForEach-Object {
                    if (-not $_.vulnerabilities -or $_.vulnerabilities.Count -eq 0) { return }
                    $pn = if ($_.package_name) { $_.package_name } else { $_.name }
                    $found = $t | Where-Object { $_.Name.ToLower() -eq $pn.ToLower() } | Select-Object -First 1
                    if (-not $found) { return }
                    foreach ($vv in $_.vulnerabilities) {
                        $sev = if ($vv.severity) { $vv.severity } else { 'medium' }
                        $cve = if ($vv.cve_id) { $vv.cve_id } else { 'N/A' }
                        $desc = if ($vv.description) { $vv.description } else { 'Security vulnerability' }
                        $vulns += [PSCustomObject]@{Pkg = $pn; Sev = $sev; CVE = $cve; Desc = $desc }
                    }
                }; break
            }
            catch {}
        }
    }
    return $vulns
}

# ── Output ─────────────────────────────────────────────────────────────────────
function trunc([string]$V, [int]$N) { if ($V.Length -le $N) { $V } else { $V.Substring(0, $N - 1) + '…' } }

function Print-Table([array]$Apps) {
    $cols = @(
        @{K = 'Name'; T = 'Package'; W = 30 }
        @{K = 'Source'; T = 'Source'; W = 12 }
        @{K = 'Version'; T = 'Current'; W = 20 }
        @{K = 'LatestVersion'; T = 'Latest'; W = 20 }
        @{K = 'Status'; T = 'Status'; W = 17 }
    )
    $sep = '  '
    $hdr = ($cols | ForEach-Object { c '1;36' $_.T.PadRight($_.W) }) -join $sep
    Write-Host $hdr; Write-Host (gray ('─' * ($hdr.Length)))
    foreach ($app in $Apps) {
        $row = $cols | ForEach-Object {
            $col = $_
            switch ($col.K) {
                'Source' { (srcBadge (trunc ($app.Source ?? '-') $col.W).Trim()).PadRight($col.W + 11) }
                'Status' { (statusBadge $app.Status).PadRight($col.W + 10) }
                'Name' { bold (trunc ($app.Name ?? '-') $col.W).PadRight($col.W) }
                'LatestVersion' { $v = (trunc ($app.LatestVersion ?? '-') $col.W).PadRight($col.W); if ($app.Status -eq $S_UPD) { yellow $v } else { $v } }
                default { (trunc ($app.($col.K) ?? '-') $col.W).PadRight($col.W) }
            }
        }
        Write-Host ($row -join $sep)
    }
}

function Print-VulnTable([array]$Vulns) {
    if (-not $Vulns) { return }
    Write-Host ''; Write-Host (cyan "┌$('─'*73)┐")
    Write-Host (c '1;31' "│ $(E 'fire') Security Vulnerabilities Detected$(' '*30)│")
    Write-Host (cyan "├$('─'*73)┤")
    Write-Host (cyan "│ $(c '1;31' 'Package'.PadRight(20))  $(c '1;31' 'Severity'.PadRight(10))  $(c '1;31' 'CVE'.PadRight(18))  $(c '1;31' 'Description'.PadRight(20)) │")
    Write-Host (cyan "├$('─'*73)┤")
    foreach ($v in $Vulns) {
        $sc = switch ($v.Sev.ToLower()) { 'critical' { '31' } 'high' { '31' } 'medium' { '33' } default { '32' } }
        $row = "$(bold (trunc $v.Pkg 20).PadRight(20))  $(c "$sc;1" $v.Sev.ToUpper().PadRight(10))  $(cyan (trunc $v.CVE 18).PadRight(18))  $(dim (trunc $v.Desc 20).PadRight(20))"
        Write-Host (cyan "│ $row │")
    }
    Write-Host (cyan "└$('─'*73)┘")
}

# ── Export ─────────────────────────────────────────────────────────────────────
function Export-Results([array]$Apps, [string]$Fmt, [string]$Out) {
    $ts = Get-Date -f 'yyyy-MM-ddTHH-mm-ss'
    $fmt = $Fmt.ToLower()
    $file = if ($Out) { $Out } else { Join-Path (Get-Location) "system_update_$ts.$fmt" }
    if ($fmt -eq 'json') {
        @{scanTime = (Get-Date -f 'o'); totalApps = $Apps.Count; apps = $Apps } | ConvertTo-Json -Depth 10 | Set-Content $file -Encoding UTF8
    }
    elseif ($fmt -eq 'csv') {
        $Apps | Select-Object Name, Source, Version, LatestVersion, Status, AppId | Export-Csv $file -NoTypeInformation -Encoding UTF8
    }
    else { throw "Unsupported format: $Fmt" }
    return $file
}

# ── Update Execution ───────────────────────────────────────────────────────────
function Exec-Update([PSCustomObject]$App, [switch]$Dry) {
    $src = $App.Source.ToLower(); $lat = $App.LatestVersion ?? ''
    $cmd = $null; $ca = @()
    switch ($src) {
        'winget' { $cmd = 'winget'; $ca = @('upgrade', '--id', $App.AppId, '--accept-source-agreements', '--accept-package-agreements'); if ($lat) { $ca += @('--version', $lat) } }
        'chocolatey' { $cmd = 'choco'; $ca = @('upgrade', $App.Name, '-y'); if ($lat) { $ca += @('--version', $lat) } }
        'npm' { $cmd = 'npm'; $pkg = if ($lat) { "$($App.Name)@$lat" } else { $App.Name }; $ca = @('install', '-g', $pkg) }
        'pnpm' { $cmd = 'pnpm'; $pkg = if ($lat) { "$($App.Name)@$lat" } else { $App.Name }; $ca = @('add', '-g', $pkg) }
        'bun' { $cmd = 'bun'; $pkg = if ($lat) { "$($App.Name)@$lat" } else { $App.Name }; $ca = @('add', '-g', $pkg) }
        'yarn' { $cmd = 'yarn'; $pkg = if ($lat) { "$($App.Name)@$lat" } else { $App.Name }; $ca = @('global', 'add', $pkg) }
        'pip' {
            $pkg = if ($lat) { "$($App.Name)==$lat" } else { $App.Name }
            if ($Dry) { Write-Host "[dry-run] pip install $pkg"; return $true }
            return (Invoke-Cmd 'pip' @('install', $pkg) -AllowFail).Ok
        }
        'path' {
            switch ($App.Name) {
                'bun' { $cmd = 'bun'; $ca = @('upgrade') }
                'deno' { $cmd = 'deno'; $ca = @('upgrade'); if ($lat) { $ca += @('--version', $lat) } }
                'git' { $cmd = 'git'; $ca = @('update-git-for-windows', '-y') }
                'pwsh' { $cmd = 'powershell'; $ca = @('-NoProfile', '-Command', 'iex "& { $(irm https://aka.ms/install-powershell.ps1) }"') }
                'yarn' { $cmd = 'npm'; $ca = @('install', '-g', $(if ($lat) { "yarn@$lat" } else { 'yarn' })) }
            }
        }
    }
    if (-not $cmd) { return $false }
    if ($Dry) { Write-Host "[dry-run] $cmd $($ca -join ' ')"; return $true }
    $r = Invoke-Cmd $cmd $ca -AllowFail -TimeoutSec 120
    if (-not $r.Ok) { Write-Log "update failed: $($App.Name) ($($App.Source)) $($r.Stderr)" }
    return $r.Ok
}

function Exec-Updates([array]$Apps, [switch]$Dry) {
    $ok = 0; $p = New-Progress $Apps.Count "$(E 'gear') Applying updates"
    foreach ($a in $Apps) {
        $lbl = "$($a.Name) ($($a.Source))"
        if (Exec-Update $a -Dry:$Dry) { $ok++; $p.Tick("$(green (E 'ok')) $(bold $lbl)") }
        else { $p.Tick("$(red (E 'fail')) $(bold $lbl)") }
    }
    $p.Done((cyan "$(E 'sparkle') finished"))
    Write-Host "`n$(E 'chart') Completed: $(bold "$ok/$($Apps.Count)") successful."
}

function Ask([string]$Msg, [switch]$Auto) {
    if ($Auto) { return $true }
    ($Host.UI.PromptForChoice('', "$Msg", @('&Yes', '&No'), 1)) -eq 0
}

# ── Help ───────────────────────────────────────────────────────────────────────
function Show-Help {
    Write-Host @"
$(E 'sparkle') $(bold (cyan "System Update PowerShell CLI v$VER"))

Usage:  .\system_update.ps1 [options]

Options:
  -UpdateAll              Update all packages with available updates
  -UpdateSource <src>     Update all packages from one source
  -Package <name>         Update a specific package by name
  -Version <ver>          Target version (with -Package)
  -Source <src>           Filter by source (winget|chocolatey|npm|pnpm|bun|yarn|pip|path|registry)
  -DryRun                 Show planned updates without executing
  -NoCache                Force fresh scan
  -ClearCache             Remove cache file and exit
  -Export <json|csv>      Export results to file
  -Output <file>          Output path for export
  -Include <csv>          Limit scan to specific sources (e.g. winget,npm)
  -Yes                    Skip confirmation prompts
  -Help                   Show this help
"@
}

# ── Main ───────────────────────────────────────────────────────────────────────
function Main {
    if ($Help) { Show-Help; return }
    if (-not(Test-Path $DATA_DIR)) { New-Item -ItemType Directory $DATA_DIR -Force | Out-Null }
    if ($ClearCache) { Clear-AppCache; Write-Host "$(E 'disk') $(green 'Cache cleared.')"; return }

    Show-Header "$(E 'rocket') System Update PowerShell CLI v$VER" "$(E 'gear') Data dir: $DATA_DIR"
    if (Test-Path $CACHE_FILE) { Write-Host "$(bold 'Cache') $(gray '->') $CACHE_FILE" }
    Write-Host ''

    $start = [datetime]::Now
    $sf = @{}
    if ($Source) { $sf[$Source.ToLower()] = $true }
    if ($Include) { $Include.Split(',') | ForEach-Object { $sf[$_.Trim().ToLower()] = $true } }

    $apps = $null
    if (-not $NoCache) {
        $apps = Load-Cache
        if ($apps) { Write-Host "$(E 'disk') $(green "Loaded $($apps.Count) apps from cache.")`n" }
    }

    if (-not $apps) {
        Write-Host "$(E 'scan') $(bold (cyan 'Scanning sources...'))"
        $scanners = [ordered]@{
            winget     = { Scan-Winget }
            chocolatey = { Scan-Chocolatey }
            npm        = { Scan-Npm }
            pnpm       = { Scan-Pnpm }
            bun        = { Scan-Bun }
            yarn       = { Scan-Yarn }
            pip        = { Scan-Pip }
            path       = { Scan-Path }
            registry   = { Scan-Registry }
        }
        $sel = @($scanners.Keys | Where-Object { $sf.Count -eq 0 -or $sf.ContainsKey($_) })
        $prog = New-Progress $sel.Count "$(E 'scan') Scanning"
        $all = @()
        foreach ($src in $sel) {
            $chunk = @(& $scanners[$src])
            $prog.Tick("$(srcBadge $src) $($chunk.Count) apps")
            $all += $chunk
        }
        $prog.Done((green "$(E 'ok') scan complete"))
        $apps = Get-Unique $all

        Write-Host "`n$(E 'package') $(bold "Discovered $($apps.Count) unique apps.")"
        Write-Host "$(E 'update') $(bold (cyan 'Checking for updates...'))"

        $checkers = [ordered]@{
            winget     = { Check-Winget $apps }
            chocolatey = { Check-Choco $apps }
            npm        = { Check-Npm $apps }
            pnpm       = { Check-Pnpm $apps }
            bun        = { Check-Bun $apps }
            yarn       = { Check-Yarn $apps }
            pip        = { Check-Pip $apps }
            path       = { Check-PathUpdates $apps }
            registry   = { Check-Registry $apps }
        }
        $prog2 = New-Progress $checkers.Count "$(E 'update') Checking updates"
        $total = 0
        foreach ($src in $checkers.Keys) {
            $cnt = & $checkers[$src]
            $msg = if ($cnt -gt 0) { "$(srcBadge $src) $(yellow "$cnt update(s)")" } else { "$(srcBadge $src) $(gray 'none')" }
            $prog2.Tick($msg); $total += $cnt
        }
        $prog2.Done((green "$(E 'ok') update checks complete"))
        Finalize $apps
        $udColor = if ($total -gt 0) { '33' } else { '32' }
        Write-Host "$(E 'chart') $(c "$udColor;1" "Detected $total update candidates.")`n"

        if ($CFG_SECURITY) {
            Write-Host "$(E 'lock') $(bold (magenta 'Checking security vulnerabilities...'))"
            $sevOrder = @{critical = 4; high = 3; medium = 2; low = 1 }
            $thresh = $sevOrder[$CFG_SEVERITY]; if (-not $thresh) { $thresh = 2 }
            $vulns = @(Check-NpmVulns $apps) + @(Check-PipVulns $apps)
            $vulns = @($vulns | Where-Object { $sv = $sevOrder[$_.Sev.ToLower()]; if (-not $sv) { $sv = 1 }; $sv -ge $thresh })
            if ($vulns.Count -gt 0) {
                $vulns | ForEach-Object {
                    $vPkg = $_.Pkg
                    $a = $apps | Where-Object { $_.Name.ToLower() -eq $vPkg.ToLower() } | Select-Object -First 1
                    if ($a) { $a.Status = $S_VULN }
                }
                Write-Host "$(E 'fire') $(red (bold "Found $($vulns.Count) security vulnerabilities."))`n"
            }
            else { Write-Host "$(E 'shield') $(green 'No security vulnerabilities found.')`n" }
        }

        Save-Cache $apps
    }

    if ($Source) { $apps = @($apps | Where-Object { $_.Source.ToLower() -eq $Source.ToLower() }) }
    if ($Include) { $inc = @($Include.ToLower().Split(',')); $apps = @($apps | Where-Object { $_.Source.ToLower() -in $inc }) }

    $updApps = @($apps | Where-Object { $_.Status -eq $S_UPD })
    $bySrc = @($apps | Group-Object Source | ForEach-Object { "$($_.Name):$($_.Count)" })
    $el = ([datetime]::Now - $start).TotalSeconds

    Write-Host (bold (magenta "`n$(E 'chart') Summary"))
    Write-Host "$(E 'package') total apps      $(bold $apps.Count)"
    $us = if ($updApps.Count -gt 0) { yellow(bold "$($updApps.Count)") } else { green(bold "$($updApps.Count)") }
    Write-Host "$(E 'update') updates         $us"
    Write-Host "$(E 'hourglass') scan duration   $(bold "$($el.ToString('0.00'))s")"
    Write-Host "$(E 'gear') sources         $($bySrc -join ', ')"
    Write-Host ''

    Print-Table $apps

    $va = @($apps | Where-Object { $_.Status -eq $S_VULN })
    if ($va -and $CFG_SECURITY) {
        Print-VulnTable ($va | ForEach-Object { [PSCustomObject]@{Pkg = $_.Name; Sev = 'high'; CVE = 'N/A'; Desc = 'Security update recommended' } })
    }

    if (-not $Package -and -not $UpdateAll -and -not $UpdateSource) {
        if ($updApps.Count -eq 0) { Write-Host "`n$(E 'sparkle') $(green 'System is up to date!')" }
        else { Write-Host "`n$(E 'update') $(yellow "Found $($updApps.Count) available updates")" }
    }

    if ($Package) {
        $wanted = $Package.ToLower()
        $m = @($apps | Where-Object { $_.Name.ToLower() -eq $wanted -and (-not $Source -or $_.Source.ToLower() -eq $Source.ToLower()) })
        if (-not $m) { Write-Host "`n$(E 'fail') $(red (bold "Package not found: $Package"))"; exit 2 }
        if ($m.Count -gt 1 -and -not $Source) {
            Write-Host "`n$(E 'warn') $(yellow 'Multiple matches. Re-run with -Source.')"
            $m | ForEach-Object { Write-Host "  $($_.Name) ($($_.Source)) $($_.Version)" }; exit 2
        }
        $tgt = $m[0]; if ($Version) { $tgt.LatestVersion = $Version }
        if (-not $tgt.LatestVersion -and $tgt.Status -ne $S_UPD -and -not $Version) {
            if (-not(Ask "$($tgt.Name) appears up-to-date. Force reinstall?" -Auto:$Yes)) { return }
        }
        Exec-Updates @($tgt) -Dry:$DryRun
    }
    elseif ($UpdateSource) {
        $cand = @($updApps | Where-Object { $_.Source.ToLower() -eq $UpdateSource.ToLower() })
        if (-not $cand) { Write-Host "`n$(E 'ok') $(green "No updates for: $UpdateSource")" }
        elseif (Ask "Proceed with $($cand.Count) update(s) from $UpdateSource?" -Auto:$Yes) { Exec-Updates $cand -Dry:$DryRun }
    }
    elseif ($UpdateAll) {
        if (-not $updApps) { Write-Host "`n$(E 'ok') $(green 'No updates available.')" }
        elseif (Ask "Proceed with all $($updApps.Count) updates?" -Auto:$Yes) { Exec-Updates $updApps -Dry:$DryRun }
    }

    if ($Export) {
        $f = Export-Results $apps $Export $Output
        Write-Host "`n$(E 'export') $(green (bold "Exported to: $f"))"
    }
}

try { Main } catch {
    Write-Log "fatal: $_"
    Write-Host "$(E 'fail') Fatal error: $_" -ForegroundColor Red
    exit 1
}
