#Requires -Version 7.0
<#
.SYNOPSIS
    System Update PowerShell CLI — Comprehensive system package manager and update checker.
    
.DESCRIPTION
    This script scans multiple package managers (winget, chocolatey, npm, pnpm, bun, yarn, pip, rust)
    and system registry to identify installed applications and check for available updates.
    It supports security vulnerability scanning for npm and pip packages, caching for performance,
    and export functionality for reporting purposes.
    
    Features:
    - Multi-source package scanning (winget, chocolatey, npm, pnpm, bun, yarn, pip, rust, registry, path)
    - Update detection with version comparison
    - Security vulnerability scanning (npm audit, pip check)
    - Caching mechanism to speed up subsequent runs
    - Export results to JSON or CSV formats
    - Dry-run mode for testing updates
    - ANSI color support for enhanced terminal output
    
.PARAMETER UpdateAll
    Automatically update all packages with available updates after confirmation.
    
.PARAMETER DryRun
    Show planned updates without actually executing them. Useful for testing.
    
.PARAMETER NoCache
    Force a fresh scan by bypassing the cache. Use when you suspect stale data.
    
.PARAMETER ClearCache
    Remove the cache file and exit immediately.
    
.PARAMETER Yes
    Skip all confirmation prompts and proceed automatically (non-interactive mode).
    
.PARAMETER Help
    Display the help message with usage information and examples.
    
.PARAMETER Export
    Export scan results to a file. Valid formats: 'json' or 'csv'.
    
.PARAMETER Output
    Specify a custom output file path for the export. If not provided, a timestamped
    file will be created in the current directory.
    
.PARAMETER Package
    Target a specific package by name for update. Use with -Source to disambiguate.
    
.PARAMETER Version
    Specify a target version when used with -Package. Forces update to that version.
    
.PARAMETER Source
    Filter scanning and/or updates to a specific source (winget, chocolatey, npm, pnpm,
    bun, yarn, pip, path, rust, registry).
    
.PARAMETER UpdateSource
    Update all packages from a specific source in one operation.
    
.PARAMETER Include
    Comma-separated list of sources to include in the scan (e.g., 'winget,npm,rust').
    
.PARAMETER ShowAll
    Display all packages in the output table, including up-to-date ones. By default,
    only packages with updates or vulnerabilities are shown.
    
.EXAMPLE
    .\system_update.ps1
    Performs a full system scan and displays available updates.
    
.EXAMPLE
    .\system_update.ps1 -UpdateAll -Yes
    Updates all packages automatically without prompting for confirmation.
    
.EXAMPLE
    .\system_update.ps1 -Source npm -NoCache
    Scans only npm packages, bypassing the cache for fresh data.
    
.EXAMPLE
    .\system_update.ps1 -Package git -Source chocolatey
    Checks and updates the 'git' package specifically from Chocolatey.
    
.EXAMPLE
    .\system_update.ps1 -Export json -Output report.json
    Exports scan results to a JSON file named 'report.json'.
    
.EXAMPLE
    .\system_update.ps1 -UpdateSource winget -DryRun
    Shows what winget updates would be performed without executing them.
    
.EXAMPLE
    .\system_update.ps1 -ShowAll
    Displays all installed packages, including those that are up-to-date.
    
.NOTES
    Version: 1.0.1
    Requires: PowerShell 7.0 or higher
    Data Directory: $env:USERPROFILE\.system_update (or $env:SYSTEM_UPDATE_HOME)
#>

[CmdletBinding()]
param(
    # Update all packages with available updates
    [parameter(Mandatory = $false)][switch]$UpdateAll,
    
    # Show planned updates without executing them
    [parameter(Mandatory = $false)][switch]$DryRun,
    
    # Force fresh scan by bypassing cache
    [parameter(Mandatory = $false)][switch]$NoCache,
    
    # Remove cache file and exit
    [parameter(Mandatory = $false)][switch]$ClearCache,
    
    # Skip confirmation prompts (non-interactive mode)
    [parameter(Mandatory = $false)][switch]$Yes,
    
    # Display help message
    [parameter(Mandatory = $false)][switch]$Help,
    
    # Export format: 'json' or 'csv'
    [parameter(Mandatory = $false)][string]$Export,
    
    # Custom output file path for export
    [parameter(Mandatory = $false)][string]$Output,
    
    # Specific package name to update
    [parameter(Mandatory = $false)][string]$Package,
    
    # Target version for package update
    [parameter(Mandatory = $false)][string]$Version,
    
    # Filter by source (winget, chocolatey, npm, etc.)
    [parameter(Mandatory = $false)][string]$Source,
    
    # Update all packages from a specific source
    [parameter(Mandatory = $false)][string]$UpdateSource,
    
    # Comma-separated list of sources to include in scan
    [parameter(Mandatory = $false)][string]$Include,
    
    # Show all packages including up-to-date ones
    [parameter(Mandatory = $false)][switch]$ShowAll
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

# ── Constants ──────────────────────────────────────────────────────────────────
# Script version number
$VER = '2.1.0'

# Data directory for cache and logs - uses environment variable if set, otherwise defaults to user profile
$DATA_DIR = if ($env:SYSTEM_UPDATE_HOME) { $env:SYSTEM_UPDATE_HOME } else { Join-Path $env:USERPROFILE '.system_update' }

# Path to the JSON cache file storing scan results
$CACHE_FILE = Join-Path $DATA_DIR 'cache.json'

# Path to the log file for recording operations
$LOG_FILE = Join-Path $DATA_DIR 'system.log'

# Status constants - used to track package state throughout the scanning process
$S_OK = 'up_to_date'           # Package is at the latest version
$S_UPD = 'update_available'    # A newer version is available
$S_UNK = 'unknown'             # Package status could not be determined
$S_VULN = 'vulnerable'         # Package has known security vulnerabilities
$S_SEC = 'security_update_available'  # Security patch is available
$S_ERR = 'error'               # An error occurred during status check

# Configuration constants
$CFG_CACHE_HOURS = 2    # Cache validity period in hours
$CFG_TIMEOUT = 45       # Default command timeout in seconds
$CFG_SECURITY = $true   # Enable security vulnerability scanning
$CFG_SEVERITY = 'medium'  # Minimum severity level to report (critical, high, medium, low)

function Get-EnvBool([string]$Name, [bool]$Default = $false) {
    $raw = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($raw)) { return $Default }
    switch ($raw.Trim().ToLowerInvariant()) {
        '1' { return $true }
        'true' { return $true }
        'yes' { return $true }
        'on' { return $true }
        '0' { return $false }
        'false' { return $false }
        'no' { return $false }
        'off' { return $false }
        default { return $Default }
    }
}

$envTimeout = [Environment]::GetEnvironmentVariable('SYSTEM_UPDATE_CMD_TIMEOUT')
if ($envTimeout) {
    $parsedTimeout = 0
    if ([int]::TryParse($envTimeout, [ref]$parsedTimeout) -and $parsedTimeout -gt 0) {
        $CFG_TIMEOUT = $parsedTimeout
    }
}

$CFG_SECURITY = Get-EnvBool 'SYSTEM_UPDATE_SECURITY' $CFG_SECURITY
$CFG_SKIP_UPDATE_CHECKS = Get-EnvBool 'SYSTEM_UPDATE_SKIP_UPDATE_CHECKS' $false

# ── ANSI Color Functions ───────────────────────────────────────────────────────
# Detect if the host console supports ANSI virtual terminal sequences
# This enables colored output on modern terminals (Windows Terminal, VS Code, etc.)
$COLOR = $Host.UI.SupportsVirtualTerminal

<#
.SYNOPSIS
    Applies ANSI color codes to text for terminal output.
.DESCRIPTION
    Wraps text with ANSI escape codes for coloring. If the terminal doesn't support
    ANSI colors, returns the text unchanged.
.PARAMETER code
    ANSI color code (e.g., '31' for red, '32' for green, '1' for bold).
.PARAMETER t
    The text to colorize.
.EXAMPLE
    c '31' 'Error message'  # Returns red text
.EXAMPLE
    c '1;36' 'Bold cyan text'  # Returns bold cyan text
#>
function c([string]$code, [string]$t) { 
    if ($COLOR) { "$([char]27)[$($code)m$t$([char]27)[0m" } else { $t } 
}

<#
.SYNOPSIS
    Returns bold-formatted text.
.DESCRIPTION
    Applies ANSI bold formatting (code 1) to the specified text.
.PARAMETER t
    The text to make bold.
.EXAMPLE
    bold 'Important message'  # Returns bold text
#>
function bold([string]$t) { c '1' $t }

<#
.SYNOPSIS
    Returns dim-formatted text.
.DESCRIPTION
    Applies ANSI dim formatting (code 2) to the specified text for subdued appearance.
.PARAMETER t
    The text to dim.
.EXAMPLE
    dim 'Secondary info'  # Returns dimmed text
#>
function dim([string]$t) { c '2' $t }

<#
.SYNOPSIS
    Returns red-colored text.
.DESCRIPTION
    Applies ANSI red color (code 31) for errors, failures, or critical messages.
.PARAMETER t
    The text to color red.
.EXAMPLE
    red 'Error occurred'  # Returns red text
#>
function red([string]$t) { c '31' $t }

<#
.SYNOPSIS
    Returns green-colored text.
.DESCRIPTION
    Applies ANSI green color (code 32) for success messages and up-to-date status.
.PARAMETER t
    The text to color green.
.EXAMPLE
    green 'Success!'  # Returns green text
#>
function green([string]$t) { c '32' $t }

<#
.SYNOPSIS
    Returns yellow-colored text.
.DESCRIPTION
    Applies ANSI yellow color (code 33) for warnings and update notifications.
.PARAMETER t
    The text to color yellow.
.EXAMPLE
    yellow 'Warning: update available'  # Returns yellow text
#>
function yellow([string]$t) { c '33' $t }

<#
.SYNOPSIS
    Returns blue-colored text.
.DESCRIPTION
    Applies ANSI blue color (code 34) for informational messages.
.PARAMETER t
    The text to color blue.
.EXAMPLE
    blue 'Info message'  # Returns blue text
#>
function blue([string]$t) { c '34' $t }

<#
.SYNOPSIS
    Returns magenta-colored text.
.DESCRIPTION
    Applies ANSI magenta color (code 35) for security-related messages.
.PARAMETER t
    The text to color magenta.
.EXAMPLE
    magenta 'Security alert'  # Returns magenta text
#>
function magenta([string]$t) { c '35' $t }

<#
.SYNOPSIS
    Returns cyan-colored text.
.DESCRIPTION
    Applies ANSI cyan color (code 36) for headers and important notices.
.PARAMETER t
    The text to color cyan.
.EXAMPLE
    cyan 'Header text'  # Returns cyan text
#>
function cyan([string]$t) { c '36' $t }

<#
.SYNOPSIS
    Returns gray-colored text.
    Applies ANSI gray color (code 90) for secondary or less important information.
.PARAMETER t
    The text to color gray.
.EXAMPLE
    gray 'Optional detail'  # Returns gray text
#>
function magenta([string]$t) { c '35' $t }
function purple([string]$t) { c '38;5;129' $t }
function pink([string]$t) { c '38;5;206' $t }
function orange([string]$t) { c '38;5;208' $t }
function gold([string]$t) { c '38;5;214' $t }
function cyan([string]$t) { c '36' $t }
function white([string]$t) { c '37' $t }
function gray([string]$t) { c '90' $t }

# ── Emoji Functions ────────────────────────────────────────────────────────────
<#
.SYNOPSIS
    Returns Unicode emoji characters by name for enhanced terminal output.
.DESCRIPTION
    Maps emoji names to their Unicode representations using [char]::ConvertFromUtf32
    for proper surrogate pair handling. This ensures emoji display correctly across
    all PowerShell versions and terminal configurations.
.PARAMETER n
    The emoji name (e.g., 'rocket', 'package', 'scan', 'update', 'ok', 'warn', 'fail').
.EXAMPLE
    E 'rocket'  # Returns 🚀
.EXAMPLE
    E 'ok'      # Returns ✅
.NOTES
    Uses UTF-32 code points for emoji that require surrogate pairs.
    Some emoji include variation selector (U+FE0F) for emoji-style presentation.
#>
function E([string]$n) {
    switch ($n) {
        'rocket' { [char]::ConvertFromUtf32(0x1F680) }  # 🚀
        'package' { [char]::ConvertFromUtf32(0x1F4E6) }  # 📦
        'scan' { [char]::ConvertFromUtf32(0x1F50E) }  # 🔎
        'update' { [char]::ConvertFromUtf32(0x1F504) }  # 🔄
        'ok' { "$([char]::ConvertFromUtf32(0x2705))" }  # ✅
        'warn' { "$([char]::ConvertFromUtf32(0x26A0))$([char]0xFE0F)" }  # ⚠️
        'fail' { [char]::ConvertFromUtf32(0x274C) }  # ❌
        'gear' { "$([char]::ConvertFromUtf32(0x2699))$([char]0xFE0F)" }  # ⚙️
        'sparkle' { [char]::ConvertFromUtf32(0x2728) }  # ✨
        'chart' { [char]::ConvertFromUtf32(0x1F4CA) }  # 📊
        'disk' { [char]::ConvertFromUtf32(0x1F4BE) }  # 💾
        'hourglass' { "$([char]::ConvertFromUtf32(0x23F1))$([char]0xFE0F)" }  # ⏱️
        'export' { [char]::ConvertFromUtf32(0x1F4C4) }  # 📄
        'lock' { [char]::ConvertFromUtf32(0x1F512) }  # 🔒
        'fire' { [char]::ConvertFromUtf32(0x1F525) }  # 🔥
        'shield' { "$([char]::ConvertFromUtf32(0x1F6E1))$([char]0xFE0F)" }  # 🛡️
        'target' { [char]::ConvertFromUtf32(0x1F3AF) }  # 🎯
        'unknown' { '❔' }  # Default unknown status emoji
        default { '' }  # Return empty string for unknown emoji names
    }
}

<#
.SYNOPSIS
    Returns a formatted status badge with emoji and color based on package status.
.DESCRIPTION
    Creates a visual status indicator for package update states. Each status has
    a unique emoji and color combination for quick visual identification in terminal output.
.PARAMETER s
    The status constant (S_UPD, S_OK, S_ERR, S_VULN, S_SEC, or unknown).
.EXAMPLE
    statusBadge $S_UPD  # Returns yellow "⬆️ update" badge
    statusBadge $S_OK   # Returns green "✅ up-to-date" badge
#>
function statusBadge([string]$s) {
    switch ($s) {
        $S_UPD { c '33;1' "$(E 'update') update" }  # Yellow bold for updates available
        $S_OK { green "$(E 'ok') up-to-date" }  # Green for up-to-date packages
        $S_ERR { red "$(E 'fail') error" }  # Red for error states
        $S_VULN { c '31;1' "$(E 'fire') vulnerable" }  # Red bold for vulnerabilities
        $S_SEC { c '35;1' "$(E 'lock') security update" }  # Magenta bold for security updates
        default { gray "$(E 'unknown') unknown" }  # Gray for unknown status
    }
}

<#
.SYNOPSIS
    Returns a color-coded source badge for package manager identification.
.DESCRIPTION
    Creates a colored text badge identifying the package source. Each source
    (winget, chocolatey, npm, etc.) has a distinct color for easy recognition.
.PARAMETER s
    The source name (winget, chocolatey, npm, pnpm, bun, yarn, pip, rust, path, registry).
.EXAMPLE
    srcBadge 'winget'     # Returns blue 'winget'
    srcBadge 'chocolatey' # Returns yellow 'chocolatey'
#>
function srcBadge([string]$s) {
    switch ($s.Trim().ToLower()) {
        'winget' { c '34;1' $s }  # Blue bold
        'chocolatey' { c '33;1' $s }  # Yellow bold
        'npm' { c '31;1' $s }  # Red bold
        'pnpm' { c '38;5;206;1' $s }  # Pink bold
        'pip' { c '36;1' $s }  # Cyan bold
        'bun' { c '94;1' $s }  # Bright blue bold
        'yarn' { c '97;1' $s }  # Bright white bold
        'rust' { c '38;5;129;1' $s }  # Purple bold
        'path' { c '32;1' $s }  # Green bold
        'registry' { gray $s }  # Gray for registry entries
        'scoop' { c '93;1' $s }  # Bright yellow bold
        'dotnet' { c '33;1' $s }  # Gold bold
        default { gray $s }  # Gray for unknown sources
    }
}

# ── Progress Bar Functions ─────────────────────────────────────────────────────
<#
.SYNOPSIS
    Creates a progress bar object for tracking long-running operations.
.DESCRIPTION
    Generates a custom progress bar object with Render, Tick, and Done methods.
    The progress bar displays a visual bar, percentage, elapsed time, and custom messages.
    Uses ANSI escape codes for in-place updates without scrolling the terminal.
.PARAMETER Total
    The total number of items to process.
.PARAMETER Label
    Descriptive label shown before the progress bar.
.EXAMPLE
    $prog = New-Progress 10 "Scanning packages"
    foreach ($pkg in $packages) {
        # Process item
        $prog.Tick("Processed $pkg")
    }
    $prog.Done("Scan complete")
.OUTPUTS
    PSCustomObject with properties: N (current), T (total), L (label), S (start time)
    and methods: Render(), Tick(), Done()
#>
function New-Progress([int]$Total, [string]$Label) {
    # Initialize progress object with counter, total, label, and start time
    $p = [PSCustomObject]@{N = 0; T = $Total; L = $Label; S = [datetime]::Now }
    
    # Render method - draws the progress bar at current position
    $p | Add-Member ScriptMethod Render { param([string]$X = '')
        # Calculate progress ratio (handle division by zero)
        $r = if ($this.T -eq 0) { 1.0 } else { [Math]::Min(1.0, $this.N / $this.T) }
        # Calculate filled portion of bar (26 characters max)
        $f = [Math]::Round(26 * $r)
        # Build bar with filled (█) and empty (░) segments
        $bar = ('█' * $f) + ('░' * (26 - $f))
        # Format percentage with right-padding for consistent width
        $pct = "$([Math]::Round($r*100))%".PadLeft(4)
        # Calculate elapsed time since progress started
        $el = ([datetime]::Now - $this.S).TotalSeconds.ToString('0.0')
        # Compose and display the full progress message
        $msg = "$($this.L) $bar $pct ($($this.N)/$($this.T)) $(E 'hourglass') ${el}s $X"
        # Use carriage return and ANSI erase to update in place
        Write-Host "`r$([char]27)[2K$msg" -NoNewline
    }
    
    # Tick method - advances progress by one step and updates display
    $p | Add-Member ScriptMethod Tick { param([string]$X = ''); $this.N++; $this.Render($X) }
    
    # Done method - completes progress bar and moves to new line
    $p | Add-Member ScriptMethod Done { param([string]$X = ''); $this.N = $this.T; $this.Render($X); Write-Host '' }
    
    # Initial render and return progress object
    $p.Render(); return $p
}

<#
.SYNOPSIS
    Displays a styled header box for section separation.
.DESCRIPTION
    Creates a decorative cyan-colored header box with a title and subtitle.
    Uses box-drawing characters for a clean, professional appearance.
.PARAMETER Title
    Main title text displayed in bold cyan.
.PARAMETER Sub
    Subtitle text displayed in dim cyan below the title.
.EXAMPLE
    Show-Header "System Update CLI v1.0" "Scanning installed packages..."
.OUTPUTS
    Writes formatted header box to host output.
#>
function Show-Header([string]$Title, [string]$Sub) {
    # Calculate box width based on content or terminal width (cap at 70)
    $w = [Math]::Min(70, $Host.UI.RawUI.WindowSize.Width - 2)
    # Draw top border of header box
    Write-Host (cyan "┌$('─'*$w)┐")
    # Display title in bold cyan, padded to fit box width
    Write-Host (c '1;36' "│ $($Title.PadRight($w - 1))│")
    # Display subtitle in dim cyan, padded to fit box width
    Write-Host (c '2;36' "│ $($Sub.PadRight($w - 1))│")
    # Draw bottom border of header box
    Write-Host (cyan "└$('─'*$w)┘")
}

# ── Logging Functions ──────────────────────────────────────────────────────────
<#
.SYNOPSIS
    Writes a timestamped message to the log file.
.DESCRIPTION
    Appends a message with ISO 8601 timestamp to the system log file.
    Errors are silently ignored to prevent logging failures from disrupting operations.
.PARAMETER Msg
    The message to log.
.EXAMPLE
    Write-Log "Scan completed successfully"
.EXAMPLE
    Write-Log "Error: Package not found - git"
.NOTES
    Log file location: $DATA_DIR\system.log
    Timestamp format: ISO 8601 (yyyy-MM-ddTHH:mm:ss.fffffff)
#>
function Write-Log([string]$Msg) {
    # Append timestamped message to log file with UTF8 encoding
    # Silently continue on error to avoid disrupting main operations
    try { "$(Get-Date -f 'o') $Msg" | Add-Content $LOG_FILE -Encoding UTF8 -EA SilentlyContinue } catch {}
}

# ── Command Execution Functions ───────────────────────────────────────────────
<#
.SYNOPSIS
    Executes external commands with proper handling for different executable types.
.DESCRIPTION
    Universal command executor that handles PowerShell scripts (.ps1), batch files
    (.cmd/.bat), and native executables (.exe) with appropriate invocation methods.
    Captures stdout/stderr, enforces timeouts, and returns structured results.
    
    Execution paths:
    - .ps1 files: Runs through pwsh -NonInteractive -NoProfile -File
    - .cmd/.bat files: Runs through cmd.exe /d /c with proper quoting
    - .exe files: Runs directly via ProcessStartInfo
    
.PARAMETER Cmd
    The command name or path to execute.
.PARAMETER CmdArgs
    Array of arguments to pass to the command.
.PARAMETER TimeoutSec
    Maximum execution time in seconds before the process is killed.
.PARAMETER AllowFail
    If set, return result even if exit code is non-zero.
.PARAMETER Stderr
    If set, include stderr output in the returned stdout.
.EXAMPLE
    $result = Invoke-Cmd 'git' @('--version')
    if ($result.Ok) { Write-Host $result.Stdout }
.EXAMPLE
    $result = Invoke-Cmd 'npm' @('install', '-g', 'package') -TimeoutSec 120
.EXAMPLE
    $result = Invoke-Cmd 'script.ps1' @('-arg1', 'value') -AllowFail
.OUTPUTS
    PSCustomObject with properties: Ok (bool), Stdout (string), Stderr (string), Code (int)
.NOTES
    Uses UTF8 encoding for stdout and stderr.
    Returns Ok=$false and Stderr='timeout' if command exceeds timeout.
#>
function Invoke-Cmd {
    param(
        [string]$Cmd,
        [string[]]$CmdArgs = @(),
        [int]$TimeoutSec = $CFG_TIMEOUT,
        [switch]$AllowFail,
        [switch]$Stderr
    )
    try {
        # Find the command in PATH to determine its type and location
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

        # Configure process for output capture
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8

        # Start process and capture output
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        $proc.Start() | Out-Null

        # Read output asynchronously to avoid deadlocks
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()
        $done = $proc.WaitForExit($TimeoutSec * 1000)

        # Handle timeout - kill process if it exceeds limit
        if (-not $done) { try { $proc.Kill() } catch {}; return [PSCustomObject]@{Ok = $false; Stdout = ''; Stderr = 'timeout'; Code = $null } }

        # Collect output and build result object
        $outStr = $outTask.GetAwaiter().GetResult().Trim()
        $errStr = $errTask.GetAwaiter().GetResult().Trim()
        $code = $proc.ExitCode
        $ok = if ($AllowFail) { $true } else { $code -eq 0 }
        $out = if ($Stderr) { "$outStr`n$errStr".Trim() } else { $outStr }
        return [PSCustomObject]@{Ok = $ok; Stdout = $out; Stderr = $errStr; Code = $code }
    }
    catch {
        # Log error and return failure object
        Write-Log "Invoke-Cmd $Cmd $($CmdArgs -join ' '): $_"
        return [PSCustomObject]@{Ok = $false; Stdout = ''; Stderr = "$_"; Code = $null }
    }
}

<#
.SYNOPSIS
    Checks if a command exists in the system PATH.
.DESCRIPTION
    Uses 'where.exe' to verify if a command is available on the system.
    Returns $true if the command is found, $false otherwise.
.PARAMETER Cmd
    The command name to check.
.EXAMPLE
    if (cmd-ok 'git') { Write-Host "Git is installed" }
.OUTPUTS
    System.Boolean
#>
function cmd-ok([string]$Cmd) {
    # Use 'where.exe' explicitly — 'where' alone is a PowerShell alias for Where-Object
    $r = Invoke-Cmd 'where.exe' @($Cmd) -AllowFail -TimeoutSec 10
    return ($r.Ok -and $r.Stdout)
}

<#
.SYNOPSIS
    Fetches GitHub release information via REST API.
.DESCRIPTION
    Makes an HTTP GET request to a GitHub API endpoint to retrieve release data.
    Includes User-Agent header as required by GitHub API.
.PARAMETER Url
    The GitHub API URL to query.
.EXAMPLE
    $release = gh-release 'https://api.github.com/repos/git/git/releases/latest'
.OUTPUTS
    PSCustomObject with release data, or $null on failure.
#>
function gh-release([string]$Url) {
    try { 
        # Use GitHub API with required User-Agent header
        return Invoke-RestMethod -Uri $Url -Headers @{'User-Agent' = 'SystemUpdateCLI' } -TimeoutSec 10 
    } catch { 
        return $null 
    }
}

<#
.SYNOPSIS
    Executes commands via PowerShell background job for encoding-sensitive tools.
.DESCRIPTION
    Runs commands in a separate PowerShell job to handle tools that are sensitive
    to console encoding (like winget which outputs UTF-16LE). This ensures proper
    character encoding for tools that don't work well with ProcessStartInfo.
.PARAMETER Cmd
    The command name to execute.
.PARAMETER CmdArgs
    Array of arguments to pass to the command.
.PARAMETER TimeoutSec
    Maximum execution time in seconds.
.PARAMETER AllowFail
    If set, return result even if exit code is non-zero.
.PARAMETER Stderr
    If set, capture stderr along with stdout.
.EXAMPLE
    $result = Invoke-NativeCmd 'winget' @('list') -AllowFail
.EXAMPLE
    $result = Invoke-NativeCmd 'npm' @('list', '-g', '--json') -Stderr
.OUTPUTS
    PSCustomObject with properties: Ok (bool), Stdout (string), Stderr (string), Code (int)
.NOTES
    Uses background jobs which have higher overhead but better encoding handling.
    UTF-8 output encoding is configured for the job.
#>
function Invoke-NativeCmd {
    param(
        [string]$Cmd,
        [string[]]$CmdArgs = @(),
        [int]$TimeoutSec = $CFG_TIMEOUT,
        [switch]$AllowFail,
        [switch]$Stderr
    )
    # Start background job to handle encoding-sensitive commands
    $job = Start-Job -ScriptBlock {
        param($c, $a, $se)
        $ErrorActionPreference = 'SilentlyContinue'
        # Configure UTF-8 output encoding for proper character handling
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
        try {
            if ($se) {
                # Capture both stdout and stderr
                $out = & $c @a 2>&1 | Out-String
            }
            else {
                # Capture stdout only, suppress stderr
                $out = & $c @a 2>$null | Out-String
            }
            @{ Out = $out.Trim(); Code = $LASTEXITCODE }
        }
        catch {
            @{ Out = ''; Code = 1 }
        }
    } -ArgumentList $Cmd, $CmdArgs, $Stderr.IsPresent

    # Wait for job completion with timeout
    if (-not (Wait-Job $job -Timeout $TimeoutSec)) {
        Stop-Job $job; Remove-Job $job -Force
        return [PSCustomObject]@{Ok = $false; Stdout = ''; Stderr = 'timeout'; Code = $null }
    }
    
    # Collect job results and cleanup
    $r = Receive-Job $job -ErrorAction SilentlyContinue
    Remove-Job $job -Force
    $rOut = if ($r -and $r.Out) { $r.Out }  else { '' }
    $rCode = if ($r -and $null -ne $r.Code) { $r.Code } else { $null }
    $ok = if ($AllowFail) { $true } else { $rCode -eq 0 }
    return [PSCustomObject]@{Ok = $ok; Stdout = $rOut; Stderr = ''; Code = $rCode }
}

# ── Winget Table Parser ────────────────────────────────────────────────────────
<#
.SYNOPSIS
    Parses winget command output into structured application objects.
.DESCRIPTION
    Extracts application information from winget's table-formatted output.
    Handles column position detection and parses Name, Id, Version, and optionally
    Available version and Source columns.
.PARAMETER Out
    The raw stdout from a winget command (list or upgrade).
.PARAMETER Avail
    If set, also extract the 'Available' column for update detection.
.EXAMPLE
    $apps = Parse-Winget (winget list)
.EXAMPLE
    $updates = Parse-Winget (winget upgrade) -Avail
.OUTPUTS
    Array of PSCustomObject with properties: Name, Source, Version, LatestVersion, AppId, Status
.NOTES
    Skips header lines and handles variable column widths.
    Returns empty array if no valid applications are found.
#>
function Parse-Winget([string]$Out, [switch]$Avail) {
    $apps = @(); if (-not $Out) { return $apps }
    $lines = $Out -split "`r?`n"
    $hi = -1
    # Find header row by looking for column names
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match 'Name' -and $lines[$i] -match 'Id' -and $lines[$i] -match 'Version') { $hi = $i; break } }
    if ($hi -lt 0) { return $apps }
    $h = $lines[$hi]
    # Calculate column positions based on header row
    $pos = @{id = $h.IndexOf('Id'); ver = $h.IndexOf('Version'); avail = $h.IndexOf('Available'); src = $h.IndexOf('Source') }
    # Parse each data row after the separator line
    foreach ($line in $lines[($hi + 2)..($lines.Count - 1)]) {
        if (-not $line.Trim()) { continue }
        try {
            # Extract fields based on column positions
            $name = $line.Substring(0, [Math]::Max($pos.id, 0)).Trim()
            $appId = if ($pos.ver -gt 0) { $line.Substring($pos.id, $pos.ver - $pos.id).Trim() }else { '' }
            $vEnd = if ($pos.avail -gt -1) { $pos.avail }elseif ($pos.src -gt -1) { $pos.src }else { $line.Length }
            $ver = if ($pos.ver -gt -1) { $line.Substring($pos.ver, $vEnd - $pos.ver).Trim() }else { '' }
            # Extract latest version if available column exists
            $latest = ''
            if ($Avail -and $pos.avail -gt -1) { $aEnd = if ($pos.src -gt -1) { $pos.src }else { $line.Length }; $latest = $line.Substring($pos.avail, $aEnd - $pos.avail).Trim() }
            # Create application object if required fields are present
            if ($name -and $appId -and $ver) {
                $apps += [PSCustomObject]@{
                    name = $name; source = 'winget'; version = $ver; 
                    latestVersion = if ($latest) { $latest } else { '' }; 
                    appId = $appId; status = if ($latest) { $S_UPD } else { $S_UNK };
                    scanTime = [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                }
            }
        }
        catch {}
    }
    return $apps
}

# ── Scanners ───────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Scans for applications installed via winget.
.DESCRIPTION
    Executes 'winget list' and parses the output to discover all applications
    managed by the Windows Package Manager. Uses Invoke-NativeCmd for proper
    UTF-16LE encoding handling.
.EXAMPLE
    $apps = Scan-Winget
.OUTPUTS
    Array of PSCustomObject with properties: Name, Source, Version, LatestVersion, AppId, Status
.NOTES
    winget outputs UTF-16LE which requires Invoke-NativeCmd for correct reading.
#>
function Scan-Winget {
    # Use Invoke-NativeCmd: winget outputs UTF-16LE which ProcessStartInfo misreads with UTF8 encoding
    $r = Invoke-NativeCmd 'winget' @('list', '--accept-source-agreements') -AllowFail
    Parse-Winget $r.Stdout
}

<#
.SYNOPSIS
    Scans for applications installed via Chocolatey.
.DESCRIPTION
    Executes 'choco list --local-only' to discover all Chocolatey-managed packages.
    Parses the pipe-delimited output format (name|version|...).
.EXAMPLE
    $apps = Scan-Chocolatey
.OUTPUTS
    Array of PSCustomObject with properties: Name, Source, Version, LatestVersion, AppId, Status
#>
function Scan-Chocolatey {
    $r = Invoke-Cmd 'choco' @('list', '--local-only', '--limit-output') -AllowFail
    @($r.Stdout -split "`r?`n" | ForEach-Object {
            $p = $_ -split '\|'
            if ($p.Count -ge 2 -and $p[0] -and $p[1]) {
                [PSCustomObject]@{
                    name = $p[0].Trim(); source = 'chocolatey'; version = $p[1].Trim(); 
                    latestVersion = ''; appId = $p[0].Trim(); status = $S_UNK;
                    scanTime = [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                }
            }
        } | Where-Object { $_ })
}

<#
.SYNOPSIS
    Scans for globally installed npm packages.
.DESCRIPTION
    Executes 'npm list -g --json' to discover globally installed Node.js packages.
    Parses the JSON output to extract package names and versions.
.EXAMPLE
    $apps = Scan-Npm
.OUTPUTS
    Array of PSCustomObject with properties: Name, Source, Version, LatestVersion, AppId, Status
.NOTES
    Uses Invoke-NativeCmd because npm may be a .ps1 ExternalScript (nvm for Windows).
#>
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
                $apps += [PSCustomObject]@{
                    name = $_.Name; source = 'npm'; version = $ver; 
                    latestVersion = ''; appId = $_.Name; status = $S_UNK;
                    scanTime = [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                }
            }
        }
    }
    catch { Write-Log "npm list: $_" }
    return $apps
}

<#
.SYNOPSIS
    Scans for globally installed pnpm packages.
.DESCRIPTION
    Executes 'pnpm list -g --json' to discover globally installed pnpm packages.
    Parses the JSON output structure to extract package information.
.EXAMPLE
    $apps = Scan-Pnpm
.OUTPUTS
    Array of PSCustomObject with properties: Name, Source, Version, LatestVersion, AppId, Status
#>
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
                $apps += [PSCustomObject]@{
                    name = $_.Name; source = 'pnpm'; version = $ver; 
                    latestVersion = ''; appId = $_.Name; status = $S_UNK;
                    scanTime = [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                }
            }
        }
    }
    catch { Write-Log "pnpm list: $_" }
    return $apps
}

<#
.SYNOPSIS
    Scans for globally installed Bun packages.
.DESCRIPTION
    Executes 'bun pm ls -g' and parses the output to find globally installed
    packages managed by Bun package manager.
.EXAMPLE
    $apps = Scan-Bun
.OUTPUTS
    Array of PSCustomObject with properties: Name, Source, Version, LatestVersion, AppId, Status
#>
function Scan-Bun {
    $r = Invoke-Cmd 'bun' @('pm', 'ls', '-g') -AllowFail
    @($r.Stdout -split "`r?`n" | ForEach-Object {
            if ($_ -match '^\s*([^\s@]+)@([^\s]+)') {
                [PSCustomObject]@{
                    name = $Matches[1]; source = 'bun'; version = $Matches[2]; 
                    latestVersion = ''; appId = $Matches[1]; status = $S_UNK;
                    scanTime = [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                }
            }
        } | Where-Object { $_ })
}

<#
.SYNOPSIS
    Scans for globally installed Yarn packages.
.DESCRIPTION
    Executes 'yarn global list' and parses the output to discover globally
    installed Yarn packages. Extracts package name and version from info lines.
.EXAMPLE
    $apps = Scan-Yarn
.OUTPUTS
    Array of PSCustomObject with properties: Name, Source, Version, LatestVersion, AppId, Status
#>
function Scan-Yarn {
    $r = Invoke-Cmd 'yarn' @('global', 'list') -AllowFail
    @($r.Stdout -split "`r?`n" | ForEach-Object {
            if ($_ -match '^info "([^@]+)@([^"]+)"') {
                [PSCustomObject]@{
                    name = $Matches[1]; source = 'yarn'; version = $Matches[2]; 
                    latestVersion = ''; appId = $Matches[1]; status = $S_UNK;
                    scanTime = [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                }
            }
        } | Where-Object { $_ })
}

<#
.SYNOPSIS
    Scans for Python pip packages.
.DESCRIPTION
    Attempts to run 'pip list --format=json' using multiple Python executables
    (py, python, python3, pip) to ensure compatibility across different installations.
    Parses JSON output to extract package names and versions.
.EXAMPLE
    $apps = Scan-Pip
.OUTPUTS
    Array of PSCustomObject with properties: Name, Source, Version, LatestVersion, AppId, Status
.NOTES
    Tries multiple Python interpreters in order: py, python, python3, then pip directly.
    Stops at first successful execution.
#>
function Scan-Pip {
    $apps = @()
    foreach ($run in @('py', 'python', 'python3', 'pip')) {
        $a = if ($run -ne 'pip') { @('-m', 'pip', 'list', '--format=json') }else { @('list', '--format=json') }
        $r = Invoke-Cmd $run $a -AllowFail
        if ($r.Stdout) {
            try {
                ($r.Stdout | ConvertFrom-Json) | ForEach-Object {
                    $apps += [PSCustomObject]@{
                        name = $_.name; source = 'pip'; version = $_.version; 
                        latestVersion = ''; appId = $_.name; status = $S_UNK;
                        scanTime = [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    }
                }
                break
            }
            catch { Write-Log "pip list: $_" }
        }
    }
    return $apps
}

<#
.SYNOPSIS
    Scans PATH for common development tools and utilities.
.DESCRIPTION
    Checks for the presence of common CLI tools in the system PATH and extracts
    their version information from --version or -version output. This provides
    visibility into tools not managed by package managers.
.EXAMPLE
    $apps = Scan-Path
.OUTPUTS
    Array of PSCustomObject with properties: Name, Source, Version, LatestVersion, AppId, Status
.NOTES
    Scans for: node, npm, pnpm, yarn, python, git, go, bun, deno, rustc, cargo, dotnet, java, pwsh
    Version extraction uses regex to find semantic version patterns.
#>
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
        $apps += [PSCustomObject]@{
            name = $tool; source = 'path'; version = $ver; 
            latestVersion = ''; appId = $tool; status = $S_UNK;
            scanTime = [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        }
    }
    return $apps
}

<#
.SYNOPSIS
    Scans for Rust crates installed via cargo.
.DESCRIPTION
    Executes 'cargo install --list' to discover globally installed Rust crates.
    Parses the output to extract crate names and versions.
.EXAMPLE
    $apps = Scan-Rust
.OUTPUTS
    Array of PSCustomObject with properties: Name, Source, Version, LatestVersion, AppId, Status
#>
function Scan-Rust {
    $r = Invoke-Cmd 'cargo' @('install', '--list') -AllowFail
    $apps = @()
    if (-not $r.Stdout) { return $apps }
    $r.Stdout -split "`r?`n" | ForEach-Object {
        if ($_ -match '^([^\s]+)\s+v([^\s:]+):') {
            $apps += [PSCustomObject]@{
                name = $Matches[1]; source = 'rust'; version = $Matches[2]; 
                latestVersion = ''; appId = $Matches[1]; status = $S_UNK;
                scanTime = [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            }
        }
    }
    return $apps
}

<#
.SYNOPSIS
    Scans Scoop for installed packages.
.DESCRIPTION
    Executes 'scoop list' to discover all packages managed by Scoop.
    Parses the output to extract package name and version.
.EXAMPLE
    $apps = Scan-Scoop
.OUTPUTS
    Array of PSCustomObject with properties: Name, Source, Version, LatestVersion, AppId, Status
#>
function Scan-Scoop {
    $r = Invoke-Cmd 'scoop' @('list') -AllowFail
    $apps = @()
    if (-not $r.Stdout) { return $apps }
    
    $lines = $r.Stdout -split "`r?`n"
    $startIndex = 0
    
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match 'Name' -and $lines[$i] -match 'Version') {
            $startIndex = $i + 2
            break
        }
    }
    
    for ($i = $startIndex; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].Trim()
        if (-not $line -or $line.StartsWith('---') -or $line.StartsWith('+')) { continue }
        
        $parts = $line -split '\s+'
        if ($parts.Count -ge 2) {
            $name = $parts[0]
            $version = $parts[1]
            if ($name -and $version -and -not $name.StartsWith(' ')) {
                $apps += [PSCustomObject]@{
                    name = $name; source = 'scoop'; version = $version;
                    latestVersion = ''; appId = $name; status = $S_UNK;
                    scanTime = [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                }
            }
        }
    }
    return $apps
}

<#
.SYNOPSIS
    Scans .NET Global Tools installed via dotnet.
.DESCRIPTION
    Executes 'dotnet tool list -g' to discover all .NET CLI tools installed globally.
    Parses the output to extract package name and version.
.EXAMPLE
    $apps = Scan-Dotnet
.OUTPUTS
    Array of PSCustomObject with properties: Name, Source, Version, LatestVersion, AppId, Status
#>
function Scan-Dotnet {
    $r = Invoke-Cmd 'dotnet' @('tool', 'list', '-g') -AllowFail
    $apps = @()
    if (-not $r.Stdout) { return $apps }

    $lines = $r.Stdout -split "`r?`n"
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].Trim()
        if (-not $line -or $line.StartsWith('---') -or $line.StartsWith('Package')) { continue }

        $parts = $line -split '\s+'
        if ($parts.Count -ge 2) {
            $name = $parts[0]
            $version = $parts[1]
            if ($name -and $version) {
                $apps += [PSCustomObject]@{
                    name = $name; source = 'dotnet'; version = $version;
                    latestVersion = ''; appId = $name; status = $S_UNK;
                    scanTime = [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                }
            }
        }
    }
    return $apps
}

<#
.SYNOPSIS
    Scans Windows Registry for installed applications.
.DESCRIPTION
    Queries the Windows Registry Uninstall keys to discover installed applications.
    Checks HKLM (both 64-bit and 32-bit views) and HKCU hives. Excludes system
    components marked with SystemComponent=1.
.EXAMPLE
    $apps = Scan-Registry
.OUTPUTS
    Array of PSCustomObject with properties: Name, Source, Version, LatestVersion, AppId, Status
.NOTES
    Registry paths scanned:
    - HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
    - HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
    - HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
#>
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
                            name = $item.DisplayName.Trim(); source = 'registry';
                            version = $item.DisplayVersion.Trim(); latestVersion = '';
                            appId = $item.PSChildName; status = $S_UNK;
                            scanTime = [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                        })
                }
                catch { }
            }
        }
        catch { }
    }
    return [array]@($list | Sort-Object Name)
}

<#
.SYNOPSIS
    Deduplicates application list by source, name, and version.
.DESCRIPTION
    Creates a unique list of applications by combining source, name, and version
    into a composite key. Returns sorted results for consistent output.
.PARAMETER Apps
    Array of application objects that may contain duplicates.
.EXAMPLE
    $unique = Get-Unique $apps
.OUTPUTS
    Array of unique PSCustomObject applications.
#>
function Get-Unique([array]$Apps) {
    $map = @{}
    foreach ($a in $Apps) { $k = "$($a.source)|$($a.name)|$($a.version)".ToLower(); $map[$k] = $a }
    return [array]@($map.Values | Sort-Object { $_.source + $_.name })
}

# ── Cache Functions ────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Loads cached application data from the cache file.
.DESCRIPTION
    Reads the JSON cache file and returns the cached applications if the cache
    is still valid (not expired). Adds missing properties for backward compatibility.
    Returns $null if cache doesn't exist or is expired.
.EXAMPLE
    $apps = Load-Cache
.OUTPUTS
    Array of PSCustomObject applications, or $null if cache is missing/expired.
.NOTES
    Cache validity is determined by $CFG_CACHE_HOURS (default: 2 hours).
    Adds 'Status' and 'LatestVersion' properties if missing for schema evolution.
#>
function Load-Cache {
    if (-not(Test-Path $CACHE_FILE)) { return $null }
    try {
        $j = Get-Content $CACHE_FILE -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not $j.timestamp) { return $null }
        $cacheTs = [datetime]::Parse($j.timestamp).ToUniversalTime()
        $cacheAge = ([datetime]::UtcNow - $cacheTs).TotalHours
        if ($cacheAge -gt $CFG_CACHE_HOURS) { return $null }
        # Map camelCase to PowerShell object properties
        $apps = @()
        if ($j.apps) {
            $apps = @($j.apps | ForEach-Object {
                if (-not $_.PSObject.Properties['status']) { $_ | Add-Member -NotePropertyName 'status' -NotePropertyValue $S_UNK }
                if (-not $_.PSObject.Properties['latestVersion']) { $_ | Add-Member -NotePropertyName 'latestVersion' -NotePropertyValue '' }
                if (-not $_.PSObject.Properties['scanTime']) { $_ | Add-Member -NotePropertyName 'scanTime' -NotePropertyValue [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
                $_
            })
        }
        return $apps
    }
    catch { return $null }
}

<#
.SYNOPSIS
    Saves application data to the cache file.
.DESCRIPTION
    Serializes the application array to JSON and writes to the cache file.
    Creates the data directory if it doesn't exist. Includes metadata like
    timestamp, version, and total app count.
.PARAMETER Apps
    Array of application objects to cache.
.EXAMPLE
    Save-Cache $apps
.NOTES
    Cache file location: $DATA_DIR\cache.json
    Uses UTF8 encoding for proper character support.
#>
function Save-Cache([array]$Apps) {
    # Create data directory if it doesn't exist
    if (-not(Test-Path $DATA_DIR)) { New-Item -ItemType Directory $DATA_DIR -Force | Out-Null }
    # Write cache with metadata (timestamp, version, totalApps, apps)
    @{timestamp = [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"); version = $VER; totalApps = $Apps.Count; apps = $Apps } | ConvertTo-Json -Depth 10 | Set-Content $CACHE_FILE -Encoding UTF8
}

<#
.SYNOPSIS
    Removes the cache file from disk.
.DESCRIPTION
    Deletes the cache file if it exists. Used for forcing fresh scans.
.EXAMPLE
    Clear-AppCache
#>
function Clear-AppCache { if (Test-Path $CACHE_FILE) { Remove-Item $CACHE_FILE -Force } }

# ── Update Checker Functions ───────────────────────────────────────────────────

<#
.SYNOPSIS
    Checks for winget package updates.
.DESCRIPTION
    Queries winget for available upgrades and matches them against the provided
    application list. Updates the LatestVersion and Status properties for apps
    with available updates.
.PARAMETER Apps
    Array of application objects to check for updates.
.EXAMPLE
    $count = Check-Winget $apps
.OUTPUTS
    Number of packages with available updates.
#>
function Check-Winget([array]$Apps) {
    $t = @($Apps | Where-Object { $_.source -eq 'winget' }); if (-not $t) { return 0 }
    # Get available upgrades from winget and parse with -Avail flag
    $upd = Parse-Winget (Invoke-NativeCmd 'winget' @('upgrade', '--accept-source-agreements') -AllowFail).Stdout -Avail
    $n = 0
    foreach ($u in $upd) {
        # Match by AppId (case-insensitive)
        $a = $t | Where-Object { $_.appId -and $u.appId -and $_.appId.ToLower() -eq $u.appId.ToLower() } | Select-Object -First 1
        if (-not $a) { continue }; $a.latestVersion = $u.latestVersion; $a.status = $S_UPD; $n++
    }
    return $n
}

<#
.SYNOPSIS
    Checks for registry package updates via winget.
.DESCRIPTION
    Uses winget upgrade list to find updates for registry-discovered applications.
    Matches by application name and updates status accordingly.
.PARAMETER Apps
    Array of application objects to check for updates.
.EXAMPLE
    $count = Check-Registry $apps
.OUTPUTS
    Number of packages with available updates.
#>
function Check-Registry([array]$Apps) {
    $t = @($Apps | Where-Object { $_.source -eq 'registry' }); if (-not $t) { return 0 }
    $upd = Parse-Winget (Invoke-NativeCmd 'winget' @('upgrade', '--accept-source-agreements') -AllowFail).Stdout -Avail
    # Build lookup map for efficient matching
    $map = @{}; foreach ($u in $upd) { $map[$u.name.ToLower()] = $u }
    $n = 0
    foreach ($a in $t) {
        $m = $map[$a.name.ToLower()]
        if ($m -and $m.LatestVersion) { $a.latestVersion = $m.latestVersion; $a.status = $S_UPD; $n++ } else { $a.status = $S_OK }
    }
    return $n
}

<#
.SYNOPSIS
    Checks for Chocolatey package updates.
.DESCRIPTION
    Runs 'choco outdated' to find packages with newer versions available.
    Updates the application list with latest versions and status.
.PARAMETER Apps
    Array of application objects to check for updates.
.EXAMPLE
    $count = Check-Choco $apps
.OUTPUTS
    Number of packages with available updates.
#>
function Check-Choco([array]$Apps) {
    $t = @($Apps | Where-Object { $_.source -eq 'chocolatey' }); if (-not $t) { return 0 }
    $r = Invoke-Cmd 'choco' @('outdated', '--limit-output') -AllowFail; $n = 0
    foreach ($line in ($r.Stdout -split "`r?`n")) {
        # Parse pipe-delimited format: name|current|latest
        $p = $line -split '\|'; if ($p.Count -lt 3 -or -not $p[0] -or -not $p[2]) { continue }
        $a = $t | Where-Object { $_.name.ToLower() -eq $p[0].Trim().ToLower() } | Select-Object -First 1
        if (-not $a) { continue }; $a.latestVersion = $p[2].Trim(); $a.status = $S_UPD; $n++
    }
    return $n
}

<#
.SYNOPSIS
    Checks for npm package updates.
.DESCRIPTION
    Runs 'npm outdated -g --json' to find globally installed packages with
    newer versions available. Updates application status accordingly.
.PARAMETER Apps
    Array of application objects to check for updates.
.EXAMPLE
    $count = Check-Npm $apps
.OUTPUTS
    Number of packages with available updates.
#>
function Check-Npm([array]$Apps) {
    $t = @($Apps | Where-Object { $_.source -eq 'npm' }); if (-not $t) { return 0 }
    $r = Invoke-NativeCmd 'npm' @('outdated', '-g', '--json') -AllowFail; if (-not $r.Stdout) { return 0 }
    $n = 0
    try {
        $j = $r.Stdout | ConvertFrom-Json
        foreach ($prop in $j.PSObject.Properties) {
            $nm = $prop.Name
            $app = $t | Where-Object { $_.name -eq $nm } | Select-Object -First 1
            if (-not $app) { continue }
            $lat = $j.$nm.latest ?? ''
            if ($lat) { $app.latestVersion = $lat; $app.status = $S_UPD; $n++ }
        }
    }
    catch { Write-Log "npm outdated: $_" }
    return $n
}

<#
.SYNOPSIS
    Checks for pnpm package updates.
.DESCRIPTION
    Runs 'pnpm outdated -g --json' to find globally installed packages with
    newer versions available. Handles both array and object JSON response formats.
.PARAMETER Apps
    Array of application objects to check for updates.
.EXAMPLE
    $count = Check-Pnpm $apps
.OUTPUTS
    Number of packages with available updates.
#>
function Check-Pnpm([array]$Apps) {
    $t = @($Apps | Where-Object { $_.source -eq 'pnpm' }); if (-not $t) { return 0 }
    $r = Invoke-NativeCmd 'pnpm' @('outdated', '-g', '--json') -AllowFail; if (-not $r.Stdout) { return 0 }
    $n = 0
    try {
        $j = $r.Stdout | ConvertFrom-Json
        # Handle both array format and object format responses
        $entries = if ($j -is [array]) { $j | ForEach-Object { [PSCustomObject]@{N = $_.name; L = $_.latest ?? $_.wanted ?? '' } } }
        else { $j.PSObject.Properties | ForEach-Object { $v = $j.$($_.Name); [PSCustomObject]@{N = $_.Name; L = $v.latest ?? $v.wanted ?? '' } } }
        foreach ($e in $entries) {
            $a = $t | Where-Object { $_.name -eq $e.N } | Select-Object -First 1
            if (-not $a -or -not $e.L) { continue }; $a.latestVersion = $e.L; $a.status = $S_UPD; $n++
        }
    }
    catch { Write-Log "pnpm outdated: $_" }
    return $n
}

<#
.SYNOPSIS
    Checks for Bun package updates.
.DESCRIPTION
    Uses 'npm info <package> version' to get the latest version for each Bun
    package since Bun doesn't have a native outdated command.
.PARAMETER Apps
    Array of application objects to check for updates.
.EXAMPLE
    $count = Check-Bun $apps
.OUTPUTS
    Number of packages with available updates.
#>
function Check-Bun([array]$Apps) {
    $t = @($Apps | Where-Object { $_.source -eq 'bun' }); $n = 0
    foreach ($a in $t) {
        $r = Invoke-NativeCmd 'npm' @('info', $a.name, 'version') -AllowFail
        $l = $r.Stdout.Trim()
        if ($l -and $l -ne $a.version -and $l -notmatch 'ERR') { $a.latestVersion = $l; $a.status = $S_UPD; $n++ }
    }; return $n
}

<#
.SYNOPSIS
    Checks for Yarn package updates.
.DESCRIPTION
    Uses 'npm info <package> version' to get the latest version for each Yarn
    package since Yarn global outdated is unreliable.
.PARAMETER Apps
    Array of application objects to check for updates.
.EXAMPLE
    $count = Check-Yarn $apps
.OUTPUTS
    Number of packages with available updates.
#>
function Check-Yarn([array]$Apps) {
    $t = @($Apps | Where-Object { $_.source -eq 'yarn' }); $n = 0
    foreach ($a in $t) {
        $r = Invoke-NativeCmd 'npm' @('info', $a.name, 'version') -AllowFail
        $l = $r.Stdout.Trim()
        if ($l -and $l -ne $a.version -and $l -notmatch 'ERR') { $a.latestVersion = $l; $a.status = $S_UPD; $n++ }
    }; return $n
}

<#
.SYNOPSIS
    Checks for Rust crate updates.
.DESCRIPTION
    Uses 'cargo install-update -l' to list installed crates with available updates.
    Parses the table output to identify crates needing updates.
.PARAMETER Apps
    Array of application objects to check for updates.
.EXAMPLE
    $count = Check-Rust $apps
.OUTPUTS
    Number of packages with available updates.
#>
function Check-Rust([array]$Apps) {
    $t = @($Apps | Where-Object { $_.source -eq 'rust' }); if (-not $t) { return 0 }
    $n = 0
    $err = 0

    foreach ($a in $t) {
        try {
            $url = "https://crates.io/api/v1/crates/$($a.name)"
            $r = Invoke-WebRequest -Uri $url -UserAgent 'SystemUpdateCLI' -TimeoutSec 10 -ErrorAction Stop
            if ($r.StatusCode -eq 200) {
                $data = $r.Content | ConvertFrom-Json
                $versions = $data.versions
                if ($versions.Count -gt 0) {
                    $latest = $versions[0].num
                    $a.latestVersion = $latest
                    $a.status = $S_UPD
                    $n++
                }
            }
        } catch {
            $err++
        }
    }

    if ($err -gt 0) { Write-Host "[dim]⚠️ $err Rust crate(s) could not be checked via API[/dim]" }
    return $n
}

<#
.SYNOPSIS
    Checks for Scoop package updates.
.DESCRIPTION
    Runs 'scoop status' to find Scoop packages with available updates.
.PARAMETER Apps
    Array of application objects to check for updates.
.EXAMPLE
    $count = Check-Scoop $apps
#>
function Check-Scoop([array]$Apps) {
    $t = @($Apps | Where-Object { $_.source -eq 'scoop' }); if (-not $t) { return 0 }
    $r = Invoke-Cmd 'scoop' @('status') -AllowFail
    if (-not $r.Stdout) { return 0 }
    
    $updateMap = @{}
    $lines = $r.Stdout -split "`r?`n"
    
    foreach ($line in $lines) {
        $line = $line.Trim()
        if (-not $line -or $line.StartsWith('---')) { continue }
        $parts = $line -split '\s+' | Where-Object { $_ }
        if ($parts.Count -ge 2) {
            $name = $parts[0]
            $current = $parts[1]
            if ($parts.Count -ge 3) {
                $latest = $parts[2]
                if ($latest.StartsWith('(') -and $latest.EndsWith(')')) {
                    $latest = $latest.Substring(1, $latest.Length - 2)
                }
                if ($current -ne $latest) {
                    $updateMap[$name] = $latest
                }
            }
        }
    }
    
    $n = 0
    foreach ($app in $t) {
        $latest = $updateMap[$app.name]
        if ($latest) {
            $app.latestVersion = $latest
            $app.status = $S_UPD
            $n++
        }
    }
    return $n
}

<#
.SYNOPSIS
    Checks for .NET Global Tool updates.
.DESCRIPTION
    Runs 'dotnet tool list -g --outdated' to find .NET tools with newer versions.
.PARAMETER Apps
    Array of application objects to check for updates.
.EXAMPLE
    $count = Check-Dotnet $apps
.OUTPUTS
    Number of packages with available updates.
#>
function Check-Dotnet([array]$Apps) {
    $t = @($Apps | Where-Object { $_.source -eq 'dotnet' }); if (-not $t) { return 0 }
    $r = Invoke-Cmd 'dotnet' @('tool', 'list', '-g', '--outdated') -AllowFail
    if (-not $r.Stdout) { return 0 }

    $n = 0
    $lines = $r.Stdout -split "`r?`n"
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].Trim()
        if (-not $line -or $line.StartsWith('---') -or $line.StartsWith('Package')) { continue }
        $parts = $line -split '\s+' | Where-Object { $_ }
        if ($parts.Count -ge 2) {
            $name = $parts[0]
            $latest = $parts[1]
            $app = $t | Where-Object { $_.name.ToLower() -eq $name.ToLower() } | Select-Object -First 1
            if ($app -and $latest) {
                $app.latestVersion = $latest
                $app.status = $S_UPD
                $n++
            }
        }
    }
    return $n
}

<#
.SYNOPSIS
    Checks for Python pip package updates.
.DESCRIPTION
    Runs 'pip list --outdated --format=json' to find Python packages with newer
    versions available. Tries multiple Python executables for compatibility.
.PARAMETER Apps
    Array of application objects to check for updates.
.EXAMPLE
    $count = Check-Pip $apps
.OUTPUTS
    Number of packages with available updates.
#>
function Check-Pip([array]$Apps) {
    $t = @($Apps | Where-Object { $_.source -eq 'pip' }); if (-not $t) { return 0 }; $n = 0
    foreach ($run in @('py', 'python', 'python3', 'pip')) {
        $a2 = if ($run -ne 'pip') { @('-m', 'pip', 'list', '--outdated', '--format=json') } else { @('list', '--outdated', '--format=json') }
        $r = Invoke-Cmd $run $a2 -AllowFail
        if ($r.Stdout) {
            try {
                ($r.Stdout | ConvertFrom-Json) | ForEach-Object {
                    $nm = $_.name; $app = $t | Where-Object { $_.name.ToLower() -eq $nm.ToLower() } | Select-Object -First 1
                    if ($app -and $_.latest_version) { $app.latestVersion = $_.latest_version; $app.status = $S_UPD; $n++ }
                }
                break
            }
            catch { Write-Log "pip outdated: $_" }
        }
    }; return $n
}

<#
.SYNOPSIS
    Checks for PATH tool updates via GitHub API and native commands.
.DESCRIPTION
    Checks for updates to PATH-discovered tools using various methods:
    - bun/deno: Native upgrade --dry-run commands
    - npm/yarn/pnpm/node: npm view for latest version
    - python/git/pwsh/rust: GitHub API release queries
    - dotnet: winget show for version info
.PARAMETER Apps
    Array of application objects to check for updates.
.EXAMPLE
    $count = Check-PathUpdates $apps
.OUTPUTS
    Number of packages with available updates.
.NOTES
    Uses GitHub API with User-Agent header for release information.
    Handles preview/stable version comparisons to avoid downgrade suggestions.
#>
function Check-PathUpdates([array]$Apps) {
    $t = @($Apps | Where-Object { $_.source -eq 'path' }); $n = 0
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
                    # Python uses tags, not releases - get latest tag
                    $d = gh-release 'https://api.github.com/repos/python/cpython/tags?per_page=1'
                    if ($d -and $d[0] -and $d[0].name -match 'v?([0-9.]+)') { $latest = $Matches[1] }
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
                { $_ -in @('rustc', 'cargo') } {
                    $d = gh-release 'https://api.github.com/repos/rust-lang/rust/releases/latest'
                    if ($d -and $d.tag_name -match '([0-9.]+)') { $latest = $Matches[1] }
                    if (-not $latest) { $latest = $app.Version }
                }
            }
        }
        catch {}
        if ($latest) {
            $cv = $app.Version -replace '^[^\d]+', ''; $cl = $latest -replace '^[^\d]+', ''
            $app.LatestVersion = $cl
            # Use proper version comparison to avoid suggesting downgrades
            if (Is-NewerVersion $app.Version $latest) { $app.Status = $S_UPD; $n++ } else { $app.Status = $S_OK }
        } else {
            # No latest version found, mark as up-to-date (don't show unknown)
            $app.LatestVersion = '-'
            $app.Status = $S_OK
        }
    }
    return $n
}

<#
.SYNOPSIS
    Finalizes application status for apps without explicit update check.
.DESCRIPTION
    Sets final status for applications that weren't processed by specific
    update checkers. Marks managed sources as OK, leaves others as unknown.
.PARAMETER Apps
    Array of application objects to finalize.
.EXAMPLE
    Finalize $apps
#>
function Finalize([array]$Apps) {
    $managed = @('winget', 'chocolatey', 'npm', 'pnpm', 'bun', 'yarn', 'pip', 'registry', 'rust', 'path', 'dotnet')
    foreach ($a in $Apps) {
        if ($a.status -in @($S_UPD, $S_OK)) { 
            if ($a.status -eq $S_OK -and -not $a.latestVersion) { $a.latestVersion = '-' }
            continue 
        }
        if ($a.latestVersion -or $a.source -in $managed) { 
            $a.status = $S_OK 
            if (-not $a.latestVersion) { $a.latestVersion = '-' }
        } else { 
            $a.status = $S_UNK 
        }
    }
}

# ── Version Comparison Functions ──────────────────────────────────────────────

<#
.SYNOPSIS
    Parses a version string into a comparable array structure.
.DESCRIPTION
    Extracts numeric components from version strings and determines stability.
    Returns an array with [major, minor, patch, isStable] for comparison.
    Handles versions with leading non-numeric characters (e.g., 'v1.2.3').
.PARAMETER verStr
    The version string to parse (e.g., '1.2.3', 'v2.0.0-preview').
.EXAMPLE
    Parse-Version '1.2.3'       # Returns @(1, 2, 3, $true)
    Parse-Version 'v2.0-beta'   # Returns @(2, 0, 0, $false)
.OUTPUTS
    Array of [int, int, int, bool] representing version components.
.NOTES
    Preview/rc/beta/alpha versions are marked as unstable (isStable=$false).
#>
function Parse-Version([string]$verStr) {
    # Remove leading non-numeric characters (e.g., 'v', 'release-')
    $clean = $verStr -replace '^[^\d]+', ''
    # Match semantic version pattern: major.minor.patch
    if ($clean -match '^(\d+)\.(\d+)\.(\d+)') {
        $isStable = $verStr -notmatch 'preview|rc|beta|alpha|-pre'
        return @([int]$Matches[1], [int]$Matches[2], [int]$Matches[3], $isStable)
    }
    # Match major.minor pattern (patch defaults to 0)
    if ($clean -match '^(\d+)\.(\d+)') {
        $isStable = $verStr -notmatch 'preview|rc|beta|alpha|-pre'
        return @([int]$Matches[1], [int]$Matches[2], 0, $isStable)
    }
    # Return zero version for unparseable strings
    return @(0, 0, 0, $false)
}

<#
.SYNOPSIS
    Compares two version strings to determine if latest is newer.
.DESCRIPTION
    Performs intelligent version comparison that handles preview releases
    and prevents downgrade suggestions. Compares major, minor, and patch
    versions while considering stability (stable vs preview).
.PARAMETER current
    The currently installed version.
.PARAMETER latest
    The latest available version to compare against.
.EXAMPLE
    Is-NewerVersion '1.0.0' '1.0.1'   # Returns $true
    Is-NewerVersion '2.0.0-preview' '1.9.0'  # Returns $false (don't downgrade)
.OUTPUTS
    System.Boolean - $true if latest is newer and should be suggested.
.NOTES
    Prevents downgrades from preview to stable when preview is newer major/minor.
    Handles preview/stable transitions correctly.
#>
function Is-NewerVersion([string]$current, [string]$latest) {
    $curr = Parse-Version $current
    $lat = Parse-Version $latest

    # If current is a newer major version preview, don't suggest downgrade
    if ($curr[0] -gt $lat[0]) { return $false }
    # If current is a newer minor in same major, don't suggest downgrade
    if ($curr[0] -eq $lat[0] -and $curr[1] -gt $lat[1]) { return $false }

    # Both stable: standard comparison
    if ($curr[3] -and $lat[3]) {
        return $lat[0] -gt $curr[0] -or `
               ($lat[0] -eq $curr[0] -and $lat[1] -gt $curr[1]) -or `
               ($lat[0] -eq $curr[0] -and $lat[1] -eq $curr[1] -and $lat[2] -gt $curr[2])
    }

    # Current is preview but same base version as latest stable
    if (-not $curr[3] -and $curr[0] -eq $lat[0] -and $curr[1] -eq $lat[1] -and $curr[2] -eq $lat[2]) {
        return $false
    }

    # Latest stable is newer than current stable
    return $lat[0] -gt $curr[0] -or `
           ($lat[0] -eq $curr[0] -and $lat[1] -gt $curr[1]) -or `
           ($lat[0] -eq $curr[0] -and $lat[1] -eq $curr[1] -and $lat[2] -gt $curr[2])
}

# ── Security Vulnerability Functions ───────────────────────────────────────────

<#
.SYNOPSIS
    Checks npm packages for security vulnerabilities.
.DESCRIPTION
    Runs 'npm audit --json' to identify known security vulnerabilities in
    globally installed npm packages. Extracts severity, CVE, and description
    for each vulnerability found.
.PARAMETER Apps
    Array of application objects to check for vulnerabilities.
.EXAMPLE
    $vulns = Check-NpmVulns $apps
.OUTPUTS
    Array of PSCustomObject with properties: Pkg, Sev, CVE, Desc
.NOTES
    Returns empty array if no vulnerabilities found or npm audit fails.
    Severity levels: critical, high, medium, low.
#>
function Check-NpmVulns([array]$Apps) {
    $t = @($Apps | Where-Object { $_.source -eq 'npm' }); if (-not $t) { return @() }
    $r = Invoke-NativeCmd 'npm' @('audit', '--json', '--silent') -AllowFail; if (-not $r.Stdout) { return @() }
    $vulns = @()
    try {
        $j = $r.Stdout | ConvertFrom-Json
        if ($j.vulnerabilities) {
            $j.vulnerabilities.PSObject.Properties | ForEach-Object {
                $nm = $_.Name; $v = $j.vulnerabilities.$nm
                $a = $t | Where-Object { $_.name.ToLower() -eq $nm.ToLower() } | Select-Object -First 1
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

<#
.SYNOPSIS
    Checks pip packages for security vulnerabilities.
.DESCRIPTION
    Runs 'pip check --format=json' to identify known security vulnerabilities
    in installed Python packages. Tries multiple Python executables for
    compatibility.
.PARAMETER Apps
    Array of application objects to check for vulnerabilities.
.EXAMPLE
    $vulns = Check-PipVulns $apps
.OUTPUTS
    Array of PSCustomObject with properties: Pkg, Sev, CVE, Desc
.NOTES
    Returns empty array if no vulnerabilities found or pip check fails.
    Tries py, python, then pip executables in order.
#>
function Check-PipVulns([array]$Apps) {
    $t = @($Apps | Where-Object { $_.source -eq 'pip' }); if (-not $t) { return @() }; $vulns = @()
    foreach ($run in @('py', 'python', 'pip')) {
        $a = if ($run -ne 'pip') { @('-m', 'pip', 'check', '--format=json') } else { @('check', '--format=json') }
        $r = Invoke-Cmd $run $a -AllowFail
        if ($r.Stdout) {
            try {
                ($r.Stdout | ConvertFrom-Json) | ForEach-Object {
                    if (-not $_.vulnerabilities -or $_.vulnerabilities.Count -eq 0) { return }
                    $pn = if ($_.package_name) { $_.package_name } else { $_.name }
                    $found = $t | Where-Object { $_.name.ToLower() -eq $pn.ToLower() } | Select-Object -First 1
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

# ── Output Formatting Functions ────────────────────────────────────────────────

<#
.SYNOPSIS
    Truncates a string to a maximum length with ellipsis.
.DESCRIPTION
    Shortens strings that exceed a specified length, adding an ellipsis
    character (…) to indicate truncation.
.PARAMETER V
    The string to truncate.
.PARAMETER N
    Maximum length of the output string.
.EXAMPLE
    trunc 'VeryLongPackageName' 15  # Returns 'VeryLongPacka…'
.OUTPUTS
    Truncated string or original if within length limit.
#>
function trunc([string]$V, [int]$N) { if ($V.Length -le $N) { $V } else { $V.Substring(0, $N - 1) + '…' } }

<#
.SYNOPSIS
    Removes ANSI escape codes from text.
.DESCRIPTION
    Strips ANSI color and formatting codes from text to get the visible
    character count. Used for proper padding calculations.
.PARAMETER Text
    The text containing ANSI codes to strip.
.EXAMPLE
    stripAnsi "$(c '31' 'red text')"  # Returns 'red text'
.OUTPUTS
    Plain text without ANSI escape codes.
#>
function stripAnsi([string]$Text) {
    return $Text -replace '\x1b\[[0-9;]*m', ''
}

<#
.SYNOPSIS
    Pads text to a specified width, accounting for ANSI codes.
.DESCRIPTION
    Adds spaces to text to reach a target width. Correctly handles
    ANSI-colored text by calculating visible length only.
.PARAMETER Text
    The text to pad (may contain ANSI codes).
.PARAMETER Width
    Target width for the padded output.
.EXAMPLE
    padAnsi "$(c '31' 'red')" 10  # Returns red 'red' + 7 spaces
.OUTPUTS
    Padded text with original ANSI codes preserved.
#>
function padAnsi([string]$Text, [int]$Width) {
    $visible = stripAnsi $Text
    $padding = [Math]::Max(0, $Width - $visible.Length)
    return $Text + (' ' * $padding)
}

<#
.SYNOPSIS
    Prints a formatted table of applications.
.DESCRIPTION
    Displays applications in a color-coded table with columns for
    Package name, Source, Current version, Latest version, and Status.
    Filters to show only updates/vulnerable by default, or all with -ShowAll.
.PARAMETER Apps
    Array of application objects to display.
.PARAMETER ShowAll
    If set, shows all packages including up-to-date ones.
.EXAMPLE
    Print-Table $apps
    Print-Table $apps -ShowAll
.OUTPUTS
    Writes formatted table to host output.
#>
function Print-Table([array]$Apps, [switch]$ShowAll) {
    # Filter apps: by default show only updates/vulnerable, unless ShowAll is true
    $displayApps = if ($ShowAll) { $Apps } else { @($Apps | Where-Object { $_.status -eq $S_UPD -or $_.status -eq $S_VULN }) }

    # Define table columns with keys, titles, and widths
    $cols = @(
        @{K = 'name'; T = 'Package'; W = 30 }
        @{K = 'source'; T = 'Source'; W = 12 }
        @{K = 'version'; T = 'Current'; W = 20 }
        @{K = 'latestVersion'; T = 'Latest'; W = 20 }
        @{K = 'status'; T = 'Status'; W = 17 }
    )
    $sep = '  '
    # Build and display header row in bold cyan
    $hdr = ($cols | ForEach-Object { c '1;36' $_.T.PadRight($_.W) }) -join $sep
    $lineWidth = [Math]::Min((stripAnsi $hdr).Length, $Host.UI.RawUI.WindowSize.Width)
    Write-Host $hdr; Write-Host (gray ('─' * $lineWidth))
    # Display each application row with appropriate colors
    foreach ($app in $displayApps) {
        $row = $cols | ForEach-Object {
            $col = $_
            switch ($col.K) {
                'source' { padAnsi (srcBadge (trunc ($app.source ?? '-') $col.W).Trim()) $col.W }
                'status' { padAnsi (statusBadge $app.status) $col.W }
                'name' { padAnsi (bold (trunc ($app.name ?? '-') $col.W)) $col.W }
                'latestVersion' {
                    if ($app.status -eq $S_OK) {
                        padAnsi '-' $col.W
                    }
                    elseif ($app.status -eq $S_UPD) {
                        padAnsi (yellow (trunc ($app.latestVersion ?? '-') $col.W)) $col.W
                    }
                    else {
                        padAnsi (trunc ($app.latestVersion ?? '-') $col.W) $col.W
                    }
                }
                default { padAnsi (trunc ($app.($col.K) ?? '-') $col.W) $col.W }
            }
        }
        Write-Host ($row -join $sep)
    }
}

<#
.SYNOPSIS
    Prints a formatted table of security vulnerabilities.
.DESCRIPTION
    Displays vulnerabilities in a color-coded table with Package, Severity,
    CVE, and Description columns. Severity colors: red (critical/high),
    yellow (medium), green (low).
.PARAMETER Vulns
    Array of vulnerability objects to display.
.EXAMPLE
    Print-VulnTable $vulns
.OUTPUTS
    Writes formatted vulnerability table to host output.
#>
function Print-VulnTable([array]$Vulns) {
    if (-not $Vulns) { return }
    # Draw table header with warning styling
    $w = [Math]::Min(73, $Host.UI.RawUI.WindowSize.Width - 2)
    Write-Host ''; Write-Host (cyan "┌$('─'*$w)┐")
    Write-Host (c '1;31' "│ $(E 'fire') Security Vulnerabilities Detected$(' '*($w - 34))│")
    Write-Host (cyan "├$('─'*$w)┤")
    Write-Host (cyan "│ $(c '1;31' 'Package'.PadRight(20))  $(c '1;31' 'Severity'.PadRight(10))  $(c '1;31' 'CVE'.PadRight(18))  $(c '1;31' 'Description'.PadRight(20)) │")
    Write-Host (cyan "├$('─'*73)┤")
    # Display each vulnerability with severity-based coloring
    foreach ($v in $Vulns) {
        $sc = switch ($v.Sev.ToLower()) { 'critical' { '31' } 'high' { '31' } 'medium' { '33' } default { '32' } }
        $row = "$(bold (trunc $v.Pkg 20).PadRight(20))  $(c "$sc;1" $v.Sev.ToUpper().PadRight(10))  $(cyan (trunc $v.CVE 18).PadRight(18))  $(dim (trunc $v.Desc 20).PadRight(20))"
        Write-Host (cyan "│ $row │")
    }
    Write-Host (cyan "└$('─'*$w)┘")
}

# ── Export Functions ───────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Exports scan results to JSON or CSV format.
.DESCRIPTION
    Writes application scan results to a file in the specified format.
    JSON includes metadata (scan time, total count). CSV includes selected columns.
.PARAMETER Apps
    Array of application objects to export.
.PARAMETER Fmt
    Export format: 'json' or 'csv'.
.PARAMETER Out
    Output file path. If not specified, generates timestamped filename in current directory.
.EXAMPLE
    Export-Results $apps 'json' 'report.json'
    Export-Results $apps 'csv'  # Creates system_update_YYYY-MM-DDTHH-mm-ss.csv
.OUTPUTS
    Path to the created export file.
.NOTES
    JSON format includes: scanTime, totalApps, apps array.
    CSV columns: Name, Source, Version, LatestVersion, Status, AppId.
#>
function Export-Results([array]$Apps, [string]$Fmt, [string]$Out) {
    $ts = Get-Date -f 'yyyy-MM-ddTHH-mm-ss'
    $fmt = $Fmt.ToLower()
    if ($fmt -ne 'json' -and $fmt -ne 'csv') { throw "Unsupported format: $Fmt. Valid formats: json, csv" }
    $file = if ($Out) { $Out } else { Join-Path (Get-Location) "system_update_$ts.$fmt" }
    if ($fmt -eq 'json') {
        # JSON export with metadata
        @{scanTime = (Get-Date -f 'o'); totalApps = $Apps.Count; apps = $Apps } | ConvertTo-Json -Depth 10 | Set-Content $file -Encoding UTF8
    }
    elseif ($fmt -eq 'csv') {
        # CSV export with selected columns
        $Apps | Select-Object Name, Source, Version, LatestVersion, Status, AppId | Export-Csv $file -NoTypeInformation -Encoding UTF8
    }
    return $file
}

# ── Update Execution Functions ─────────────────────────────────────────────────

<#
.SYNOPSIS
    Executes an update for a single application.
.DESCRIPTION
    Determines the correct update command based on package source and
    executes it. Supports dry-run mode to preview commands without execution.
.PARAMETER App
    Application object to update.
.PARAMETER Dry
    If set, only display the command without executing.
.EXAMPLE
    Exec-Update $app
    Exec-Update $app -Dry
.OUTPUTS
    System.Boolean - $true if update succeeded (or dry-run), $false on failure.
.NOTES
    Handles different command syntax for each source:
    - winget: upgrade --id with optional --version
    - choco: upgrade with optional --version
    - npm/pnpm/bun/yarn: install/add with optional @version
    - pip: install with ==version
    - rust: cargo install-update
    - path: tool-specific commands
#>
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
        'rust' { $cmd = 'cargo'; $ca = @('install-update', $App.Name) }
        'dotnet' { $cmd = 'dotnet'; $ca = @('tool', 'update', '-g', $App.Name) }
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

<#
.SYNOPSIS
    Executes updates for multiple applications with progress tracking.
.DESCRIPTION
    Iterates through applications and executes updates with a progress bar.
    Displays success/failure status for each package and a summary at the end.
.PARAMETER Apps
    Array of application objects to update.
.PARAMETER Dry
    If set, only display commands without executing.
.EXAMPLE
    Exec-Updates $updApps
    Exec-Updates $updApps -Dry
.OUTPUTS
    Writes progress and results to host output.
#>
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

<#
.SYNOPSIS
    Prompts user for confirmation before proceeding.
.DESCRIPTION
    Displays a yes/no prompt using PowerShell's native UI. Returns $true
    for yes, $false for no. Auto-returns $true when -Auto is set.
.PARAMETER Msg
    The confirmation message to display.
.PARAMETER Auto
    If set, automatically returns $true without prompting.
.EXAMPLE
    if (Ask "Proceed with update?") { Exec-Updates $apps }
    if (Ask "Confirm?" -Auto:$Yes) { ... }
.OUTPUTS
    System.Boolean - $true for yes, $false for no.
#>
function Ask([string]$Msg, [switch]$Auto) {
    if ($Auto) { return $true }
    # Use PowerShell's native prompt with Yes/No options (No is default)
    ($Host.UI.PromptForChoice('', "$Msg", @('&Yes', '&No'), 1)) -eq 0
}

# ── Help Display Function ──────────────────────────────────────────────────────

<#
.SYNOPSIS
    Displays the help message with usage information and examples.
.DESCRIPTION
    Shows comprehensive help including all available options, their descriptions,
    and usage examples. Uses emoji and colors for visual appeal.
.EXAMPLE
    Show-Help
.OUTPUTS
    Writes formatted help message to host output.
#>
function Show-Help {
    Write-Host @"
$(E 'sparkle') $(bold (cyan "System Update PowerShell CLI v$VER"))

Usage:  .\system_update.ps1 [options]

Options:
  -UpdateAll              Update all packages with available updates
  -UpdateSource <src>     Update all packages from one source (winget|choco|npm|pnpm|pip|bun|yarn|path|rust|registry)
  -Package <name>         Update a specific package by name
  -Version <ver>          Target version (with -Package)
  -Source <src>           Filter by source (winget|chocolatey|npm|pnpm|bun|yarn|pip|path|rust|registry)
  -DryRun                 Show planned updates without executing
  -NoCache                Force fresh scan
  -ClearCache             Remove cache file and exit
  -Export <json|csv>      Export results to file
  -Output <file>          Output path for export
  -Include <csv>          Limit scan to specific sources (e.g. winget,npm,rust)
  -Yes                    Skip confirmation prompts
  -Help                   Show this help
  -ShowAll                Show all packages (including up-to-date)

Examples:
  .\system_update.ps1
  .\system_update.ps1 -UpdateAll -Yes
  .\system_update.ps1 -Package git -Source chocolatey
  .\system_update.ps1 -UpdateSource winget -DryRun
  .\system_update.ps1 -Export json -Output report.json
  .\system_update.ps1 -ShowAll
"@
}

# ── Main Function ──────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Main entry point for the System Update CLI.
.DESCRIPTION
    Orchestrates the entire update scanning and execution workflow:
    1. Parses command-line arguments
    2. Loads cache or performs fresh scan
    3. Checks for updates across all sources
    4. Scans for security vulnerabilities
    5. Displays results table and summary
    6. Executes updates based on user choice
    
    Handles all command-line options: -UpdateAll, -Package, -UpdateSource,
    -Source, -Include, -Export, -DryRun, -NoCache, -ClearCache, -Yes, -ShowAll
.EXAMPLE
    Main
.OUTPUTS
    Writes all output to host and log file.
.NOTES
    Entry point is wrapped in try/catch for fatal error handling.
    Exit codes: 0 (success), 1 (fatal error), 2 (package not found)
#>
function Main {
    $script:SecurityFindings = @()
    $sourceAliases = @{ choco = 'chocolatey' }
    $normalizedSource = if ($Source) { ($sourceAliases[$Source.ToLower()] ?? $Source.ToLower()) } else { $null }
    $normalizedUpdateSource = if ($UpdateSource) { ($sourceAliases[$UpdateSource.ToLower()] ?? $UpdateSource.ToLower()) } else { $null }
    # Handle help flag first
    if ($Help) { Show-Help; return }
    # Ensure data directory exists
    if (-not(Test-Path $DATA_DIR)) { New-Item -ItemType Directory $DATA_DIR -Force | Out-Null }
    # Handle cache clear request
    if ($ClearCache) { Clear-AppCache; Write-Host "$(E 'disk') $(green 'Cache cleared.')"; return }

    # Display header with version and data directory
    Show-Header "$(E 'rocket') System Update PowerShell CLI v$VER" "$(E 'gear') Data dir: $DATA_DIR"
    if (Test-Path $CACHE_FILE) { Write-Host "$(bold 'Cache') $(gray '->') $CACHE_FILE" }
    Write-Host ''

    # Record start time for duration calculation
    $start = [datetime]::Now
    # Build source filter from -Source or -Include options
    $sf = @{}
    if ($normalizedSource) { $sf[$normalizedSource] = $true }
    if ($Include) {
        $Include.Split(',') | ForEach-Object {
            $s = $_.Trim().ToLower()
            if ($s) { $sf[($sourceAliases[$s] ?? $s)] = $true }
        }
    }

    # Try to load from cache first (unless -NoCache)
    $apps = $null
    if (-not $NoCache) {
        $apps = Load-Cache
        if ($apps) { Write-Host "$(E 'disk') $(green "Loaded $($apps.Count) apps from cache.")`n" }
    }

    # If cache miss or disabled, perform full scan
    if (-not $apps) {
        Write-Host "$(E 'scan') $(bold (cyan 'Scanning sources...'))"
        # Define scanner functions for each source
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
            rust       = { Scan-Rust }
            scoop      = { Scan-Scoop }
            dotnet    = { Scan-Dotnet }
        }
        # Filter scanners based on source selection
        $sel = @($scanners.Keys | Where-Object { $sf.Count -eq 0 -or $sf.ContainsKey($_) })
        $prog = New-Progress $sel.Count "$(E 'scan') Scanning"
        $all = @()
        # Run each scanner and collect results
        foreach ($src in $sel) {
            $chunk = @(& $scanners[$src])
            $prog.Tick("$(srcBadge $src) $($chunk.Count) apps")
            $all += $chunk
        }
        $prog.Done((green "$(E 'ok') scan complete"))
        $apps = Get-Unique $all

        Write-Host "`n$(E 'package') $(bold "Discovered $($apps.Count) unique apps.")"
        if ($CFG_SKIP_UPDATE_CHECKS) {
            Finalize $apps
            Write-Host "$(E 'update') $(yellow 'Skipping update checks (SYSTEM_UPDATE_SKIP_UPDATE_CHECKS).')`n"
        } else {
            Write-Host "$(E 'update') $(bold (cyan 'Checking for updates...'))"

            # Define update checker functions for each source
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
                rust       = { Check-Rust $apps }
                scoop      = { Check-Scoop $apps }
                dotnet    = { Check-Dotnet $apps }
            }
            $prog2 = New-Progress $checkers.Count "$(E 'update') Checking updates"
            $total = 0
            # Run each checker and count updates
            foreach ($src in $checkers.Keys) {
                $cnt = & $checkers[$src]
                $msg = if ($cnt -gt 0) { "$(srcBadge $src) $(yellow "$cnt update(s)")" } else { "$(srcBadge $src) $(gray 'none')" }
                $prog2.Tick($msg); $total += $cnt
            }
            $prog2.Done((green "$(E 'ok') update checks complete"))
            Finalize $apps
            $udColor = if ($total -gt 0) { '33' } else { '32' }
            Write-Host "$(E 'chart') $(c "$udColor;1" "Detected $total update candidates.")`n"
        }

        # Security vulnerability scanning (if enabled)
        if ($CFG_SECURITY -and -not $CFG_SKIP_UPDATE_CHECKS) {
            Write-Host "$(E 'lock') $(bold (magenta 'Checking security vulnerabilities...'))"
            $sevOrder = @{critical = 4; high = 3; medium = 2; low = 1 }
            $thresh = $sevOrder[$CFG_SEVERITY]; if (-not $thresh) { $thresh = 2 }
            $vulns = @(Check-NpmVulns $apps) + @(Check-PipVulns $apps)
            # Filter vulnerabilities by severity threshold
            $vulns = @($vulns | Where-Object { $sv = $sevOrder[$_.Sev.ToLower()]; if (-not $sv) { $sv = 1 }; $sv -ge $thresh })
            $script:SecurityFindings = $vulns
            if ($vulns.Count -gt 0) {
                $vulns | ForEach-Object {
                    $vPkg = $_.Pkg
                    $a = $apps | Where-Object { $_.name.ToLower() -eq $vPkg.ToLower() } | Select-Object -First 1
                    if ($a) { $a.Status = $S_VULN }
                }
                Write-Host "$(E 'fire') $(red (bold "Found $($vulns.Count) security vulnerabilities."))`n"
            }
            else { Write-Host "$(E 'shield') $(green 'No security vulnerabilities found.')`n" }
        }

        # Save results to cache
        Save-Cache $apps
    }

    # Apply source filters if specified
    if ($normalizedSource) { $apps = @($apps | Where-Object { $_.Source.ToLower() -eq $normalizedSource }) }
    if ($Include) {
        $inc = @($Include.ToLower().Split(',') | ForEach-Object {
                $s = $_.Trim()
                if ($s) { ($sourceAliases[$s] ?? $s) }
            })
        $apps = @($apps | Where-Object { $_.Source.ToLower() -in $inc })
    }

    # Calculate summary statistics
    $updApps = @($apps | Where-Object { $_.Status -eq $S_UPD })
    $vulnApps = @($apps | Where-Object { $_.Status -eq $S_VULN })
    $el = ([datetime]::Now - $start).TotalSeconds

    # Display summary section
    Write-Host (bold (magenta "`n$(E 'chart') Summary"))
    Write-Host "$(E 'package') total apps      $(bold $apps.Count)"
    $us = if ($updApps.Count -gt 0) { yellow(bold "$($updApps.Count)") } else { green(bold "$($updApps.Count)") }
    Write-Host "$(E 'update') updates         $us"
    Write-Host "$(E 'hourglass') scan duration   $(bold "$($el.ToString('0.00'))s")"
    $coloredSrc = @($apps | Group-Object Source | ForEach-Object { "$(srcBadge $_.Name):$(bold $_.Count)" })
    Write-Host "$(E 'gear') sources         $($coloredSrc -join ', ')"
    Write-Host ''

    # Display applications table
    Print-Table $apps -ShowAll:$ShowAll

    # Display showing status after table (matching JS behavior)
    if ($ShowAll) {
        Write-Host "`n$(E 'disk') $(dim 'Showing: all packages')"
    } else {
        Write-Host "`n$(E 'disk') $(dim 'Showing: updates only')"
    }

    # Display vulnerability table if vulnerabilities found
    $va = @($apps | Where-Object { $_.Status -eq $S_VULN })
    if ($va -and $CFG_SECURITY) {
        if ($script:SecurityFindings -and $script:SecurityFindings.Count -gt 0) {
            Print-VulnTable $script:SecurityFindings
        } else {
            Print-VulnTable ($va | ForEach-Object { [PSCustomObject]@{Pkg = $_.Name; Sev = 'high'; CVE = 'N/A'; Desc = 'Security update recommended' } })
        }
    }

    # Display status message if no specific action requested
    if (-not $Package -and -not $UpdateAll -and -not $UpdateSource) {
        if ($updApps.Count -eq 0) { Write-Host "`n$(E 'sparkle') $(green 'System is up to date!')" }
        else { Write-Host "`n$(E 'target') $(yellow (bold "Found $($updApps.Count) available updates"))" }
    }

    # Handle -Package: update specific package
    if ($Package) {
        $wanted = $Package.ToLower()
        $m = @($apps | Where-Object { $_.name.ToLower() -eq $wanted -and (-not $normalizedSource -or $_.Source.ToLower() -eq $normalizedSource) })
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
    # Handle -UpdateSource: update all from specific source
    elseif ($UpdateSource) {
        $cand = @($updApps | Where-Object { $_.Source.ToLower() -eq $normalizedUpdateSource })
        if (-not $cand) { Write-Host "`n$(E 'ok') $(green "No updates for: $normalizedUpdateSource")" }
        elseif (Ask "Proceed with $($cand.Count) update(s) from $normalizedUpdateSource?" -Auto:$Yes) { Exec-Updates $cand -Dry:$DryRun }
    }
    # Handle -UpdateAll: update everything
    elseif ($UpdateAll) {
        if (-not $updApps) { Write-Host "`n$(E 'ok') $(green 'No updates available.')" }
        elseif (Ask "Proceed with all $($updApps.Count) updates?" -Auto:$Yes) { Exec-Updates $updApps -Dry:$DryRun }
    }

    # Handle -Export: export results to file
    if ($Export) {
        $exportFmt = $Export.Trim().ToLower()
        # Handle case where Export might have leading dashes or unexpected format
        if ($exportFmt -like '*json*') { $exportFmt = 'json' }
        elseif ($exportFmt -like '*csv*') { $exportFmt = 'csv' }
        if ($exportFmt -eq 'json' -or $exportFmt -eq 'csv') {
            $f = Export-Results $apps $exportFmt $Output
            Write-Host "`n$(E 'export') $(green (bold "Exported to: $f"))"
        } else {
            Write-Host "`n$(E 'warn') $(yellow "Invalid export format: '$Export'. Use: json or csv")"
        }
    }
}

# ── Script Entry Point ─────────────────────────────────────────────────────────
# Execute Main function with error handling for fatal errors
try { Main } catch {
    Write-Log "fatal: $_"
    Write-Host "$(E 'fail') Fatal error: $_" -ForegroundColor Red
    exit 1
}
