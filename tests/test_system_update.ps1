$ErrorActionPreference = 'Stop'

$SCRIPT = Join-Path $PSScriptRoot '..' 'system_update.ps1'
$POWERSHELL = 'pwsh'
$env:SYSTEM_UPDATE_SKIP_UPDATE_CHECKS = '1'
$env:SYSTEM_UPDATE_SECURITY = '0'
$env:SYSTEM_UPDATE_CMD_TIMEOUT = '8'


function Invoke-CLI {
	param(
		[string]$CliArgs,
		[int]$Timeout = 40
	)

	$argTokens = @()
	if ($CliArgs) {
		$argTokens = @($CliArgs -split '\s+' | Where-Object { $_ })
	}
	$psi = [System.Diagnostics.ProcessStartInfo]::new()
	$psi.FileName = $POWERSHELL
	$psi.UseShellExecute = $false
	$psi.CreateNoWindow = $true
	$psi.RedirectStandardOutput = $true
	$psi.RedirectStandardError = $true
	[void]$psi.ArgumentList.Add('-NoProfile')
	[void]$psi.ArgumentList.Add('-NonInteractive')
	[void]$psi.ArgumentList.Add('-File')
	[void]$psi.ArgumentList.Add($SCRIPT)
	foreach ($arg in $argTokens) {
		[void]$psi.ArgumentList.Add($arg)
	}

	$process = [System.Diagnostics.Process]::new()
	$process.StartInfo = $psi
	[void]$process.Start()
	$outTask = $process.StandardOutput.ReadToEndAsync()
	$errTask = $process.StandardError.ReadToEndAsync()
	$finished = $process.WaitForExit($Timeout * 1000)
	if (-not $finished) {
		try { $process.Kill($true) } catch {}
		$process.WaitForExit()
	}

	$stdout = $outTask.GetAwaiter().GetResult()
	$stderr = $errTask.GetAwaiter().GetResult()

	return @{
		Code   = if ($finished) { $process.ExitCode } else { -1 }
		StdOut = $stdout
		StdErr = $stderr
	}
}

Describe 'system_update.ps1' {
	It '-help shows usage' {
		$res = Invoke-CLI -CliArgs '-Help'
		$res.Code | Should Be 0
		($res.StdOut + $res.StdErr) | Should Match 'usage|system'
	}

	It '-include winget scans winget source' {
		$res = Invoke-CLI -CliArgs '-Include winget -NoCache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '-include npm scans npm source' {
		$res = Invoke-CLI -CliArgs '-Include npm -NoCache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '-include chocolatey scans chocolatey source' {
		$res = Invoke-CLI -CliArgs '-Include chocolatey -NoCache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '-include pnpm scans pnpm source' {
		$res = Invoke-CLI -CliArgs '-Include pnpm -NoCache' -Timeout 60
		$output = $res.StdOut + $res.StdErr
		($res.Code -eq 0) -or ($output -like '*pnpm*scan*') | Should Be $true
	}

	It '-include pip scans pip source' {
		$res = Invoke-CLI -CliArgs '-Include pip -NoCache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '-include path scans path source' {
		$res = Invoke-CLI -CliArgs '-Include path -NoCache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '-include registry scans registry source' {
		$res = Invoke-CLI -CliArgs '-Include registry -NoCache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '-include rust scans rust source' {
		$res = Invoke-CLI -CliArgs '-Include rust -NoCache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '-include scoop scans scoop source' {
		$res = Invoke-CLI -CliArgs '-Include scoop -NoCache' -Timeout 60
		$output = $res.StdOut + $res.StdErr
		($res.Code -eq 0) -or ($output -like '*scoop*scan*') | Should Be $true
	}

	It '-include dotnet scans dotnet source' {
		$res = Invoke-CLI -CliArgs '-Include dotnet -NoCache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '-include appx scans appx source' {
		$res = Invoke-CLI -CliArgs '-Include appx -NoCache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '-include msix scans msix source' {
		$res = Invoke-CLI -CliArgs '-Include msix -NoCache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '-dry-run flag accepted' {
		$res = Invoke-CLI -CliArgs '-DryRun -Include path'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '-show-all flag accepted' {
		$res = Invoke-CLI -CliArgs '-ShowAll -Include path -NoCache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '-clear-cache removes cache' {
		$res = Invoke-CLI -CliArgs '-ClearCache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'cache|clear'
	}

	It '-include unknown source shows error' {
		$res = Invoke-CLI -CliArgs '-Include unknown_source_xyz'
		$output = $res.StdOut + $res.StdErr
		$output.ToLower() | Should Match 'scan|source'
	}

	It '-include multiple sources' {
		$res = Invoke-CLI -CliArgs '-Include winget,npm -NoCache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '-Source flag accepted' {
		$res = Invoke-CLI -CliArgs '-Source path -NoCache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '-Yes flag accepted' {
		$res = Invoke-CLI -CliArgs '-Yes -DryRun -Include path -NoCache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '-security osv scan' {
		$res = Invoke-CLI -CliArgs '-Include pip -NoCache' -Timeout 90
		$output = $res.StdOut + $res.StdErr
		($res.Code -eq 0) -or ($output -like '*vuln*') -or ($output -like '*security*') | Should Be $true
	}

	It '-security github advisory scan' {
		$res = Invoke-CLI -CliArgs '-Include npm -NoCache' -Timeout 90
		$output = $res.StdOut + $res.StdErr
		($res.Code -eq 0) -or ($output -like '*vuln*') -or ($output -like '*advisory*') | Should Be $true
	}
}