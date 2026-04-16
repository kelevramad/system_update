$ErrorActionPreference = 'Stop'

$SCRIPT = Join-Path $PSScriptRoot '..' 'system_update.ps1'
$POWERSHELL = 'pwsh'


function Invoke-CLI {
	param(
		[string]$Args,
		[int]$Timeout = 60
	)

	$tempOut = "$env:TEMP\su_stdout_$PID.txt"
	$tempErr = "$env:TEMP\su_stderr_$PID.txt"

	$process = Start-Process -FilePath $POWERSHELL -ArgumentList "-NoProfile", "-NonInteractive", "-File", $SCRIPT, $Args -PassThru -NoNewWindow -Wait -RedirectStandardOutput $tempOut -RedirectStandardError $tempErr

	$stdout = if (Test-Path $tempOut) { Get-Content $tempOut -Raw -ErrorAction SilentlyContinue } else { '' }
	$stderr = if (Test-Path $tempErr) { Get-Content $tempErr -Raw -ErrorAction SilentlyContinue } else { '' }

	Remove-Item $tempOut -ErrorAction SilentlyContinue
	Remove-Item $tempErr -ErrorAction SilentlyContinue

	return @{
		Code = $process.ExitCode
		StdOut = $stdout
		StdErr = $stderr
	}
}

Describe 'system_update.ps1' {
	It '--help shows usage' {
		$res = Invoke-CLI -Args '--help'
		$res.Code | Should Be 0
		($res.StdOut + $res.StdErr) | Should Match 'usage|system'
	}

	It '--include winget scans winget source' {
		$res = Invoke-CLI -Args '--include winget --no-cache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '--include npm scans npm source' {
		$res = Invoke-CLI -Args '--include npm --no-cache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '--include chocolatey scans chocolatey source' {
		$res = Invoke-CLI -Args '--include chocolatey --no-cache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '--include pnpm scans pnpm source' {
		$res = Invoke-CLI -Args '--include pnpm --no-cache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '--include pip scans pip source' {
		$res = Invoke-CLI -Args '--include pip --no-cache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '--include path scans path source' {
		$res = Invoke-CLI -Args '--include path --no-cache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '--include registry scans registry source' {
		$res = Invoke-CLI -Args '--include registry --no-cache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '--include rust scans rust source' {
		$res = Invoke-CLI -Args '--include rust --no-cache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '--include scoop scans scoop source' {
		$res = Invoke-CLI -Args '--include scoop --no-cache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '--dry-run flag accepted' {
		$res = Invoke-CLI -Args '--dry-run --include path'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '--show-all flag accepted' {
		$res = Invoke-CLI -Args '--show-all --include path --no-cache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '--clear-cache removes cache' {
		$res = Invoke-CLI -Args '--clear-cache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'cache|clear'
	}

	It '--include unknown source shows error' {
		$res = Invoke-CLI -Args '--include unknown_source_xyz'
		$output = $res.StdOut + $res.StdErr
		$output.ToLower() | Should Match 'scan|source'
	}

	It '--include multiple sources' {
		$res = Invoke-CLI -Args '--include winget,npm --no-cache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '--log flag accepted' {
		$res = Invoke-CLI -Args '--log --include path --no-cache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}

	It '--debug flag accepted' {
		$res = Invoke-CLI -Args '--debug --include path --no-cache'
		$output = $res.StdOut + $res.StdErr
		$res.Code | Should Be 0
		$output.ToLower() | Should Match 'scan|apps'
	}
}