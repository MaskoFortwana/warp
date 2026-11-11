#
# Runtime verification of the portable zip, run on a Windows machine (the CI
# runner) with the zip used the way a user uses it. Implements M3-design.md
# section 4: S0, A3, A4, A5, A8a, A6/A7, A8b, D4, A9, A11, A10.
#
# Every check returns { Id, Status (pass|fail|skipped), Evidence, Note } and a
# failing check never stops the run. The script writes runtime-report.md and
# runtime-report.json to -ReportDir and exits 1 if any check failed (skipped
# does not fail).
#
# The decision logic (snapshot comparison, profile change listing, settings
# diff, report rendering) is pure and exercised by `-SelfTest` on any OS.
# Everything that needs Windows lives in win32.ps1 or in the Invoke-Check*
# functions and is not loaded by -SelfTest.

[CmdletBinding()]
param(
    [string]$ZipPath,
    [string]$WorkRoot = (Join-Path -Path $(if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }) -ChildPath 'Portable Test'),
    [string]$ReportDir = (Join-Path -Path (Join-Path -Path 'dist' -ChildPath 'portable') -ChildPath 'runtime'),
    [switch]$SkipStandardUser,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $SelfTest) {
    # Dot-sourced at script scope so its functions are visible everywhere below.
    . (Join-Path -Path $PSScriptRoot -ChildPath 'win32.ps1')
}

# Timeouts, in seconds (explicit per M3-design.md section 5).
$script:WindowTimeout = 60
$script:MarkerTimeout = 60
$script:CloseTimeout = 30
$script:MessageBoxTimeout = 30
$script:SettleSeconds = 10

# Names of the six places Warp must not leave anything behind (SPEC 5.3).
$script:TraceNames = @(
    '%APPDATA%\warp',
    '%LOCALAPPDATA%\warp',
    '%USERPROFILE%\.warp-oss',
    'HKCU\Software\Warp.dev',
    'HKCU\Software\Classes\warposs',
    'HKCU\...\CurrentVersion\Run value WarpOss'
)

# Name of the secure-storage file for the signed-in user: service name (the app
# id) + '-' + key 'User'.
$script:SecureStorageFileName = 'dev.warp.WarpOss-User'

# ---------------------------------------------------------------------------
# Pure logic (tested by -SelfTest)
# ---------------------------------------------------------------------------

function New-CheckResult {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][ValidateSet('pass', 'fail', 'skipped')][string]$Status,
        [string[]]$Evidence = @(),
        [string]$Note = ''
    )
    return [pscustomobject]@{
        Id       = $Id
        Status   = $Status
        Evidence = [string[]]@($Evidence)
        Note     = $Note
    }
}

function Compare-TraceSnapshot {
    # Before and After map each trace name to "exists". A finding is a trace that
    # exists after but did not exist before (a missing key counts as "did not
    # exist"). Traces that already existed are not Warp's doing and are ignored.
    param(
        [Parameter(Mandatory = $true)][hashtable]$Before,
        [Parameter(Mandatory = $true)][hashtable]$After
    )

    $findings = [System.Collections.Generic.List[string]]::new()
    foreach ($name in ($After.Keys | Sort-Object)) {
        $existedBefore = $Before.ContainsKey($name) -and [bool]$Before[$name]
        if ([bool]$After[$name] -and -not $existedBefore) {
            $findings.Add("$name was created during the run")
        }
    }
    return $findings.ToArray()
}

function Test-PathExcluded {
    # Plain case-insensitive prefix match. Directory excludes carry a trailing
    # separator in the list, so 'Temp\' does not swallow 'Temp2'; file-name
    # prefixes (NTUSER.DAT) deliberately have none.
    param([string]$Path, [string[]]$ExcludePrefix)

    foreach ($prefix in $ExcludePrefix) {
        if ($prefix -and $Path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Get-ProfileChanges {
    # Files under Root whose last-write time is later than Since, minus the
    # excluded prefixes. Only the last-write time is used: a copied or extracted
    # file keeps an old mtime but gets a new creation time, which would be a
    # false positive; a file Warp writes always has a fresh mtime. Excluded
    # directories are pruned, not walked, because a profile can be large.
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][datetime]$Since,
        [string[]]$ExcludePrefix = @()
    )

    $sinceUtc = $Since.ToUniversalTime()
    $changed = [System.Collections.Generic.List[string]]::new()
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push([System.IO.Path]::GetFullPath($Root))
    $sep = [System.IO.Path]::DirectorySeparatorChar

    while ($pending.Count -gt 0) {
        $dir = $pending.Pop()
        try {
            foreach ($entry in [System.IO.Directory]::EnumerateFileSystemEntries($dir)) {
                $info = [System.IO.FileInfo]::new($entry)
                $isDir = ($info.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0
                if ($isDir) {
                    # Never follow junctions/symlinks: they loop and leave the profile.
                    if (($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    if (Test-PathExcluded -Path ($entry + $sep) -ExcludePrefix $ExcludePrefix) { continue }
                    $pending.Push($entry)
                } else {
                    if (Test-PathExcluded -Path $entry -ExcludePrefix $ExcludePrefix) { continue }
                    if ($info.LastWriteTimeUtc -gt $sinceUtc) { $changed.Add($entry) }
                }
            }
        } catch {
            # Unreadable directory (another user's data, a locked folder): skip it.
            continue
        }
    }
    return @($changed | Sort-Object)
}

function Compare-RegistryExport {
    # Compares two `reg export` dumps by line. AddedKeys are the key headers that
    # are new; WarpKeys are the new key headers that mention Warp, which is the
    # failing part. Value lines are not used for the verdict: Windows itself
    # records executed programs under existing keys (AppCompatFlags, MuiCache)
    # and those lines mention the exe path without Warp having written them.
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$BeforeLines,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$AfterLines
    )

    $known = [System.Collections.Generic.HashSet[string]]::new([string[]]$BeforeLines, [System.StringComparer]::Ordinal)
    $addedKeys = [System.Collections.Generic.List[string]]::new()
    $addedCount = 0
    foreach ($line in $AfterLines) {
        if ($known.Contains($line)) { continue }
        $addedCount++
        if ($line.StartsWith('[')) { $addedKeys.Add($line) }
    }
    $warpKeys = @($addedKeys | Where-Object { $_ -match '(?i)warp' })
    return [pscustomobject]@{
        AddedLineCount = $addedCount
        AddedKeys      = $addedKeys.ToArray()
        WarpKeys       = $warpKeys
    }
}

function ConvertTo-FlatSettings {
    # Flattens a settings file into path -> text. JSON is parsed; anything else
    # (settings.toml) is read as `key = value` lines with [section] prefixes.
    # Prefix tells the files apart in one map.
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory = $true)][string]$Prefix
    )

    $flat = [ordered]@{}
    if ($Text.Trim() -eq '') { return $flat }

    $parsed = $null
    $isJson = $false
    if ($Text.TrimStart().StartsWith('{')) {
        try {
            $parsed = ConvertFrom-Json -InputObject $Text -AsHashtable -Depth 20
            $isJson = $true
        } catch {
            $isJson = $false
        }
    }

    if ($isJson) {
        $walk = {
            param($Node, [string]$Path)
            if ($Node -is [System.Collections.IDictionary]) {
                foreach ($k in $Node.Keys) { & $walk $Node[$k] "$Path.$k" }
            } elseif ($Node -is [System.Collections.IList]) {
                for ($i = 0; $i -lt $Node.Count; $i++) { & $walk $Node[$i] "$Path[$i]" }
            } else {
                $flat[$Path] = if ($null -eq $Node) { 'null' } else { ConvertTo-Json -InputObject $Node -Compress }
            }
        }
        & $walk $parsed $Prefix
        return $flat
    }

    $section = ''
    $lineNo = 0
    foreach ($raw in ($Text -split "`r?`n")) {
        $lineNo++
        $line = $raw.Trim()
        if ($line -eq '' -or $line.StartsWith('#')) { continue }
        if ($line -match '^\[(.+)\]$') { $section = $Matches[1]; continue }
        if ($line -match '^([^=]+?)\s*=\s*(.*)$') {
            $flat["$Prefix.$section.$($Matches[1])"] = $Matches[2]
        } else {
            $flat["$Prefix.line$lineNo"] = $line
        }
    }
    return $flat
}

function Get-SettingDiff {
    # Keys whose value is new or different in After. Removed keys are ignored:
    # the check is about a value that was changed and must survive.
    param(
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Before,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$After
    )

    $changes = [System.Collections.Generic.List[object]]::new()
    foreach ($key in $After.Keys) {
        $was = if ($Before.Contains($key)) { [string]$Before[$key] } else { $null }
        if ($null -eq $was -or $was -ne [string]$After[$key]) {
            $changes.Add([pscustomobject]@{ Key = $key; Before = $was; After = [string]$After[$key] })
        }
    }
    return $changes.ToArray()
}

function Select-FontSettingChange {
    # Prefers changes whose key looks font-related; falls back to all changes.
    # Returns the chosen set and whether it is the font-specific one.
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Changes)

    $font = @($Changes | Where-Object { $_.Key -match '(?i)font|zoom' })
    if ($font.Count -gt 0) {
        return [pscustomobject]@{ Chosen = $font; FontSpecific = $true }
    }
    return [pscustomobject]@{ Chosen = @($Changes); FontSpecific = $false }
}

function Get-RandomPasswordChars {
    # 24 characters from four classes, at least one of each, shuffled with a
    # cryptographic RNG. Returned as chars so the caller can build a
    # SecureString without ever creating a plain string.
    param([int]$Length = 24)

    $classes = @(
        'ABCDEFGHJKLMNPQRSTUVWXYZ',
        'abcdefghijkmnopqrstuvwxyz',
        '23456789',
        '!#%+-=?@_'
    )
    $all = -join $classes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]
    $chars = [System.Collections.Generic.List[char]]::new()
    foreach ($class in $classes) { $chars.Add($class[$rng::GetInt32($class.Length)]) }
    while ($chars.Count -lt $Length) { $chars.Add($all[$rng::GetInt32($all.Length)]) }
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $j = $rng::GetInt32($i + 1)
        $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
    }
    return $chars.ToArray()
}

function New-RandomSecureString {
    $secure = [System.Security.SecureString]::new()
    foreach ($c in (Get-RandomPasswordChars)) { $secure.AppendChar($c) }
    $secure.MakeReadOnly()
    return $secure
}

function ConvertTo-MarkdownCell {
    param([AllowEmptyString()][string]$Text)
    return ($Text -replace '\|', '\|' -replace "`r?`n", ' ')
}

function ConvertTo-RuntimeReportMarkdown {
    param(
        [Parameter(Mandatory = $true)][object[]]$Results,
        [Parameter(Mandatory = $true)][hashtable]$Meta
    )

    $sb = [System.Text.StringBuilder]::new()
    $failed = @($Results | Where-Object { $_.Status -eq 'fail' }).Count
    $skipped = @($Results | Where-Object { $_.Status -eq 'skipped' }).Count
    $passed = @($Results | Where-Object { $_.Status -eq 'pass' }).Count
    $verdict = if ($failed -eq 0) { 'PASS' } else { 'FAIL' }

    [void]$sb.AppendLine('# Runtime verification')
    [void]$sb.AppendLine()
    foreach ($k in ($Meta.Keys | Sort-Object)) { [void]$sb.AppendLine("- $k`: $($Meta[$k])") }
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("**Result: $verdict** ($passed passed, $failed failed, $skipped skipped)")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('| Check | Status | Note | Evidence |')
    [void]$sb.AppendLine('|---|---|---|---|')
    foreach ($r in $Results) {
        $evidence = ($r.Evidence | ForEach-Object { ConvertTo-MarkdownCell -Text $_ }) -join ', '
        [void]$sb.AppendLine("| $($r.Id) | $($r.Status) | $(ConvertTo-MarkdownCell -Text $r.Note) | $evidence |")
    }
    [void]$sb.AppendLine()
    foreach ($r in $Results) {
        $images = @($r.Evidence | Where-Object { $_ -like '*.png' })
        if ($images.Count -eq 0) { continue }
        [void]$sb.AppendLine("## $($r.Id) screenshots")
        [void]$sb.AppendLine()
        foreach ($img in $images) {
            [void]$sb.AppendLine("![$img]($img)")
            [void]$sb.AppendLine()
        }
    }
    return $sb.ToString()
}

# ---------------------------------------------------------------------------
# Self test (any OS)
# ---------------------------------------------------------------------------

function Invoke-SelfTest {
    $failures = [System.Collections.Generic.List[string]]::new()
    function Assert-Equal {
        param($Actual, $Expected, [string]$What)
        if ("$Actual" -ne "$Expected") { $failures.Add("$What : expected '$Expected', got '$Actual'") }
    }

    # Compare-TraceSnapshot
    $before = @{ 'a' = $false; 'b' = $true; 'c' = $false }
    $clean = @(Compare-TraceSnapshot -Before $before -After @{ 'a' = $false; 'b' = $true; 'c' = $false })
    Assert-Equal $clean.Count 0 'clean snapshot has no findings'
    $dirty = @(Compare-TraceSnapshot -Before $before -After @{ 'a' = $true; 'b' = $true; 'c' = $false; 'd' = $true })
    Assert-Equal $dirty.Count 2 'new traces are findings (including keys missing before)'
    Assert-Equal @($dirty | Where-Object { $_ -like 'a *' }).Count 1 'finding names the trace'
    $kept = @(Compare-TraceSnapshot -Before $before -After @{ 'b' = $true })
    Assert-Equal $kept.Count 0 'pre-existing trace is not a finding'

    # Get-ProfileChanges on a temp tree with fake timestamps
    $root = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("wp-selftest-" + [guid]::NewGuid().ToString('N'))
    try {
        $t0 = [datetime]::UtcNow.AddHours(-1)
        $old = $t0.AddHours(-5)
        $new = $t0.AddMinutes(10)
        $layout = @{
            'old.txt'                   = $old
            'new.txt'                   = $new
            'Temp/cache.bin'            = $new
            'Temp2/keep.bin'            = $new
            'sub/deep/warp/state.json'  = $new
            'sub/deep/untouched.txt'    = $old
            'NTUSER.DAT.LOG1'           = $new
        }
        foreach ($rel in $layout.Keys) {
            $full = Join-Path -Path $root -ChildPath $rel
            [void](New-Item -ItemType Directory -Path (Split-Path -Path $full -Parent) -Force)
            [System.IO.File]::WriteAllText($full, 'x')
            [System.IO.File]::SetLastWriteTimeUtc($full, $layout[$rel])
        }
        $sep = [System.IO.Path]::DirectorySeparatorChar
        $excludes = @(((Join-Path -Path $root -ChildPath 'Temp') + $sep), (Join-Path -Path $root -ChildPath 'NTUSER.DAT'))
        $changes = @(Get-ProfileChanges -Root $root -Since $t0 -ExcludePrefix $excludes)
        $rel = @($changes | ForEach-Object { [System.IO.Path]::GetRelativePath($root, $_).Replace('\', '/') })
        Assert-Equal ($rel -join ',') 'new.txt,sub/deep/warp/state.json,Temp2/keep.bin' 'profile changes after T0 minus excludes'
        $all = @(Get-ProfileChanges -Root $root -Since $t0)
        Assert-Equal $all.Count 5 'without excludes all five new files are listed'
        $none = @(Get-ProfileChanges -Root $root -Since $t0.AddDays(1))
        Assert-Equal $none.Count 0 'nothing is newer than the future'
    } finally {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Compare-RegistryExport
    $regBefore = @('Windows Registry Editor Version 5.00', '[HKEY_CURRENT_USER\Software\Existing]', '"a"="1"')
    $regAfter = $regBefore + @('"b"="2"', '[HKEY_CURRENT_USER\Software\Warp.dev]', '"x"="y"', '[HKEY_CURRENT_USER\Software\Other]',
        '"path"="C:\\Portable Test\\WarpPortable\\warp-oss.exe"')
    $reg = Compare-RegistryExport -BeforeLines $regBefore -AfterLines $regAfter
    Assert-Equal $reg.AddedKeys.Count 2 'added registry keys'
    Assert-Equal $reg.WarpKeys.Count 1 'only the Warp key header is a Warp finding (value lines are ignored)'
    Assert-Equal $reg.AddedLineCount 5 'added registry lines'

    # Settings flattening and diff
    $jsonBefore = '{"FontSize": 13, "Theme": "dark", "Nested": {"a": [1, 2]}}'
    $jsonAfter = '{"FontSize": 14, "Theme": "dark", "Nested": {"a": [1, 3]}, "New": true}'
    $diff = @(Get-SettingDiff -Before (ConvertTo-FlatSettings -Text $jsonBefore -Prefix 'p') -After (ConvertTo-FlatSettings -Text $jsonAfter -Prefix 'p'))
    Assert-Equal (($diff | ForEach-Object { $_.Key } | Sort-Object) -join ',') 'p.FontSize,p.Nested.a[1],p.New' 'JSON diff keys'
    $pick = Select-FontSettingChange -Changes $diff
    Assert-Equal $pick.FontSpecific $true 'font-specific change is preferred'
    Assert-Equal $pick.Chosen.Count 1 'only the font change is chosen'
    $pickAll = Select-FontSettingChange -Changes @($diff | Where-Object { $_.Key -notmatch 'Font' })
    Assert-Equal $pickAll.FontSpecific $false 'falls back to all changes'
    Assert-Equal $pickAll.Chosen.Count 2 'fallback keeps all changes'
    $toml = "# c`n[appearance]`nfont_size = 14`n`n[other]`nx = `"y`"`n"
    $flatToml = ConvertTo-FlatSettings -Text $toml -Prefix 't'
    Assert-Equal $flatToml['t.appearance.font_size'] '14' 'toml value parsed'
    Assert-Equal $flatToml['t.other.x'] '"y"' 'toml string parsed'
    Assert-Equal (ConvertTo-FlatSettings -Text '' -Prefix 'e').Count 0 'empty text flattens to nothing'
    $noChange = @(Get-SettingDiff -Before (ConvertTo-FlatSettings -Text $jsonBefore -Prefix 'p') -After (ConvertTo-FlatSettings -Text $jsonBefore -Prefix 'p'))
    Assert-Equal $noChange.Count 0 'identical settings have no diff'

    # Password characters
    $pwChars = @(Get-RandomPasswordChars)
    Assert-Equal $pwChars.Count 24 'password length'
    $pwText = -join $pwChars
    Assert-Equal ($pwText -cmatch '[A-Z]') $true 'password has upper case'
    Assert-Equal ($pwText -cmatch '[a-z]') $true 'password has lower case'
    Assert-Equal ($pwText -match '[0-9]') $true 'password has a digit'
    Assert-Equal ($pwText -match '[!#%+=?@_-]') $true 'password has a symbol'
    $secure = New-RandomSecureString
    Assert-Equal $secure.Length 24 'secure string length'
    Assert-Equal $secure.IsReadOnly() $true 'secure string is read-only'

    # Report rendering
    $results = @(
        (New-CheckResult -Id 'S0' -Status pass -Evidence @('s0-before.json') -Note 'ok'),
        (New-CheckResult -Id 'A3' -Status fail -Evidence @('a3-first-start.png') -Note 'no window | pipe'),
        (New-CheckResult -Id 'A10' -Status skipped -Note 'secondary logon unavailable')
    )
    $md = ConvertTo-RuntimeReportMarkdown -Results $results -Meta @{ Zip = 'x.zip' }
    Assert-Equal ($md -match 'Result: FAIL\*\* \(1 passed, 1 failed, 1 skipped\)') $true 'report summary line'
    Assert-Equal ($md.Contains('![a3-first-start.png](a3-first-start.png)')) $true 'report embeds screenshots'
    Assert-Equal ($md.Contains('no window \| pipe')) $true 'report escapes pipes'
    Assert-Equal ($md.Contains('| A10 | skipped |')) $true 'report lists skipped checks'
    $json = ConvertTo-Json -InputObject @($results) -Depth 5 | ConvertFrom-Json
    Assert-Equal $json.Count 3 'results round-trip through JSON'
    $allPass = ConvertTo-RuntimeReportMarkdown -Results @($results[0]) -Meta @{}
    Assert-Equal ($allPass -match 'Result: PASS') $true 'all-pass verdict'

    if ($failures.Count -gt 0) {
        $failures | ForEach-Object { [Console]::Error.WriteLine("SELFTEST FAIL: $_") }
        return $false
    }
    Write-Host 'SelfTest passed.'
    return $true
}

# ---------------------------------------------------------------------------
# Windows helpers
# ---------------------------------------------------------------------------

function Resolve-FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function Get-TraceSnapshot {
    # Existence of the six trace locations. The registry root and the three
    # directories are parameters so the same function checks another user.
    param(
        [string]$AppData = $env:APPDATA,
        [string]$LocalAppData = $env:LOCALAPPDATA,
        [string]$UserProfileDir = $env:USERPROFILE,
        [string]$RegistryRoot = 'HKCU:'
    )

    $runKey = "$RegistryRoot\Software\Microsoft\Windows\CurrentVersion\Run"
    $runValue = $false
    if (Test-Path -LiteralPath $runKey) {
        $props = Get-ItemProperty -LiteralPath $runKey
        $runValue = $null -ne $props.PSObject.Properties['WarpOss']
    }
    $snapshot = [ordered]@{}
    $snapshot[$script:TraceNames[0]] = Test-Path -LiteralPath (Join-Path -Path $AppData -ChildPath 'warp')
    $snapshot[$script:TraceNames[1]] = Test-Path -LiteralPath (Join-Path -Path $LocalAppData -ChildPath 'warp')
    $snapshot[$script:TraceNames[2]] = Test-Path -LiteralPath (Join-Path -Path $UserProfileDir -ChildPath '.warp-oss')
    $snapshot[$script:TraceNames[3]] = Test-Path -LiteralPath "$RegistryRoot\Software\Warp.dev"
    $snapshot[$script:TraceNames[4]] = Test-Path -LiteralPath "$RegistryRoot\Software\Classes\warposs"
    $snapshot[$script:TraceNames[5]] = $runValue
    return $snapshot
}

function ConvertTo-PlainHashtable {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Dictionary)
    $h = @{}
    foreach ($k in $Dictionary.Keys) { $h[$k] = $Dictionary[$k] }
    return $h
}

function Export-HkcuRegistry {
    param([Parameter(Mandatory = $true)][string]$Path)
    & reg.exe export HKCU $Path /y | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "reg export HKCU failed with exit code $LASTEXITCODE" }
    return [System.IO.File]::ReadAllLines($Path)
}

function Get-DefaultProfileExcludes {
    # Writes that are acceptable by the brief (%TEMP%, GPU shader caches) plus
    # background noise of Windows and PowerShell itself on a CI runner. Each
    # entry is a prefix; directories end with a separator.
    param([Parameter(Mandatory = $true)][string]$ProfileDir, [string[]]$Extra = @())

    $local = Join-Path -Path $ProfileDir -ChildPath 'AppData\Local'
    $roaming = Join-Path -Path $ProfileDir -ChildPath 'AppData\Roaming'
    $dirs = @(
        (Join-Path $local 'Temp'),
        (Join-Path $local 'D3DSCache'),
        (Join-Path $local 'NVIDIA'),
        (Join-Path $local 'AMD'),
        (Join-Path $local 'Microsoft\Windows\INetCache'),
        (Join-Path $local 'Microsoft\Windows\Explorer'),
        (Join-Path $local 'Microsoft\Windows\WER'),
        (Join-Path $local 'Microsoft\Windows\WebCache'),
        (Join-Path $local 'Microsoft\Windows\Caches'),
        (Join-Path $local 'Microsoft\Windows\PowerShell'),
        (Join-Path $local 'Microsoft\CLR_v4.0'),
        (Join-Path $local 'Microsoft\CLR_v4.0_32'),
        (Join-Path $local 'Microsoft\PowerShell'),
        (Join-Path $local 'CrashDumps'),
        (Join-Path $roaming 'Microsoft\Windows\Recent'),
        (Join-Path $roaming 'Microsoft\Windows\PowerShell'),
        (Join-Path $roaming 'Microsoft\Windows\Start Menu')
    ) | ForEach-Object { $_ + [System.IO.Path]::DirectorySeparatorChar }
    $files = @((Join-Path $ProfileDir 'NTUSER.DAT'), (Join-Path $ProfileDir 'ntuser.ini'))
    $more = @($Extra | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') + '\' })
    return @($dirs + $files + $more)
}

function Test-ProcessAlive {
    param([Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process)
    try {
        $Process.Refresh()
        return -not $Process.HasExited
    } catch {
        return $null -ne (Get-Process -Id $Process.Id -ErrorAction SilentlyContinue)
    }
}

function Stop-ProcessTree {
    param([System.Diagnostics.Process]$Process)
    if ($null -eq $Process) { return }
    if (Test-ProcessAlive -Process $Process) {
        & taskkill.exe /PID $Process.Id /T /F 2>&1 | Out-Null
        [void]$Process.WaitForExit(10000)
    }
}

function Stop-WarpProcessesIn {
    # Safety net for "always kill leftovers": every process whose executable
    # lives inside the folder (warp-oss.exe, OpenConsole.exe) goes.
    param([Parameter(Mandatory = $true)][string]$Folder)

    $prefix = $Folder.TrimEnd('\') + '\'
    foreach ($p in @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue)) {
        if ($p.ExecutablePath -and $p.ExecutablePath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            & taskkill.exe /PID $p.ProcessId /T /F 2>&1 | Out-Null
        }
    }
}

function Start-WarpApp {
    # Started with the folder as working directory, like a double-click.
    param(
        [Parameter(Mandatory = $true)][string]$ExeDir,
        [pscredential]$Credential
    )

    $exe = Join-Path -Path $ExeDir -ChildPath 'warp-oss.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "warp-oss.exe not found in $ExeDir" }
    $arguments = @{ FilePath = $exe; WorkingDirectory = $ExeDir; PassThru = $true }
    if ($null -ne $Credential) {
        $arguments['Credential'] = $Credential
        $arguments['LoadUserProfile'] = $true
    }
    $process = Start-Process @arguments
    # Touching the handle caches the exit code for processes that end quickly.
    [void]$process.Handle
    return $process
}

function Close-WarpApp {
    # WM_CLOSE like the X button, wait for exit, kill after the timeout and say so.
    param([Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process)

    if (-not (Test-ProcessAlive -Process $Process)) {
        return [pscustomobject]@{ Forced = $false; Note = 'already exited' }
    }
    [void](Close-ProcessWindow -ProcessId $Process.Id)
    if ($Process.WaitForExit($script:CloseTimeout * 1000)) {
        return [pscustomobject]@{ Forced = $false; Note = "closed gracefully, exit code $($Process.ExitCode)" }
    }
    Stop-ProcessTree -Process $Process
    return [pscustomobject]@{ Forced = $true; Note = "did not exit within $($script:CloseTimeout) s after WM_CLOSE; killed" }
}

function Wait-Condition {
    param([scriptblock]$Condition, [int]$TimeoutSeconds, [int]$IntervalMilliseconds = 500)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (& $Condition) { return $true }
        Start-Sleep -Milliseconds $IntervalMilliseconds
    } while ([DateTime]::UtcNow -lt $deadline)
    return [bool](& $Condition)
}

function Read-SharedText {
    # Reads a file the app may still have open.
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    $stream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
    try {
        $reader = [System.IO.StreamReader]::new($stream)
        try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally {
        $stream.Dispose()
    }
}

function Save-Screenshot {
    # Never throws: a failed screenshot must not hide the check's own result.
    # Returns the file name on success, $null otherwise.
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][string]$Name,
        [string]$TitleLike
    )

    try {
        $windows = @(Get-ProcessWindows -ProcessId $ProcessId)
        if ($TitleLike) { $windows = @($windows | Where-Object { $_.Title -like $TitleLike }) }
        if ($windows.Count -eq 0) { return $null }
        Save-WindowScreenshot -Handle $windows[0].Handle -Path (Join-Path -Path $script:Ctx.ReportDir -ChildPath $Name)
        return $Name
    } catch {
        Write-Host "  screenshot $Name failed: $($_.Exception.Message)"
        return $null
    }
}

function Copy-FolderLogs {
    # data\state\logs of one copy into <ReportDir>\logs\<Label>\.
    param([Parameter(Mandatory = $true)][string]$ExeDir, [Parameter(Mandatory = $true)][string]$Label)

    $source = Join-Path -Path $ExeDir -ChildPath 'data\state\logs'
    if (-not (Test-Path -LiteralPath $source -PathType Container)) { return $false }
    $target = Join-Path -Path (Join-Path -Path $script:Ctx.ReportDir -ChildPath 'logs') -ChildPath $Label
    [void](New-Item -ItemType Directory -Path $target -Force)
    foreach ($file in Get-ChildItem -LiteralPath $source -Recurse -File) {
        $rel = [System.IO.Path]::GetRelativePath($source, $file.FullName)
        $dest = Join-Path -Path $target -ChildPath $rel
        [void](New-Item -ItemType Directory -Path (Split-Path -Path $dest -Parent) -Force)
        try {
            $in = [System.IO.FileStream]::new($file.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
            try {
                $out = [System.IO.File]::Create($dest)
                try { $in.CopyTo($out) } finally { $out.Dispose() }
            } finally { $in.Dispose() }
        } catch {
            Write-Host "  could not copy log $($file.FullName): $($_.Exception.Message)"
        }
    }
    return $true
}

function Copy-PortableFolder {
    # Copies <Source>\WarpPortable into a new <DestRoot> (created), returns the
    # new exe dir.
    param([Parameter(Mandatory = $true)][string]$SourceExeDir, [Parameter(Mandatory = $true)][string]$DestRoot)

    [void](New-Item -ItemType Directory -Path $DestRoot -Force)
    Copy-Item -LiteralPath $SourceExeDir -Destination $DestRoot -Recurse -Force
    return Join-Path -Path $DestRoot -ChildPath (Split-Path -Path $SourceExeDir -Leaf)
}

function Test-WerFaultFor {
    # True when Windows Error Reporting has a crash dialog open for this pid.
    param([Parameter(Mandatory = $true)][int]$ProcessId)
    foreach ($p in @(Get-CimInstance -ClassName Win32_Process -Filter "Name='WerFault.exe'" -ErrorAction SilentlyContinue)) {
        if ($p.CommandLine -match "(^|\s)-p\s+$ProcessId(\s|$)") { return $true }
    }
    return $false
}

function Wait-AppStart {
    # Window within the timeout, then a settle period, then still alive.
    # Returns { Ok; Window; Detail }.
    param([Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process)

    $window = Wait-ProcessWindow -ProcessId $Process.Id -TimeoutSeconds $script:WindowTimeout
    if ($null -eq $window) {
        $detail = if (Test-ProcessAlive -Process $Process) { "no visible window within $($script:WindowTimeout) s" } else { "process exited with code $($Process.ExitCode) before any window appeared" }
        return [pscustomobject]@{ Ok = $false; Window = $null; Detail = $detail }
    }
    Start-Sleep -Seconds $script:SettleSeconds
    if (-not (Test-ProcessAlive -Process $Process)) {
        return [pscustomobject]@{ Ok = $false; Window = $window; Detail = "process exited with code $($Process.ExitCode) within $($script:SettleSeconds) s after the window appeared" }
    }
    return [pscustomobject]@{ Ok = $true; Window = $window; Detail = "window '$($window.Title)' ($($window.Width)x$($window.Height))" }
}

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

function Invoke-CheckSafe {
    # Last line of defence: an unexpected error becomes a failed check.
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)][scriptblock]$Body)

    Write-Host "== $Id =="
    try {
        $out = @(& $Body)
        $result = @($out | Where-Object { $_ -is [pscustomobject] -and $null -ne $_.PSObject.Properties['Status'] -and $null -ne $_.PSObject.Properties['Id'] }) | Select-Object -Last 1
        if ($null -eq $result) { $result = New-CheckResult -Id $Id -Status fail -Note 'check returned no result' }
    } catch {
        $result = New-CheckResult -Id $Id -Status fail -Note "Unhandled error: $($_.Exception.Message)"
    }
    Write-Host "   -> $($result.Status): $($result.Note)"
    return $result
}

function Invoke-CheckS0 {
    $evidence = [System.Collections.Generic.List[string]]::new()
    $status = 'pass'
    $note = ''
    try {
        $script:Ctx.Before = Get-TraceSnapshot
        $script:Ctx.T0 = Get-Date
        [System.IO.File]::WriteAllText((Join-Path $script:Ctx.ReportDir 's0-before.json'), (ConvertTo-Json -InputObject $script:Ctx.Before))
        $evidence.Add('s0-before.json')
        $script:Ctx.RegBeforePath = Join-Path -Path $script:Ctx.WorkRoot -ChildPath 'reg-before.reg'
        try {
            $script:Ctx.RegBeforeLines = Export-HkcuRegistry -Path $script:Ctx.RegBeforePath
        } catch {
            $script:Ctx.RegBeforeLines = $null
            $note = "HKCU export failed ($($_.Exception.Message)); registry diff will not be available. "
        }
        $existing = @($script:Ctx.Before.Keys | Where-Object { $script:Ctx.Before[$_] })
        $note += if ($existing.Count -gt 0) { "Already present before the run (ignored later): $($existing -join '; ')" } else { 'None of the six trace locations existed before the run.' }
        $note += " T0=$($script:Ctx.T0.ToString('o'))"
    } catch {
        $status = 'fail'
        $note = "Unexpected error: $($_.Exception.Message)"
    }
    return New-CheckResult -Id 'S0' -Status $status -Evidence $evidence.ToArray() -Note $note
}

function Invoke-CheckA3 {
    $evidence = [System.Collections.Generic.List[string]]::new()
    $status = 'fail'
    $note = ''
    try {
        $rootA = Join-Path -Path $script:Ctx.WorkRoot -ChildPath 'Folder A'
        [void](New-Item -ItemType Directory -Path $rootA -Force)
        # ZipFile is much faster than Expand-Archive on a zip of this size.
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($script:Ctx.ZipPath, $rootA)
        $dirA = Join-Path -Path $rootA -ChildPath 'WarpPortable'
        if (-not (Test-Path -LiteralPath (Join-Path $dirA 'warp-oss.exe') -PathType Leaf)) {
            throw "The zip does not contain WarpPortable\warp-oss.exe (extracted to $rootA)"
        }
        $script:Ctx.DirA = $dirA

        # The shell Warp starts inherits these; A4 uses them to avoid typing quotes.
        $env:WP_MARKER = Join-Path -Path $script:Ctx.WorkRoot -ChildPath 'a4-marker.txt'
        $env:WP_OK = 'warp-portable-ok'

        $script:Ctx.ProcA = Start-WarpApp -ExeDir $dirA
        $window = Wait-ProcessWindow -ProcessId $script:Ctx.ProcA.Id -TimeoutSeconds $script:WindowTimeout
        if ($null -ne $window) {
            Start-Sleep -Seconds 5
            $shot = Save-Screenshot -ProcessId $script:Ctx.ProcA.Id -Name 'a3-first-start.png'
            if ($shot) { $evidence.Add($shot) }
            Start-Sleep -Seconds ($script:SettleSeconds - 5)
        }
        $alive = Test-ProcessAlive -Process $script:Ctx.ProcA
        if ($null -eq $window) {
            $note = if ($alive) { "No visible window within $($script:WindowTimeout) s (path with spaces: $dirA)" } else { "Process exited with code $($script:Ctx.ProcA.ExitCode) before any window appeared" }
        } elseif (-not $alive) {
            $note = "Process exited with code $($script:Ctx.ProcA.ExitCode) after the window appeared"
        } else {
            $status = 'pass'
            $note = "Started from '$dirA': window '$($window.Title)' ($($window.Width)x$($window.Height)), process alive after $($script:SettleSeconds) s."
            # Dismiss attempt for onboarding / sign-in: only Escape. Tab/Enter
            # guesses are not reliable, so the screenshots are the record.
            try {
                Send-Keys -Handle $window.Handle -Keys 'Escape'
                Start-Sleep -Seconds 3
                $shot = Save-Screenshot -ProcessId $script:Ctx.ProcA.Id -Name 'a3-after-escape.png'
                if ($shot) { $evidence.Add($shot) }
            } catch {
                $note += " Escape not sent: $($_.Exception.Message)"
            }
        }
    } catch {
        $status = 'fail'
        $note = "Unexpected error: $($_.Exception.Message)"
    } finally {
        # The window is needed by A4/A8a on success; on failure nothing may linger.
        if ($status -ne 'pass' -and $null -ne $script:Ctx.ProcA) {
            Stop-ProcessTree -Process $script:Ctx.ProcA
        }
    }
    # Kept so A12a can point at the same screenshots.
    $script:Ctx.A3Evidence = $evidence.ToArray()
    return New-CheckResult -Id 'A3' -Status $status -Evidence $evidence.ToArray() -Note $note
}

function Invoke-CheckA12a {
    # Evidence only: whether the first screen is a sign-in entry point needs a
    # human to look at it (ADR-0008). Not faked as a pass.
    $evidence = @()
    if ($script:Ctx.ContainsKey('A3Evidence')) { $evidence = @($script:Ctx.A3Evidence) }
    return New-CheckResult -Id 'A12a' -Status skipped -Evidence $evidence -Note 'Screenshots of the first screen are recorded for review; whether the sign-in entry point is reachable is not asserted automatically (ADR-0008, owner verifies A12b).'
}

function Invoke-CheckA4 {
    $evidence = [System.Collections.Generic.List[string]]::new()
    $status = 'fail'
    $note = ''
    try {
        $proc = $script:Ctx.ProcA
        if ($null -eq $proc -or -not (Test-ProcessAlive -Process $proc)) {
            throw 'Prerequisite missing: warp-oss.exe from A3 is not running.'
        }
        $marker = $env:WP_MARKER
        if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker -Force }

        # No quotes or brackets in the command: Warp's editor may auto-close them.
        # The marker path and the first word come from the environment instead.
        # The file ends up with two lines: 'warp-portable-ok' and the version.
        $command = 'Set-Content -LiteralPath $env:WP_MARKER -Value $env:WP_OK,$PSVersionTable.PSVersion'
        $deadline = [DateTime]::UtcNow.AddSeconds($script:MarkerTimeout)
        $attempts = 0
        $found = $false
        while (-not $found -and [DateTime]::UtcNow -lt $deadline) {
            $window = Wait-ProcessWindow -ProcessId $proc.Id -TimeoutSeconds 5
            if ($null -eq $window) { throw 'The Warp window disappeared.' }
            # The shell may still be starting; the command is idempotent, so it
            # is simply typed again every 15 s until the marker shows up.
            Send-Text -Handle $window.Handle -Text $command
            Start-Sleep -Milliseconds 300
            Send-Keys -Handle $window.Handle -Keys 'Enter'
            $attempts++
            $found = Wait-Condition -TimeoutSeconds 15 -Condition { Test-Path -LiteralPath $marker -PathType Leaf }
        }
        $shot = Save-Screenshot -ProcessId $proc.Id -Name 'a4-powershell.png'
        if ($shot) { $evidence.Add($shot) }
        if (-not $found) {
            $note = "Marker file did not appear within $($script:MarkerTimeout) s ($attempts attempts). Typing probably did not reach a PowerShell prompt (onboarding or sign-in screen in front?); see the screenshots."
        } else {
            $text = (Read-SharedText -Path $marker).Trim()
            if ($text -match '(?s)^warp-portable-ok\s+\d+\.\d+') {
                $status = 'pass'
                $note = "PowerShell session ran the typed command (attempt $attempts); marker text: $($text -replace '\s+', ' ')"
            } else {
                $note = "Marker file exists but has unexpected content: $($text -replace '\s+', ' ')"
            }
        }
    } catch {
        $status = 'fail'
        $note = "Unexpected error: $($_.Exception.Message)"
    }
    return New-CheckResult -Id 'A4' -Status $status -Evidence $evidence.ToArray() -Note $note
}

function Invoke-CheckA5 {
    $status = 'fail'
    $note = ''
    try {
        $dir = $script:Ctx.DirA
        if (-not $dir) { throw 'Prerequisite missing: folder A was not extracted.' }
        $prefs = Join-Path $dir 'data\config\user_preferences.json'
        $log = Join-Path $dir 'data\state\logs\warp-oss.log'
        [void](Wait-Condition -TimeoutSeconds 30 -Condition { (Test-Path -LiteralPath $prefs) -and (Test-Path -LiteralPath $log) })
        $stateDir = Join-Path $dir 'data\state'
        $db = @()
        if (Test-Path -LiteralPath $stateDir) {
            $db = @(Get-ChildItem -LiteralPath $stateDir -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -in '.sqlite', '.sqlite3', '.db' })
        }
        $missing = [System.Collections.Generic.List[string]]::new()
        if (-not (Test-Path -LiteralPath $prefs -PathType Leaf)) { $missing.Add('data\config\user_preferences.json') }
        if (-not (Test-Path -LiteralPath $log -PathType Leaf)) { $missing.Add('data\state\logs\warp-oss.log') }
        if ($db.Count -eq 0) { $missing.Add('a sqlite database (*.sqlite, *.sqlite3, *.db) under data\state') }
        if ($missing.Count -eq 0) {
            $status = 'pass'
            $note = "Found user_preferences.json, warp-oss.log and $($db[0].Name) under $dir\data."
        } else {
            $listing = (Get-ChildItem -LiteralPath (Join-Path $dir 'data') -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 40 | ForEach-Object { [System.IO.Path]::GetRelativePath($dir, $_.FullName) }) -join '; '
            $note = "Missing: $($missing -join ', '). Files under data (first 40): $listing"
        }
    } catch {
        $status = 'fail'
        $note = "Unexpected error: $($_.Exception.Message)"
    }
    return New-CheckResult -Id 'A5' -Status $status -Note $note
}

function Get-SettingsSnapshot {
    # Flat map of both settings files of a folder, plus the raw texts.
    param([Parameter(Mandatory = $true)][string]$ExeDir)

    $prefsText = Read-SharedText -Path (Join-Path $ExeDir 'data\config\user_preferences.json')
    $tomlText = Read-SharedText -Path (Join-Path $ExeDir 'data\config\settings.toml')
    $flat = [ordered]@{}
    foreach ($kv in (ConvertTo-FlatSettings -Text $prefsText -Prefix 'user_preferences.json').GetEnumerator()) { $flat[$kv.Key] = $kv.Value }
    foreach ($kv in (ConvertTo-FlatSettings -Text $tomlText -Prefix 'settings.toml').GetEnumerator()) { $flat[$kv.Key] = $kv.Value }
    return [pscustomobject]@{ Flat = $flat; PrefsText = $prefsText; TomlText = $tomlText }
}

function Invoke-CheckA8a {
    $evidence = [System.Collections.Generic.List[string]]::new()
    $status = 'fail'
    $note = ''
    try {
        $proc = $script:Ctx.ProcA
        if ($null -eq $proc -or -not (Test-ProcessAlive -Process $proc)) {
            throw 'Prerequisite missing: warp-oss.exe from A3 is not running.'
        }
        $before = Get-SettingsSnapshot -ExeDir $script:Ctx.DirA
        [System.IO.File]::WriteAllText((Join-Path $script:Ctx.ReportDir 'a8-user_preferences.before.json'), $before.PrefsText)
        [System.IO.File]::WriteAllText((Join-Path $script:Ctx.ReportDir 'a8-settings.before.toml'), $before.TomlText)
        $evidence.Add('a8-user_preferences.before.json'); $evidence.Add('a8-settings.before.toml')

        $window = Wait-ProcessWindow -ProcessId $proc.Id -TimeoutSeconds 10
        if ($null -eq $window) { throw 'The Warp window disappeared.' }
        # Three steps so a change is visible even if the first keypress is eaten.
        for ($i = 0; $i -lt 3; $i++) {
            Send-Keys -Handle $window.Handle -Keys 'Ctrl+='
            Start-Sleep -Milliseconds 700
        }
        Start-Sleep -Seconds 5
        $shot = Save-Screenshot -ProcessId $proc.Id -Name 'a8-after-ctrl-equals.png'
        if ($shot) { $evidence.Add($shot) }

        # Settings may only be flushed at exit, so close first, then compare.
        $closed = Close-WarpApp -Process $proc
        $after = Get-SettingsSnapshot -ExeDir $script:Ctx.DirA
        [System.IO.File]::WriteAllText((Join-Path $script:Ctx.ReportDir 'a8-user_preferences.after.json'), $after.PrefsText)
        [System.IO.File]::WriteAllText((Join-Path $script:Ctx.ReportDir 'a8-settings.after.toml'), $after.TomlText)
        $evidence.Add('a8-user_preferences.after.json'); $evidence.Add('a8-settings.after.toml')

        $diff = @(Get-SettingDiff -Before $before.Flat -After $after.Flat)
        if ($diff.Count -eq 0) {
            $note = "no setting change detected after Ctrl+= x3 ($($closed.Note))"
        } else {
            $pick = Select-FontSettingChange -Changes $diff
            $script:Ctx.ChangedSettings = @($pick.Chosen)
            $script:Ctx.ChangedSettingsFontSpecific = $pick.FontSpecific
            $status = 'pass'
            $summary = ($pick.Chosen | Select-Object -First 5 | ForEach-Object { "$($_.Key): $($_.Before) -> $($_.After)" }) -join '; '
            $kind = if ($pick.FontSpecific) { 'font-related' } else { 'NOT font-related (no font key changed; other changed keys recorded)' }
            $note = "Changed settings ($kind): $summary. App $($closed.Note)."
        }
        if ($closed.Forced) { $note += ' WARNING: the app had to be killed.' }
    } catch {
        $status = 'fail'
        $note = "Unexpected error: $($_.Exception.Message)"
    } finally {
        if ($null -ne $script:Ctx.ProcA) { Stop-ProcessTree -Process $script:Ctx.ProcA }
        if ($script:Ctx.DirA) { Stop-WarpProcessesIn -Folder $script:Ctx.DirA }
    }
    return New-CheckResult -Id 'A8a' -Status $status -Evidence $evidence.ToArray() -Note $note
}

function Invoke-TraceCheck {
    # A6/A7: the six locations, the registry diff, and files written to the
    # profile after T0. Run once after A8a and once at the very end.
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)][string]$Tag)

    $evidence = [System.Collections.Generic.List[string]]::new()
    $problems = [System.Collections.Generic.List[string]]::new()
    $notes = [System.Collections.Generic.List[string]]::new()
    try {
        $after = Get-TraceSnapshot
        [System.IO.File]::WriteAllText((Join-Path $script:Ctx.ReportDir "$Tag-after.json"), (ConvertTo-Json -InputObject $after))
        $evidence.Add("$Tag-after.json")
        foreach ($f in (Compare-TraceSnapshot -Before (ConvertTo-PlainHashtable $script:Ctx.Before) -After (ConvertTo-PlainHashtable $after))) {
            $problems.Add($f)
        }

        if ($null -ne $script:Ctx.RegBeforeLines) {
            try {
                $afterLines = Export-HkcuRegistry -Path (Join-Path $script:Ctx.WorkRoot "reg-$Tag-after.reg")
                $reg = Compare-RegistryExport -BeforeLines $script:Ctx.RegBeforeLines -AfterLines $afterLines
                $regFile = "$Tag-registry-diff.txt"
                $regText = @("Added lines: $($reg.AddedLineCount)", 'Added keys:') + $reg.AddedKeys
                [System.IO.File]::WriteAllLines((Join-Path $script:Ctx.ReportDir $regFile), [string[]]$regText)
                $evidence.Add($regFile)
                foreach ($k in $reg.WarpKeys) { $problems.Add("registry key created: $k") }
                $notes.Add("registry: $($reg.AddedKeys.Count) new keys (informational), $($reg.WarpKeys.Count) mention Warp")
            } catch {
                $notes.Add("registry diff not available: $($_.Exception.Message)")
            }
        } else {
            $notes.Add('registry diff not available (HKCU export failed in S0)')
        }

        $excludes = Get-DefaultProfileExcludes -ProfileDir $env:USERPROFILE -Extra @($script:Ctx.WorkRoot, $script:Ctx.ReportDir, $env:TEMP, $env:PUBLIC)
        $changes = @(Get-ProfileChanges -Root $env:USERPROFILE -Since $script:Ctx.T0.AddSeconds(-2) -ExcludePrefix $excludes)
        $fsFile = "$Tag-profile-changes.txt"
        [System.IO.File]::WriteAllLines((Join-Path $script:Ctx.ReportDir $fsFile), [string[]]$changes)
        $evidence.Add($fsFile)
        $warpish = @($changes | Where-Object { $_ -match '(?i)warp' })
        foreach ($p in $warpish) { $problems.Add("file written to the profile: $p") }
        $other = @($changes | Where-Object { $_ -notmatch '(?i)warp' })
        $notes.Add("profile: $($changes.Count) files modified after T0 outside the allow-list; $($warpish.Count) look like Warp's, $($other.Count) not attributed to Warp (listed in $fsFile)")
        if ($other.Count -gt 0) {
            $notes.Add("not attributed, first 10: $(($other | Select-Object -First 10) -join '; ')")
        }
    } catch {
        $problems.Add("Unexpected error: $($_.Exception.Message)")
    }
    $status = if ($problems.Count -eq 0) { 'pass' } else { 'fail' }
    $note = (@($problems) + @($notes)) -join ' | '
    return New-CheckResult -Id $Id -Status $status -Evidence $evidence.ToArray() -Note $note
}

function Invoke-CheckA8b {
    $evidence = [System.Collections.Generic.List[string]]::new()
    $status = 'fail'
    $note = ''
    try {
        if (-not $script:Ctx.DirA) { throw 'Prerequisite missing: folder A was not extracted.' }
        $rootB = Join-Path -Path $script:Ctx.WorkRoot -ChildPath 'Folder B (copy)'
        $script:Ctx.DirB = Copy-PortableFolder -SourceExeDir $script:Ctx.DirA -DestRoot $rootB
        $script:Ctx.ProcB = Start-WarpApp -ExeDir $script:Ctx.DirB
        $start = Wait-AppStart -Process $script:Ctx.ProcB
        $shot = Save-Screenshot -ProcessId $script:Ctx.ProcB.Id -Name 'a8b-folder-b.png'
        if ($shot) { $evidence.Add($shot) }
        if (-not $start.Ok) {
            $note = "Copy did not start: $($start.Detail)"
        } else {
            $changed = @()
            if ($script:Ctx.ContainsKey('ChangedSettings')) { $changed = @($script:Ctx.ChangedSettings) }
            if ($changed.Count -eq 0) {
                $note = 'A8a recorded no changed setting, so survival of a setting is not proven. The copy itself started.'
            } else {
                $snap = Get-SettingsSnapshot -ExeDir $script:Ctx.DirB
                [System.IO.File]::WriteAllText((Join-Path $script:Ctx.ReportDir 'a8b-user_preferences.json'), $snap.PrefsText)
                $evidence.Add('a8b-user_preferences.json')
                $present = @($changed | Where-Object { $snap.Flat.Contains($_.Key) -and [string]$snap.Flat[$_.Key] -eq $_.After })
                # With a font key every changed value must survive. Without one
                # the set may contain incidental keys, so one match is enough.
                $needed = if ($script:Ctx.ChangedSettingsFontSpecific) { $changed.Count } else { 1 }
                if ($present.Count -ge $needed) {
                    $status = 'pass'
                    $note = "In the copy (started from '$($script:Ctx.DirB)', alive, $($start.Detail)): $($present.Count) of $($changed.Count) changed values present, e.g. $($present[0].Key) = $($present[0].After)."
                } else {
                    $note = "Changed values missing in the copy: $($present.Count) of $($changed.Count) present."
                }
            }
        }
    } catch {
        $status = 'fail'
        $note = "Unexpected error: $($_.Exception.Message)"
    } finally {
        # B stays running for D4, which closes it. A failed start must not linger.
        if ($status -ne 'pass' -and $null -ne $script:Ctx.ProcB -and -not (Test-ProcessAlive -Process $script:Ctx.ProcB)) {
            $script:Ctx.ProcB = $null
        }
    }
    return New-CheckResult -Id 'A8b' -Status $status -Evidence $evidence.ToArray() -Note $note
}

function Invoke-CheckD4 {
    $evidence = [System.Collections.Generic.List[string]]::new()
    $status = 'fail'
    $note = ''
    $procA2 = $null
    try {
        if (-not $script:Ctx.DirA) { throw 'Prerequisite missing: folder A was not extracted.' }
        if ($null -eq $script:Ctx.DirB) {
            $script:Ctx.DirB = Copy-PortableFolder -SourceExeDir $script:Ctx.DirA -DestRoot (Join-Path $script:Ctx.WorkRoot 'Folder B (copy)')
        }
        if ($null -eq $script:Ctx.ProcB -or -not (Test-ProcessAlive -Process $script:Ctx.ProcB)) {
            $script:Ctx.ProcB = Start-WarpApp -ExeDir $script:Ctx.DirB
            $startB = Wait-AppStart -Process $script:Ctx.ProcB
            if (-not $startB.Ok) { throw "Folder B did not start: $($startB.Detail)" }
        }
        $procA2 = Start-WarpApp -ExeDir $script:Ctx.DirA
        $startA = Wait-AppStart -Process $procA2
        $shotA = Save-Screenshot -ProcessId $procA2.Id -Name 'd4-folder-a.png'
        if ($shotA) { $evidence.Add($shotA) }
        $shotB = Save-Screenshot -ProcessId $script:Ctx.ProcB.Id -Name 'd4-folder-b.png'
        if ($shotB) { $evidence.Add($shotB) }
        $aliveB = Test-ProcessAlive -Process $script:Ctx.ProcB
        $winB = if ($aliveB) { Wait-ProcessWindow -ProcessId $script:Ctx.ProcB.Id -TimeoutSeconds 5 } else { $null }
        if ($startA.Ok -and $aliveB -and $null -ne $winB) {
            $status = 'pass'
            $note = "Folder A (pid $($procA2.Id)) and folder B (pid $($script:Ctx.ProcB.Id)) run side by side, each with its own window (ADR-0009)."
        } else {
            $note = "A: $($startA.Detail); B alive: $aliveB, B window: $($null -ne $winB)"
        }
    } catch {
        $status = 'fail'
        $note = "Unexpected error: $($_.Exception.Message)"
    } finally {
        foreach ($p in @($procA2, $script:Ctx.ProcB)) {
            if ($null -ne $p) {
                $closed = Close-WarpApp -Process $p
                if ($closed.Forced) { $note += " WARNING (pid $($p.Id)): $($closed.Note)" }
            }
        }
        if ($script:Ctx.DirA) { Stop-WarpProcessesIn -Folder $script:Ctx.DirA }
        if ($script:Ctx.DirB) { Stop-WarpProcessesIn -Folder $script:Ctx.DirB }
        $script:Ctx.ProcB = $null
    }
    return New-CheckResult -Id 'D4' -Status $status -Evidence $evidence.ToArray() -Note $note
}

function Invoke-CheckA9 {
    $evidence = [System.Collections.Generic.List[string]]::new()
    $status = 'fail'
    $note = ''
    $proc = $null
    $dirC = $null
    try {
        if (-not $script:Ctx.DirA) { throw 'Prerequisite missing: folder A was not extracted.' }
        $rootC = Join-Path -Path $script:Ctx.WorkRoot -ChildPath 'Folder C (credentials)'
        $dirC = Copy-PortableFolder -SourceExeDir $script:Ctx.DirA -DestRoot $rootC
        $script:Ctx.DirC = $dirC
        # A fresh copy: no state of A's earlier runs.
        $data = Join-Path $dirC 'data'
        if (Test-Path -LiteralPath $data) { Remove-Item -LiteralPath $data -Recurse -Force }
        $stateDir = Join-Path $data 'state'
        [void](New-Item -ItemType Directory -Path $stateDir -Force)

        # DPAPI only decrypts for the same user on the same machine; random bytes
        # stand in for a blob from another machine. Any existing *-User file
        # would be replaced too (none exists in a fresh copy).
        $names = [System.Collections.Generic.List[string]]::new()
        $names.Add($script:SecureStorageFileName)
        foreach ($f in @(Get-ChildItem -LiteralPath $stateDir -Filter '*-User' -File -ErrorAction SilentlyContinue)) {
            if (-not $names.Contains($f.Name)) { $names.Add($f.Name) }
        }
        foreach ($n in $names) {
            $bytes = [byte[]]::new(256)
            [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
            [System.IO.File]::WriteAllBytes((Join-Path $stateDir $n), $bytes)
        }

        $proc = Start-WarpApp -ExeDir $dirC
        $start = Wait-AppStart -Process $proc
        $shot = Save-Screenshot -ProcessId $proc.Id -Name 'a9-bad-credentials.png'
        if ($shot) { $evidence.Add($shot) }
        $crashDialog = Test-WerFaultFor -ProcessId $proc.Id
        if ($start.Ok -and -not $crashDialog) {
            $status = 'pass'
            $note = "Started with undecryptable $($names -join ', '): $($start.Detail), alive after $($script:SettleSeconds) s, no WerFault dialog. Whether the UI shows the signed-out state is visible in the screenshot only."
        } else {
            $note = "$($start.Detail); WerFault dialog for the process: $crashDialog"
        }
    } catch {
        $status = 'fail'
        $note = "Unexpected error: $($_.Exception.Message)"
    } finally {
        if ($null -ne $proc) { [void](Close-WarpApp -Process $proc) }
        if ($dirC) { Stop-WarpProcessesIn -Folder $dirC }
    }
    return New-CheckResult -Id 'A9' -Status $status -Evidence $evidence.ToArray() -Note $note
}

function Invoke-CheckA11 {
    $evidence = [System.Collections.Generic.List[string]]::new()
    $status = 'fail'
    $note = ''
    $proc = $null
    $dirD = $null
    $identity = "$env:USERDOMAIN\$env:USERNAME"
    $denied = $false
    try {
        if (-not $script:Ctx.DirA) { throw 'Prerequisite missing: folder A was not extracted.' }
        $rootD = Join-Path -Path $script:Ctx.WorkRoot -ChildPath 'Folder D (read-only)'
        $dirD = Copy-PortableFolder -SourceExeDir $script:Ctx.DirA -DestRoot $rootD
        $script:Ctx.DirD = $dirD
        $data = Join-Path $dirD 'data'
        if (Test-Path -LiteralPath $data) { Remove-Item -LiteralPath $data -Recurse -Force }

        # An explicit deny beats the allow entries, even for an administrator.
        # Read and execute stay allowed so the exe can still start.
        $out = & icacls.exe $dirD /deny "${identity}:(OI)(CI)(W,DC)" 2>&1
        if ($LASTEXITCODE -ne 0) { throw "icacls deny failed: $out" }
        $denied = $true
        $startedAt = Get-Date

        $proc = Start-WarpApp -ExeDir $dirD
        $box = Wait-ProcessWindow -ProcessId $proc.Id -TimeoutSeconds $script:MessageBoxTimeout -TitleLike 'Warp Portable'
        if ($null -eq $box) {
            $alive = Test-ProcessAlive -Process $proc
            $shot = Save-Screenshot -ProcessId $proc.Id -Name 'a11-no-message-box.png'
            if ($shot) { $evidence.Add($shot) }
            $note = if ($alive) { "No window titled 'Warp Portable' within $($script:MessageBoxTimeout) s (the process is still running)" } else { "Process exited with code $($proc.ExitCode) without a 'Warp Portable' window" }
        } else {
            $shot = Save-Screenshot -ProcessId $proc.Id -Name 'a11-message-box.png' -TitleLike 'Warp Portable'
            if ($shot) { $evidence.Add($shot) }
            Send-Keys -Handle $box.Handle -Keys 'Enter'
            $exited = $proc.WaitForExit($script:CloseTimeout * 1000)
            if (-not $exited) {
                $note = "The message box was shown but the process did not exit within $($script:CloseTimeout) s after Enter"
            } elseif ($proc.ExitCode -ne 2) {
                $note = "The message box was shown but the exit code is $($proc.ExitCode), expected 2"
            } else {
                $after = Get-TraceSnapshot
                $trace = @(Compare-TraceSnapshot -Before (ConvertTo-PlainHashtable $script:Ctx.Before) -After (ConvertTo-PlainHashtable $after))
                $excludes = Get-DefaultProfileExcludes -ProfileDir $env:USERPROFILE -Extra @($script:Ctx.WorkRoot, $script:Ctx.ReportDir, $env:TEMP, $env:PUBLIC)
                $written = @(Get-ProfileChanges -Root $env:USERPROFILE -Since $startedAt.AddSeconds(-2) -ExcludePrefix $excludes | Where-Object { $_ -match '(?i)warp' })
                if ($trace.Count -eq 0 -and $written.Count -eq 0) {
                    $status = 'pass'
                    $note = "Message box 'Warp Portable' shown, dismissed with Enter, exit code 2, nothing Warp-related written to the profile or registry."
                } else {
                    $note = "Message box and exit code 2 were right, but traces appeared: $((@($trace) + @($written)) -join '; ')"
                }
            }
        }
    } catch {
        $status = 'fail'
        $note = "Unexpected error: $($_.Exception.Message)"
    } finally {
        if ($null -ne $proc) { Stop-ProcessTree -Process $proc }
        if ($dirD) { Stop-WarpProcessesIn -Folder $dirD }
        if ($denied) {
            # Always restore, otherwise the folder cannot be cleaned up.
            $restore = & icacls.exe $dirD /remove:d $identity 2>&1
            if ($LASTEXITCODE -ne 0) { $note += " WARNING: could not remove the deny ACE: $restore" }
        }
    }
    return New-CheckResult -Id 'A11' -Status $status -Evidence $evidence.ToArray() -Note $note
}

function Invoke-CheckA10 {
    $evidence = [System.Collections.Generic.List[string]]::new()
    $status = 'fail'
    $note = ''
    $name = 'wpv' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $userCreated = $false
    $sid = $null
    $proc = $null
    $rootE = Join-Path -Path $env:PUBLIC -ChildPath 'Portable Test E'
    $cleanupNotes = [System.Collections.Generic.List[string]]::new()
    try {
        if ($SkipStandardUser) {
            return New-CheckResult -Id 'A10' -Status skipped -Note '-SkipStandardUser was given.'
        }
        if (-not $script:Ctx.DirA) { throw 'Prerequisite missing: folder A was not extracted.' }

        $password = New-RandomSecureString
        try {
            New-LocalUser -Name $name -Password $password -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword `
                -Description 'Temporary Warp portable verification user' | Out-Null
        } catch {
            return New-CheckResult -Id 'A10' -Status skipped -Note "Could not create a local user: $($_.Exception.Message)"
        }
        $userCreated = $true
        $sid = (Get-LocalUser -Name $name).SID.Value
        # Standard user: member of Users (S-1-5-32-545), and demonstrably not of Administrators.
        Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $name
        $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID.Value -eq $sid })
        if ($admins.Count -gt 0) { throw 'The temporary user is an administrator; refusing to continue.' }

        if (Test-Path -LiteralPath $rootE) { Remove-Item -LiteralPath $rootE -Recurse -Force }
        $dirE = Copy-PortableFolder -SourceExeDir $script:Ctx.DirA -DestRoot $rootE
        $script:Ctx.DirE = $dirE
        $dataE = Join-Path $dirE 'data'
        if (Test-Path -LiteralPath $dataE) { Remove-Item -LiteralPath $dataE -Recurse -Force }
        $grant = & icacls.exe $rootE /grant "${name}:(OI)(CI)M" 2>&1
        if ($LASTEXITCODE -ne 0) { throw "icacls grant failed: $grant" }

        $credential = [pscredential]::new("$env:COMPUTERNAME\$name", $password)
        try {
            $proc = Start-WarpApp -ExeDir $dirE -Credential $credential
        } catch {
            return New-CheckResult -Id 'A10' -Status skipped -Note "Secondary-logon start of the exe failed on this runner: $($_.Exception.Message)"
        }

        $start = Wait-AppStart -Process $proc
        $shot = Save-Screenshot -ProcessId $proc.Id -Name 'a10-standard-user.png'
        if ($shot) { $evidence.Add($shot) }

        $profileDir = $null
        $profile = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$sid'" -ErrorAction SilentlyContinue
        if ($null -ne $profile) { $profileDir = $profile.LocalPath }
        if (-not $profileDir) { $profileDir = Join-Path -Path (Split-Path -Path $env:USERPROFILE -Parent) -ChildPath $name }

        $hiveRoot = "Registry::HKEY_USERS\$sid"
        $hiveVisible = Test-Path -LiteralPath $hiveRoot
        $snapshot = Get-TraceSnapshot -AppData (Join-Path $profileDir 'AppData\Roaming') -LocalAppData (Join-Path $profileDir 'AppData\Local') `
            -UserProfileDir $profileDir -RegistryRoot $hiveRoot
        $zero = [ordered]@{}
        foreach ($n in $script:TraceNames) { $zero[$n] = $false }
        $findings = @(Compare-TraceSnapshot -Before (ConvertTo-PlainHashtable $zero) -After (ConvertTo-PlainHashtable $snapshot))

        # Logs from the other user's run, copied while the folder still exists.
        if (Test-ProcessAlive -Process $proc) { [void](Close-WarpApp -Process $proc) }
        [void](Copy-FolderLogs -ExeDir $dirE -Label 'folder-E-standard-user')

        if ($start.Ok -and $findings.Count -eq 0) {
            $status = 'pass'
            $registryNote = if ($hiveVisible) { 'registry hive of that user checked' } else { 'registry hive of that user was NOT loaded, so only the file locations were checked' }
            $note = "Ran as standard local user '$name' (not in Administrators): $($start.Detail); none of the six traces in $profileDir ($registryNote)."
        } elseif (-not $start.Ok) {
            $note = "Standard user start failed: $($start.Detail)"
        } else {
            $note = "Traces found in the standard user's profile: $($findings -join '; ')"
        }
    } catch {
        $status = 'fail'
        $note = "Unexpected error: $($_.Exception.Message)"
    } finally {
        if ($null -ne $proc) { Stop-ProcessTree -Process $proc }
        if (Test-Path -LiteralPath $rootE) { Stop-WarpProcessesIn -Folder (Join-Path $rootE 'WarpPortable') }
        if ($userCreated) {
            Start-Sleep -Seconds 3
            try { Remove-LocalUser -Name $name } catch { $cleanupNotes.Add("could not remove user ${name}: $($_.Exception.Message)") }
            if ($sid) {
                for ($i = 0; $i -lt 5; $i++) {
                    try {
                        $prof = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$sid'" -ErrorAction SilentlyContinue
                        if ($null -eq $prof) { break }
                        Remove-CimInstance -InputObject $prof
                        break
                    } catch {
                        if ($i -eq 4) { $cleanupNotes.Add("could not remove the profile of ${name}: $($_.Exception.Message)") }
                        Start-Sleep -Seconds 3
                    }
                }
            }
        }
        if (Test-Path -LiteralPath $rootE) {
            try { Remove-Item -LiteralPath $rootE -Recurse -Force } catch { $cleanupNotes.Add("could not remove ${rootE}: $($_.Exception.Message)") }
        }
    }
    if ($cleanupNotes.Count -gt 0) { $note += ' Cleanup: ' + ($cleanupNotes -join '; ') }
    return New-CheckResult -Id 'A10' -Status $status -Evidence $evidence.ToArray() -Note $note
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

function Invoke-Main {
    if ($SelfTest) {
        if (Invoke-SelfTest) { return 0 } else { return 1 }
    }
    if (-not $ZipPath) { throw '-ZipPath is required.' }
    if (-not (Test-Path -LiteralPath $ZipPath -PathType Leaf)) { throw "Zip not found: $ZipPath" }

    $workRootFull = Resolve-FullPath -Path $WorkRoot
    if ([System.IO.Path]::GetPathRoot($workRootFull) -eq $workRootFull) { throw "-WorkRoot must not be a drive root: $workRootFull" }
    $reportFull = Resolve-FullPath -Path $ReportDir

    # A clean slate: leftovers of an earlier run would pollute copies and checks.
    if (Test-Path -LiteralPath $workRootFull) { Remove-Item -LiteralPath $workRootFull -Recurse -Force }
    [void](New-Item -ItemType Directory -Path $workRootFull -Force)
    [void](New-Item -ItemType Directory -Path $reportFull -Force)

    $script:Ctx = @{
        ZipPath   = (Resolve-Path -LiteralPath $ZipPath).ProviderPath
        WorkRoot  = $workRootFull
        ReportDir = $reportFull
        ProcA     = $null
        ProcB     = $null
        DirA      = $null
        DirB      = $null
        DirC      = $null
        DirD      = $null
        DirE      = $null
        Before    = @{}
        T0        = Get-Date
    }
    $script:Ctx.ChangedSettingsFontSpecific = $false

    $results = [System.Collections.Generic.List[object]]::new()
    try {
        $results.Add((Invoke-CheckSafe -Id 'S0' -Body { Invoke-CheckS0 }))
        $results.Add((Invoke-CheckSafe -Id 'A3' -Body { Invoke-CheckA3 }))
        $results.Add((Invoke-CheckSafe -Id 'A12a' -Body { Invoke-CheckA12a }))
        $results.Add((Invoke-CheckSafe -Id 'A4' -Body { Invoke-CheckA4 }))
        $results.Add((Invoke-CheckSafe -Id 'A5' -Body { Invoke-CheckA5 }))
        $results.Add((Invoke-CheckSafe -Id 'A8a' -Body { Invoke-CheckA8a }))
        $results.Add((Invoke-CheckSafe -Id 'A6/A7' -Body { Invoke-TraceCheck -Id 'A6/A7' -Tag 'a6a7' }))
        $results.Add((Invoke-CheckSafe -Id 'A8b' -Body { Invoke-CheckA8b }))
        $results.Add((Invoke-CheckSafe -Id 'D4' -Body { Invoke-CheckD4 }))
        $results.Add((Invoke-CheckSafe -Id 'A9' -Body { Invoke-CheckA9 }))
        $results.Add((Invoke-CheckSafe -Id 'A11' -Body { Invoke-CheckA11 }))
        $results.Add((Invoke-CheckSafe -Id 'A10' -Body { Invoke-CheckA10 }))
        # Everything ran by now; the same trace check again covers B, C, D and E too.
        $results.Add((Invoke-CheckSafe -Id 'A6/A7 final' -Body { Invoke-TraceCheck -Id 'A6/A7 final' -Tag 'a6a7-final' }))
    } finally {
        foreach ($p in @($script:Ctx.ProcA, $script:Ctx.ProcB)) { if ($null -ne $p) { Stop-ProcessTree -Process $p } }
        foreach ($d in @($script:Ctx.DirA, $script:Ctx.DirB, $script:Ctx.DirC, $script:Ctx.DirD)) {
            if ($d) { Stop-WarpProcessesIn -Folder $d }
        }
        $labels = @{ 'folder-A' = $script:Ctx.DirA; 'folder-B' = $script:Ctx.DirB; 'folder-C' = $script:Ctx.DirC; 'folder-D' = $script:Ctx.DirD }
        foreach ($label in $labels.Keys) {
            if ($labels[$label]) {
                try { [void](Copy-FolderLogs -ExeDir $labels[$label] -Label $label) } catch { Write-Host "  log copy for $label failed: $($_.Exception.Message)" }
            }
        }
        Remove-Item -Path Env:WP_MARKER, Env:WP_OK -ErrorAction SilentlyContinue
    }

    $meta = @{
        Zip       = (Split-Path -Path $script:Ctx.ZipPath -Leaf)
        Generated = (Get-Date).ToString('o')
        Runner    = "$env:COMPUTERNAME, $([System.Environment]::OSVersion.VersionString), user $env:USERNAME"
        WorkRoot  = $workRootFull
    }
    $markdown = ConvertTo-RuntimeReportMarkdown -Results $results.ToArray() -Meta $meta
    [System.IO.File]::WriteAllText((Join-Path $reportFull 'runtime-report.md'), $markdown, [System.Text.UTF8Encoding]::new($false))
    $json = ConvertTo-Json -InputObject ([pscustomobject]@{ Meta = $meta; Results = $results.ToArray() }) -Depth 6
    [System.IO.File]::WriteAllText((Join-Path $reportFull 'runtime-report.json'), $json, [System.Text.UTF8Encoding]::new($false))

    Write-Host ''
    Write-Host '== Summary =='
    foreach ($r in $results) { Write-Host ("{0,-14} {1,-8} {2}" -f $r.Id, $r.Status, $r.Note) }
    $failed = @($results | Where-Object { $_.Status -eq 'fail' })
    Write-Host "== Result: $(if ($failed.Count -eq 0) { 'PASS' } else { 'FAIL' }) ($($failed.Count) failed) =="
    if ($failed.Count -gt 0) { return 1 }
    return 0
}

try {
    $code = Invoke-Main
} catch {
    [Console]::Error.WriteLine("verify_runtime.ps1 failed: $($_.Exception.Message)")
    [Console]::Error.WriteLine($_.ScriptStackTrace)
    exit 1
}
exit $code
