param(
    [string]$Python = "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
    [switch]$SkipExecutable
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$DeployTool = Join-Path $ProjectRoot ".venv\Scripts\pyside6-deploy.exe"
$DeployConfig = Join-Path $ProjectRoot "pysidedeploy.spec"
$GeneratedExecutable = Join-Path $ProjectRoot "main.exe"
$Executable = Join-Path $ProjectRoot "ShareGuard.exe"
$Icon = Join-Path $ProjectRoot "assets\shareguard.ico"
$DistDirectory = Join-Path $ProjectRoot "dist"
$ChecksumFile = Join-Path $DistDirectory "SHA256SUMS"
$Utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)

function Get-ProjectVersion {
    param([string]$Root)

    $pyprojectPath = Join-Path $Root "pyproject.toml"
    if (-not (Test-Path -LiteralPath $pyprojectPath -PathType Leaf)) {
        throw "Project metadata was not found: $pyprojectPath"
    }

    $pyprojectText = Get-Content -LiteralPath $pyprojectPath -Raw
    $versionMatch = [regex]::Match($pyprojectText, '(?m)^version\s*=\s*"([^"]+)"\s*$')
    if (-not $versionMatch.Success) {
        throw "Project version could not be read from pyproject.toml."
    }

    return $versionMatch.Groups[1].Value
}

function Backup-And-RemoveArtifact {
    param(
        [string]$Path,
        [string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    $backupDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "ShareGuard-build-backups"
    New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null

    $sourceItem = Get-Item -LiteralPath $Path
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss-fff"
    $nonce = [guid]::NewGuid().ToString("N").Substring(0, 8)
    $backupName = "{0}-{1}-{2}{3}" -f $sourceItem.BaseName, $stamp, $nonce, $sourceItem.Extension
    $backupPath = Join-Path $backupDirectory $backupName

    Copy-Item -LiteralPath $Path -Destination $backupPath
    $sourceHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    $backupHash = (Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash
    if ($sourceItem.Length -ne (Get-Item -LiteralPath $backupPath).Length -or $sourceHash -ne $backupHash) {
        Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
        throw "$Label could not be backed up safely; the original was not removed."
    }

    Remove-Item -LiteralPath $Path -Force
    if (Test-Path -LiteralPath $Path) {
        throw "$Label still exists after backup and removal: $Path"
    }

    return $backupPath
}

function Assert-DeployExtraArgs {
    param(
        [string]$ConfigPath,
        [string]$ExpectedLine
    )

    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        throw "Deploy config was not found: $ConfigPath"
    }

    $writtenConfig = Get-Content -LiteralPath $ConfigPath -Raw
    # pyside6-deploy may rewrite the INI file with CRLF endings. In .NET's
    # multiline regex mode, `$` stops before `\n` but leaves the preceding
    # `\r`, so accept that carriage return explicitly.
    $exactPattern = '(?m)^[ \t]*' + [regex]::Escape($ExpectedLine) + '[ \t]*\r?$'
    if (-not [regex]::IsMatch($writtenConfig, $exactPattern)) {
        throw "Deploy config does not contain the required GUI extra_args line."
    }
}

$Version = Get-ProjectVersion -Root $ProjectRoot
$ReleaseFileName = "ShareGuard-$Version-windows-x64.exe"
$ReleaseExecutable = Join-Path $DistDirectory $ReleaseFileName

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Python bulunamadi: $Python"
}

if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
    & $Python -m venv (Join-Path $ProjectRoot ".venv")
    if ($LASTEXITCODE -ne 0) { throw "virtual environment creation failed with exit code $LASTEXITCODE" }
}

Push-Location $ProjectRoot
try {
    & $VenvPython -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed with exit code $LASTEXITCODE" }
    & $VenvPython -m pip install -e "."
    if ($LASTEXITCODE -ne 0) { throw "project installation failed with exit code $LASTEXITCODE" }
    & $VenvPython -m compileall -q main.py src
    if ($LASTEXITCODE -ne 0) { throw "source validation failed with exit code $LASTEXITCODE" }

    if (-not $SkipExecutable) {
        if (-not (Test-Path -LiteralPath $DeployTool -PathType Leaf)) {
            throw "pyside6-deploy was not installed: $DeployTool"
        }

        & $VenvPython (Join-Path $PSScriptRoot "generate_icon.py") $Icon
        if ($LASTEXITCODE -ne 0) { throw "icon generation failed with exit code $LASTEXITCODE" }
        if (-not (Test-Path -LiteralPath $Icon -PathType Leaf)) { throw "Icon generation completed without shareguard.ico" }

        if (-not (Test-Path -LiteralPath $DeployConfig -PathType Leaf)) {
            & $DeployTool main.py --name ShareGuard --init
            if ($LASTEXITCODE -ne 0) { throw "pyside6-deploy --init failed with exit code $LASTEXITCODE" }
            if (-not (Test-Path -LiteralPath $DeployConfig -PathType Leaf)) {
                throw "pyside6-deploy --init completed without pysidedeploy.spec"
            }
        }

        # pyside6-deploy 6.5.x creates a console executable by default. Keep
        # the generated machine-specific config, but force a normal GUI app.
        $expectedExtraArgs = "extra_args = --quiet --noinclude-qt-translations=True --nofollow-import-to=tkinter --windows-icon-from-ico=assets/shareguard.ico --disable-console"
        $extraArgsPattern = '(?m)^[ \t]*extra_args[ \t]*=.*$'
        $configText = Get-Content -LiteralPath $DeployConfig -Raw
        $extraArgsMatches = [regex]::Matches($configText, $extraArgsPattern)
        if ($extraArgsMatches.Count -ne 1) {
            throw "Expected exactly one extra_args entry in pysidedeploy.spec; found $($extraArgsMatches.Count)."
        }
        $configText = [regex]::Replace($configText, $extraArgsPattern, $expectedExtraArgs)
        [System.IO.File]::WriteAllText($DeployConfig, $configText, $Utf8WithoutBom)
        Assert-DeployExtraArgs -ConfigPath $DeployConfig -ExpectedLine $expectedExtraArgs

        # A previously opened app may hold an output executable open. Stop only
        # processes whose full path belongs to this project.
        $expectedExecutables = @(
            [System.IO.Path]::GetFullPath($GeneratedExecutable),
            [System.IO.Path]::GetFullPath($Executable)
        )
        Get-Process -Name "main", "ShareGuard" -ErrorAction SilentlyContinue | ForEach-Object {
            $candidateProcess = $_
            try {
                if ($candidateProcess.Path -and $expectedExecutables -contains ([System.IO.Path]::GetFullPath($candidateProcess.Path))) {
                    Stop-Process -Id $candidateProcess.Id -Force
                    $candidateProcess.WaitForExit()
                }
            }
            catch {
                Write-Warning "Could not inspect or stop process $($candidateProcess.Id): $($_.Exception.Message)"
            }
        }

        # Removing the old deploy output before invoking the compiler makes it
        # impossible to mistake a stale main.exe for a successful new build.
        $buildStartedUtc = [DateTime]::UtcNow
        $staleMainBackup = Backup-And-RemoveArtifact -Path $GeneratedExecutable -Label "Stale generated executable"
        if ($staleMainBackup) {
            Write-Output "STALE_MAIN_BACKUP=$staleMainBackup"
        }

        $deployStartedUtc = [DateTime]::UtcNow
        & $DeployTool --config-file $DeployConfig --force
        $deployExitCode = $LASTEXITCODE
        if ($deployExitCode -ne 0) { throw "pyside6-deploy failed with exit code $deployExitCode" }
        Assert-DeployExtraArgs -ConfigPath $DeployConfig -ExpectedLine $expectedExtraArgs

        if (-not (Test-Path -LiteralPath $GeneratedExecutable -PathType Leaf)) {
            throw "pyside6-deploy returned success without producing main.exe"
        }

        $generatedItem = Get-Item -LiteralPath $GeneratedExecutable
        if ($generatedItem.Length -le 0) { throw "pyside6-deploy produced an empty main.exe" }
        if ($generatedItem.LastWriteTimeUtc -lt $deployStartedUtc -or $generatedItem.LastWriteTimeUtc -lt $buildStartedUtc) {
            throw "main.exe is older than this build and will not be published."
        }
        $generatedHash = (Get-FileHash -LiteralPath $GeneratedExecutable -Algorithm SHA256).Hash

        Move-Item -LiteralPath $GeneratedExecutable -Destination $Executable -Force
        if (Test-Path -LiteralPath $GeneratedExecutable) { throw "main.exe still exists after promotion" }
        if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) { throw "Build completed without ShareGuard.exe" }

        $executableItem = Get-Item -LiteralPath $Executable
        $executableHash = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash
        if ($executableItem.LastWriteTimeUtc -lt $buildStartedUtc -or $executableHash -ne $generatedHash) {
            throw "ShareGuard.exe does not match the executable produced by this build."
        }

        New-Item -ItemType Directory -Path $DistDirectory -Force | Out-Null
        $releaseTemp = Join-Path $DistDirectory (".{0}.{1}.tmp" -f $ReleaseFileName, $PID)
        try {
            Copy-Item -LiteralPath $Executable -Destination $releaseTemp -Force
            $releaseTempHash = (Get-FileHash -LiteralPath $releaseTemp -Algorithm SHA256).Hash
            if ($releaseTempHash -ne $executableHash) {
                throw "The staged release executable does not match ShareGuard.exe."
            }
            Move-Item -LiteralPath $releaseTemp -Destination $ReleaseExecutable -Force
        }
        finally {
            Remove-Item -LiteralPath $releaseTemp -Force -ErrorAction SilentlyContinue
        }

        $releaseItem = Get-Item -LiteralPath $ReleaseExecutable
        $releaseHash = (Get-FileHash -LiteralPath $ReleaseExecutable -Algorithm SHA256).Hash
        if ($releaseItem.LastWriteTimeUtc -lt $buildStartedUtc -or $releaseHash -ne $executableHash) {
            throw "Versioned release executable is stale or does not match ShareGuard.exe."
        }

        $checksumLine = "{0}  {1}" -f $releaseHash.ToLowerInvariant(), $ReleaseFileName
        # SHA256SUMS is consumed on both Windows and Unix. Always use LF so
        # GNU sha256sum does not treat a trailing CR as part of the filename.
        [System.IO.File]::WriteAllText($ChecksumFile, $checksumLine + "`n", $Utf8WithoutBom)
        if ((Get-Content -LiteralPath $ChecksumFile -Raw).Trim() -ne $checksumLine) {
            throw "SHA256SUMS could not be verified after writing."
        }

        Write-Output "BUILD_STARTED_UTC=$($buildStartedUtc.ToString('o'))"
        Write-Output "EXECUTABLE=$Executable"
        Write-Output "RELEASE=$ReleaseExecutable"
        Write-Output "SHA256=$releaseHash"
        Write-Output "SHA256SUMS=$ChecksumFile"
    }
}
finally {
    Pop-Location
}
