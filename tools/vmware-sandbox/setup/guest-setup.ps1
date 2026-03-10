# guest-setup.ps1 — Automated guest VM tool installer for vmware-sandbox
# Run inside the guest VM to download and install all analysis tools.
# Usage: powershell -ExecutionPolicy Bypass -File guest-setup.ps1 [-ToolsDir <path>] [-SkipOptional]

param(
    [string]$ToolsDir = "$env:USERPROFILE\Desktop\tools",
    [string]$AnalysisDir = "$env:USERPROFILE\Desktop\analysis",
    [switch]$SkipOptional,
    [switch]$Force
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"  # Speed up Invoke-WebRequest

# ============================================================
# Helpers
# ============================================================

function Write-Step($msg) { Write-Host "[*] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "[-] $msg" -ForegroundColor Red }

function Ensure-Dir($path) {
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        Write-Step "Created: $path"
    }
}

function Download-File($url, $outPath) {
    if ((Test-Path $outPath) -and -not $Force) {
        Write-Warn "Already exists, skipping: $outPath"
        return $true
    }
    try {
        Write-Step "Downloading: $url"
        Invoke-WebRequest -Uri $url -OutFile $outPath -UseBasicParsing
        if ((Get-Item $outPath).Length -eq 0) {
            Write-Err "Downloaded file is 0 bytes: $outPath"
            Remove-Item $outPath -Force
            return $false
        }
        return $true
    } catch {
        Write-Err "Failed to download: $url ($_)"
        return $false
    }
}

function Get-GithubLatestRelease($repo) {
    try {
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -UseBasicParsing
        return $rel
    } catch {
        Write-Err "Failed to get latest release for $repo"
        return $null
    }
}

function Extract-Zip($zipPath, $destDir) {
    Ensure-Dir $destDir
    try {
        Expand-Archive -Path $zipPath -DestinationPath $destDir -Force
        Write-Step "Extracted to: $destDir"
        return $true
    } catch {
        Write-Err "Failed to extract: $zipPath ($_)"
        return $false
    }
}

# ============================================================
# Tool definitions
# ============================================================

$tempDir = "$env:TEMP\sandbox-setup"
Ensure-Dir $tempDir
Ensure-Dir $ToolsDir
Ensure-Dir $AnalysisDir

$results = @()

# ============================================================
# Required Tools
# ============================================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " Required Tools" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# --- x64dbg ---
Write-Step "Installing x64dbg..."
$x64dbgDir = "$ToolsDir\x64dbg"
if ((Test-Path "$x64dbgDir\release\x64\x64dbg.exe") -and -not $Force) {
    Write-Warn "x64dbg already installed"
    $results += [PSCustomObject]@{Tool="x64dbg"; Status="SKIP"}
} else {
    $rel = Get-GithubLatestRelease "x64dbg/x64dbg"
    if ($rel) {
        $asset = $rel.assets | Where-Object { $_.name -like "snapshot_*.zip" } | Select-Object -First 1
        if ($asset) {
            $zip = "$tempDir\x64dbg.zip"
            if (Download-File $asset.browser_download_url $zip) {
                Extract-Zip $zip $x64dbgDir
                $results += [PSCustomObject]@{Tool="x64dbg"; Status="OK"}
            } else { $results += [PSCustomObject]@{Tool="x64dbg"; Status="FAIL"} }
        } else { $results += [PSCustomObject]@{Tool="x64dbg"; Status="FAIL (no asset)"} }
    } else { $results += [PSCustomObject]@{Tool="x64dbg"; Status="FAIL (API)"} }
}

# --- PE-sieve64 ---
Write-Step "Installing PE-sieve64..."
$pesieveExe = "$ToolsDir\pe-sieve64.exe"
if ((Test-Path $pesieveExe) -and -not $Force) {
    Write-Warn "PE-sieve64 already installed"
    $results += [PSCustomObject]@{Tool="pe-sieve64"; Status="SKIP"}
} else {
    $rel = Get-GithubLatestRelease "hasherezade/pe-sieve"
    if ($rel) {
        $asset = $rel.assets | Where-Object { $_.name -like "*64*.zip" -or $_.name -like "*x64*" } | Select-Object -First 1
        if (-not $asset) { $asset = $rel.assets | Where-Object { $_.name -like "*.zip" } | Select-Object -First 1 }
        if ($asset) {
            $zip = "$tempDir\pe-sieve.zip"
            if (Download-File $asset.browser_download_url $zip) {
                $extractDir = "$tempDir\pe-sieve-extract"
                Extract-Zip $zip $extractDir
                $exe = Get-ChildItem -Path $extractDir -Recurse -Filter "pe-sieve64.exe" | Select-Object -First 1
                if (-not $exe) { $exe = Get-ChildItem -Path $extractDir -Recurse -Filter "pe-sieve*.exe" | Select-Object -First 1 }
                if ($exe) {
                    Copy-Item $exe.FullName $pesieveExe -Force
                    $results += [PSCustomObject]@{Tool="pe-sieve64"; Status="OK"}
                } else { $results += [PSCustomObject]@{Tool="pe-sieve64"; Status="FAIL (no exe)"} }
            } else { $results += [PSCustomObject]@{Tool="pe-sieve64"; Status="FAIL"} }
        } else { $results += [PSCustomObject]@{Tool="pe-sieve64"; Status="FAIL (no asset)"} }
    } else { $results += [PSCustomObject]@{Tool="pe-sieve64"; Status="FAIL (API)"} }
}

# --- HollowsHunter64 ---
Write-Step "Installing HollowsHunter64..."
$hhExe = "$ToolsDir\hollows_hunter64.exe"
if ((Test-Path $hhExe) -and -not $Force) {
    Write-Warn "HollowsHunter64 already installed"
    $results += [PSCustomObject]@{Tool="hollows_hunter64"; Status="SKIP"}
} else {
    $rel = Get-GithubLatestRelease "hasherezade/hollows_hunter"
    if ($rel) {
        $asset = $rel.assets | Where-Object { $_.name -like "*64*.zip" -or $_.name -like "*x64*" } | Select-Object -First 1
        if (-not $asset) { $asset = $rel.assets | Where-Object { $_.name -like "*.zip" } | Select-Object -First 1 }
        if ($asset) {
            $zip = "$tempDir\hollows_hunter.zip"
            if (Download-File $asset.browser_download_url $zip) {
                $extractDir = "$tempDir\hh-extract"
                Extract-Zip $zip $extractDir
                $exe = Get-ChildItem -Path $extractDir -Recurse -Filter "hollows_hunter64.exe" | Select-Object -First 1
                if (-not $exe) { $exe = Get-ChildItem -Path $extractDir -Recurse -Filter "hollows_hunter*.exe" | Select-Object -First 1 }
                if ($exe) {
                    Copy-Item $exe.FullName $hhExe -Force
                    $results += [PSCustomObject]@{Tool="hollows_hunter64"; Status="OK"}
                } else { $results += [PSCustomObject]@{Tool="hollows_hunter64"; Status="FAIL (no exe)"} }
            } else { $results += [PSCustomObject]@{Tool="hollows_hunter64"; Status="FAIL"} }
        } else { $results += [PSCustomObject]@{Tool="hollows_hunter64"; Status="FAIL (no asset)"} }
    } else { $results += [PSCustomObject]@{Tool="hollows_hunter64"; Status="FAIL (API)"} }
}

# --- Process Monitor (Sysinternals) ---
Write-Step "Installing Process Monitor..."
$procmonDir = "$ToolsDir\procmon"
if ((Test-Path "$procmonDir\Procmon.exe") -and -not $Force) {
    Write-Warn "Procmon already installed"
    $results += [PSCustomObject]@{Tool="procmon"; Status="SKIP"}
} else {
    $zip = "$tempDir\ProcessMonitor.zip"
    if (Download-File "https://download.sysinternals.com/files/ProcessMonitor.zip" $zip) {
        Extract-Zip $zip $procmonDir
        $results += [PSCustomObject]@{Tool="procmon"; Status="OK"}
    } else { $results += [PSCustomObject]@{Tool="procmon"; Status="FAIL"} }
}

# --- Detect It Easy (DiE) ---
Write-Step "Installing Detect It Easy..."
$dieDir = "$ToolsDir\die"
if ((Test-Path "$dieDir\die.exe") -and -not $Force) {
    Write-Warn "DiE already installed"
    $results += [PSCustomObject]@{Tool="die"; Status="SKIP"}
} else {
    $rel = Get-GithubLatestRelease "horsicq/DIE-engine"
    if ($rel) {
        $asset = $rel.assets | Where-Object { $_.name -like "*win64*portable*.zip" } | Select-Object -First 1
        if (-not $asset) { $asset = $rel.assets | Where-Object { $_.name -like "*win*64*.zip" } | Select-Object -First 1 }
        if ($asset) {
            $zip = "$tempDir\die.zip"
            if (Download-File $asset.browser_download_url $zip) {
                Extract-Zip $zip $dieDir
                # DiE sometimes extracts into a subdirectory
                $dieExe = Get-ChildItem -Path $dieDir -Recurse -Filter "die.exe" | Select-Object -First 1
                if ($dieExe -and $dieExe.DirectoryName -ne $dieDir) {
                    # Move contents up if in subdirectory
                    Get-ChildItem $dieExe.DirectoryName | Move-Item -Destination $dieDir -Force -ErrorAction SilentlyContinue
                }
                $results += [PSCustomObject]@{Tool="die"; Status="OK"}
            } else { $results += [PSCustomObject]@{Tool="die"; Status="FAIL"} }
        } else { $results += [PSCustomObject]@{Tool="die"; Status="FAIL (no asset)"} }
    } else { $results += [PSCustomObject]@{Tool="die"; Status="FAIL (API)"} }
}

# --- pestudio ---
Write-Step "Installing pestudio..."
$pestudioDir = "$ToolsDir\pestudio"
if ((Test-Path "$pestudioDir\pestudio\pestudio.exe") -and -not $Force) {
    Write-Warn "pestudio already installed"
    $results += [PSCustomObject]@{Tool="pestudio"; Status="SKIP"}
} else {
    $zip = "$tempDir\pestudio.zip"
    if (Download-File "https://www.winitor.com/tools/pestudio/current/pestudio.zip" $zip) {
        Extract-Zip $zip $pestudioDir
        $results += [PSCustomObject]@{Tool="pestudio"; Status="OK"}
    } else { $results += [PSCustomObject]@{Tool="pestudio"; Status="FAIL"} }
}

# ============================================================
# Optional Tools
# ============================================================

if (-not $SkipOptional) {

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " Optional Tools" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# --- FakeNet-NG ---
Write-Step "Installing FakeNet-NG..."
$fakenetDir = "$ToolsDir\fakenet"
if ((Test-Path "$fakenetDir\fakenet3.5\fakenet.exe") -and -not $Force) {
    Write-Warn "FakeNet-NG already installed"
    $results += [PSCustomObject]@{Tool="fakenet"; Status="SKIP"}
} else {
    $rel = Get-GithubLatestRelease "mandiant/flare-fakenet-ng"
    if ($rel) {
        $asset = $rel.assets | Where-Object { $_.name -like "*.zip" } | Select-Object -First 1
        if ($asset) {
            $zip = "$tempDir\fakenet.zip"
            if (Download-File $asset.browser_download_url $zip) {
                Extract-Zip $zip $fakenetDir
                $results += [PSCustomObject]@{Tool="fakenet"; Status="OK"}
            } else { $results += [PSCustomObject]@{Tool="fakenet"; Status="FAIL"} }
        } else { $results += [PSCustomObject]@{Tool="fakenet"; Status="FAIL (no asset)"} }
    } else { $results += [PSCustomObject]@{Tool="fakenet"; Status="FAIL (API)"} }
}

# --- dnSpy ---
Write-Step "Installing dnSpy..."
$dnspyDir = "$ToolsDir\dnSpy"
if ((Test-Path "$dnspyDir\dnSpy.exe") -and -not $Force) {
    Write-Warn "dnSpy already installed"
    $results += [PSCustomObject]@{Tool="dnSpy"; Status="SKIP"}
} else {
    # dnSpy official repo is archived, use dnSpyEx fork
    $rel = Get-GithubLatestRelease "dnSpyEx/dnSpy"
    if ($rel) {
        $asset = $rel.assets | Where-Object { $_.name -like "*win-x64*.zip" -or $_.name -like "*win64*.zip" } | Select-Object -First 1
        if (-not $asset) { $asset = $rel.assets | Where-Object { $_.name -like "*win*.zip" } | Select-Object -First 1 }
        if ($asset) {
            $zip = "$tempDir\dnspy.zip"
            if (Download-File $asset.browser_download_url $zip) {
                Extract-Zip $zip $dnspyDir
                $results += [PSCustomObject]@{Tool="dnSpy"; Status="OK"}
            } else { $results += [PSCustomObject]@{Tool="dnSpy"; Status="FAIL"} }
        } else { $results += [PSCustomObject]@{Tool="dnSpy"; Status="FAIL (no asset)"} }
    } else { $results += [PSCustomObject]@{Tool="dnSpy"; Status="FAIL (API)"} }
}

# --- CyberChef ---
Write-Step "Installing CyberChef..."
$cyberchefDir = "$ToolsDir\cyberchef"
if ((Test-Path "$cyberchefDir\CyberChef*.html") -and -not $Force) {
    Write-Warn "CyberChef already installed"
    $results += [PSCustomObject]@{Tool="cyberchef"; Status="SKIP"}
} else {
    $rel = Get-GithubLatestRelease "gchq/CyberChef"
    if ($rel) {
        $asset = $rel.assets | Where-Object { $_.name -like "CyberChef*.zip" } | Select-Object -First 1
        if ($asset) {
            $zip = "$tempDir\cyberchef.zip"
            if (Download-File $asset.browser_download_url $zip) {
                Extract-Zip $zip $cyberchefDir
                $results += [PSCustomObject]@{Tool="cyberchef"; Status="OK"}
            } else { $results += [PSCustomObject]@{Tool="cyberchef"; Status="FAIL"} }
        } else { $results += [PSCustomObject]@{Tool="cyberchef"; Status="FAIL (no asset)"} }
    } else { $results += [PSCustomObject]@{Tool="cyberchef"; Status="FAIL (API)"} }
}

# --- HxD ---
Write-Step "Installing HxD..."
$hxdDir = "$ToolsDir\hxd"
if ((Test-Path "$hxdDir\*\HxD.exe") -and -not $Force) {
    Write-Warn "HxD already installed"
    $results += [PSCustomObject]@{Tool="hxd"; Status="SKIP"}
} else {
    $zip = "$tempDir\hxd.zip"
    if (Download-File "https://mh-nexus.de/downloads/HxDSetup.zip" $zip) {
        Extract-Zip $zip $hxdDir
        $results += [PSCustomObject]@{Tool="hxd"; Status="OK"}
    } else { $results += [PSCustomObject]@{Tool="hxd"; Status="FAIL"} }
}

# --- YARA ---
Write-Step "Installing YARA..."
$yaraDir = "$ToolsDir\yara"
if ((Test-Path "$yaraDir\yara64.exe") -and -not $Force) {
    Write-Warn "YARA already installed"
    $results += [PSCustomObject]@{Tool="yara"; Status="SKIP"}
} else {
    $rel = Get-GithubLatestRelease "VirusTotal/yara"
    if ($rel) {
        $asset = $rel.assets | Where-Object { $_.name -like "*win64*.zip" -or $_.name -like "*w64*.zip" } | Select-Object -First 1
        if ($asset) {
            $zip = "$tempDir\yara.zip"
            if (Download-File $asset.browser_download_url $zip) {
                Extract-Zip $zip $yaraDir
                $results += [PSCustomObject]@{Tool="yara"; Status="OK"}
            } else { $results += [PSCustomObject]@{Tool="yara"; Status="FAIL"} }
        } else { $results += [PSCustomObject]@{Tool="yara"; Status="FAIL (no asset)"} }
    } else { $results += [PSCustomObject]@{Tool="yara"; Status="FAIL (API)"} }
}

# --- Autoruns (Sysinternals) ---
Write-Step "Installing Autoruns..."
$autorunsDir = "$ToolsDir\autoruns"
if ((Test-Path "$autorunsDir\autoruns64.exe") -and -not $Force) {
    Write-Warn "Autoruns already installed"
    $results += [PSCustomObject]@{Tool="autoruns"; Status="SKIP"}
} else {
    $zip = "$tempDir\Autoruns.zip"
    if (Download-File "https://download.sysinternals.com/files/Autoruns.zip" $zip) {
        Extract-Zip $zip $autorunsDir
        $results += [PSCustomObject]@{Tool="autoruns"; Status="OK"}
    } else { $results += [PSCustomObject]@{Tool="autoruns"; Status="FAIL"} }
}

# --- Regshot ---
Write-Step "Installing Regshot..."
$regshotDir = "$ToolsDir\regshot"
if ((Test-Path "$regshotDir\*Regshot*") -and -not $Force) {
    Write-Warn "Regshot already installed"
    $results += [PSCustomObject]@{Tool="regshot"; Status="SKIP"}
} else {
    # Regshot is on SourceForge - use direct link for known version
    $zip = "$tempDir\regshot.zip"
    $regshotUrl = "https://sourceforge.net/projects/regshot/files/regshot/1.9.0/Regshot-1.9.0.7z/download"
    Write-Warn "Regshot requires manual download from SourceForge (auto-download unreliable)"
    Write-Warn "URL: https://sourceforge.net/projects/regshot/"
    $results += [PSCustomObject]@{Tool="regshot"; Status="MANUAL"}
}

# --- TCPView (Sysinternals) ---
Write-Step "Installing TCPView..."
$tcpviewDir = "$ToolsDir\tcpview"
if ((Test-Path "$tcpviewDir\tcpview64.exe") -and -not $Force) {
    Write-Warn "TCPView already installed"
    $results += [PSCustomObject]@{Tool="tcpview"; Status="SKIP"}
} else {
    $zip = "$tempDir\TCPView.zip"
    if (Download-File "https://download.sysinternals.com/files/TCPView.zip" $zip) {
        Extract-Zip $zip $tcpviewDir
        $results += [PSCustomObject]@{Tool="tcpview"; Status="OK"}
    } else { $results += [PSCustomObject]@{Tool="tcpview"; Status="FAIL"} }
}

# --- Process Hacker ---
Write-Step "Installing Process Hacker..."
$phDir = "$ToolsDir\processhacker"
if ((Test-Path "$phDir\*ProcessHacker*") -and -not $Force) {
    Write-Warn "Process Hacker already installed"
    $results += [PSCustomObject]@{Tool="processhacker"; Status="SKIP"}
} else {
    # Process Hacker has moved to System Informer - use portable
    $rel = Get-GithubLatestRelease "winsiderss/si-builds"
    if ($rel) {
        $asset = $rel.assets | Where-Object { $_.name -like "*x64*release*bin*.zip" -or $_.name -like "*64*portable*.zip" } | Select-Object -First 1
        if (-not $asset) { $asset = $rel.assets | Where-Object { $_.name -like "*.zip" } | Select-Object -First 1 }
        if ($asset) {
            $zip = "$tempDir\processhacker.zip"
            if (Download-File $asset.browser_download_url $zip) {
                Extract-Zip $zip $phDir
                $results += [PSCustomObject]@{Tool="processhacker"; Status="OK"}
            } else { $results += [PSCustomObject]@{Tool="processhacker"; Status="FAIL"} }
        } else { $results += [PSCustomObject]@{Tool="processhacker"; Status="FAIL (no asset)"} }
    } else { $results += [PSCustomObject]@{Tool="processhacker"; Status="FAIL (API)"} }
}

} # end SkipOptional

# ============================================================
# Windows Settings (Defender, ExecutionPolicy)
# ============================================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " Windows Settings" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Disable Windows Defender realtime (requires admin)
Write-Step "Disabling Windows Defender realtime monitoring..."
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    $results += [PSCustomObject]@{Tool="Defender-Disable"; Status="OK"}
} catch {
    Write-Warn "Failed (requires admin): $_"
    $results += [PSCustomObject]@{Tool="Defender-Disable"; Status="SKIP (no admin)"}
}

# Set PowerShell execution policy
Write-Step "Setting ExecutionPolicy to Bypass..."
try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force
    $results += [PSCustomObject]@{Tool="ExecutionPolicy"; Status="OK"}
} catch {
    Write-Warn "Failed: $_"
    $results += [PSCustomObject]@{Tool="ExecutionPolicy"; Status="FAIL"}
}

# ============================================================
# Cleanup & Summary
# ============================================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " Setup Summary" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$results | Format-Table -AutoSize

$okCount = ($results | Where-Object { $_.Status -eq "OK" }).Count
$skipCount = ($results | Where-Object { $_.Status -eq "SKIP" }).Count
$failCount = ($results | Where-Object { $_.Status -like "FAIL*" }).Count
$manualCount = ($results | Where-Object { $_.Status -eq "MANUAL" }).Count

Write-Host "`nOK: $okCount | Skipped: $skipCount | Failed: $failCount | Manual: $manualCount" -ForegroundColor $(if ($failCount -gt 0) { "Yellow" } else { "Green" })

# Cleanup temp
Write-Step "Cleaning up temp files..."
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`n[DONE] Tools directory: $ToolsDir" -ForegroundColor Green
Write-Host "[DONE] Analysis directory: $AnalysisDir`n" -ForegroundColor Green

if ($failCount -gt 0) {
    Write-Warn "Some tools failed to install. Check the summary above."
    Write-Warn "You can retry with: .\guest-setup.ps1 -Force"
}
if ($manualCount -gt 0) {
    Write-Warn "Some tools require manual download. See messages above."
}
