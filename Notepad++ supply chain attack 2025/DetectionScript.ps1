<#
Notepad++ Supply Chain / Chrysalis Backdoor Detection Script
Campaign: Lotus Blossom hijack of Notepad++ update infra, June - Dec 2025

Checks for artifacts from the "Chrysalis" backdoor that got pushed out
through a hijacked Notepad++ update. Hashes below are copied straight from
Rapid7's writeup (Ivan Feigl, "The Chrysalis Backdoor: A Deep Dive into
Lotus Blossom's toolkit") not retyped by hand, pasted directly from their
published table. My first draft of this had a bunch of typo'd hashes that
would've silently never matched anything, so this version fixes that.

Rapid7's writeup confirms three files get dropped into a hidden
%AppData%\Bluetooth folder, not two like I originally had:
  - BluetoothService.exe  (legit renamed Bitdefender binary, used to sideload)
  - log.dll               (the malicious DLL doing the sideloading)
  - BluetoothService      (no extension - this is the actual encrypted payload)

Exit 0 = clean
Exit 1 = suspect (found the staging folder, but nothing hashed out as confirmed bad)
Exit 2 = confirmed (a file matched a known-bad hash)

Author: Kushal Bhandari
Last updated: 5th ofJuly 2026
#>

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Output "=== Chrysalis / Notepad++ IOC Check ==="

function Get-FileVersionSafe {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        try { return (Get-Item -LiteralPath $Path).VersionInfo.FileVersion } catch { return $null }
    }
    return $null
}

# known-bad SHA256 hashes, pulled from Rapid7's published IOC table.
# covers the NSIS installer chain, all the loader/shellcode variants, and
# the Cobalt Strike / tcc-related files they found on the infected host.
# double checked every one of these is a real 64-char hash before using it -
# learned that lesson the hard way on the first pass.
$BadHashes = @(
    'a511be5164dc1122fb5a7daa3eef9467e43d8458425b15a640235796006590c9', # update.exe
    '8ea8b83645fba6e23d48075a0d3fc73ad2ba515b4536710cda4f1f232718f53e', # [NSIS].nsi
    '2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924', # BluetoothService.exe
    '77bfea78def679aa1117f569a35e8fd1542df21f7e00e27f192c907e61d63a2e', # BluetoothService (the shellcode one)
    '3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad', # log.dll
    '9276594e73cda1c69b7d265b3f08dc8fa84bf2d6599086b9acc0bb3745146600', # u.bat
    'f4d829739f2d6ba7e3ede83dad428a0ced1a703ec582fc73a4eee3df3704629a', # conf.c
    '4a52570eeaf9d27722377865df312e295a7a23c3b6eb991944c2ecd707cc9906', # libtcc.dll
    '831e1ea13a1bd405f5bda2b9d8f2265f7b1db6c668dd2165ccc8a9c4c15ea7dd', # admin
    '0a9b8df968df41920b6ff07785cbfebe8bda29e6b512c94a3b2a83d10014d2fd', # loader1
    '4c2ea8193f4a5db63b897a2d3ce127cc5d89687f380b97a1d91e0c8db542e4f8', # loader1 shellcode (uffhxpSy)
    'e7cd605568c38bd6e0aba31045e1633205d0598c607a855e2e1bca4cca1c6eda', # loader2
    '078a9e5c6c787e5532a7e728720cbafee9021bfec4a30e3c2be110748d7c43c5', # loader2 shellcode (3yzr31vk)
    'b4169a831292e245ebdffedd5820584d73b129411546e7d3eccf4663d5fc5be3', # ConsoleApplication2.exe (loader3)
    '7add554a98d3a99b319f2127688356c1283ed073a084805f14e33b4f6a6126fd', # loader3/4 shellcode
    'fcc2765305bcd213b7558025b2039df2265c3e0b6401e4833123c461df2de51a'  # s047t5g.exe (loader4)
) | ForEach-Object { $_.ToLowerInvariant() }

$confirmed = $false
$suspect = $false

# just grabbing this for context in the output, not using it to actually
# decide if a box is affected - the hash/artifact checks below are what
# actually matters
$notepad64 = Join-Path $env:ProgramFiles 'Notepad++\notepad++.exe'
$pf86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')

if (Test-Path -LiteralPath $notepad64) {
    $ver = Get-FileVersionSafe -Path $notepad64
    Write-Output "[INFO] Notepad++ found (64-bit) | Path: $notepad64 | Version: $ver"
} elseif ($pf86) {
    # only bother building this path if the env var actually exists - don't
    # want a missing ProgramFiles(x86) var to blow up the whole script given
    # we're running with ErrorActionPreference = Stop
    $notepad32 = Join-Path $pf86 'Notepad++\notepad++.exe'
    if (Test-Path -LiteralPath $notepad32) {
        $ver = Get-FileVersionSafe -Path $notepad32
        Write-Output "[INFO] Notepad++ found (32-bit) | Path: $notepad32 | Version: $ver"
    } else {
        Write-Output "[INFO] Notepad++ not installed"
    }
} else {
    Write-Output "[INFO] Notepad++ not installed"
}

# go through real user profiles and check the Bluetooth staging path
$profilesRoot = Join-Path $env:SystemDrive 'Users'
$skipNames = @('Public','Default','Default User','All Users','WDAGUtilityAccount','Administrator')

function Get-HashSafe {
    param([string]$Path)
    try {
        if (Get-Command Get-FileHash -ErrorAction SilentlyContinue) {
            return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        } else {
            # fallback for ancient PowerShell versions without Get-FileHash
            $out = certutil.exe -hashfile """$Path""" SHA256 2>$null
            return ($out | Where-Object { $_ -match '^[0-9a-fA-F]{64}$' } | Select-Object -Last 1).ToLowerInvariant()
        }
    }
    catch {
        Write-Output "[ERROR] Hashing failed for: $Path | $($_.Exception.Message)"
        return $null
    }
}

$profiles = Get-ChildItem -LiteralPath $profilesRoot -Directory -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -notin $skipNames -and
        -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
        (Test-Path -LiteralPath (Join-Path $_.FullName 'NTUSER.DAT') -ErrorAction SilentlyContinue)
    }

foreach ($p in $profiles) {
    $user = $p.Name
    $btDir = Join-Path $p.FullName 'AppData\Roaming\Bluetooth'

    if (Test-Path -LiteralPath $btDir -ErrorAction SilentlyContinue) {
        Write-Output "[WARNING] Bluetooth staging directory FOUND for user $user | $btDir"
        $suspect = $true

        # Rapid7 says the installer marks this folder Hidden - a real
        # AppData\Roaming\Bluetooth folder being hidden on top of everything
        # else is a pretty strong extra tell
        try {
            $dirInfo = Get-Item -LiteralPath $btDir -Force -ErrorAction Stop
            if ($dirInfo.Attributes -band [IO.FileAttributes]::Hidden) {
                Write-Output "[WARNING] Staging directory is Hidden (matches known IOC behavior) | $btDir"
            }
        } catch {
            continue
        }
    }

    # check all three dropped files here, not just two - the extensionless
    # "BluetoothService" file is the actual encrypted shellcode and I missed
    # it completely in my first version
    foreach ($name in 'BluetoothService.exe', 'log.dll', 'BluetoothService') {
        $t = Join-Path $btDir $name
        if (Test-Path -LiteralPath $t -ErrorAction SilentlyContinue) {
            Write-Output "[ALERT] Candidate file: $t"
            $h = Get-HashSafe -Path $t
            if ($h) {
                Write-Output "[ALERT] SHA256 $h | File: $t"
                if ($BadHashes -contains $h) {
                    Write-Output "[CONFIRMED] Hash matches known IOC | $t"
                    $confirmed = $true
                }
            }
        }
    }
}

if (-not $suspect -and -not $confirmed)
{
    Write-Output "[STATUS] No Chrysalis/Lotus Blossom artifacts found in scanned profiles."
}

Write-Output "=== Check Complete ==="

if ($confirmed) { exit 2 }
elseif ($suspect) { exit 1 }
else { exit 0 }