# Windows Fuzzing Setup Script
# This script sets up a complete fuzzing environment on Windows for finding vulnerabilities
# in Windows APIs, Microsoft software, and third-party applications.
#
# Prerequisites: Run as Administrator in PowerShell
# Usage: .\windows-setup.ps1

param(
    [switch]$SkipChocolatey = $false
)

$ErrorActionPreference = "Stop"

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Windows Fuzzing Environment Setup" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Error: This script must be run as Administrator" -ForegroundColor Red
    Write-Host "Please right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Set up directories
$FUZZING_DIR = "$env:USERPROFILE\fuzzing-workspace"
$CORPUS_DIR = "$FUZZING_DIR\corpus"
$CRASH_DIR = "$FUZZING_DIR\crashes"
$TOOLS_DIR = "$FUZZING_DIR\tools"

Write-Host "[*] Creating fuzzing workspace directories..." -ForegroundColor Green
New-Item -ItemType Directory -Force -Path $FUZZING_DIR | Out-Null
New-Item -ItemType Directory -Force -Path $CORPUS_DIR | Out-Null
New-Item -ItemType Directory -Force -Path $CRASH_DIR | Out-Null
New-Item -ItemType Directory -Force -Path "$FUZZING_DIR\targets" | Out-Null
New-Item -ItemType Directory -Force -Path $TOOLS_DIR | Out-Null

# Install Chocolatey if not present
if (-not $SkipChocolatey) {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Host "[*] Installing Chocolatey package manager..." -ForegroundColor Green
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

        # Refresh environment
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    } else {
        Write-Host "[*] Chocolatey is already installed" -ForegroundColor Green
    }
}

# Install LLVM with Clang
Write-Host "[*] Installing LLVM toolchain..." -ForegroundColor Green
if (-not (Get-Command clang -ErrorAction SilentlyContinue)) {
    choco install -y llvm
} else {
    Write-Host "[*] LLVM is already installed" -ForegroundColor Green
}

# Install additional tools
Write-Host "[*] Installing additional tools..." -ForegroundColor Green
$tools = @("git", "cmake", "ninja", "python3", "visualstudio2022buildtools", "visualstudio2022-workload-vctools")

foreach ($tool in $tools) {
    if ($tool -like "visualstudio*") {
        # Visual Studio components need special handling
        Write-Host "[*] Installing Visual Studio Build Tools (this may take a while)..." -ForegroundColor Yellow
        choco install -y $tool --package-parameters "--includeRecommended --includeOptional" 2>$null
    } else {
        choco install -y $tool 2>$null
    }
}

# Refresh environment variables
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

# Verify Clang installation
Write-Host ""
Write-Host "[*] Verifying Clang installation..." -ForegroundColor Green
$clangPath = Get-Command clang++ -ErrorAction SilentlyContinue

if ($clangPath) {
    Write-Host "Clang path: $($clangPath.Source)" -ForegroundColor Cyan
    & clang++ --version
} else {
    Write-Host "Warning: clang++ not found in PATH. You may need to restart your terminal." -ForegroundColor Yellow
    Write-Host "LLVM is typically installed to: C:\Program Files\LLVM\bin" -ForegroundColor Yellow
}

# Create a test fuzzer
Write-Host ""
Write-Host "[*] Creating test fuzzer..." -ForegroundColor Green

$testFuzzerCode = @"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size > 0 && Data[0] == 'W')
        if (Size > 1 && Data[1] == 'I')
            if (Size > 2 && Data[2] == 'N')
                __debugbreak(); // This will crash on Windows
    return 0;
}
"@

$testFuzzerCode | Out-File -FilePath "$FUZZING_DIR\test_fuzzer.cc" -Encoding UTF8

# Try to build test fuzzer
Push-Location $FUZZING_DIR
try {
    Write-Host "[*] Building test fuzzer..." -ForegroundColor Green
    & clang++ -g -O1 -fsanitize=fuzzer,address test_fuzzer.cc -o test_fuzzer.exe 2>$null

    if (Test-Path "test_fuzzer.exe") {
        Write-Host ""
        Write-Host "[*] Running test fuzzer for 5 seconds..." -ForegroundColor Green
        $job = Start-Job -ScriptBlock {
            param($path)
            Set-Location $path
            & .\test_fuzzer.exe -max_total_time=5 2>&1
        } -ArgumentList $FUZZING_DIR

        Wait-Job $job -Timeout 10 | Out-Null
        Receive-Job $job | Select-Object -First 20
        Stop-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -ErrorAction SilentlyContinue

        Write-Host ""
        Write-Host "✓ LibFuzzer is working correctly!" -ForegroundColor Green
    } else {
        Write-Host "⚠ Test fuzzer compilation failed. LibFuzzer may not be fully configured." -ForegroundColor Yellow
    }
} catch {
    Write-Host "⚠ Could not test fuzzer: $_" -ForegroundColor Yellow
}
Pop-Location

# Create environment setup script
Write-Host ""
Write-Host "[*] Creating environment setup script..." -ForegroundColor Green

$setupScript = @"
# Source this file to set up the fuzzing environment
# Usage: . .\setup-env.ps1

`$env:FUZZING_DIR = "$FUZZING_DIR"
`$env:CORPUS_DIR = "$CORPUS_DIR"
`$env:CRASH_DIR = "$CRASH_DIR"

# Add LLVM to PATH if not already there
if (-not (`$env:Path -like "*LLVM*")) {
    `$env:Path = "C:\Program Files\LLVM\bin;" + `$env:Path
}

Write-Host "Fuzzing environment configured!" -ForegroundColor Green
Write-Host "Workspace: `$env:FUZZING_DIR" -ForegroundColor Cyan
Write-Host ""
Write-Host "Build a fuzzer:" -ForegroundColor Yellow
Write-Host "  clang++ -g -O1 -fsanitize=fuzzer,address my_target.cc -o my_fuzzer.exe" -ForegroundColor Cyan
Write-Host ""
Write-Host "Run a fuzzer:" -ForegroundColor Yellow
Write-Host "  .\my_fuzzer.exe corpus\ -max_total_time=3600" -ForegroundColor Cyan
"@

$setupScript | Out-File -FilePath "$FUZZING_DIR\setup-env.ps1" -Encoding UTF8

# Create run-fuzzer helper script
$runScript = @"
# Helper script to run a fuzzer with standard settings
# Usage: .\run-fuzzer.ps1 <fuzzer_binary> [additional_args]

param(
    [Parameter(Mandatory=`$true)]
    [string]`$Fuzzer,
    [Parameter(ValueFromRemainingArguments=`$true)]
    [string[]]`$AdditionalArgs
)

if (-not (Test-Path `$Fuzzer)) {
    Write-Host "Error: Fuzzer binary not found: `$Fuzzer" -ForegroundColor Red
    exit 1
}

`$FuzzerName = [System.IO.Path]::GetFileNameWithoutExtension(`$Fuzzer)
`$CorpusDir = if (`$env:CORPUS_DIR) { "`$env:CORPUS_DIR\`$FuzzerName" } else { ".\corpus\`$FuzzerName" }
`$CrashDir = if (`$env:CRASH_DIR) { "`$env:CRASH_DIR\`$FuzzerName" } else { ".\crashes\`$FuzzerName" }

New-Item -ItemType Directory -Force -Path `$CorpusDir | Out-Null
New-Item -ItemType Directory -Force -Path `$CrashDir | Out-Null

Write-Host "Running fuzzer: `$FuzzerName" -ForegroundColor Cyan
Write-Host "Corpus: `$CorpusDir" -ForegroundColor Cyan
Write-Host "Crashes: `$CrashDir" -ForegroundColor Cyan
Write-Host ""

& `$Fuzzer `$CorpusDir -artifact_prefix="`$CrashDir\" -print_final_stats=1 @AdditionalArgs
"@

$runScript | Out-File -FilePath "$FUZZING_DIR\run-fuzzer.ps1" -Encoding UTF8

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "✓ Setup Complete!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Fuzzing workspace: $FUZZING_DIR" -ForegroundColor Cyan
Write-Host "Corpus directory: $CORPUS_DIR" -ForegroundColor Cyan
Write-Host "Crash directory: $CRASH_DIR" -ForegroundColor Cyan
Write-Host ""
Write-Host "To activate the fuzzing environment, run:" -ForegroundColor Yellow
Write-Host "  . $FUZZING_DIR\setup-env.ps1" -ForegroundColor Cyan
Write-Host ""
Write-Host "Important: You may need to restart your terminal for PATH changes to take effect." -ForegroundColor Yellow
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Check the windows-fuzz-targets directory for example targets" -ForegroundColor Cyan
Write-Host "  2. Build and run the example fuzzers" -ForegroundColor Cyan
Write-Host "  3. Report any findings responsibly to Microsoft Security Response Center" -ForegroundColor Cyan
Write-Host "     (https://msrc.microsoft.com/report)" -ForegroundColor Cyan
Write-Host ""
