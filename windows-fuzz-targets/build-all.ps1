# Build script for all Windows fuzzers
#
# Usage: .\build-all.ps1

$ErrorActionPreference = "Stop"

# Check if clang++ is available
if (-not (Get-Command clang++ -ErrorAction SilentlyContinue)) {
    Write-Host "Error: clang++ not found in PATH" -ForegroundColor Red
    Write-Host "Please run windows-setup.ps1 first or add LLVM to your PATH" -ForegroundColor Yellow
    exit 1
}

Write-Host "Using compiler: $(Get-Command clang++ | Select-Object -ExpandProperty Source)" -ForegroundColor Cyan
clang++ --version

# Common build flags
$FUZZ_FLAGS = "-g", "-O1", "-fsanitize=fuzzer,address"

# Optionally add undefined behavior sanitizer (slower but more thorough)
# $FUZZ_FLAGS += "-fsanitize=undefined"

$BUILD_DIR = "build"
New-Item -ItemType Directory -Force -Path $BUILD_DIR | Out-Null

Write-Host ""
Write-Host "Building Windows Framework Fuzzers..." -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

# GDI+ Image Fuzzer
Write-Host "[1/4] Building GDI+ Image Fuzzer..." -ForegroundColor Green
try {
    & clang++ @FUZZ_FLAGS `
        gdiplus_image_fuzzer.cc `
        -lgdiplus -lole32 -loleaut32 `
        -o "$BUILD_DIR\gdiplus_image_fuzzer.exe"
    Write-Host "✓ Built: $BUILD_DIR\gdiplus_image_fuzzer.exe" -ForegroundColor Green
} catch {
    Write-Host "✗ Failed to build GDI+ fuzzer: $_" -ForegroundColor Red
}

# DirectWrite Font Fuzzer
Write-Host "[2/4] Building DirectWrite Font Fuzzer..." -ForegroundColor Green
try {
    & clang++ @FUZZ_FLAGS `
        directwrite_font_fuzzer.cc `
        -ld2d1 -ldwrite -lole32 `
        -o "$BUILD_DIR\directwrite_font_fuzzer.exe"
    Write-Host "✓ Built: $BUILD_DIR\directwrite_font_fuzzer.exe" -ForegroundColor Green
} catch {
    Write-Host "✗ Failed to build DirectWrite fuzzer: $_" -ForegroundColor Red
}

# Windows Imaging Component Fuzzer
Write-Host "[3/4] Building Windows Imaging Component Fuzzer..." -ForegroundColor Green
try {
    & clang++ @FUZZ_FLAGS `
        wic_fuzzer.cc `
        -lwindowscodecs -lole32 -loleaut32 `
        -o "$BUILD_DIR\wic_fuzzer.exe"
    Write-Host "✓ Built: $BUILD_DIR\wic_fuzzer.exe" -ForegroundColor Green
} catch {
    Write-Host "✗ Failed to build WIC fuzzer: $_" -ForegroundColor Red
}

# Shell Link Fuzzer
Write-Host "[4/4] Building Shell Link (LNK) Fuzzer..." -ForegroundColor Green
try {
    & clang++ @FUZZ_FLAGS `
        lnk_fuzzer.cc `
        -lshell32 -lole32 -luuid `
        -o "$BUILD_DIR\lnk_fuzzer.exe"
    Write-Host "✓ Built: $BUILD_DIR\lnk_fuzzer.exe" -ForegroundColor Green
} catch {
    Write-Host "✗ Failed to build LNK fuzzer: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Build complete!" -ForegroundColor Green
Write-Host ""

if (Test-Path "$BUILD_DIR\*.exe") {
    Write-Host "Fuzzers built in: $BUILD_DIR\" -ForegroundColor Cyan
    Get-ChildItem "$BUILD_DIR\*.exe" | ForEach-Object {
        Write-Host "  - $($_.Name)" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "To run a fuzzer:" -ForegroundColor Yellow
    Write-Host "  cd $BUILD_DIR" -ForegroundColor Cyan
    Write-Host "  .\gdiplus_image_fuzzer.exe -max_total_time=60" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "For more options, see README.md" -ForegroundColor Yellow
} else {
    Write-Host "No fuzzers were built successfully." -ForegroundColor Red
    Write-Host "Check error messages above for details." -ForegroundColor Yellow
}
