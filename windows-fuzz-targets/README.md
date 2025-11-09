# Windows Framework Fuzz Targets

This directory contains fuzz targets for finding vulnerabilities in Windows APIs and Microsoft frameworks.

## Important Notice

**Responsible Disclosure**: If you find any security vulnerabilities, please report them to:
- **Microsoft Security Response Center (MSRC)**: https://msrc.microsoft.com/report
- **Email**: secure@microsoft.com
- **Bug Bounty**: https://www.microsoft.com/en-us/msrc/bounty

## Available Fuzz Targets

### 1. GDI+ Image Fuzzer (`gdiplus_image_fuzzer.cc`)
Fuzzes Windows GDI+ image parsing:
- PNG, JPEG, BMP, GIF, TIFF parsers
- Image format conversions
- GDI+ graphics operations

**Past CVEs**: CVE-2020-0618, CVE-2020-1425, CVE-2021-24092

### 2. DirectWrite Font Fuzzer (`directwrite_font_fuzzer.cc`)
Fuzzes DirectWrite font rendering:
- TrueType/OpenType font parsing
- Font collection handling
- Text layout and glyph rendering

**Past CVEs**: CVE-2020-1020, CVE-2021-26415

### 3. XML Parser Fuzzer (`msxml_fuzzer.cc`)
Fuzzes MSXML parsing:
- XML document parsing
- DTD validation
- XPath queries

**Past CVEs**: CVE-2019-0756, CVE-2020-0760

### 4. Windows Imaging Component (WIC) Fuzzer (`wic_fuzzer.cc`)
Fuzzes WIC codec framework:
- Various image format codecs
- Thumbnail generation
- Metadata handling

**Past CVEs**: CVE-2020-0853, CVE-2020-17008

### 5. Cabinet File Fuzzer (`cabinet_fuzzer.cc`)
Fuzzes Windows Cabinet file extraction:
- CAB file parsing
- Decompression
- Path traversal checks

### 6. Registry Fuzzer (`registry_fuzzer.cc`)
Fuzzes Windows Registry operations:
- Registry file parsing
- Key/value operations
- Security descriptor handling

### 7. Shell Link (LNK) Fuzzer (`lnk_fuzzer.cc`)
Fuzzes Windows shortcut files:
- LNK file parsing
- Icon location parsing
- Path resolution

**Past CVEs**: CVE-2017-8464 (Stuxnet-style)

## Building Fuzz Targets

### Prerequisites

Run the Windows setup script first:
```powershell
# As Administrator
.\windows-setup.ps1
. $HOME\fuzzing-workspace\setup-env.ps1
```

### Build Individual Targets

```powershell
cd windows-fuzz-targets

# GDI+ Image Fuzzer
clang++ -g -O1 -fsanitize=fuzzer,address `
    gdiplus_image_fuzzer.cc `
    -lgdiplus -lole32 -loleaut32 `
    -o gdiplus_image_fuzzer.exe

# DirectWrite Font Fuzzer
clang++ -g -O1 -fsanitize=fuzzer,address `
    directwrite_font_fuzzer.cc `
    -ld2d1 -ldwrite -lole32 `
    -o directwrite_font_fuzzer.exe

# Windows Imaging Component Fuzzer
clang++ -g -O1 -fsanitize=fuzzer,address `
    wic_fuzzer.cc `
    -lwindowscodecs -lole32 -loleaut32 `
    -o wic_fuzzer.exe

# Shell Link Fuzzer
clang++ -g -O1 -fsanitize=fuzzer,address `
    lnk_fuzzer.cc `
    -lshell32 -lole32 -luuid `
    -o lnk_fuzzer.exe
```

Or use the build script:
```powershell
.\build-all.ps1
```

## Running Fuzz Targets

### Basic Usage

```powershell
# Run for 1 hour
.\gdiplus_image_fuzzer.exe -max_total_time=3600

# Run with multiple workers
.\directwrite_font_fuzzer.exe -jobs=8 -workers=4 corpus\

# Use seed corpus
mkdir corpus\images
Copy-Item C:\Windows\Web\Wallpaper\*.jpg corpus\images\
.\gdiplus_image_fuzzer.exe corpus\images\ -max_total_time=3600
```

### Using Helper Script

```powershell
$HOME\fuzzing-workspace\run-fuzzer.ps1 .\gdiplus_image_fuzzer.exe -max_total_time=3600
```

## Seed Corpus Locations

### System Images
```powershell
# Wallpapers
Get-ChildItem C:\Windows\Web\* -Include *.jpg,*.png -Recurse | Copy-Item -Destination corpus\images\

# Icons (for GDI+ testing)
Get-ChildItem C:\Windows\System32\*.ico | Select-Object -First 20 | Copy-Item -Destination corpus\icons\
```

### System Fonts
```powershell
Get-ChildItem C:\Windows\Fonts\*.ttf | Select-Object -First 10 | Copy-Item -Destination corpus\fonts\
```

### LNK Files
```powershell
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu" -Filter *.lnk -Recurse | Select-Object -First 20 | Copy-Item -Destination corpus\lnk\
```

## Using Dictionaries

Dictionaries from the main repo work on Windows:

```powershell
# Image fuzzing with PNG dictionary
.\gdiplus_image_fuzzer.exe corpus\ -dict=..\dictionaries\png.dict

# Font fuzzing
.\directwrite_font_fuzzer.exe corpus\ -dict=..\dictionaries\otf.dict
```

## Advanced Techniques

### Coverage Analysis

```powershell
# Build with coverage
clang++ -fprofile-instr-generate -fcoverage-mapping `
    gdiplus_image_fuzzer.cc `
    -lgdiplus -lole32 `
    main.c -o fuzzer_coverage.exe

# Run on corpus
$env:LLVM_PROFILE_FILE="fuzzer.profraw"
.\fuzzer_coverage.exe corpus\*

# Generate report
llvm-profdata merge -sparse fuzzer.profraw -o fuzzer.profdata
llvm-cov show fuzzer_coverage.exe -instr-profile=fuzzer.profdata
llvm-cov report fuzzer_coverage.exe -instr-profile=fuzzer.profdata
```

### Minimizing Crashes

```powershell
.\gdiplus_image_fuzzer.exe -minimize_crash=1 -runs=10000 crash-xxxxx
```

### Parallel Fuzzing

```powershell
# Run 4 parallel instances
1..4 | ForEach-Object {
    Start-Job -ScriptBlock {
        param($id, $fuzzer, $corpus)
        & $fuzzer $corpus -jobs=100 -workers=1 > "fuzz-$id.log" 2>&1
    } -ArgumentList $_, (Get-Location).Path + "\gdiplus_image_fuzzer.exe", "corpus\"
}

# Monitor progress
Get-Job | Receive-Job -Keep
```

## Tips for Finding Vulnerabilities

1. **Target Complex Parsers**: Image and font parsers have the most vulnerabilities
2. **Test Edge Cases**: Zero-size inputs, huge dimensions, malformed headers
3. **Monitor Memory**: Use AddressSanitizer to catch corruption
4. **Run Long Sessions**: Let fuzzers run for 24+ hours
5. **Combine Sanitizers**: Try `-fsanitize=fuzzer,address,undefined`

## Common Issues

### "Cannot find library" errors
- Ensure Visual Studio Build Tools are installed
- Run from "x64 Native Tools Command Prompt for VS 2022"

### Slow fuzzing
- Disable Windows Defender real-time scanning for fuzzing workspace
- Use SSD for corpus storage
- Reduce `-max_len` if inputs are large

### Access violations
- Some Windows APIs require COM initialization
- Run with appropriate privileges (some APIs need admin)

## Resources

- **Microsoft Bug Bounty**: https://www.microsoft.com/en-us/msrc/bounty
- **MSRC Portal**: https://msrc.microsoft.com/
- **Windows API Documentation**: https://docs.microsoft.com/en-us/windows/win32/
- **libFuzzer Guide**: http://llvm.org/docs/LibFuzzer.html
