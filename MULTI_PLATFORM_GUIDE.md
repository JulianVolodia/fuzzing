# Multi-Platform Security Fuzzing Guide

This comprehensive guide covers fuzzing on macOS, Windows, and Linux to find vulnerabilities in operating systems and popular software.

## 🎯 Quick Start by Platform

### macOS
```bash
git clone <this-repo>
cd fuzzing
./macos-setup.sh
source ~/fuzzing-workspace/setup-env.sh
cd apple-fuzz-targets
./build-all.sh
```

### Windows
```powershell
git clone <this-repo>
cd fuzzing
# Run as Administrator
.\windows-setup.ps1
. $HOME\fuzzing-workspace\setup-env.ps1
cd windows-fuzz-targets
.\build-all.ps1
```

### Linux
```bash
git clone <this-repo>
cd fuzzing
# Install dependencies
sudo apt-get install -y clang libpng-dev libfreetype6-dev libwebp-dev
cd cross-platform-targets
./build-linux.sh
```

## 📁 Repository Structure

```
fuzzing/
├── macos-setup.sh              # macOS environment setup
├── windows-setup.ps1           # Windows environment setup
│
├── apple-fuzz-targets/         # macOS/iOS specific
│   ├── cf_string_fuzzer.cc     # CoreFoundation strings
│   ├── cg_image_fuzzer.cc      # CoreGraphics images
│   ├── coretext_font_fuzzer.cc # Font rendering
│   ├── plist_fuzzer.cc         # Property lists
│   ├── archive_fuzzer.cc       # Archive handling
│   ├── xml_fuzzer.cc           # XML parsing
│   └── build-all.sh
│
├── windows-fuzz-targets/       # Windows specific
│   ├── gdiplus_image_fuzzer.cc # GDI+ images
│   ├── directwrite_font_fuzzer.cc # DirectWrite fonts
│   ├── wic_fuzzer.cc           # Windows Imaging Component
│   ├── lnk_fuzzer.cc           # Shell Link files
│   └── build-all.ps1
│
├── cross-platform-targets/     # Multi-platform libraries
│   ├── libpng_fuzzer.cc        # PNG images
│   ├── freetype_fuzzer.cc      # Font rendering
│   ├── webp_fuzzer.cc          # WebP images
│   ├── build-linux.sh
│   └── build-macos.sh
│
├── dictionaries/               # Format-specific dictionaries
│   ├── png.dict
│   ├── jpeg.dict
│   ├── xml.dict
│   └── ...
│
├── docs/                       # Educational materials
│   ├── libFuzzerTutorial.md
│   ├── good-fuzz-target.md
│   └── structure-aware-fuzzing.md
│
├── MACOS_FUZZING_GUIDE.md      # Platform-specific guide
├── MULTI_PLATFORM_GUIDE.md     # This file
└── VENDOR_REPORTING.md         # How to report bugs

```

## 🎯 Target Selection by Platform

### High-Value Targets Comparison

| Target Area | macOS | Windows | Linux/Cross-Platform |
|-------------|-------|---------|---------------------|
| **Image Parsing** | CoreGraphics ⭐⭐⭐⭐⭐ | GDI+/WIC ⭐⭐⭐⭐⭐ | libpng/libjpeg ⭐⭐⭐⭐⭐ |
| **Font Rendering** | CoreText ⭐⭐⭐⭐⭐ | DirectWrite ⭐⭐⭐⭐ | FreeType ⭐⭐⭐⭐⭐ |
| **Document Parsing** | PDFKit ⭐⭐⭐⭐⭐ | - | - |
| **Archive Handling** | libarchive ⭐⭐⭐⭐ | Cabinet ⭐⭐⭐ | libarchive ⭐⭐⭐⭐ |
| **XML Parsing** | libxml2 ⭐⭐⭐⭐ | MSXML ⭐⭐⭐ | libxml2 ⭐⭐⭐⭐ |
| **Web Formats** | WebKit ⭐⭐⭐⭐⭐ | Edge/IE ⭐⭐⭐⭐ | Chrome ⭐⭐⭐⭐⭐ |
| **Modern Images** | HEIF ⭐⭐⭐⭐⭐ | - | WebP ⭐⭐⭐⭐⭐ |

## 🚀 Getting Started on Each Platform

### macOS Setup (Detailed)

1. **Install Prerequisites**
```bash
# Homebrew should be installed by setup script
# But if you need to install manually:
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

2. **Run Setup**
```bash
./macos-setup.sh
# This installs: LLVM, Clang, cmake, ninja
```

3. **Build Apple-Specific Targets**
```bash
cd apple-fuzz-targets
./build-all.sh
```

4. **Run Your First Fuzzer**
```bash
cd build
# Find system images for corpus
mkdir corpus
find /System/Library -name "*.png" 2>/dev/null | head -20 | xargs -I {} cp {} corpus/
# Run fuzzer for 1 hour
./cg_image_fuzzer corpus/ -max_total_time=3600
```

### Windows Setup (Detailed)

1. **Run Setup Script (as Administrator)**
```powershell
# Right-click PowerShell, "Run as Administrator"
Set-ExecutionPolicy Bypass -Scope Process -Force
.\windows-setup.ps1
```

2. **Activate Environment**
```powershell
. $HOME\fuzzing-workspace\setup-env.ps1
```

3. **Build Windows Targets**
```powershell
cd windows-fuzz-targets
.\build-all.ps1
```

4. **Run Your First Fuzzer**
```powershell
cd build
# Create corpus from system images
mkdir corpus
Get-ChildItem C:\Windows\Web\* -Include *.jpg,*.png -Recurse | Select-Object -First 20 | Copy-Item -Destination corpus\
# Run fuzzer
.\gdiplus_image_fuzzer.exe corpus\ -max_total_time=3600
```

### Linux Setup (Detailed)

1. **Install Dependencies**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    clang llvm \
    libpng-dev libjpeg-dev libfreetype6-dev \
    libwebp-dev libbrotli-dev libprotobuf-dev \
    zlib1g-dev libsqlite3-dev libssl-dev \
    libxml2-dev

# Or Fedora/RHEL
sudo dnf install -y \
    clang llvm \
    libpng-devel libjpeg-turbo-devel freetype-devel \
    libwebp-devel brotli-devel protobuf-devel \
    zlib-devel sqlite-devel openssl-devel \
    libxml2-devel
```

2. **Build Cross-Platform Targets**
```bash
cd cross-platform-targets
./build-linux.sh
```

3. **Run Your First Fuzzer**
```bash
cd build
mkdir corpus
# Find some images
find /usr/share/pixmaps -name "*.png" | head -20 | xargs -I {} cp {} corpus/
./libpng_fuzzer corpus/ -max_total_time=3600
```

## 🔥 High-Impact Fuzzing Campaigns

### Campaign 1: Image Parser Safari

Target image parsing across all platforms:

**macOS:**
```bash
cd apple-fuzz-targets/build
./cg_image_fuzzer corpus/ -dict=../../dictionaries/png.dict -jobs=8 -max_total_time=86400
```

**Windows:**
```powershell
cd windows-fuzz-targets\build
.\gdiplus_image_fuzzer.exe corpus\ -dict=..\..\dictionaries\png.dict -jobs=8 -max_total_time=86400
.\wic_fuzzer.exe corpus\ -jobs=8 -max_total_time=86400
```

**Linux:**
```bash
cd cross-platform-targets/build
./libpng_fuzzer corpus/ -dict=../../dictionaries/png.dict -jobs=8 -max_total_time=86400
./webp_fuzzer corpus/ -dict=../../dictionaries/webp.dict -jobs=8 -max_total_time=86400
```

### Campaign 2: Font Rendering Blitz

Font parsers are gold mines for vulnerabilities:

**macOS:**
```bash
cd apple-fuzz-targets/build
mkdir corpus && find /System/Library/Fonts -name "*.ttf" | head -10 | xargs -I {} cp {} corpus/
./coretext_font_fuzzer corpus/ -dict=../../dictionaries/otf.dict -jobs=8 -max_total_time=172800
```

**Windows:**
```powershell
cd windows-fuzz-targets\build
mkdir corpus && Get-ChildItem C:\Windows\Fonts\*.ttf | Select-Object -First 10 | Copy-Item -Destination corpus\
.\directwrite_font_fuzzer.exe corpus\ -dict=..\..\dictionaries\otf.dict -jobs=8 -max_total_time=172800
```

**Linux:**
```bash
cd cross-platform-targets/build
mkdir corpus && find /usr/share/fonts -name "*.ttf" | head -10 | xargs -I {} cp {} corpus/
./freetype_fuzzer corpus/ -dict=../../dictionaries/otf.dict -jobs=8 -max_total_time=172800
```

### Campaign 3: Platform-Specific Attacks

**macOS HEIF (High Value):**
```bash
# HEIF is newer and less tested
cd apple-fuzz-targets/build
mkdir corpus && find ~/Pictures -name "*.heic" | head -20 | xargs -I {} cp {} corpus/
./cg_image_fuzzer corpus/ -dict=../../dictionaries/heif.dict -max_total_time=259200
```

**Windows LNK Files (Stuxnet-style):**
```powershell
# LNK vulnerabilities can lead to RCE
cd windows-fuzz-targets\build
mkdir corpus
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu" -Filter *.lnk -Recurse | Select-Object -First 20 | Copy-Item -Destination corpus\
.\lnk_fuzzer.exe corpus\ -max_total_time=259200
```

## 💰 Bug Bounty Potential

### Apple Security Bounty
- **Critical RCE**: Up to $1,000,000
- **Kernel Code Execution**: $250,000 - $500,000
- **Sandbox Escape**: $100,000 - $250,000
- **Memory Corruption**: $50,000 - $150,000

**Best targets**: CoreGraphics, CoreText, PDFKit, WebKit

### Microsoft Bug Bounty
- **Hyper-V Vulnerabilities**: Up to $250,000
- **Windows RCE**: $20,000 - $100,000
- **Edge RCE**: $30,000 - $100,000
- **Office RCE**: $15,000 - $100,000

**Best targets**: GDI+, DirectWrite, WIC, Edge

### Google/Chrome Bounty
- **Chrome RCE**: $5,000 - $250,000+
- **High quality bonus**: 1.5x - 3x multiplier
- **Android**: $1,000 - $250,000

**Best targets**: WebP, FreeType, libpng, V8

## 🛠️ Advanced Techniques

### Parallel Multi-Platform Fuzzing

Run campaigns across all platforms simultaneously:

```bash
# macOS terminal 1
./apple-fuzz-targets/build/cg_image_fuzzer corpus/ -jobs=4 &

# Windows PowerShell 1
Start-Job { .\windows-fuzz-targets\build\gdiplus_image_fuzzer.exe corpus\ -jobs=4 }

# Linux terminal 1
./cross-platform-targets/build/libpng_fuzzer corpus/ -jobs=4 &
```

### Corpus Sharing Between Platforms

Share interesting test cases across platforms:

```bash
# On macOS
rsync -av corpus/ user@windows-machine:/path/to/corpus/
rsync -av corpus/ user@linux-machine:/path/to/corpus/

# Merge results
mkdir merged-corpus
./fuzzer merged-corpus/ macos-corpus/ windows-corpus/ linux-corpus/ -merge=1
```

### Coverage-Guided Cross-Platform Testing

1. **Generate coverage on each platform**
2. **Identify platform-specific code paths**
3. **Create targeted inputs for uncovered paths**

```bash
# macOS coverage
clang++ -fprofile-instr-generate -fcoverage-mapping fuzzer.cc -o fuzzer-cov
LLVM_PROFILE_FILE="macos.profraw" ./fuzzer-cov corpus/*
llvm-profdata merge -sparse macos.profraw -o macos.profdata
llvm-cov report fuzzer-cov -instr-profile=macos.profdata

# Compare with Windows/Linux coverage to find gaps
```

## 📊 Success Metrics

Track your fuzzing campaigns:

| Metric | Target | Notes |
|--------|--------|-------|
| **Exec/sec** | 1000+ | Higher is better |
| **Coverage** | Increasing | Track with llvm-cov |
| **Corpus Size** | Stable | Should plateau after initial growth |
| **Unique Crashes** | Maximize | De-duplicate with libFuzzer |
| **Time per Campaign** | 24-72 hours | Minimum for meaningful results |

## 🎓 Learning Path

1. **Week 1**: Set up all three platforms, run example fuzzers
2. **Week 2**: Run extended campaigns on high-value targets
3. **Week 3**: Analyze crashes, minimize test cases
4. **Week 4**: Write first vulnerability report
5. **Month 2-3**: Deep dive into specific subsystems
6. **Month 4+**: Contribute to OSS-Fuzz, collect bounties

## 📚 Platform-Specific Resources

### macOS
- [MACOS_FUZZING_GUIDE.md](MACOS_FUZZING_GUIDE.md)
- [Apple Security Bounty](https://security.apple.com/)
- [Apple Platform Security Guide](https://support.apple.com/guide/security/)

### Windows
- [windows-fuzz-targets/README.md](windows-fuzz-targets/README.md)
- [MSRC Portal](https://msrc.microsoft.com/)
- [Windows Security Documentation](https://docs.microsoft.com/en-us/windows/security/)

### Cross-Platform
- [cross-platform-targets/README.md](cross-platform-targets/README.md)
- [Google Security Blog](https://security.googleblog.com/)
- [Chromium Security](https://www.chromium.org/Home/chromium-security/)

## 🆘 Troubleshooting

### "Fuzzer runs but no coverage"
- Verify you're using correct compiler (clang with libFuzzer)
- Check that `-fsanitize=fuzzer` is in compile flags
- Try with a known-good fuzzer first

### "Out of memory"
- Add size limits in fuzz target
- Use `-rss_limit_mb=2048`
- Use `-max_len=` to limit input size

### "Permission denied" (macOS)
- Grant terminal Full Disk Access in System Preferences
- Some directories require elevated permissions

### "Access violation" (Windows)
- Run as Administrator for some APIs
- Disable Windows Defender for fuzzing directory (temporary)

### Build failures
- Ensure all dependencies are installed
- Check library paths with `pkg-config --libs <library>`
- Use platform-specific help in each directory's README

## ⚖️ Legal and Ethical Guidelines

**✅ ALWAYS:**
- Test on your own systems
- Report responsibly to vendors
- Follow disclosure timelines (90-120 days)
- Respect vendor bug bounty terms

**❌ NEVER:**
- Test on systems you don't own
- Exploit vulnerabilities maliciously
- Publicly disclose before patches
- Attack vendor infrastructure

## 🎯 Next Steps

1. Choose your platform (or all three!)
2. Run the setup script
3. Build the fuzzers
4. Start with high-value targets
5. Let fuzzers run for 24+ hours
6. Check for crashes
7. Minimize and report findings
8. Collect bounties! 💰

Happy fuzzing! 🐛🔍🔒
