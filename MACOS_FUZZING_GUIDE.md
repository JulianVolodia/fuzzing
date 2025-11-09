# macOS Security Fuzzing Guide

This guide explains how to use this repository to find security vulnerabilities in macOS using fuzzing.

## Overview

This repository contains:
- **libFuzzer tutorial**: Educational materials on fuzzing (from Google)
- **Apple-specific fuzz targets**: Ready-to-use fuzzers for macOS frameworks
- **Setup scripts**: Automated environment configuration for macOS

## Quick Start

### 1. Set Up Your Environment

```bash
# Clone this repository (if not already done)
git clone https://github.com/google/fuzzing.git
cd fuzzing

# Run the macOS setup script
chmod +x macos-setup.sh
./macos-setup.sh

# Activate the fuzzing environment
source ~/fuzzing-workspace/setup-env.sh
```

### 2. Build the Apple Framework Fuzzers

```bash
cd apple-fuzz-targets
chmod +x build-all.sh
./build-all.sh
```

### 3. Run Your First Fuzzer

```bash
cd build

# Run the CoreFoundation string fuzzer for 1 hour
./cf_string_fuzzer -max_total_time=3600

# Run the image fuzzer with seed corpus
mkdir corpus
find /System/Library -name "*.png" 2>/dev/null | head -20 | xargs -I {} cp {} corpus/
./cg_image_fuzzer corpus/ -max_total_time=3600
```

## Available Fuzz Targets

### 1. CoreFoundation String Fuzzer (`cf_string_fuzzer`)
Targets string handling in CoreFoundation:
- Tests various character encodings (UTF-8, UTF-16, UTF-32, etc.)
- String conversion and manipulation
- Boundary conditions

**Why fuzz this?**
- CoreFoundation is used throughout macOS/iOS
- String handling bugs can lead to memory corruption
- Past vulnerabilities: CVE-2016-4613, CVE-2016-4669

**Run command:**
```bash
./cf_string_fuzzer -max_total_time=3600 -max_len=65536
```

### 2. CoreGraphics Image Fuzzer (`cg_image_fuzzer`)
Targets image parsing in ImageIO/CoreGraphics:
- PNG, JPEG, HEIF, GIF, TIFF, and more
- Image metadata (EXIF, XMP, IPTC)
- Incremental loading

**Why fuzz this?**
- Image parsers have complex file formats
- High-value targets (can be triggered via web, email, messages)
- Past vulnerabilities: CVE-2020-9783, CVE-2021-30663, CVE-2021-30713

**Run command:**
```bash
# Create seed corpus from system images
mkdir -p corpus/images
find /Library/Desktop\ Pictures -name "*.heic" -o -name "*.jpg" | head -10 | xargs -I {} cp {} corpus/images/

./cg_image_fuzzer corpus/images/ -dict=../dictionaries/png.dict -max_total_time=7200
```

### 3. Property List Fuzzer (`plist_fuzzer`)
Targets property list parsing:
- XML plists
- Binary plists
- Serialization/deserialization

**Why fuzz this?**
- Plists are used for configuration throughout macOS
- Can be exploited via malicious apps or files
- Past vulnerabilities: CVE-2011-0200

**Run command:**
```bash
mkdir -p corpus/plists
find /System/Library/LaunchDaemons -name "*.plist" | head -10 | xargs -I {} cp {} corpus/plists/

./plist_fuzzer corpus/plists/ -max_total_time=3600
```

### 4. CoreText Font Fuzzer (`coretext_font_fuzzer`)
Targets font file parsing:
- TrueType (.ttf) and OpenType (.otf) fonts
- Font tables and glyph rendering
- Font descriptors

**Why fuzz this?**
- Font parsers are notoriously complex
- Can be triggered remotely (web fonts, documents)
- Past vulnerabilities: CVE-2015-1093, CVE-2015-5874, CVE-2020-9956

**Run command:**
```bash
mkdir -p corpus/fonts
find /System/Library/Fonts -name "*.ttf" -o -name "*.otf" | head -10 | xargs -I {} cp {} corpus/fonts/

./coretext_font_fuzzer corpus/fonts/ -max_total_time=7200
```

### 5. Archive Fuzzer (`archive_fuzzer`)
Targets archive handling (libarchive):
- ZIP, TAR, GZIP, BZIP2, XZ
- Compression and decompression
- Path traversal checks

**Why fuzz this?**
- Archive parsers handle untrusted files
- Compression algorithms are complex
- Past vulnerabilities: CVE-2016-1541, CVE-2019-18408

**Run command:**
```bash
./archive_fuzzer -max_total_time=3600
```

### 6. XML Fuzzer (`xml_fuzzer`)
Targets libxml2 parsing:
- XML document parsing
- XPath queries
- DTD handling

**Why fuzz this?**
- libxml2 is widely used in macOS
- XML parsing is complex
- Past vulnerabilities: CVE-2017-5130, CVE-2020-24977

**Run command:**
```bash
./xml_fuzzer -dict=../dictionaries/xml.dict -max_total_time=3600
```

## Advanced Fuzzing Techniques

### Running with Multiple Cores

```bash
# Run 8 parallel workers
./cf_string_fuzzer corpus/ -jobs=8 -workers=8 -max_total_time=14400
```

### Using Dictionaries

Dictionaries significantly improve fuzzing efficiency:

```bash
# List available dictionaries
ls ../dictionaries/

# Use a dictionary
./cg_image_fuzzer corpus/ -dict=../dictionaries/png.dict
```

### Minimizing Crashes

When you find a crash, minimize the input:

```bash
# Find crash files
ls crash-*

# Minimize a crash
./cf_string_fuzzer -minimize_crash=1 -runs=10000 crash-XXXXX
```

### Coverage Analysis

Generate coverage reports to see what code is being tested:

```bash
# Build with coverage
clang++ -fprofile-instr-generate -fcoverage-mapping \
    cf_string_fuzzer.cc \
    -framework CoreFoundation \
    -o cf_string_coverage

# Run on corpus
LLVM_PROFILE_FILE="cf_string.profraw" ./cf_string_coverage corpus/*

# Generate report
llvm-profdata merge -sparse cf_string.profraw -o cf_string.profdata
llvm-cov show cf_string_coverage -instr-profile=cf_string.profdata
llvm-cov report cf_string_coverage -instr-profile=cf_string.profdata
```

### Continuous Fuzzing

Set up a continuous fuzzing loop:

```bash
#!/bin/bash
# continuous-fuzz.sh

FUZZER="./cg_image_fuzzer"
CORPUS="corpus/images"
MAX_TIME=3600  # 1 hour per iteration

while true; do
    echo "[$(date)] Starting fuzzing iteration..."

    # Fuzz
    $FUZZER $CORPUS -max_total_time=$MAX_TIME

    # Minimize corpus every 10 iterations
    if [ $((RANDOM % 10)) -eq 0 ]; then
        echo "[$(date)] Minimizing corpus..."
        mkdir new_corpus
        $FUZZER new_corpus $CORPUS -merge=1
        rm -rf $CORPUS
        mv new_corpus $CORPUS
    fi

    # Check for crashes
    if ls crash-* 1> /dev/null 2>&1; then
        echo "[$(date)] CRASH FOUND!"
        mkdir -p crashes/$(date +%Y%m%d)
        mv crash-* crashes/$(date +%Y%m%d)/
    fi
done
```

## Responsible Disclosure

### Before Reporting

1. **Verify the crash**: Ensure it's reproducible
2. **Minimize the test case**: Use `-minimize_crash=1`
3. **Check if it's known**: Search existing CVEs
4. **Test on latest macOS**: Verify on current version

### Reporting to Apple

Apple has a security bounty program. Report vulnerabilities to:

- **Apple Security Bounty**: https://support.apple.com/en-us/HT201220
- **Email**: product-security@apple.com
- **Bug Bounty Portal**: https://security.apple.com/

### Information to Include

1. **Description**: Clear explanation of the vulnerability
2. **Affected component**: Framework/library name and version
3. **macOS version**: Output of `sw_vers`
4. **Reproduction steps**: Exact commands to reproduce
5. **Test case**: Minimized crashing input (if safe to share)
6. **Impact**: Potential security impact
7. **Crash log**: Symbolicated crash report

### Example Report Template

```
Subject: [FUZZING] Memory corruption in CoreGraphics image parsing

Description:
A heap buffer overflow exists in CoreGraphics when parsing malformed PNG files.

Affected Component:
- Framework: CoreGraphics/ImageIO
- Function: CGImageSourceCreateWithData
- macOS Version: 14.1 (23B74)

Reproduction:
1. Build the fuzzer: clang++ -fsanitize=fuzzer,address cg_image_fuzzer.cc -framework CoreGraphics -framework ImageIO -framework CoreFoundation -o fuzzer
2. Run: ./fuzzer crash-file
3. Observe heap buffer overflow

Impact:
Remote code execution via malicious image file (e.g., in Messages, Safari, Mail)

Attached:
- Minimized test case: crash.png
- Full crash log with symbols
```

## Finding More Targets

### Identifying Vulnerable Code

Look for:
1. **Complex parsers**: Font, image, archive, document formats
2. **Network-facing code**: URL parsing, protocol handlers
3. **IPC mechanisms**: XPC services, Mach messages
4. **Legacy code**: Older C/C++ code without modern protections

### Creating Custom Fuzz Targets

Template for a new fuzzer:

```cpp
#include <TargetFramework/TargetFramework.h>
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 10) {
        return 0;
    }

    // Your API calls here
    // Example: Parse Data as some format

    return 0;
}
```

Build:
```bash
clang++ -g -O1 -fsanitize=fuzzer,address \
    my_fuzzer.cc \
    -framework MyFramework \
    -o my_fuzzer
```

## Troubleshooting

### Fuzzer runs but finds no coverage

- Check that you're using the right LLVM clang (not Xcode clang)
- Verify `-fsanitize=fuzzer` is in compile flags
- Try with a seed corpus

### Out of memory errors

- Use `-rss_limit_mb=2048` to limit memory
- Add size checks in your fuzz target
- Use `-max_len=` to limit input size

### False positives

- Run without sanitizers to verify
- Check if it's a bug in test harness vs. real bug
- Test on multiple macOS versions

### Slow fuzzing

- Use `-jobs=N` for parallel fuzzing
- Provide good seed corpus
- Use dictionaries for format-based inputs
- Profile with `-print_pcs=1` to find slow paths

## Resources

- **libFuzzer docs**: https://llvm.org/docs/LibFuzzer.html
- **Apple Security**: https://security.apple.com/
- **OSS-Fuzz**: https://github.com/google/oss-fuzz
- **Fuzzing Book**: https://www.fuzzingbook.org/
- **This tutorial**: See `tutorial/libFuzzerTutorial.md`

## Legal and Ethical Considerations

⚠️ **Important**:
- Only test on your own systems
- Do not test on production Apple services
- Follow responsible disclosure practices
- Respect Apple's legal terms
- Use findings for defensive purposes only

Good luck and happy (ethical) fuzzing! 🐛
