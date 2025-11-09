# Cross-Platform Fuzz Targets

This directory contains fuzz targets for popular cross-platform software and libraries, primarily targeting Google products but also other widely-used open source software.

## Important Notice

**Responsible Disclosure**: Report vulnerabilities to the appropriate vendors:

- **Google**: https://bughunters.google.com/
- **Chrome/Chromium**: https://bugs.chromium.org/p/chromium/issues/entry?template=Security+Bug
- **Mozilla**: https://www.mozilla.org/en-US/security/bug-bounty/
- **Others**: Check individual project security policies

## Available Fuzz Targets

### 1. Chromium/Chrome Fuzzers

#### libpng Fuzzer (`libpng_fuzzer.cc`)
- PNG image format parsing
- Used by Chrome, Firefox, and many applications
- Past CVEs: CVE-2019-7317, CVE-2018-14550

#### libjpeg-turbo Fuzzer (`libjpeg_fuzzer.cc`)
- JPEG image format parsing
- Used throughout Chrome and many apps
- Past CVEs: CVE-2020-13790, CVE-2021-29390

#### FreeType Font Fuzzer (`freetype_fuzzer.cc`)
- Font rendering library
- Used by Chrome, Android, Linux
- Past CVEs: CVE-2020-15999 (actively exploited)

#### WebP Fuzzer (`webp_fuzzer.cc`)
- Google's WebP image format
- Native in Chrome, used widely
- Past CVEs: CVE-2023-4863 (critical RCE)

#### Brotli Compression Fuzzer (`brotli_fuzzer.cc`)
- Compression algorithm used in Chrome
- Network protocol compression
- Past CVEs: CVE-2020-8927

### 2. Protocol Buffers Fuzzer (`protobuf_fuzzer.cc`)
- Google's data serialization format
- Used across Google products
- Wire format parsing

### 3. zlib Compression Fuzzer (`zlib_fuzzer.cc`)
- Ubiquitous compression library
- Used in nearly every application
- Past CVEs: CVE-2018-25032

### 4. SQLite Fuzzer (`sqlite_fuzzer.cc`)
- Embedded database engine
- Used in Chrome, browsers, mobile apps
- Past CVEs: CVE-2020-13871, CVE-2022-35737

### 5. JSON Parsers

#### RapidJSON Fuzzer (`rapidjson_fuzzer.cc`)
- Fast C++ JSON parser
- Used in many applications

#### nlohmann/json Fuzzer (`nlohmann_json_fuzzer.cc`)
- Popular header-only JSON library

### 6. OpenSSL/BoringSSL Fuzzers

#### TLS Handshake Fuzzer (`tls_fuzzer.cc`)
- SSL/TLS protocol implementation
- Critical for all HTTPS traffic

#### X.509 Certificate Fuzzer (`x509_fuzzer.cc`)
- Certificate parsing
- Critical security component

## Platform Support

All targets in this directory are designed to work on:
- ✅ Linux
- ✅ macOS
- ✅ Windows (with appropriate libraries)

## Building on Different Platforms

### Linux/macOS

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install -y \
    libpng-dev libjpeg-dev libfreetype6-dev \
    libwebp-dev libbrotli-dev libprotobuf-dev \
    zlib1g-dev libsqlite3-dev libssl-dev

# Or on macOS
brew install libpng libjpeg-turbo freetype webp brotli protobuf zlib sqlite3 openssl

# Build
cd cross-platform-targets
./build-linux.sh  # or ./build-macos.sh
```

### Windows

```powershell
# Install dependencies via vcpkg
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg install libpng libjpeg-turbo freetype webp brotli protobuf zlib sqlite3 openssl

# Build
cd cross-platform-targets
.\build-windows.ps1
```

## Running Fuzzers

### Basic Usage

```bash
# Linux/macOS
./libpng_fuzzer corpus/ -max_total_time=3600

# Windows
.\libpng_fuzzer.exe corpus\ -max_total_time=3600
```

### With Seed Corpus

Many of these libraries have existing corpora in OSS-Fuzz:

```bash
# Clone OSS-Fuzz corpus
git clone https://github.com/google/oss-fuzz.git
cd oss-fuzz

# Use existing corpus
./libpng_fuzzer ../oss-fuzz/projects/libpng/corpus/
```

Or download pre-built corpora:
```bash
# For libpng
gsutil -m rsync gs://libpng-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/libpng_read_fuzzer/ corpus/libpng/

# For freetype
gsutil -m rsync gs://freetype2-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/freetype2-2016/ corpus/freetype/
```

## Dictionaries

Use dictionaries from the main repo:

```bash
# PNG fuzzing
./libpng_fuzzer corpus/ -dict=../dictionaries/png.dict

# JPEG fuzzing
./libjpeg_fuzzer corpus/ -dict=../dictionaries/jpeg.dict

# Font fuzzing
./freetype_fuzzer corpus/ -dict=../dictionaries/otf.dict
```

## High-Value Targets

### Priority 1: Image Parsers (Critical)
- **libpng_fuzzer** - Remote exploitation via image
- **libjpeg_fuzzer** - Widely used, high impact
- **webp_fuzzer** - Recently had critical CVE-2023-4863
- **freetype_fuzzer** - Font rendering, often exploited

### Priority 2: Compression (High)
- **brotli_fuzzer** - Network compression
- **zlib_fuzzer** - Ubiquitous library

### Priority 3: Crypto/Network (High)
- **tls_fuzzer** - TLS implementation bugs
- **x509_fuzzer** - Certificate validation

### Priority 4: Data Parsing (Medium-High)
- **protobuf_fuzzer** - Google services
- **sqlite_fuzzer** - Database bugs
- **json_fuzzers** - API parsing

## Bug Bounty Programs

### Google VRP (Vulnerability Reward Program)
- **Chrome**: $5,000 - $250,000+
- **Android**: $1,000 - $250,000+
- **Google Cloud**: $100 - $31,337+
- Report at: https://bughunters.google.com/

### Chromium Bug Bounty
- **Baseline**: $500 - $15,000
- **High quality**: 1.5x multiplier
- **Exceptional**: 3x+ multiplier
- Report at: https://www.chromium.org/Home/chromium-security/vulnerability-rewards-program/

### Mozilla Bug Bounty
- **Critical**: $5,000 - $10,000
- **High**: $3,000 - $5,000
- **Moderate**: $500 - $2,000
- Report at: https://www.mozilla.org/security/bug-bounty/

## OSS-Fuzz Integration

Many of these targets are already in OSS-Fuzz. You can:
1. Check existing coverage
2. Submit improvements
3. Learn from existing fuzzers

```bash
# Clone OSS-Fuzz
git clone https://github.com/google/oss-fuzz.git

# Check project
ls oss-fuzz/projects/libpng/
ls oss-fuzz/projects/freetype2/
ls oss-fuzz/projects/chromium/
```

## Advanced Techniques

### Continuous Fuzzing

```bash
#!/bin/bash
# continuous-fuzz.sh
while true; do
    ./libpng_fuzzer corpus/ -max_total_time=3600

    # Minimize corpus periodically
    if [ $((RANDOM % 10)) -eq 0 ]; then
        mkdir new_corpus
        ./libpng_fuzzer new_corpus corpus/ -merge=1
        rm -rf corpus
        mv new_corpus corpus
    fi

    # Archive crashes
    if ls crash-* 1> /dev/null 2>&1; then
        mkdir -p crashes/$(date +%Y%m%d)
        mv crash-* crashes/$(date +%Y%m%d)/
    fi
done
```

### Differential Fuzzing

Compare different implementations:

```cpp
// Compare libjpeg vs libjpeg-turbo
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Parse with both libraries
    Image img1 = parse_with_libjpeg(Data, Size);
    Image img2 = parse_with_libjpeg_turbo(Data, Size);

    // Check if results differ
    if (img1.valid && img2.valid) {
        if (img1.width != img2.width || img1.height != img2.height) {
            // Found inconsistency!
            abort();
        }
    }
    return 0;
}
```

### Structure-Aware Fuzzing

Use libprotobuf-mutator for Protocol Buffers:

```bash
# Build with structure-aware fuzzing
clang++ -fsanitize=fuzzer,address \
    protobuf_fuzzer.cc \
    -lprotobuf -lprotobuf-mutator \
    -o protobuf_fuzzer
```

## Resources

- **OSS-Fuzz**: https://github.com/google/oss-fuzz
- **ClusterFuzz**: https://github.com/google/clusterfuzz
- **Fuzzer Test Suite**: https://github.com/google/fuzzer-test-suite
- **Chrome Security**: https://www.chromium.org/Home/chromium-security/
- **Google Security Blog**: https://security.googleblog.com/

## Contributing

Found a bug? Follow these steps:

1. **Minimize the test case**
2. **Verify on latest version**
3. **Check if already reported**
4. **Report to appropriate vendor**
5. **Wait for fix (90 days typical)**
6. **Collect bounty** 💰
