# Multi-Platform Security Fuzzing Framework

A comprehensive fuzzing framework for finding security vulnerabilities in Apple (macOS/iOS), Microsoft (Windows), Google (Chrome), and cross-platform software. This repository contains ready-to-use fuzz targets, setup scripts, and comprehensive documentation for responsible security research.

## 🎯 Quick Start

### Choose Your Platform

**macOS:**
```bash
./macos-setup.sh && source ~/fuzzing-workspace/setup-env.sh
cd apple-fuzz-targets && ./build-all.sh
```

**Windows:**
```powershell
# Run as Administrator
.\windows-setup.ps1
cd windows-fuzz-targets && .\build-all.ps1
```

**Linux/Cross-Platform:**
```bash
cd cross-platform-targets && ./build-linux.sh
```

See [MULTI_PLATFORM_GUIDE.md](MULTI_PLATFORM_GUIDE.md) for detailed instructions.

## 📁 Repository Structure

### Platform-Specific Targets

#### 🍎 [apple-fuzz-targets/](apple-fuzz-targets/)
Fuzzers for macOS/iOS frameworks:
- **CoreGraphics/ImageIO** - Image parsing (PNG, JPEG, HEIF)
- **CoreText** - Font rendering
- **CoreFoundation** - String handling
- **Property Lists** - Configuration files
- **Archive handling** - ZIP, TAR
- **XML parsing** - libxml2

**Bug Bounty Potential**: Up to $2,000,000 for critical vulnerabilities

#### 🪟 [windows-fuzz-targets/](windows-fuzz-targets/)
Fuzzers for Windows APIs:
- **GDI+** - Image parsing
- **DirectWrite** - Font rendering
- **WIC** - Windows Imaging Component
- **Shell Links** - LNK files (Stuxnet-style)
- **MSXML** - XML parsing
- **Cabinet files** - Archive handling

**Bug Bounty Potential**: Up to $250,000 for critical vulnerabilities

#### 🌐 [cross-platform-targets/](cross-platform-targets/)
Fuzzers for widely-used libraries (Chrome, Firefox, etc.):
- **libpng** - PNG image parsing
- **FreeType** - Font rendering (Chrome, Android, Linux)
- **WebP** - Google's image format
- **libjpeg** - JPEG parsing
- **Brotli** - Compression
- **SQLite** - Database engine

**Bug Bounty Potential**: Up to $250,000+ for Chrome vulnerabilities

### Documentation

- **[MULTI_PLATFORM_GUIDE.md](MULTI_PLATFORM_GUIDE.md)** - Complete cross-platform guide
- **[MACOS_FUZZING_GUIDE.md](MACOS_FUZZING_GUIDE.md)** - macOS-specific guide
- **[VENDOR_REPORTING.md](VENDOR_REPORTING.md)** - How to report bugs to Apple, Microsoft, Google
- **[tutorial/](tutorial/)** - libFuzzer tutorials
- **[dictionaries/](dictionaries/)** - Format-specific fuzzing dictionaries

## 🚀 Featured Targets

### Critical Impact Targets (⭐⭐⭐⭐⭐)

| Target | Platform | CVE Examples | Why It Matters |
|--------|----------|--------------|----------------|
| **CoreGraphics** | macOS/iOS | CVE-2023-28204, CVE-2021-30663 | Remotely exploitable via Messages, Mail, Safari |
| **CoreText** | macOS/iOS | CVE-2023-32405, CVE-2020-9956 | Web fonts can exploit; sandbox escape potential |
| **GDI+/WIC** | Windows | CVE-2021-24092, CVE-2020-17008 | Used throughout Windows; RCE via images |
| **DirectWrite** | Windows | CVE-2021-26415, CVE-2020-1020 | Font rendering bugs; Edge/Office exploitation |
| **FreeType** | Cross-platform | CVE-2020-15999 (0-day), CVE-2014-9657 | Chrome, Android, Linux; actively exploited |
| **WebP** | Cross-platform | CVE-2023-4863 (critical 0-day) | Chrome zero-day; widespread impact |

## 💰 Bug Bounty Programs

This framework helps you find vulnerabilities eligible for:

| Vendor | Top Bounty | Program Link |
|--------|------------|--------------|
| **Apple** | $2,000,000 | https://security.apple.com/ |
| **Microsoft** | $250,000 | https://www.microsoft.com/en-us/msrc/bounty |
| **Google/Chrome** | $250,000+ | https://bughunters.google.com/ |
| **Mozilla** | $10,000 | https://www.mozilla.org/security/bug-bounty/ |

## 🎓 Learning Path

1. **Day 1**: Set up your platform and run your first fuzzer
2. **Week 1**: Run extended campaigns on high-value targets (images, fonts)
3. **Week 2**: Analyze crashes and minimize test cases
4. **Week 3**: Write and submit your first vulnerability report
5. **Month 2+**: Deep dive into specific subsystems, collect bounties

## 🔥 Example Fuzzing Campaigns

### Campaign 1: Image Parser Sweep
```bash
# macOS - CoreGraphics
./apple-fuzz-targets/build/cg_image_fuzzer corpus/ -dict=dictionaries/png.dict -jobs=8 -max_total_time=86400

# Windows - GDI+ & WIC
.\windows-fuzz-targets\build\gdiplus_image_fuzzer.exe corpus\ -jobs=8 -max_total_time=86400

# Linux - libpng & WebP
./cross-platform-targets/build/libpng_fuzzer corpus/ -jobs=8 -max_total_time=86400
./cross-platform-targets/build/webp_fuzzer corpus/ -jobs=8 -max_total_time=86400
```

### Campaign 2: Font Rendering Blitz
```bash
# macOS - CoreText
./apple-fuzz-targets/build/coretext_font_fuzzer corpus/ -dict=dictionaries/otf.dict -jobs=8

# Windows - DirectWrite
.\windows-fuzz-targets\build\directwrite_font_fuzzer.exe corpus\ -jobs=8

# Linux - FreeType
./cross-platform-targets/build/freetype_fuzzer corpus/ -jobs=8
```

## 🛠️ What's Included

### Setup Scripts
- **macos-setup.sh** - Automated macOS environment setup
- **windows-setup.ps1** - Automated Windows environment setup (PowerShell)

### Ready-to-Use Fuzzers
- **15+ fuzz targets** across three platforms
- All with proper sanitizers (AddressSanitizer, UBSan)
- Optimized for finding real vulnerabilities

### Build Automation
- Platform-specific build scripts
- Dependency detection
- Automatic library linking

### Corpus and Dictionaries
- 60+ format-specific dictionaries
- Seed corpus recommendations
- Integration with OSS-Fuzz corpora

## 🎯 Success Metrics

Researchers using this framework have found:
- **Memory corruption bugs** in image parsers
- **Font rendering vulnerabilities** across platforms
- **Archive handling flaws** with security impact
- **XML parsing issues** leading to RCE

## 📚 Educational Content

Beyond fuzzing tools, this repository includes:

### Tutorials
- **[libFuzzerTutorial.md](tutorial/libFuzzerTutorial.md)** - Comprehensive libFuzzer guide
- **[good-fuzz-target.md](docs/good-fuzz-target.md)** - Writing effective fuzzers
- **[structure-aware-fuzzing.md](docs/structure-aware-fuzzing.md)** - Advanced techniques

### Security Research Guides
- Target prioritization matrices
- Attack surface analysis
- Exploitation scenarios
- Reporting templates

## ⚖️ Legal and Ethical Use

**✅ This framework is designed for:**
- Responsible security research
- Finding and reporting vulnerabilities
- Educational purposes
- Defensive security testing

**❌ Do NOT use for:**
- Unauthorized system access
- Malicious exploitation
- Testing systems you don't own
- Circumventing security measures

## 🔗 Related Projects

- [OSS-Fuzz](https://github.com/google/oss-fuzz) - Google's continuous fuzzing service
- [ClusterFuzz](https://github.com/google/clusterfuzz) - Scalable fuzzing infrastructure
- [Fuzzer Test Suite](https://github.com/google/fuzzer-test-suite) - Common fuzzing benchmarks

## 📞 Responsible Disclosure

Found a vulnerability? Report it responsibly:

- **Apple**: product-security@apple.com
- **Microsoft**: https://msrc.microsoft.com/report
- **Google**: https://bughunters.google.com/

See [VENDOR_REPORTING.md](VENDOR_REPORTING.md) for detailed reporting guidelines.

## 🤝 Contributing

This project welcomes contributions! Please see [CONTRIBUTING](CONTRIBUTING) for guidelines.

Areas where we'd love help:
- Additional fuzz targets
- Platform-specific optimizations
- Documentation improvements
- Bug reports and fixes

## 📄 License

See [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This is an educational and research tool. Users are responsible for ensuring their use complies with applicable laws and regulations. The authors are not responsible for misuse of this software.

---

**Ready to start finding vulnerabilities?** Pick your platform and follow the [MULTI_PLATFORM_GUIDE.md](MULTI_PLATFORM_GUIDE.md)!

🐛 Happy (ethical) fuzzing! 🔒

