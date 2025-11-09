# Apple Framework Fuzz Targets

This directory contains example fuzz targets for finding vulnerabilities in Apple frameworks and system libraries.

## Important Notice

**Responsible Disclosure**: If you find any security vulnerabilities using these fuzz targets, please report them responsibly to Apple through their security bounty program:
- Apple Security Bounty: https://support.apple.com/en-us/HT201220
- Email: product-security@apple.com

## Available Fuzz Targets

### 1. CoreFoundation String Fuzzer (`cf_string_fuzzer.cc`)
Fuzzes Apple's CoreFoundation string handling APIs including:
- CFStringCreateWithBytes
- CFStringGetCString
- CFString encoding conversions

### 2. CoreGraphics Image Fuzzer (`cg_image_fuzzer.cc`)
Fuzzes image parsing in CoreGraphics/ImageIO:
- CGImageSourceCreateWithData
- PNG, JPEG, HEIF, and other image format parsers
- Image metadata handling

### 3. Property List Fuzzer (`plist_fuzzer.cc`)
Fuzzes property list parsing:
- XML property lists
- Binary property lists
- Property list serialization/deserialization

### 4. CoreText Font Fuzzer (`coretext_font_fuzzer.cc`)
Fuzzes font file parsing:
- TrueType fonts
- OpenType fonts
- Font descriptor creation

### 5. SQLite Fuzzer (`sqlite_fuzzer.cc`)
Fuzzes SQLite (bundled with macOS):
- SQL query parsing
- Database operations

### 6. Archive Utility Fuzzer (`archive_fuzzer.cc`)
Fuzzes libarchive (used by macOS):
- ZIP files
- TAR files
- Other archive formats

### 7. XML Parser Fuzzer (`xml_fuzzer.cc`)
Fuzzes libxml2:
- XML parsing
- DTD validation
- XPath queries

## Building Fuzz Targets

First, set up your environment:

```bash
# From the fuzzing repository root
./macos-setup.sh
source ~/fuzzing-workspace/setup-env.sh
```

Build individual targets:

```bash
cd apple-fuzz-targets

# CoreFoundation string fuzzer
clang++ -g -O1 -fsanitize=fuzzer,address \
    cf_string_fuzzer.cc \
    -framework CoreFoundation \
    -o cf_string_fuzzer

# CoreGraphics image fuzzer
clang++ -g -O1 -fsanitize=fuzzer,address \
    cg_image_fuzzer.cc \
    -framework CoreGraphics -framework ImageIO -framework CoreFoundation \
    -o cg_image_fuzzer

# Property list fuzzer
clang++ -g -O1 -fsanitize=fuzzer,address \
    plist_fuzzer.cc \
    -framework CoreFoundation \
    -o plist_fuzzer

# CoreText font fuzzer
clang++ -g -O1 -fsanitize=fuzzer,address \
    coretext_font_fuzzer.cc \
    -framework CoreText -framework CoreFoundation -framework CoreGraphics \
    -o coretext_font_fuzzer

# Archive fuzzer
clang++ -g -O1 -fsanitize=fuzzer,address \
    archive_fuzzer.cc \
    -larchive \
    -o archive_fuzzer

# XML fuzzer
clang++ -g -O1 -fsanitize=fuzzer,address \
    xml_fuzzer.cc \
    -I/usr/include/libxml2 -lxml2 \
    -o xml_fuzzer
```

Or use the provided build script:

```bash
./build-all.sh
```

## Running Fuzz Targets

Basic usage:

```bash
# Run for 1 hour
./cf_string_fuzzer -max_total_time=3600

# Run with multiple workers
./cg_image_fuzzer -jobs=8 -workers=8

# Run with a seed corpus
./plist_fuzzer corpus/ -max_total_time=3600
```

Using the helper script:

```bash
~/fuzzing-workspace/run-fuzzer.sh ./cf_string_fuzzer -max_total_time=3600
```

## Finding Seed Corpora

Good seed corpora significantly improve fuzzing efficiency:

1. **System files**: macOS has many examples in `/System/Library/`, `/Library/`, etc.
   ```bash
   # For image fuzzer
   find /System/Library -name "*.png" -o -name "*.jpg" | head -20 | xargs -I {} cp {} corpus/

   # For plist fuzzer
   find /System/Library -name "*.plist" | head -20 | xargs -I {} cp {} corpus/

   # For font fuzzer
   find /System/Library/Fonts -name "*.ttf" -o -name "*.otf" | head -10 | xargs -I {} cp {} corpus/
   ```

2. **Online corpora**:
   - https://github.com/google/fuzzing/tree/master/dictionaries
   - https://github.com/dvyukov/go-fuzz-corpus

## Advanced Techniques

### Using Dictionaries

Many fuzzers benefit from dictionaries:

```bash
# Use a dictionary from this repo
./xml_fuzzer -dict=../dictionaries/xml.dict corpus/
./cg_image_fuzzer -dict=../dictionaries/png.dict corpus/
```

### Continuous Fuzzing

Set up a continuous fuzzing loop:

```bash
#!/bin/bash
while true; do
    ./cf_string_fuzzer corpus/ -max_total_time=3600 -max_len=65536
    # Minimize corpus periodically
    mkdir new_corpus
    ./cf_string_fuzzer new_corpus/ corpus/ -merge=1
    rm -rf corpus
    mv new_corpus corpus
done
```

### Coverage Analysis

Use Clang's source-based code coverage:

```bash
# Build with coverage
clang++ -fprofile-instr-generate -fcoverage-mapping \
    cf_string_fuzzer.cc \
    -framework CoreFoundation \
    StandaloneFuzzTargetMain.c \
    -o cf_string_coverage

# Run on corpus
./cf_string_coverage corpus/*

# Generate coverage report
llvm-profdata merge -sparse *.profraw -o default.profdata
llvm-cov show cf_string_coverage -instr-profile=default.profdata
```

## Tips for Finding Vulnerabilities

1. **Target complex parsers**: Image, font, archive, and document parsers often have bugs
2. **Use multiple sanitizers**: Try `-fsanitize=address,undefined,integer` combinations
3. **Vary input sizes**: Use `-max_len` to test different input sizes
4. **Run for extended periods**: Many bugs require millions of iterations to find
5. **Test edge cases**: Zero-length inputs, very large inputs, malformed data
6. **Combine with other tools**: Use with Instruments, dtrace, or fs_usage for deeper analysis

## Common Issues

### Crashes in System Libraries

If you find a crash in a system library:
1. Verify it's reproducible
2. Minimize the test case with `-minimize_crash=1`
3. Check if it's already known/fixed in newer macOS versions
4. Report to Apple if it's a new vulnerability

### False Positives

Some crashes may be false positives:
- Check if the crash is in fuzzer infrastructure
- Verify with different sanitizer combinations
- Test on a clean macOS installation

## Resources

- [libFuzzer Documentation](http://llvm.org/docs/LibFuzzer.html)
- [Apple Security Research](https://security.apple.com/)
- [Fuzzing Book](https://www.fuzzingbook.org/)
- [OSS-Fuzz](https://github.com/google/oss-fuzz)
