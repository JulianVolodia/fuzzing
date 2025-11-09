#!/bin/bash
#
# Build script for all Apple framework fuzzers
#
# Usage: ./build-all.sh
#

set -e

# Determine LLVM path
if command -v brew &> /dev/null; then
    LLVM_PATH=$(brew --prefix llvm 2>/dev/null || echo "")
    if [ -n "$LLVM_PATH" ]; then
        export PATH="$LLVM_PATH/bin:$PATH"
        CXX="$LLVM_PATH/bin/clang++"
    else
        CXX="clang++"
    fi
else
    CXX="clang++"
fi

echo "Using compiler: $CXX"
$CXX --version

# Common build flags
FUZZ_FLAGS="-g -O1 -fsanitize=fuzzer,address"

# Optionally add undefined behavior sanitizer
# Uncomment the next line for more thorough checking (slower)
# FUZZ_FLAGS="$FUZZ_FLAGS -fsanitize=undefined"

BUILD_DIR="build"
mkdir -p "$BUILD_DIR"

echo ""
echo "Building Apple Framework Fuzzers..."
echo "===================================="

# CoreFoundation String Fuzzer
echo "[1/6] Building CoreFoundation String Fuzzer..."
$CXX $FUZZ_FLAGS \
    cf_string_fuzzer.cc \
    -framework CoreFoundation \
    -o "$BUILD_DIR/cf_string_fuzzer"
echo "✓ Built: $BUILD_DIR/cf_string_fuzzer"

# CoreGraphics Image Fuzzer
echo "[2/6] Building CoreGraphics Image Fuzzer..."
$CXX $FUZZ_FLAGS \
    cg_image_fuzzer.cc \
    -framework CoreGraphics -framework ImageIO -framework CoreFoundation \
    -o "$BUILD_DIR/cg_image_fuzzer"
echo "✓ Built: $BUILD_DIR/cg_image_fuzzer"

# Property List Fuzzer
echo "[3/6] Building Property List Fuzzer..."
$CXX $FUZZ_FLAGS \
    plist_fuzzer.cc \
    -framework CoreFoundation \
    -o "$BUILD_DIR/plist_fuzzer"
echo "✓ Built: $BUILD_DIR/plist_fuzzer"

# CoreText Font Fuzzer
echo "[4/6] Building CoreText Font Fuzzer..."
$CXX $FUZZ_FLAGS \
    coretext_font_fuzzer.cc \
    -framework CoreText -framework CoreFoundation -framework CoreGraphics \
    -o "$BUILD_DIR/coretext_font_fuzzer"
echo "✓ Built: $BUILD_DIR/coretext_font_fuzzer"

# Archive Fuzzer (check if libarchive is available)
echo "[5/6] Building Archive Fuzzer..."
if pkg-config --exists libarchive 2>/dev/null || [ -f /usr/local/lib/libarchive.dylib ] || [ -f /opt/homebrew/lib/libarchive.dylib ]; then
    $CXX $FUZZ_FLAGS \
        archive_fuzzer.cc \
        -larchive \
        -o "$BUILD_DIR/archive_fuzzer"
    echo "✓ Built: $BUILD_DIR/archive_fuzzer"
else
    echo "⚠ Skipping archive_fuzzer (libarchive not found)"
    echo "  Install with: brew install libarchive"
fi

# XML Fuzzer
echo "[6/6] Building XML Fuzzer..."
if pkg-config --exists libxml-2.0 2>/dev/null || [ -f /usr/include/libxml2/libxml/parser.h ]; then
    XML_CFLAGS=$(pkg-config --cflags libxml-2.0 2>/dev/null || echo "-I/usr/include/libxml2")
    XML_LIBS=$(pkg-config --libs libxml-2.0 2>/dev/null || echo "-lxml2")

    $CXX $FUZZ_FLAGS \
        $XML_CFLAGS \
        xml_fuzzer.cc \
        $XML_LIBS \
        -o "$BUILD_DIR/xml_fuzzer"
    echo "✓ Built: $BUILD_DIR/xml_fuzzer"
else
    echo "⚠ Skipping xml_fuzzer (libxml2 not found)"
    echo "  libxml2 should be pre-installed on macOS"
fi

echo ""
echo "===================================="
echo "Build complete!"
echo ""
echo "Fuzzers built in: $BUILD_DIR/"
ls -lh "$BUILD_DIR/"
echo ""
echo "To run a fuzzer:"
echo "  cd $BUILD_DIR"
echo "  ./cf_string_fuzzer -max_total_time=60"
echo ""
echo "For more options, see README.md"
