#!/bin/bash
#
# Build script for cross-platform fuzzers on macOS
#
# Usage: ./build-macos.sh
#

set -e

echo "================================================"
echo "Building Cross-Platform Fuzzers (macOS)"
echo "================================================"
echo ""

# Detect LLVM path
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

echo "Using compiler: $(which $CXX)"
$CXX --version

# Common flags
FUZZ_FLAGS="-g -O1 -fsanitize=fuzzer,address"

BUILD_DIR="build"
mkdir -p "$BUILD_DIR"

# libpng fuzzer
echo ""
echo "[1/3] Building libpng fuzzer..."
if pkg-config --exists libpng; then
    PNG_FLAGS=$(pkg-config --cflags --libs libpng)
    $CXX $FUZZ_FLAGS libpng_fuzzer.cc $PNG_FLAGS -o "$BUILD_DIR/libpng_fuzzer"
    echo "✓ Built: $BUILD_DIR/libpng_fuzzer"
else
    echo "⚠ Skipping libpng fuzzer (libpng not found)"
    echo "  Install with: brew install libpng"
fi

# FreeType fuzzer
echo "[2/3] Building FreeType fuzzer..."
if pkg-config --exists freetype2; then
    FT_FLAGS=$(pkg-config --cflags --libs freetype2)
    $CXX $FUZZ_FLAGS freetype_fuzzer.cc $FT_FLAGS -o "$BUILD_DIR/freetype_fuzzer"
    echo "✓ Built: $BUILD_DIR/freetype_fuzzer"
else
    echo "⚠ Skipping FreeType fuzzer (freetype2 not found)"
    echo "  Install with: brew install freetype"
fi

# WebP fuzzer
echo "[3/3] Building WebP fuzzer..."
if pkg-config --exists libwebp libwebpdemux; then
    WEBP_FLAGS=$(pkg-config --cflags --libs libwebp libwebpdemux)
    $CXX $FUZZ_FLAGS webp_fuzzer.cc $WEBP_FLAGS -o "$BUILD_DIR/webp_fuzzer"
    echo "✓ Built: $BUILD_DIR/webp_fuzzer"
else
    echo "⚠ Skipping WebP fuzzer (libwebp not found)"
    echo "  Install with: brew install webp"
fi

echo ""
echo "================================================"
echo "Build complete!"
echo ""
echo "Fuzzers built in: $BUILD_DIR/"
ls -lh "$BUILD_DIR/" 2>/dev/null || echo "No fuzzers built"
echo ""
echo "To run a fuzzer:"
echo "  ./$BUILD_DIR/libpng_fuzzer -max_total_time=3600"
echo ""
