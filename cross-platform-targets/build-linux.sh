#!/bin/bash
#
# Build script for cross-platform fuzzers on Linux
#
# Usage: ./build-linux.sh
#

set -e

echo "================================================"
echo "Building Cross-Platform Fuzzers (Linux)"
echo "================================================"
echo ""

# Check for clang++
if ! command -v clang++ &> /dev/null; then
    echo "Error: clang++ not found"
    echo "Install with: sudo apt-get install clang"
    exit 1
fi

echo "Using compiler: $(which clang++)"
clang++ --version

# Common flags
FUZZ_FLAGS="-g -O1 -fsanitize=fuzzer,address"

BUILD_DIR="build"
mkdir -p "$BUILD_DIR"

# libpng fuzzer
echo ""
echo "[1/3] Building libpng fuzzer..."
if pkg-config --exists libpng; then
    PNG_FLAGS=$(pkg-config --cflags --libs libpng)
    clang++ $FUZZ_FLAGS libpng_fuzzer.cc $PNG_FLAGS -o "$BUILD_DIR/libpng_fuzzer"
    echo "✓ Built: $BUILD_DIR/libpng_fuzzer"
else
    echo "⚠ Skipping libpng fuzzer (libpng not found)"
    echo "  Install with: sudo apt-get install libpng-dev"
fi

# FreeType fuzzer
echo "[2/3] Building FreeType fuzzer..."
if pkg-config --exists freetype2; then
    FT_FLAGS=$(pkg-config --cflags --libs freetype2)
    clang++ $FUZZ_FLAGS freetype_fuzzer.cc $FT_FLAGS -o "$BUILD_DIR/freetype_fuzzer"
    echo "✓ Built: $BUILD_DIR/freetype_fuzzer"
else
    echo "⚠ Skipping FreeType fuzzer (freetype2 not found)"
    echo "  Install with: sudo apt-get install libfreetype6-dev"
fi

# WebP fuzzer
echo "[3/3] Building WebP fuzzer..."
if pkg-config --exists libwebp libwebpdemux; then
    WEBP_FLAGS=$(pkg-config --cflags --libs libwebp libwebpdemux)
    clang++ $FUZZ_FLAGS webp_fuzzer.cc $WEBP_FLAGS -o "$BUILD_DIR/webp_fuzzer"
    echo "✓ Built: $BUILD_DIR/webp_fuzzer"
else
    echo "⚠ Skipping WebP fuzzer (libwebp not found)"
    echo "  Install with: sudo apt-get install libwebp-dev"
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
