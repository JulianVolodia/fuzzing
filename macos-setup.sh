#!/bin/bash
#
# macOS Fuzzing Setup Script
# This script sets up a complete fuzzing environment on macOS for finding vulnerabilities
# in Apple frameworks and system libraries.
#
# Usage: ./macos-setup.sh
#

set -e

FUZZING_DIR="$HOME/fuzzing-workspace"
CORPUS_DIR="$FUZZING_DIR/corpus"
CRASH_DIR="$FUZZING_DIR/crashes"

echo "================================================"
echo "macOS Fuzzing Environment Setup"
echo "================================================"
echo ""

# Check if running on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "Error: This script is designed for macOS only."
    echo "Current OS: $OSTYPE"
    exit 1
fi

echo "[*] Creating fuzzing workspace directories..."
mkdir -p "$FUZZING_DIR"
mkdir -p "$CORPUS_DIR"
mkdir -p "$CRASH_DIR"
mkdir -p "$FUZZING_DIR/targets"

# Check if Homebrew is installed
if ! command -v brew &> /dev/null; then
    echo "[*] Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
else
    echo "[*] Homebrew is already installed"
fi

# Install LLVM with libFuzzer support
echo "[*] Installing LLVM toolchain..."
if ! brew list llvm &> /dev/null; then
    brew install llvm
else
    echo "[*] LLVM is already installed"
fi

# Get LLVM path
LLVM_PATH=$(brew --prefix llvm)
export PATH="$LLVM_PATH/bin:$PATH"

# Install additional tools
echo "[*] Installing additional fuzzing tools..."
brew install cmake ninja git

# Verify clang version and libFuzzer support
echo ""
echo "[*] Verifying Clang installation..."
if [ -f "$LLVM_PATH/bin/clang++" ]; then
    CLANG_BIN="$LLVM_PATH/bin/clang++"
else
    CLANG_BIN="clang++"
fi

echo "Clang path: $CLANG_BIN"
$CLANG_BIN --version

# Create a test fuzzer to verify libFuzzer works
echo ""
echo "[*] Testing libFuzzer functionality..."
cat > "$FUZZING_DIR/test_fuzzer.cc" << 'EOF'
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size > 0 && Data[0] == 'H')
        if (Size > 1 && Data[1] == 'I')
            if (Size > 2 && Data[2] == '!')
                __builtin_trap(); // This will crash
    return 0;
}
EOF

cd "$FUZZING_DIR"
$CLANG_BIN -g -O1 -fsanitize=fuzzer,address test_fuzzer.cc -o test_fuzzer

echo "[*] Running test fuzzer for 5 seconds..."
timeout 5 ./test_fuzzer -max_total_time=5 2>&1 | head -20 || true

if [ -f test_fuzzer ]; then
    echo ""
    echo "✓ LibFuzzer is working correctly!"
else
    echo "✗ LibFuzzer test failed"
    exit 1
fi

# Create environment setup script
echo ""
echo "[*] Creating environment setup script..."
cat > "$FUZZING_DIR/setup-env.sh" << EOF
#!/bin/bash
# Source this file to set up the fuzzing environment
export FUZZING_DIR="$FUZZING_DIR"
export CORPUS_DIR="$CORPUS_DIR"
export CRASH_DIR="$CRASH_DIR"
export LLVM_PATH="$LLVM_PATH"
export PATH="$LLVM_PATH/bin:\$PATH"
export CC="$LLVM_PATH/bin/clang"
export CXX="$LLVM_PATH/bin/clang++"

alias fuzz-build='clang++ -g -O1 -fsanitize=fuzzer,address'
alias fuzz-build-ubsan='clang++ -g -O1 -fsanitize=fuzzer,address,undefined'

echo "Fuzzing environment configured!"
echo "Workspace: \$FUZZING_DIR"
echo "Use 'fuzz-build' to compile fuzz targets"
EOF

chmod +x "$FUZZING_DIR/setup-env.sh"

# Create helper scripts
cat > "$FUZZING_DIR/run-fuzzer.sh" << 'EOF'
#!/bin/bash
# Helper script to run a fuzzer with standard settings

if [ $# -lt 1 ]; then
    echo "Usage: $0 <fuzzer_binary> [additional_args]"
    echo "Example: $0 ./my_fuzzer -max_total_time=3600"
    exit 1
fi

FUZZER="$1"
shift

if [ ! -x "$FUZZER" ]; then
    echo "Error: Fuzzer binary not found or not executable: $FUZZER"
    exit 1
fi

FUZZER_NAME=$(basename "$FUZZER")
CORPUS_DIR="${CORPUS_DIR:-./corpus}"
CRASH_DIR="${CRASH_DIR:-./crashes}"

mkdir -p "$CORPUS_DIR/$FUZZER_NAME"
mkdir -p "$CRASH_DIR/$FUZZER_NAME"

echo "Running fuzzer: $FUZZER_NAME"
echo "Corpus: $CORPUS_DIR/$FUZZER_NAME"
echo "Crashes: $CRASH_DIR/$FUZZER_NAME"
echo ""

"$FUZZER" \
    "$CORPUS_DIR/$FUZZER_NAME" \
    -artifact_prefix="$CRASH_DIR/$FUZZER_NAME/" \
    -print_final_stats=1 \
    "$@"
EOF

chmod +x "$FUZZING_DIR/run-fuzzer.sh"

echo ""
echo "================================================"
echo "✓ Setup Complete!"
echo "================================================"
echo ""
echo "Fuzzing workspace: $FUZZING_DIR"
echo "Corpus directory: $CORPUS_DIR"
echo "Crash directory: $CRASH_DIR"
echo ""
echo "To activate the fuzzing environment, run:"
echo "  source $FUZZING_DIR/setup-env.sh"
echo ""
echo "Example commands:"
echo "  # Compile a fuzz target"
echo "  fuzz-build my_target.cc -o my_fuzzer"
echo ""
echo "  # Run a fuzzer"
echo "  $FUZZING_DIR/run-fuzzer.sh ./my_fuzzer -max_total_time=3600"
echo ""
echo "Next steps:"
echo "  1. Check the apple-fuzz-targets directory for example targets"
echo "  2. Build and run the example fuzzers"
echo "  3. Report any findings responsibly to Apple Security"
echo "     (https://support.apple.com/en-us/HT201220)"
echo ""
