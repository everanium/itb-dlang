#!/usr/bin/env bash
#
# run_tests.sh — Compile and run every D test program under tests/.
#
# Mirrors the Ada / Rust per-test-binary discipline: each tests/test_*.d
# is compiled to its own standalone executable in tests/build/, then run
# in turn. Per-process isolation gives every test a fresh libitb global
# state without needing an in-process serial lock.
#
# Compiler:
#   - DMD 2.112+ (default).
#   - Override via the COMPILER environment variable: COMPILER=ldc2 ./run_tests.sh
#     or COMPILER=gdc ./run_tests.sh (GDC requires --no-build-tag adjustments;
#     start with DMD/LDC2 first).
#
# Library lookup:
#   - libitb.so is expected at <repo>/dist/linux-amd64/libitb.so. The script
#     resolves the repo root from its own location and exports
#     LD_LIBRARY_PATH so the compiled tests find libitb at run time.
#   - The same dist directory is wired into the embedded RPATH so installed
#     binaries also find libitb without LD_LIBRARY_PATH.
#
# Usage:
#   ./run_tests.sh           # compile + run every test, default DMD
#   COMPILER=ldc2 ./run_tests.sh
#   ./run_tests.sh test_blake3 test_easy_blake3   # only the named tests

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

if [[ ! -f "$DIST_DIR/libitb.so" ]]; then
    echo "error: libitb.so not found at $DIST_DIR" >&2
    echo "       Build it via: cd $REPO_ROOT && ./bindings/dlang/build.sh" >&2
    exit 1
fi

COMPILER="${COMPILER:-dmd}"
BUILD_DIR="$SCRIPT_DIR/tests/build"
mkdir -p "$BUILD_DIR"

# Collect test source files. If positional arguments are provided, use
# them as a filter; otherwise compile every tests/test_*.d.
declare -a TEST_SOURCES=()
if [[ $# -gt 0 ]]; then
    for arg in "$@"; do
        # Allow either "test_blake3" or "tests/test_blake3.d" form.
        local_path="${arg#tests/}"
        local_path="${local_path%.d}"
        TEST_SOURCES+=("tests/${local_path}.d")
    done
else
    while IFS= read -r -d '' f; do
        TEST_SOURCES+=("$f")
    done < <(find tests -maxdepth 1 -name 'test_*.d' -print0 | sort -z)
fi

if [[ ${#TEST_SOURCES[@]} -eq 0 ]]; then
    echo "no tests found under tests/test_*.d" >&2
    exit 0
fi

# Compiler-specific flag forms. DMD/LDC2 use -L<flag> to forward to the
# linker driver via -Xlinker; GDC uses gcc-style -Wl,...
declare -a LINK_FLAGS
case "$COMPILER" in
    dmd|ldc2)
        LINK_FLAGS=(
            -L-L"$DIST_DIR"
            -L-litb
            "-L-rpath=\$ORIGIN/../../../dist/linux-amd64"
        )
        IMPORT_FLAG="-I=src"
        OUTPUT_FLAG="-of="
        ;;
    gdc)
        LINK_FLAGS=(
            -L"$DIST_DIR"
            -litb
            "-Wl,-rpath,\$ORIGIN/../../../dist/linux-amd64"
        )
        IMPORT_FLAG="-Isrc"
        OUTPUT_FLAG="-o"
        ;;
    *)
        echo "error: unknown COMPILER=$COMPILER (expected dmd / ldc2 / gdc)" >&2
        exit 1
        ;;
esac

PASS=0
FAIL=0
FAILED=()

for src in "${TEST_SOURCES[@]}"; do
    name="$(basename "$src" .d)"
    bin="$BUILD_DIR/$name"

    printf "[compile] %-40s" "$name"
    if "$COMPILER" "${OUTPUT_FLAG}${bin}" $IMPORT_FLAG src/itb/*.d "$src" "${LINK_FLAGS[@]}" >"$BUILD_DIR/$name.compile.log" 2>&1; then
        printf " ok\n"
    else
        printf " FAIL\n"
        echo "  see $BUILD_DIR/$name.compile.log" >&2
        FAIL=$((FAIL + 1))
        FAILED+=("$name (compile)")
        continue
    fi

    printf "[run]     %-40s" "$name"
    if LD_LIBRARY_PATH="$DIST_DIR" "$bin" >"$BUILD_DIR/$name.run.log" 2>&1; then
        printf " PASS\n"
        PASS=$((PASS + 1))
    else
        printf " FAIL\n"
        echo "  --- $BUILD_DIR/$name.run.log ---" >&2
        cat "$BUILD_DIR/$name.run.log" >&2
        FAIL=$((FAIL + 1))
        FAILED+=("$name (run)")
    fi
done

echo
echo "========================================"
echo "  D binding test summary"
echo "----------------------------------------"
echo "  compiler   : $COMPILER"
echo "  passed     : $PASS"
echo "  failed     : $FAIL"
if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo "  failed list:"
    for t in "${FAILED[@]}"; do
        echo "    - $t"
    done
fi
echo "========================================"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
