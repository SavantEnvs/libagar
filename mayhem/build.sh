#!/usr/bin/env bash
#
# mayhem/build.sh — build libAgar's fuzz harnesses + the behavioral oracle.
#
# Targets (historical Mayhem target names preserved):
#   agar-disasm     — libFuzzer harness over AG_ObjectUnserialize() (core/object.c):
#                     parses an untrusted serialized AG_Object archive. Converted from
#                     the old raw tools/agar-disasm CLI, which over-reads its own buffer
#                     under ASan on nearly every input (0 edges = unfuzzable as a raw
#                     target); the in-process harness drives the same parse path.
#   ag-length-utf8  — libFuzzer harness over AG_LengthUTF8() (core/string.c).
#
# Two independent builds:
#   (A) NORMAL-flags core -> the behavioral oracle /mayhem/agar_selftest (test.sh runs it).
#   (B) SANITIZED core    -> the fuzz targets + standalone reproducer.
#
# libAgar uses BSDBuild (./configure + BSD-style make). configure honors CC/CFLAGS.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

INCFLAGS="-U_XOPEN_SOURCE -D_XOPEN_SOURCE=600"

CONFIGURE_COMMON="--disable-gui --disable-math --disable-au --disable-map \
--disable-net --disable-sk --disable-sg --disable-vg --disable-micro \
--without-manpages --without-manlinks --without-docs --without-bundles"

# ---------------------------------------------------------------------------
# (A) NORMAL build -> behavioral oracle
# ---------------------------------------------------------------------------
make cleandir >/dev/null 2>&1 || true
CC="$CC" CFLAGS="-O2 $DEBUG_FLAGS" ./configure $CONFIGURE_COMMON --prefix=/tmp/agar-normal
make depend >/dev/null 2>&1 || true
make -j"$MAYHEM_JOBS"
mkdir -p /tmp/agar-normal/share/agar /tmp/agar-normal/share/aclocal
make install

"$CC" -O2 $DEBUG_FLAGS "$SRC/mayhem/agar_selftest.c" \
    -I/tmp/agar-normal/include/agar $INCFLAGS \
    /tmp/agar-normal/lib/libag_core.a -lpthread -lm \
    -o /mayhem/agar_selftest

# ---------------------------------------------------------------------------
# (B) SANITIZED build -> fuzz targets
# ---------------------------------------------------------------------------
# Instrument the core with SanitizerCoverage (fuzzer-no-link) so the in-process
# libFuzzer harnesses see edges INSIDE the library, not just in the harness TU.
make cleandir >/dev/null 2>&1 || true
CC="$CC" CFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS" ./configure $CONFIGURE_COMMON --prefix=/tmp/agar-san
make depend >/dev/null 2>&1 || true
make -j"$MAYHEM_JOBS"
mkdir -p /tmp/agar-san/share/agar /tmp/agar-san/share/aclocal
make install

# agar-disasm libFuzzer harness (AG_ObjectUnserialize over an in-memory archive).
"$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    "$SRC/mayhem/fuzz_agar_disasm.cpp" \
    -I/tmp/agar-san/include/agar $INCFLAGS \
    /tmp/agar-san/lib/libag_core.a -lpthread -lm \
    -o /mayhem/agar-disasm

# agar-disasm standalone reproducer.
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main_disasm.o
"$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS \
    "$SRC/mayhem/fuzz_agar_disasm.cpp" /tmp/standalone_main_disasm.o \
    -I/tmp/agar-san/include/agar $INCFLAGS \
    /tmp/agar-san/lib/libag_core.a -lpthread -lm \
    -o /mayhem/agar-disasm-standalone

# ag-length-utf8 libFuzzer harness.
"$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    "$SRC/mayhem/fuzz_ag_length_utf8.cpp" \
    -I/tmp/agar-san/include/agar $INCFLAGS \
    /tmp/agar-san/lib/libag_core.a -lpthread -lm \
    -o /mayhem/fuzz_ag_length_utf8

# ag-length-utf8 standalone reproducer (run-once, natural crash — no libFuzzer runtime).
# Compile the C driver as a C object first so its LLVMFuzzerTestOneInput ref keeps C linkage.
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
"$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS \
    "$SRC/mayhem/fuzz_ag_length_utf8.cpp" /tmp/standalone_main.o \
    -I/tmp/agar-san/include/agar $INCFLAGS \
    /tmp/agar-san/lib/libag_core.a -lpthread -lm \
    -o /mayhem/fuzz_ag_length_utf8-standalone

echo "build.sh: done"
ls -l /mayhem/agar-disasm /mayhem/agar-disasm-standalone \
      /mayhem/fuzz_ag_length_utf8 \
      /mayhem/fuzz_ag_length_utf8-standalone /mayhem/agar_selftest
