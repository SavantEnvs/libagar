#!/usr/bin/env bash
#
# mayhem/build.sh — BACKPORT build for repro-46e5cd6 (libagar-repro-buggy-mhh-run-39).
#
# Target (historical mayhemheroes name preserved, suffixed -buggy-mhh-run-39):
#   agar-disasm-buggy-mhh-run-39 — the tools/agar-disasm CLI (raw file input; hand-walks a
#     serialized AG_Object dataset with its own ad-hoc, unaligned-read scanner). This is the
#     EXACT harness the mayhemheroes run at commit 33b69e8 fuzzed — the current live `mayhem`
#     branch later replaced it with an in-process libFuzzer harness over the public
#     AG_ObjectUnserialize() decoders (a DIFFERENT input shape/code path), so that harness would
#     not reproduce this run's bugs; the original raw-CLI driver is reconstructed here instead
#     (BACKPORT.md "input-interface caveat").
#
# Two independent builds:
#   (A) NORMAL-flags core -> the behavioral oracle /mayhem/agar_selftest (test.sh runs it).
#   (B) SANITIZED core    -> the agar-disasm-buggy-mhh-run-39 target + standalone reproducer.
#
# libAgar uses BSDBuild (./configure + BSD-style make). configure honors CC/CFLAGS.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

# agar-disasm walks a byte buffer reading multi-byte integers via `*(Uint32*)p`, which is
# unaligned by construction — a benign, pervasive UBSan `alignment` trip that would abort on
# essentially every input and starve the fuzzer. Relax ONLY alignment; ASan + the rest of UBSan
# stay ON and HALTING (so the real out-of-bounds reads / UB are still caught).
DISASM_SAN="$SANITIZER_FLAGS -fno-sanitize=alignment"

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
# (B) SANITIZED build -> agar-disasm-buggy-mhh-run-39 (raw file-input CLI)
# ---------------------------------------------------------------------------
make cleandir >/dev/null 2>&1 || true
CC="$CC" CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" ./configure $CONFIGURE_COMMON --prefix=/tmp/agar-san
make depend >/dev/null 2>&1 || true
make -j"$MAYHEM_JOBS"
mkdir -p /tmp/agar-san/share/agar /tmp/agar-san/share/aclocal
make install

# agar-disasm CLI (file-input target). It IS its own standalone reproducer, matching the
# original mayhemheroes Mayhemfile's `cmd: /mayhem/agar-disasm @@`.
"$CC" $DISASM_SAN $DEBUG_FLAGS "$SRC/tools/agar-disasm/agar-disasm.c" \
    -I/tmp/agar-san/include/agar $INCFLAGS \
    /tmp/agar-san/lib/libag_core.a -lpthread -lm \
    -o /mayhem/agar-disasm-buggy-mhh-run-39

echo "build.sh: done"
ls -l /mayhem/agar-disasm-buggy-mhh-run-39 /mayhem/agar_selftest
