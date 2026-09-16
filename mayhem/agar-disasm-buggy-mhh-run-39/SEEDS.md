# Seed corpus — `agar-disasm-buggy-mhh-run-39`

Two provenances, both from the historical `mayhemheroes/libagar` `agar-disasm` harness that this
branch reconstructs (BACKPORT.md step 4 + the "seed fidelity" caveat):

1. **78 files** — the corpus `mayhem download mayhemheroes/libagar/agar-disasm/39` returns for the
   anchor run. That is the run's *coverage* corpus, not its labelled crashers.

2. **34 files** — regression crashers recovered locally by mutating (1) with the **same** harness
   binary this branch builds (`/mayhem/agar-disasm-buggy-mhh-run-39`), keeping one or two smallest
   inputs per distinct sanitizer signature. The mutation loop is an ordinary bit-flip / splice /
   truncate / type-code-dictionary fuzzer; the AG_SOURCE_* dictionary is `core/data_source.h`.

Why (2) exists: the anchor run inherited **1838** testcases from the target's server-side
accumulated `testsuite.tar` — 38 earlier runs' worth of saved crashers — and re-reported 11 defects
from them in 1116 executions (0.43 tests/s). Only the 78-file coverage corpus is downloadable, so a
run seeded with (1) alone re-finds a fraction of those defects (savantenvs run 1: 4 of 11). Set (2)
rebuilds the equivalent of that accumulated regression corpus for the same target.

Every crasher in (2) faults inside upstream's own tool code — `main` in
`tools/agar-disasm/agar-disasm.c`, over the dataset buffer malloc'd at line 124 — never in harness
code (this target *is* upstream's CLI; there is no driver file). The signatures cover the anchor
run's crash sites exactly: 134, 160, 168, 172, 176, 180, 186 and 200 (8 × CWE-125), the
allocation-size-too-big at 124 (CWE-789), the `AG_FatalError` aborts (CWE-20) and the dataset-buffer
leak (CWE-401), plus four further `FORWARD()` under-reads of the same class (164, 190, 196, 205)
that the original run did not separate out.
