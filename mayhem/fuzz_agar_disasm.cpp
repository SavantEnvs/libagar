// In-process libFuzzer harness for the Agar object-archive parser.
//
// The historical `agar-disasm` target was a raw file-input CLI (tools/agar-disasm)
// which reads an Agar object header with the library and then "disassembles" the
// serialized dataset. To do so the tool slurps the dataset into a heap buffer and
// hand-walks it with its OWN ad-hoc scanner (unaligned `*(Uint32*)p` reads guarded
// by an after-the-fact FORWARD() bounds check). That scanner over-reads its own
// buffer on almost every input, so as a raw target it crashes under ASan before
// Mayhem can record any coverage (0 edges = unfuzzable) — and the bug is in the
// throwaway debug tool, not in libAgar.
//
// Per the port-repo harness policy we convert it, KEEPING the historical target
// name `agar-disasm`, into an in-process libFuzzer harness that drives the SAME
// functionality against libAgar's PUBLIC deserialization API over an in-memory
// data source (AG_OpenConstCore), i.e. the real load path an application hits when
// it opens an untrusted Agar archive:
//
//   * AG_ObjectReadHeader() — the exact first library call the tool makes: decodes
//     the signature/version, the class-hierarchy + module strings, the dataset
//     offset and flags (AG_ReadVersion + AG_CopyString + integer decoders).
//   * then a bounded walk of the dataset that disassembles it into typed records
//     using the public typed decoders (AG_ReadUint8/16/32/64, AG_ReadSint*,
//     AG_ReadFloat/Double, AG_ReadString) — the same decoders AG_Object load
//     methods use, exercised memory-safely (the data source bounds-checks every
//     read and raises on EOF; strings are freed).
//
// Agar treats a malformed data source as a *fatal* condition: the default data
// source error handler (ErrorDefault) calls AG_FatalError()->abort(). That is a
// deliberate design choice, not a memory-safety defect, and left in place it would
// make almost every malformed input "crash", starving the fuzzer. A real app that
// loads untrusted archives installs its own handler; we do the same, unwinding
// with longjmp back here so a rejected/truncated archive is a clean return and
// only genuine ASan/UBSan faults are reported. Every routine driven below writes
// only into stack storage or frees what it allocates before raising, so unwinding
// out of any of them leaks nothing.

#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>

extern "C" {
#include <agar/core.h>
}

static jmp_buf g_unwind;

/* AG_DataSource exception handler: unwind instead of AG_FatalError()->abort(). */
static void
FuzzDataSourceError(AG_Event *event)
{
    (void)event;
    longjmp(g_unwind, 1);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int inited = 0;
    if (!inited) {
        if (AG_InitCore("agar-disasm-fuzz", 0) == -1)
            return 0;
        inited = 1;
    }

    AG_DataSource *ds = AG_OpenConstCore(data, size);
    if (ds == NULL)
        return 0;
    AG_DataSourceSetErrorFn(ds, FuzzDataSourceError, NULL);

    if (setjmp(g_unwind) == 0) {
        AG_ObjectHeader oh;

        /* Public archive-header decoder — the tool's first library call. */
        if (AG_ObjectReadHeader(ds, &oh) == 0) {
            /*
             * Disassemble the dataset with the public typed decoders. A leading
             * selector byte picks a decoder, mirroring how the archive interleaves
             * typed records; any short read raises through the data source and
             * unwinds us out of the loop cleanly.
             */
            for (int i = 0; i < 4096; i++) {
                uint8_t sel = (uint8_t)AG_ReadUint8(ds);

                switch (sel & 0x0f) {
                case 0:  (void)AG_ReadUint8(ds);   break;
                case 1:  (void)AG_ReadSint8(ds);   break;
                case 2:  (void)AG_ReadUint16(ds);  break;
                case 3:  (void)AG_ReadSint16(ds);  break;
                case 4:  (void)AG_ReadUint32(ds);  break;
                case 5:  (void)AG_ReadSint32(ds);  break;
                case 6:  (void)AG_ReadUint64(ds);  break;
                case 7:  (void)AG_ReadSint64(ds);  break;
                case 8:  (void)AG_ReadFloat(ds);   break;
                case 9:  (void)AG_ReadDouble(ds);  break;
                default: {
                    char *s = AG_ReadString(ds);
                    AG_Free(s);
                    break;
                }
                }
            }
        }
    }

    AG_CloseDataSource(ds);
    return 0;
}
