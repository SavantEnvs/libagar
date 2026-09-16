/*
 * agar_selftest.c — AUTHORED behavioral known-answer oracle for the mayhem port.
 *
 * Upstream libAgar ships no headless, self-asserting unit-test suite: its tests/
 * tree is a set of interactive GUI demos (agartest) that require a driver and an
 * event loop, so there is no `make check` / ctest to run. This oracle therefore
 * exercises the SAME core code paths the fuzz targets drive — the UTF-8 string
 * routines (ag-length-utf8 target) and the AG_DataSource / AG_Object
 * (de)serialization the agar-disasm target parses — with known-answer assertions.
 *
 * It is deliberately behavioral: every check compares against an expected value,
 * so neutering the library to a no-op / exit(0) makes it fail.
 *
 * Output: one line per check ("ok N - desc" / "not ok N - desc").
 * Exit status is 0 iff every check passes.
 */

#include <agar/core.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

static int nPass = 0;
static int nFail = 0;

static void
check(int cond, const char *desc)
{
	if (cond) {
		nPass++;
		printf("ok %d - %s\n", nPass + nFail, desc);
	} else {
		nFail++;
		printf("not ok %d - %s\n", nPass + nFail, desc);
	}
}

int
main(void)
{
	AG_DataSource *ds;
	uint32_t u32;
	char *rs;

	if (AG_InitCore("agar-selftest", 0) == -1) {
		fprintf(stderr, "AG_InitCore: %s\n", AG_GetError());
		return (2);
	}

	/* --- UTF-8 length (ag-length-utf8 target's code path) --- */
	check(AG_LengthUTF8("") == 0,            "AG_LengthUTF8 empty string == 0");
	check(AG_LengthUTF8("hello") == 5,       "AG_LengthUTF8 ASCII \"hello\" == 5");
	check(AG_LengthUTF8("abcdefghij") == 10, "AG_LengthUTF8 10 ASCII chars == 10");
	/* "caf\u00e9" = 'c','a','f',0xC3,0xA9 -> 4 Unicode characters */
	check(AG_LengthUTF8("caf\xC3\xA9") == 4, "AG_LengthUTF8 \"caf\\u00e9\" == 4 chars");
	/* Euro sign U+20AC = 0xE2 0x82 0xAC (3 bytes) -> 1 character */
	check(AG_LengthUTF8("\xE2\x82\xAC") == 1, "AG_LengthUTF8 euro sign == 1 char");

	/* --- byteswap (used throughout serialization / agar-disasm) --- */
	check(AG_SwapBE32(0x01020304U) == 0x01020304U ||
	      AG_SwapBE32(0x01020304U) == 0x04030201U,
	      "AG_SwapBE32 is a consistent endian swap");
	check(AG_SwapLE16(AG_SwapLE16(0xBEEFU)) == 0xBEEFU,
	      "AG_SwapLE16 round-trips");

	/* --- AG_DataSource integral + string round-trip (agar-disasm reads these) --- */
	if ((ds = AG_OpenAutoCore()) == NULL) {
		fprintf(stderr, "AG_OpenAutoCore: %s\n", AG_GetError());
		return (2);
	}
	AG_WriteUint32(ds, 0xDEADBEEFU);
	AG_WriteString(ds, "agar dataset");
	if (AG_Seek(ds, 0, AG_SEEK_SET) == -1) {
		fprintf(stderr, "AG_Seek: %s\n", AG_GetError());
		return (2);
	}
	u32 = AG_ReadUint32(ds);
	check(u32 == 0xDEADBEEFU, "AG_DataSource Uint32 write/read round-trips");
	rs = AG_ReadString(ds);
	check(rs != NULL && strcmp(rs, "agar dataset") == 0,
	      "AG_DataSource string write/read round-trips");
	AG_Free(rs);
	AG_CloseAutoCore(ds);

	/* --- AG_Object serialize -> read-back header (agar-disasm's ReadHeader path) --- */
	{
		AG_Object obj;
		AG_ObjectHeader oh;
		const char *path = "/tmp/agar_selftest_obj.bin";

		AG_ObjectInitStatic(&obj, &agObjectClass);
		AG_ObjectSetNameS(&obj, "selftest");

		if ((ds = AG_OpenFile(path, "wb")) == NULL) {
			fprintf(stderr, "AG_OpenFile(w): %s\n", AG_GetError());
			return (2);
		}
		check(AG_ObjectSerialize(&obj, ds) == 0,
		      "AG_ObjectSerialize succeeds");
		AG_CloseFile(ds);
		AG_ObjectDestroy(&obj);

		if ((ds = AG_OpenFile(path, "rb")) == NULL) {
			fprintf(stderr, "AG_OpenFile(r): %s\n", AG_GetError());
			return (2);
		}
		memset(&oh, 0, sizeof(oh));
		check(AG_ObjectReadHeader(ds, &oh) == 0,
		      "AG_ObjectReadHeader accepts a freshly serialized object");
		check(strcmp(oh.cs.hier, "AG_Object") == 0,
		      "serialized object's class hierarchy == \"AG_Object\"");
		AG_CloseFile(ds);
		unlink(path);
	}

	AG_Destroy();

	fprintf(stderr, "selftest: %d passed, %d failed\n", nPass, nFail);
	return (nFail == 0 ? 0 : 1);
}
