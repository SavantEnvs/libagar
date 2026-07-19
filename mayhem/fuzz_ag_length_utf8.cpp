#include <stdint.h>
#include <stdio.h>
#include <climits>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
    #include <agar/core.h>
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();

    /* Exercise Agar's UTF-8 length routine on the (NUL-terminated) string. */
    (void)AG_LengthUTF8(str.c_str());

    return 0;
}
