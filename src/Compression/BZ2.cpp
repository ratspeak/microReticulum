/// BZ2 compression implementation using vendored libbzip2.
#include "BZ2.h"

extern "C" {
#include "bzlib.h"
}

#include <cstdlib>
#include <cstring>
#include <algorithm>

namespace RNS {
namespace Compression {

Bytes bz2_compress(const uint8_t* data, size_t len) {
    if (len == 0) return Bytes();

    // bz2 output can be slightly larger than input for incompressible data
    unsigned int dest_len = (unsigned int)(len + len / 100 + 600);
    char* dest = (char*)malloc(dest_len);
    if (!dest) return Bytes();

    int ret = BZ2_bzBuffToBuffCompress(
        dest, &dest_len,
        (char*)data, (unsigned int)len,
        9,    // blockSize100k (1-9, 9 = best compression)
        0,    // verbosity
        30    // workFactor (default)
    );

    if (ret != BZ_OK) {
        free(dest);
        return Bytes();
    }

    Bytes result((const uint8_t*)dest, dest_len);
    free(dest);
    return result;
}

Bytes bz2_decompress(const uint8_t* data, size_t len, size_t max_size) {
    if (len == 0) return Bytes();

    // Try with progressively larger buffers
    size_t multipliers[] = {4, 16, 64, 256};
    for (size_t mult : multipliers) {
        unsigned int dest_len = (unsigned int)(len * mult);
        if (dest_len < 1024) dest_len = 1024;
        if (max_size > 0 && dest_len > (unsigned int)max_size) dest_len = (unsigned int)max_size;

        char* dest = (char*)malloc(dest_len);
        if (!dest) return Bytes();

        int ret = BZ2_bzBuffToBuffDecompress(
            dest, &dest_len,
            (char*)data, (unsigned int)len,
            0, 0  // small=0, verbosity=0
        );

        if (ret == BZ_OK) {
            if (max_size > 0 && dest_len > (unsigned int)max_size) {
                free(dest);
                return Bytes();
            }
            Bytes result((const uint8_t*)dest, dest_len);
            free(dest);
            return result;
        }

        free(dest);
        if (ret != BZ_OUTBUFF_FULL) return Bytes();  // Unrecoverable error
    }

    return Bytes();
}

CompressResult try_compress(const Bytes& data) {
    Bytes compressed = bz2_compress(data);
    if (compressed.size() > 0 && compressed.size() < data.size()) {
        return { compressed, true };
    }
    return { data, false };
}

} // namespace Compression
} // namespace RNS
