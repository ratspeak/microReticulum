/// BZ2 compression shim — no-op on this build.
///
/// The vendored libbzip2 is intentionally NOT linked on embedded targets:
/// bzip2's working-set memory and decode-table state are too large for
/// MCU-class devices (a single decompress can use multiples of available
/// SRAM). The functions below are kept so callers in Resource.cpp can
/// still link against this symbol surface without any conditional
/// compilation, but they never compress and never decompress.
///
/// To re-introduce a portable compression scheme later, replace these
/// implementations with something MCU-safe (e.g. heatshrink or LZ4) and
/// negotiate support through the LXMF announce capability list, NOT bz2.

#include "BZ2.h"

namespace RNS {
namespace Compression {

Bytes bz2_compress(const uint8_t* /*data*/, size_t /*len*/) {
    return Bytes();
}

Bytes bz2_decompress(const uint8_t* /*data*/, size_t /*len*/, size_t /*max_size*/) {
    return Bytes();
}

CompressResult try_compress(const Bytes& data) {
    return { data, false };
}

} // namespace Compression
} // namespace RNS
