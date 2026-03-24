#pragma once

/// BZ2 compression/decompression wrapper for Reticulum Resource transfers.
/// Uses the vendored libbzip2 (bzip2-1.0.8, BSD license).
///
/// Matches Python's bz2.compress()/bz2.decompress() and Rust's bzip2 crate.

#include "../Bytes.h"
#include <cstdint>
#include <cstddef>

namespace RNS {
namespace Compression {

/// Compress data using bz2. Returns empty Bytes on failure.
Bytes bz2_compress(const uint8_t* data, size_t len);
inline Bytes bz2_compress(const Bytes& data) { return bz2_compress(data.data(), data.size()); }

/// Decompress bz2 data. Returns empty Bytes on failure.
/// max_size limits decompressed output (0 = no limit).
Bytes bz2_decompress(const uint8_t* data, size_t len, size_t max_size = 0);
inline Bytes bz2_decompress(const Bytes& data, size_t max_size = 0) { return bz2_decompress(data.data(), data.size(), max_size); }

/// Try compression: returns (compressed, true) if smaller, (original, false) otherwise.
struct CompressResult {
    Bytes data;
    bool compressed;
};
CompressResult try_compress(const Bytes& data);

} // namespace Compression
} // namespace RNS
