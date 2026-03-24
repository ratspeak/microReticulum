/// Resource transfer protocol implementation.
///
/// Matches Python Resource.py and Rust rns-protocol/resource.rs.

#include "Resource.h"
#include "ResourceData.h"
#include "Link.h"
#include "Packet.h"
#include "Identity.h"
#include "Compression/BZ2.h"
#include "Log.h"

#include <cstring>
#include <cmath>
#include <algorithm>

using namespace RNS;

// ============================================================
// MsgPack helpers (manual encoding for deterministic output)
// ============================================================

static void mpPackFixStr(Bytes& buf, const char* str) {
    size_t len = strlen(str);
    buf.append((uint8_t)(0xA0 | (len & 0x1F)));
    buf.append((const uint8_t*)str, len);
}

static void mpPackUint(Bytes& buf, size_t val) {
    if (val <= 127) {
        buf.append((uint8_t)val);
    } else if (val <= 0xFFFF) {
        buf.append((uint8_t)0xCD);
        buf.append((uint8_t)((val >> 8) & 0xFF));
        buf.append((uint8_t)(val & 0xFF));
    } else {
        buf.append((uint8_t)0xCE);
        buf.append((uint8_t)((val >> 24) & 0xFF));
        buf.append((uint8_t)((val >> 16) & 0xFF));
        buf.append((uint8_t)((val >> 8) & 0xFF));
        buf.append((uint8_t)(val & 0xFF));
    }
}

static void mpPackBin(Bytes& buf, const uint8_t* data, size_t len) {
    if (len < 256) {
        buf.append((uint8_t)0xC4);
        buf.append((uint8_t)len);
    } else {
        buf.append((uint8_t)0xC5);
        buf.append((uint8_t)((len >> 8) & 0xFF));
        buf.append((uint8_t)(len & 0xFF));
    }
    buf.append(data, len);
}

static void mpPackNil(Bytes& buf) {
    buf.append((uint8_t)0xC0);
}

// Simple msgpack reader helpers
struct MpReader {
    const uint8_t* data;
    size_t len;
    size_t pos;

    bool readUint(size_t& val) {
        if (pos >= len) return false;
        uint8_t b = data[pos];
        if (b <= 0x7F) { val = b; pos++; return true; }
        if (b == 0xCC) { if (pos + 2 > len) return false; val = data[pos+1]; pos += 2; return true; }
        if (b == 0xCD) { if (pos + 3 > len) return false; val = ((size_t)data[pos+1] << 8) | data[pos+2]; pos += 3; return true; }
        if (b == 0xCE) { if (pos + 5 > len) return false; val = ((size_t)data[pos+1] << 24) | ((size_t)data[pos+2] << 16) | ((size_t)data[pos+3] << 8) | data[pos+4]; pos += 5; return true; }
        return false;
    }

    bool readBin(const uint8_t*& out, size_t& outLen) {
        if (pos >= len) return false;
        uint8_t b = data[pos];
        if (b == 0xC4) { if (pos + 2 > len) return false; outLen = data[pos+1]; pos += 2; }
        else if (b == 0xC5) { if (pos + 3 > len) return false; outLen = ((size_t)data[pos+1] << 8) | data[pos+2]; pos += 3; }
        else return false;
        if (pos + outLen > len) return false;
        out = &data[pos];
        pos += outLen;
        return true;
    }

    bool readStr(std::string& str) {
        if (pos >= len) return false;
        uint8_t b = data[pos];
        size_t slen = 0;
        if ((b & 0xE0) == 0xA0) { slen = b & 0x1F; pos++; }
        else if (b == 0xD9) { if (pos + 2 > len) return false; slen = data[pos+1]; pos += 2; }
        else return false;
        if (pos + slen > len) return false;
        str.assign((const char*)&data[pos], slen);
        pos += slen;
        return true;
    }

    bool isNil() {
        if (pos >= len) return false;
        if (data[pos] == 0xC0) { pos++; return true; }
        return false;
    }

    bool skipValue() {
        if (pos >= len) return false;
        uint8_t b = data[pos];
        if (b == 0xC0 || b == 0xC2 || b == 0xC3) { pos++; return true; }
        if ((b & 0x80) == 0x00 || (b & 0xE0) == 0xE0) { pos++; return true; }
        if ((b & 0xE0) == 0xA0) { size_t s = b & 0x1F; pos += 1 + s; return pos <= len; }
        if (b == 0xC4) { if (pos + 2 > len) return false; pos += 2 + data[pos+1]; return pos <= len; }
        if (b == 0xC5) { if (pos + 3 > len) return false; pos += 3 + (((size_t)data[pos+1] << 8) | data[pos+2]); return pos <= len; }
        if (b == 0xCC || b == 0xD0) { pos += 2; return pos <= len; }
        if (b == 0xCD || b == 0xD1) { pos += 3; return pos <= len; }
        if (b == 0xCE || b == 0xD2 || b == 0xCA) { pos += 5; return pos <= len; }
        if (b == 0xCF || b == 0xD3 || b == 0xCB) { pos += 9; return pos <= len; }
        return false;
    }
};

// ============================================================
// ResourceAdvertisement
// ============================================================

Bytes ResourceAdvertisement::pack() const {
    Bytes buf;
    // Map with 11 entries
    buf.append((uint8_t)0x8B);  // fixmap(11)

    // "t": transfer_size
    mpPackFixStr(buf, "t"); mpPackUint(buf, transfer_size);
    // "d": data_size
    mpPackFixStr(buf, "d"); mpPackUint(buf, data_size);
    // "n": num_parts
    mpPackFixStr(buf, "n"); mpPackUint(buf, num_parts);
    // "h": resource_hash (32 bytes)
    mpPackFixStr(buf, "h"); mpPackBin(buf, resource_hash, 32);
    // "r": random_hash (4 bytes)
    mpPackFixStr(buf, "r"); mpPackBin(buf, random_hash, 4);
    // "o": original_hash (32 bytes)
    mpPackFixStr(buf, "o"); mpPackBin(buf, original_hash, 32);
    // "i": segment_index
    mpPackFixStr(buf, "i"); mpPackUint(buf, segment_index);
    // "l": total_segments
    mpPackFixStr(buf, "l"); mpPackUint(buf, total_segments);
    // "q": request_id (bin or nil)
    mpPackFixStr(buf, "q");
    if (request_id.size() > 0) { mpPackBin(buf, request_id.data(), request_id.size()); }
    else { mpPackNil(buf); }
    // "f": flags byte
    mpPackFixStr(buf, "f"); mpPackUint(buf, flags.to_byte());
    // "m": hashmap (concatenated 4-byte hashes)
    mpPackFixStr(buf, "m"); mpPackBin(buf, hashmap.data(), hashmap.size());

    return buf;
}

bool ResourceAdvertisement::unpack(const Bytes& data, ResourceAdvertisement& adv) {
    MpReader r = { data.data(), data.size(), 0 };

    // Read map header
    if (r.pos >= r.len) return false;
    uint8_t mh = r.data[r.pos];
    size_t map_size = 0;
    if ((mh & 0xF0) == 0x80) { map_size = mh & 0x0F; r.pos++; }
    else if (mh == 0xDE) {
        if (r.pos + 3 > r.len) return false;
        map_size = ((size_t)r.data[r.pos+1] << 8) | r.data[r.pos+2];
        r.pos += 3;
    }
    else return false;

    for (size_t i = 0; i < map_size; i++) {
        std::string key;
        if (!r.readStr(key)) return false;

        if (key == "t") { if (!r.readUint(adv.transfer_size)) return false; }
        else if (key == "d") { if (!r.readUint(adv.data_size)) return false; }
        else if (key == "n") { if (!r.readUint(adv.num_parts)) return false; }
        else if (key == "h") {
            const uint8_t* p; size_t l;
            if (!r.readBin(p, l) || l < 32) return false;
            memcpy(adv.resource_hash, p, 32);
        }
        else if (key == "r") {
            const uint8_t* p; size_t l;
            if (!r.readBin(p, l) || l < 4) return false;
            memcpy(adv.random_hash, p, 4);
        }
        else if (key == "o") {
            const uint8_t* p; size_t l;
            if (!r.readBin(p, l) || l < 32) return false;
            memcpy(adv.original_hash, p, 32);
        }
        else if (key == "i") { if (!r.readUint(adv.segment_index)) return false; }
        else if (key == "l") { if (!r.readUint(adv.total_segments)) return false; }
        else if (key == "q") {
            if (r.isNil()) { adv.request_id = Bytes(); }
            else {
                const uint8_t* p; size_t l;
                if (!r.readBin(p, l)) { r.skipValue(); }
                else { adv.request_id = Bytes(p, l); }
            }
        }
        else if (key == "f") {
            size_t fv; if (!r.readUint(fv)) return false;
            adv.flags = ResourceFlags::from_byte((uint8_t)fv);
        }
        else if (key == "m") {
            const uint8_t* p; size_t l;
            if (!r.readBin(p, l)) return false;
            adv.hashmap = Bytes(p, l);
        }
        else { r.skipValue(); }
    }
    return true;
}

std::vector<std::array<uint8_t, 4>> ResourceAdvertisement::get_map_hashes() const {
    std::vector<std::array<uint8_t, 4>> hashes;
    for (size_t i = 0; i + 4 <= hashmap.size(); i += 4) {
        std::array<uint8_t, 4> h;
        memcpy(h.data(), hashmap.data() + i, 4);
        hashes.push_back(h);
    }
    return hashes;
}

// ============================================================
// Hash functions
// ============================================================

void RNS::get_map_hash(const uint8_t* data, size_t data_len,
                       const uint8_t* random_hash, size_t random_len,
                       uint8_t out[4]) {
    Bytes input(data, data_len);
    input.append(random_hash, random_len);
    Bytes hash = Identity::full_hash(input);
    memcpy(out, hash.data(), 4);
}

Bytes RNS::compute_resource_hash(const Bytes& data, const uint8_t random_hash[4]) {
    Bytes input(data.data(), data.size());
    input.append(random_hash, 4);
    return Identity::full_hash(input);
}

Bytes RNS::compute_expected_proof(const Bytes& data, const uint8_t resource_hash[32]) {
    Bytes input(data.data(), data.size());
    input.append(resource_hash, 32);
    return Identity::full_hash(input);
}

// ============================================================
// OutboundResource
// ============================================================

bool OutboundResource::init(const Bytes& plaintext, Link& link, bool auto_compress) {
    _data_size = plaintext.size();
    _flags.encrypted = true;

    // Try bz2 compression (matches Python Resource.py:387-403)
    Bytes data_to_pack;
    if (auto_compress) {
        auto result = Compression::try_compress(plaintext);
        data_to_pack = result.data;
        _flags.compressed = result.compressed;
    } else {
        data_to_pack = plaintext;
        _flags.compressed = false;
    }

    // Prepend 4-byte random_hash
    Bytes rh = Identity::get_random_hash();
    memcpy(_random_hash, rh.data(), 4);
    Bytes to_encrypt(_random_hash, 4);
    to_encrypt.append(data_to_pack.data(), data_to_pack.size());

    // Encrypt with link session key (Resource.py line 424)
    Bytes encrypted = link.encrypt(to_encrypt);
    if (encrypted.size() == 0) return false;

    _transfer_size = encrypted.size();

    // Compute resource hash
    Bytes rh_full = compute_resource_hash(encrypted, _random_hash);
    memcpy(_resource_hash, rh_full.data(), 32);
    memcpy(_original_hash, _resource_hash, 32);

    // Compute expected proof
    _expected_proof = compute_expected_proof(encrypted, _resource_hash);

    // Split into SDU-sized chunks
    size_t sdu = Type::Resource::SDU;
    size_t num = (encrypted.size() + sdu - 1) / sdu;
    _parts.clear();
    _parts.reserve(num);

    Bytes hashmap_bytes;
    for (size_t i = 0; i < num; i++) {
        size_t offset = i * sdu;
        size_t chunk_len = std::min(sdu, encrypted.size() - offset);
        Bytes chunk(encrypted.data() + offset, chunk_len);

        // Compute map hash for this chunk
        uint8_t mh[4];
        get_map_hash(chunk.data(), chunk.size(), _random_hash, 4, mh);
        hashmap_bytes.append(mh, 4);

        _parts.push_back(chunk);
    }

    _hashmap = hashmap_bytes;
    _status = ResourceStatus::ADVERTISED;
    return true;
}

ResourceAdvertisement OutboundResource::get_advertisement() const {
    ResourceAdvertisement adv;
    adv.transfer_size = _transfer_size;
    adv.data_size = _data_size;
    adv.num_parts = _parts.size();
    memcpy(adv.resource_hash, _resource_hash, 32);
    memcpy(adv.random_hash, _random_hash, 4);
    memcpy(adv.original_hash, _original_hash, 32);
    adv.segment_index = 1;
    adv.total_segments = 1;
    adv.flags = _flags;
    adv.hashmap = _hashmap;
    return adv;
}

Bytes OutboundResource::get_part(size_t index) const {
    if (index < _parts.size()) return _parts[index];
    return Bytes();
}

std::vector<size_t> OutboundResource::handle_request(const Bytes& request_data) {
    // Request format: [exhausted_flag(1)][?last_map_hash(4)][resource_hash(32)][requested_hashes(N*4)]
    std::vector<size_t> indices;
    if (request_data.size() < 33) return indices;

    size_t pos = 0;
    uint8_t exhausted = request_data.data()[pos++];
    if (exhausted == 0xFF && request_data.size() > pos + 4) {
        pos += 4; // skip last_map_hash
    }

    // Skip resource_hash (32 bytes)
    if (pos + 32 > request_data.size()) return indices;
    pos += 32;

    // Remaining are requested map hashes (4 bytes each)
    while (pos + 4 <= request_data.size()) {
        uint8_t wanted[4];
        memcpy(wanted, request_data.data() + pos, 4);
        pos += 4;

        // Find matching part index
        for (size_t i = 0; i < _parts.size(); i++) {
            uint8_t mh[4];
            get_map_hash(_parts[i].data(), _parts[i].size(), _random_hash, 4, mh);
            if (memcmp(mh, wanted, 4) == 0) {
                indices.push_back(i);
                break;
            }
        }
    }

    _status = ResourceStatus::TRANSFERRING;
    return indices;
}

bool OutboundResource::handle_proof(const Bytes& proof_data) {
    if (proof_data.size() < 32) return false;
    if (memcmp(proof_data.data(), _expected_proof.data(), 32) == 0) {
        _status = ResourceStatus::COMPLETE;
        return true;
    }
    return false;
}

// ============================================================
// InboundResource
// ============================================================

bool InboundResource::init(const ResourceAdvertisement& adv, Link& link) {
    _transfer_size = adv.transfer_size;
    _data_size = adv.data_size;
    _total_parts = adv.num_parts;
    memcpy(_resource_hash, adv.resource_hash, 32);
    memcpy(_random_hash, adv.random_hash, 4);
    memcpy(_original_hash, adv.original_hash, 32);
    _flags = adv.flags;
    _map_hashes = adv.get_map_hashes();
    _received = 0;
    _window = 4;

    // Initialize part slots
    _parts.resize(_total_parts);

    _status = ResourceStatus::TRANSFERRING;
    return true;
}

bool InboundResource::receive_part(const Bytes& data) {
    // Compute map hash of this part
    uint8_t mh[4];
    get_map_hash(data.data(), data.size(), _random_hash, 4, mh);

    // Find matching slot in our hashmap
    for (size_t i = 0; i < _map_hashes.size() && i < _total_parts; i++) {
        if (memcmp(_map_hashes[i].data(), mh, 4) == 0 && _parts[i].size() == 0) {
            _parts[i] = data;
            _received++;
            return true;
        }
    }
    return false;
}

bool InboundResource::is_complete() const {
    return _received >= _total_parts;
}

Bytes InboundResource::assemble(Link& link) {
    // Concatenate all parts in order
    Bytes assembled;
    for (size_t i = 0; i < _total_parts; i++) {
        if (_parts[i].size() == 0) {
            _status = ResourceStatus::CORRUPT;
            return Bytes();
        }
        assembled.append(_parts[i].data(), _parts[i].size());
    }

    // Decrypt with link session key
    Bytes decrypted = link.decrypt(assembled);
    if (decrypted.size() == 0) {
        _status = ResourceStatus::CORRUPT;
        return Bytes();
    }

    // Strip 4-byte random_hash prefix
    if (decrypted.size() <= 4) {
        _status = ResourceStatus::CORRUPT;
        return Bytes();
    }
    Bytes payload(decrypted.data() + 4, decrypted.size() - 4);

    // Decompress if compressed (matches Python Resource.py assemble())
    Bytes plaintext;
    if (_flags.compressed) {
        plaintext = Compression::bz2_decompress(payload, _data_size * 2 + 4096);
        if (plaintext.size() == 0) {
            _status = ResourceStatus::CORRUPT;
            return Bytes();
        }
    } else {
        plaintext = payload;
    }

    _status = ResourceStatus::COMPLETE;
    return plaintext;
}

Bytes InboundResource::generate_proof() const {
    // Proof = SHA256(assembled_encrypted_data || resource_hash)
    Bytes assembled;
    for (size_t i = 0; i < _total_parts; i++) {
        assembled.append(_parts[i].data(), _parts[i].size());
    }
    return compute_expected_proof(assembled, _resource_hash);
}

Bytes InboundResource::get_initial_request() const {
    // Build request: [exhausted(1)][resource_hash(32)][wanted_hashes(N*4)]
    Bytes request;
    request.append((uint8_t)0x00);  // HASHMAP_IS_NOT_EXHAUSTED

    // Resource hash
    request.append(_resource_hash, 32);

    // Request all map hashes (initial window)
    size_t count = std::min(_window, _map_hashes.size());
    for (size_t i = 0; i < count; i++) {
        request.append(_map_hashes[i].data(), 4);
    }

    return request;
}

// ============================================================
// Legacy Resource class (compatibility with Link.cpp)
// ============================================================

Resource::Resource(const Bytes& data, const Link& link, const Bytes& request_id, bool is_response, double timeout) :
    _object(new ResourceData(link))
{
}

Resource::Resource(const Bytes& data, const Link& link, bool advertise, bool auto_compress,
                   Callbacks::concluded callback, Callbacks::progress progress_callback,
                   double timeout, int segment_index, const Bytes& original_hash,
                   const Bytes& request_id, bool is_response) :
    _object(new ResourceData(link))
{
}

void Resource::validate_proof(const Bytes& proof_data) {}
void Resource::cancel() {}
float Resource::get_progress() const { return 0.0; }

void Resource::set_concluded_callback(Callbacks::concluded callback) {
    if (_object) _object->_callbacks._concluded = callback;
}

void Resource::set_progress_callback(Callbacks::progress callback) {
    if (_object) _object->_callbacks._progress = callback;
}

std::string Resource::toString() const {
    return _object ? "{Resource}" : "";
}

const Bytes& Resource::hash() const { assert(_object); return _object->_hash; }
const Bytes& Resource::request_id() const { assert(_object); return _object->_request_id; }
const Bytes& Resource::data() const { assert(_object); return _object->_data; }
const Type::Resource::status Resource::status() const { assert(_object); return _object->_status; }
const size_t Resource::size() const { assert(_object); return _object->_size; }
const size_t Resource::total_size() const { assert(_object); return _object->_total_size; }
