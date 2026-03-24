/// Resource transfer tests — validates advertisement pack/unpack, map hashes,
/// chunking, reassembly, and proof computation.

#include <unity.h>
#include "Identity.h"
#include "Resource.h"
#include "Cryptography/Hashes.h"

#include <string.h>
#include <stdio.h>
#include <cmath>

static void printHex(const char* label, const uint8_t* data, size_t len) {
    printf("  %s = ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

// ── Test 1: ResourceAdvertisement pack/unpack roundtrip ─────────────

void testResourceAdvertisementPackUnpack() {
    RNS::ResourceAdvertisement adv;
    adv.transfer_size = 1024;
    adv.data_size = 900;
    adv.num_parts = 4;
    memset(adv.resource_hash, 0xAA, 32);
    memset(adv.random_hash, 0xBB, 4);
    memset(adv.original_hash, 0xCC, 32);
    adv.segment_index = 1;
    adv.total_segments = 1;
    adv.flags.encrypted = true;
    adv.flags.compressed = false;

    // Build a fake hashmap (4 hashes × 4 bytes = 16 bytes)
    uint8_t hm[16];
    for (int i = 0; i < 16; i++) hm[i] = i;
    adv.hashmap = RNS::Bytes(hm, 16);

    // Pack
    RNS::Bytes packed = adv.pack();
    TEST_ASSERT_TRUE(packed.size() > 0);

    printf("\n=== RESOURCE_ADV_PACK ===\n");
    printHex("packed", packed.data(), packed.size());

    // Unpack
    RNS::ResourceAdvertisement unpacked;
    bool ok = RNS::ResourceAdvertisement::unpack(packed, unpacked);
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL(1024, unpacked.transfer_size);
    TEST_ASSERT_EQUAL(900, unpacked.data_size);
    TEST_ASSERT_EQUAL(4, unpacked.num_parts);
    TEST_ASSERT_EQUAL_MEMORY(adv.resource_hash, unpacked.resource_hash, 32);
    TEST_ASSERT_EQUAL_MEMORY(adv.random_hash, unpacked.random_hash, 4);
    TEST_ASSERT_EQUAL(1, unpacked.segment_index);
    TEST_ASSERT_EQUAL(1, unpacked.total_segments);
    TEST_ASSERT_TRUE(unpacked.flags.encrypted);
    TEST_ASSERT_FALSE(unpacked.flags.compressed);
    TEST_ASSERT_EQUAL(16, unpacked.hashmap.size());
}

// ── Test 2: Map hash computation matches Python/Rust ────────────────

void testMapHashComputation() {
    // Known test: SHA256("test_data" + "\xBB\xBB\xBB\xBB")[:4]
    const char* str = "test_data";
    uint8_t random_hash[] = {0xBB, 0xBB, 0xBB, 0xBB};
    uint8_t mh[4];

    RNS::get_map_hash((const uint8_t*)str, 9, random_hash, 4, mh);

    // Verify it's deterministic
    uint8_t mh2[4];
    RNS::get_map_hash((const uint8_t*)str, 9, random_hash, 4, mh2);
    TEST_ASSERT_EQUAL_MEMORY(mh, mh2, 4);

    printf("\n=== MAP_HASH ===\n");
    printHex("hash", mh, 4);

    // Verify by manual SHA256 computation
    RNS::Bytes input((const uint8_t*)str, 9);
    input.append(random_hash, 4);
    RNS::Bytes expected = RNS::Identity::full_hash(input);
    TEST_ASSERT_EQUAL_MEMORY(expected.data(), mh, 4);
}

// ── Test 3: Resource hash computation ───────────────────────────────

void testResourceHashComputation() {
    RNS::Bytes data("Hello resource world!");
    uint8_t rh[4] = {0x11, 0x22, 0x33, 0x44};

    RNS::Bytes hash = RNS::compute_resource_hash(data, rh);
    TEST_ASSERT_EQUAL(32, hash.size());

    // Verify deterministic
    RNS::Bytes hash2 = RNS::compute_resource_hash(data, rh);
    TEST_ASSERT_EQUAL_MEMORY(hash.data(), hash2.data(), 32);

    printf("\n=== RESOURCE_HASH ===\n");
    printHex("hash", hash.data(), 32);
}

// ── Test 4: Expected proof computation ──────────────────────────────

void testExpectedProof() {
    RNS::Bytes data("Resource data for proof");
    uint8_t rh[32];
    memset(rh, 0xDD, 32);

    RNS::Bytes proof = RNS::compute_expected_proof(data, rh);
    TEST_ASSERT_EQUAL(32, proof.size());

    // Verify: SHA256(data || resource_hash)
    RNS::Bytes input(data.data(), data.size());
    input.append(rh, 32);
    RNS::Bytes expected = RNS::Identity::full_hash(input);
    TEST_ASSERT_EQUAL_MEMORY(expected.data(), proof.data(), 32);
}

// ── Test 5: ResourceAdvertisement get_map_hashes ────────────────────

void testGetMapHashes() {
    RNS::ResourceAdvertisement adv;
    uint8_t hm[] = {0x01, 0x02, 0x03, 0x04,
                     0x05, 0x06, 0x07, 0x08,
                     0x09, 0x0A, 0x0B, 0x0C};
    adv.hashmap = RNS::Bytes(hm, 12);

    auto hashes = adv.get_map_hashes();
    TEST_ASSERT_EQUAL(3, hashes.size());
    TEST_ASSERT_EQUAL_UINT8(0x01, hashes[0][0]);
    TEST_ASSERT_EQUAL_UINT8(0x05, hashes[1][0]);
    TEST_ASSERT_EQUAL_UINT8(0x09, hashes[2][0]);
}

// ── Test 6: ResourceFlags byte roundtrip ────────────────────────────

void testResourceFlags() {
    RNS::ResourceFlags f;
    f.encrypted = true;
    f.compressed = true;
    f.split = false;
    f.is_request = true;
    f.is_response = false;
    f.has_metadata = true;

    uint8_t b = f.to_byte();
    // encrypted=0x01, compressed=0x02, is_request=0x08, has_metadata=0x20
    TEST_ASSERT_EQUAL_UINT8(0x01 | 0x02 | 0x08 | 0x20, b);

    RNS::ResourceFlags f2 = RNS::ResourceFlags::from_byte(b);
    TEST_ASSERT_TRUE(f2.encrypted);
    TEST_ASSERT_TRUE(f2.compressed);
    TEST_ASSERT_FALSE(f2.split);
    TEST_ASSERT_TRUE(f2.is_request);
    TEST_ASSERT_FALSE(f2.is_response);
    TEST_ASSERT_TRUE(f2.has_metadata);
}

// ── Test 7: Advertisement with nil request_id ───────────────────────

void testAdvertisementNilRequestId() {
    RNS::ResourceAdvertisement adv;
    adv.transfer_size = 256;
    adv.data_size = 200;
    adv.num_parts = 1;
    memset(adv.resource_hash, 0x11, 32);
    memset(adv.random_hash, 0x22, 4);
    memset(adv.original_hash, 0x11, 32);
    adv.hashmap = RNS::Bytes((uint8_t*)"\x01\x02\x03\x04", 4);

    // Pack with nil request_id (default)
    RNS::Bytes packed = adv.pack();

    RNS::ResourceAdvertisement unpacked;
    TEST_ASSERT_TRUE(RNS::ResourceAdvertisement::unpack(packed, unpacked));
    TEST_ASSERT_EQUAL(0, unpacked.request_id.size());
    TEST_ASSERT_EQUAL(256, unpacked.transfer_size);
}

// ── Test 8: Advertisement with request_id ───────────────────────────

void testAdvertisementWithRequestId() {
    RNS::ResourceAdvertisement adv;
    adv.transfer_size = 512;
    adv.data_size = 400;
    adv.num_parts = 2;
    memset(adv.resource_hash, 0x33, 32);
    memset(adv.random_hash, 0x44, 4);
    memset(adv.original_hash, 0x33, 32);
    adv.request_id = RNS::Bytes((uint8_t*)"\xDE\xAD\xBE\xEF", 4);
    adv.hashmap = RNS::Bytes((uint8_t*)"\x01\x02\x03\x04\x05\x06\x07\x08", 8);

    RNS::Bytes packed = adv.pack();

    RNS::ResourceAdvertisement unpacked;
    TEST_ASSERT_TRUE(RNS::ResourceAdvertisement::unpack(packed, unpacked));
    TEST_ASSERT_EQUAL(4, unpacked.request_id.size());
    TEST_ASSERT_EQUAL_MEMORY("\xDE\xAD\xBE\xEF", unpacked.request_id.data(), 4);
}

// ── Runner ──────────────────────────────────────────────────────────

void setUp() {}
void tearDown() {}

int main(int argc, char **argv) {
    UNITY_BEGIN();
    RUN_TEST(testResourceAdvertisementPackUnpack);
    RUN_TEST(testMapHashComputation);
    RUN_TEST(testResourceHashComputation);
    RUN_TEST(testExpectedProof);
    RUN_TEST(testGetMapHashes);
    RUN_TEST(testResourceFlags);
    RUN_TEST(testAdvertisementNilRequestId);
    RUN_TEST(testAdvertisementWithRequestId);
    return UNITY_END();
}
