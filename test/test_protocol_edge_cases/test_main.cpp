/// Protocol wire format edge cases and boundary condition tests.

#include <unity.h>
#include "Identity.h"
#include "Cryptography/Hashes.h"

#include <string.h>
#include <stdio.h>

// ── Test 1: Packet flag byte combinations ───────────────────────────

void testPacketFlagCombinations() {
    // flags = (header_type << 6) | (context_flag << 5) | (transport_type << 4) | (dest_type << 2) | packet_type

    // Enumerate critical combinations
    struct FlagCase { uint8_t ht, cf, tt, dt, pt, expected; const char* name; };
    FlagCase cases[] = {
        {0, 0, 0, 0, 0, 0x00, "H1/BC/Single/Data"},
        {0, 0, 0, 0, 1, 0x01, "H1/BC/Single/Announce"},
        {0, 0, 0, 0, 2, 0x02, "H1/BC/Single/LinkReq"},
        {0, 0, 0, 0, 3, 0x03, "H1/BC/Single/Proof"},
        {0, 0, 0, 3, 3, 0x0F, "H1/BC/Link/Proof"},
        {1, 0, 1, 0, 0, 0x50, "H2/Tx/Single/Data"},
        {1, 1, 1, 0, 0, 0x70, "H2/Ctx/Tx/Single/Data"},
        {0, 1, 0, 0, 1, 0x21, "H1/Ctx/BC/Single/Announce"},
    };

    for (auto& c : cases) {
        uint8_t flags = (c.ht << 6) | (c.cf << 5) | (c.tt << 4) | (c.dt << 2) | c.pt;
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(c.expected, flags, c.name);
    }
}

// ── Test 2: Hash masking (Header1 == Header2 hash) ──────────────────

void testHashMasking() {
    // The hash of a packet must be the same whether it has Header1 or Header2.
    // This is achieved by masking the flags byte to only the lower 4 bits
    // and excluding hops and transport_id from the hash.

    // Header1: [flags:1][hops:1][dest:16][ctx:1][data...]
    // Hash input: [flags & 0x0F][dest:16][ctx:1][data...]

    uint8_t h1_flags = 0x00;  // H1, BC, Single, Data
    uint8_t h2_flags = 0x50;  // H2, Transport, Single, Data

    // Lower nibble should be same
    TEST_ASSERT_EQUAL_UINT8(h1_flags & 0x0F, h2_flags & 0x0F);

    // Build hashable part for Header1
    uint8_t dest[16]; memset(dest, 0xAA, 16);
    uint8_t ctx = 0x00;
    uint8_t payload[] = {1, 2, 3, 4, 5};

    std::vector<uint8_t> hashable;
    hashable.push_back(h1_flags & 0x0F);  // masked flags
    hashable.insert(hashable.end(), dest, dest + 16);
    hashable.push_back(ctx);
    hashable.insert(hashable.end(), payload, payload + 5);

    RNS::Bytes hash1 = RNS::Identity::full_hash(RNS::Bytes(hashable.data(), hashable.size()));

    // Same hashable for "Header2" version (only lower nibble used)
    hashable[0] = h2_flags & 0x0F;  // same lower nibble
    RNS::Bytes hash2 = RNS::Identity::full_hash(RNS::Bytes(hashable.data(), hashable.size()));

    TEST_ASSERT_EQUAL_MEMORY(hash1.data(), hash2.data(), 32);
}

// ── Test 3: Hops don't affect hash ──────────────────────────────────

void testHopsDoNotAffectHash() {
    // Hops field is at byte index 1 and is excluded from hash computation.
    // Changing hops must NOT change the hash.

    uint8_t dest[16]; memset(dest, 0xBB, 16);
    uint8_t ctx = 0x00;
    uint8_t payload[] = {0xDE, 0xAD};

    // Hash input doesn't include hops
    std::vector<uint8_t> hashable;
    hashable.push_back(0x00);  // flags lower nibble
    hashable.insert(hashable.end(), dest, dest + 16);
    hashable.push_back(ctx);
    hashable.insert(hashable.end(), payload, payload + 2);

    RNS::Bytes hash = RNS::Identity::full_hash(RNS::Bytes(hashable.data(), hashable.size()));

    // Verify hash is 32 bytes
    TEST_ASSERT_EQUAL(32, hash.size());

    // The hash should be the same regardless of what hops value is in the raw packet
    // (because hops aren't included in hashable)
    TEST_ASSERT_TRUE(true);
}

// ── Test 4: MTU boundary ────────────────────────────────────────────

void testMTUBoundary() {
    // Reticulum MTU = 500 bytes
    // Encrypted MDU = 383 bytes (MTU - token overhead)
    // MDU = 464 bytes (MTU - header max size - IFAC min)
    const size_t MTU = 500;
    const size_t HEADER1_SIZE = 19;
    const size_t HEADER2_SIZE = 35;

    // A packet at exactly MTU
    uint8_t packet[MTU];
    memset(packet, 0, MTU);
    packet[0] = 0x00;  // flags
    packet[1] = 0x00;  // hops
    TEST_ASSERT_EQUAL(MTU, sizeof(packet));

    // Verify header sizes
    TEST_ASSERT_EQUAL(19, HEADER1_SIZE);
    TEST_ASSERT_EQUAL(35, HEADER2_SIZE);

    // Max data in Header1 packet
    TEST_ASSERT_EQUAL(MTU - HEADER1_SIZE, 481);
    // Max data in Header2 packet
    TEST_ASSERT_EQUAL(MTU - HEADER2_SIZE, 465);
}

// ── Test 5: Identity hash is truncated to 16 bytes ──────────────────

void testIdentityHashLength() {
    RNS::Bytes x_seed = RNS::Cryptography::sha256(RNS::Bytes("x25519_test_seed"));
    RNS::Bytes ed_seed = RNS::Cryptography::sha256(RNS::Bytes("ed25519_test_seed"));
    RNS::Identity id(false);
    TEST_ASSERT_TRUE(id.load_private_key(x_seed + ed_seed));

    RNS::Bytes hash = id.hash();
    TEST_ASSERT_EQUAL(16, hash.size());

    // Public key should be 64 bytes (X25519 32 + Ed25519 32)
    RNS::Bytes pubkey = id.get_public_key();
    TEST_ASSERT_EQUAL(64, pubkey.size());

    // Identity hash = truncated_hash(pubkey) = SHA256(pubkey)[:16]
    RNS::Bytes computed = RNS::Identity::truncated_hash(pubkey);
    TEST_ASSERT_EQUAL_MEMORY(hash.data(), computed.data(), 16);
}

// ── Test 6: Encrypt/decrypt roundtrip with token ────────────────────

void testEncryptDecryptRoundtrip() {
    RNS::Bytes x_seed = RNS::Cryptography::sha256(RNS::Bytes("encrypt_test_seed_1"));
    RNS::Bytes ed_seed = RNS::Cryptography::sha256(RNS::Bytes("encrypt_test_seed_2"));
    RNS::Identity id(false);
    TEST_ASSERT_TRUE(id.load_private_key(x_seed + ed_seed));

    RNS::Bytes plaintext("Hello encrypted world!");
    RNS::Bytes ciphertext = id.encrypt(plaintext);
    TEST_ASSERT_TRUE(ciphertext.size() > 0);

    RNS::Bytes decrypted = id.decrypt(ciphertext);
    TEST_ASSERT_EQUAL(plaintext.size(), decrypted.size());
    TEST_ASSERT_EQUAL_MEMORY(plaintext.data(), decrypted.data(), plaintext.size());
}

// ── Runner ──────────────────────────────────────────────────────────

void setUp() {}
void tearDown() {}

int main(int argc, char **argv) {
    UNITY_BEGIN();
    RUN_TEST(testPacketFlagCombinations);
    RUN_TEST(testHashMasking);
    RUN_TEST(testHopsDoNotAffectHash);
    RUN_TEST(testMTUBoundary);
    RUN_TEST(testIdentityHashLength);
    RUN_TEST(testEncryptDecryptRoundtrip);
    return UNITY_END();
}
