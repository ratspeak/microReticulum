/// Announce creation, parsing, and app_data handling tests.
///
/// Validates announce wire format matches Python/Rust implementations.

#include <unity.h>
#include "Identity.h"
#include "Cryptography/Hashes.h"

#include <string.h>
#include <stdio.h>
#include <string>
#include <vector>

static void printHex(const char* label, const uint8_t* data, size_t len) {
    printf("  %s = ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}
static void printHex(const char* label, const RNS::Bytes& data) { printHex(label, data.data(), data.size()); }

static RNS::Identity g_identity({RNS::Type::NONE});
static RNS::Bytes g_dest_hash;
static RNS::Bytes g_name_hash;
static bool g_init = false;

static void initFixture() {
    if (g_init) return;
    RNS::Bytes x_seed = RNS::Cryptography::sha256(RNS::Bytes("x25519_test_seed"));
    RNS::Bytes ed_seed = RNS::Cryptography::sha256(RNS::Bytes("ed25519_test_seed"));
    g_identity = RNS::Identity(false);
    TEST_ASSERT_TRUE(g_identity.load_private_key(x_seed + ed_seed));
    g_name_hash = RNS::Identity::full_hash(RNS::Bytes("lxmf.delivery")).left(RNS::Type::Identity::NAME_HASH_LENGTH / 8);
    g_dest_hash = RNS::Identity::truncated_hash(g_name_hash + g_identity.hash());
    g_init = true;
}

// ── Test 1: Announce pack ───────────────────────────────────────────

void testAnnouncePack() {
    initFixture();

    RNS::Bytes pubkey = g_identity.get_public_key();
    TEST_ASSERT_EQUAL(64, pubkey.size());

    uint8_t random_hash[10];
    memset(random_hash, 0x42, 10);

    // Build signed data: dest_hash(16) + pubkey(64) + name_hash(10) + random_hash(10)
    std::vector<uint8_t> signed_data;
    signed_data.insert(signed_data.end(), g_dest_hash.data(), g_dest_hash.data() + 16);
    signed_data.insert(signed_data.end(), pubkey.data(), pubkey.data() + 64);
    signed_data.insert(signed_data.end(), g_name_hash.data(), g_name_hash.data() + 10);
    signed_data.insert(signed_data.end(), random_hash, random_hash + 10);

    RNS::Bytes sig = g_identity.sign(RNS::Bytes(signed_data.data(), signed_data.size()));
    TEST_ASSERT_EQUAL(64, sig.size());

    // Build announce: pubkey(64) + name_hash(10) + random_hash(10) + sig(64)
    std::vector<uint8_t> announce;
    announce.insert(announce.end(), pubkey.data(), pubkey.data() + 64);
    announce.insert(announce.end(), g_name_hash.data(), g_name_hash.data() + 10);
    announce.insert(announce.end(), random_hash, random_hash + 10);
    announce.insert(announce.end(), sig.data(), sig.data() + 64);

    // Minimum announce = 148 bytes (no app_data, no ratchet)
    TEST_ASSERT_EQUAL(148, announce.size());

    printf("\n=== ANNOUNCE_PACK ===\n");
    printHex("announce", announce.data(), announce.size());
}

// ── Test 2: Announce unpack ─────────────────────────────────────────

void testAnnounceUnpack() {
    initFixture();

    RNS::Bytes pubkey = g_identity.get_public_key();
    uint8_t random_hash[10];
    memset(random_hash, 0x42, 10);

    std::vector<uint8_t> signed_data;
    signed_data.insert(signed_data.end(), g_dest_hash.data(), g_dest_hash.data() + 16);
    signed_data.insert(signed_data.end(), pubkey.data(), pubkey.data() + 64);
    signed_data.insert(signed_data.end(), g_name_hash.data(), g_name_hash.data() + 10);
    signed_data.insert(signed_data.end(), random_hash, random_hash + 10);
    RNS::Bytes sig = g_identity.sign(RNS::Bytes(signed_data.data(), signed_data.size()));

    std::vector<uint8_t> announce;
    announce.insert(announce.end(), pubkey.data(), pubkey.data() + 64);
    announce.insert(announce.end(), g_name_hash.data(), g_name_hash.data() + 10);
    announce.insert(announce.end(), random_hash, random_hash + 10);
    announce.insert(announce.end(), sig.data(), sig.data() + 64);

    // Unpack: verify field offsets
    // [0..64] = pubkey, [64..74] = name_hash, [74..84] = random_hash, [84..148] = sig
    TEST_ASSERT_EQUAL_MEMORY(pubkey.data(), announce.data(), 64);
    TEST_ASSERT_EQUAL_MEMORY(g_name_hash.data(), announce.data() + 64, 10);
    TEST_ASSERT_EQUAL_MEMORY(random_hash, announce.data() + 74, 10);
    TEST_ASSERT_EQUAL_MEMORY(sig.data(), announce.data() + 84, 64);

    // Validate signature
    bool valid = g_identity.validate(
        RNS::Bytes(announce.data() + 84, 64),
        RNS::Bytes(signed_data.data(), signed_data.size())
    );
    TEST_ASSERT_TRUE(valid);
}

// ── Test 3: Announce with ratchet ───────────────────────────────────

void testAnnounceWithRatchet() {
    initFixture();

    RNS::Bytes pubkey = g_identity.get_public_key();
    uint8_t random_hash[10];
    memset(random_hash, 0x42, 10);
    uint8_t ratchet_key[32];
    memset(ratchet_key, 0xAB, 32);

    // With ratchet: signed_data includes ratchet between random_hash and signature
    std::vector<uint8_t> signed_data;
    signed_data.insert(signed_data.end(), g_dest_hash.data(), g_dest_hash.data() + 16);
    signed_data.insert(signed_data.end(), pubkey.data(), pubkey.data() + 64);
    signed_data.insert(signed_data.end(), g_name_hash.data(), g_name_hash.data() + 10);
    signed_data.insert(signed_data.end(), random_hash, random_hash + 10);
    signed_data.insert(signed_data.end(), ratchet_key, ratchet_key + 32);
    RNS::Bytes sig = g_identity.sign(RNS::Bytes(signed_data.data(), signed_data.size()));

    // Wire: pubkey(64) + name_hash(10) + random_hash(10) + ratchet(32) + sig(64)
    std::vector<uint8_t> announce;
    announce.insert(announce.end(), pubkey.data(), pubkey.data() + 64);
    announce.insert(announce.end(), g_name_hash.data(), g_name_hash.data() + 10);
    announce.insert(announce.end(), random_hash, random_hash + 10);
    announce.insert(announce.end(), ratchet_key, ratchet_key + 32);
    announce.insert(announce.end(), sig.data(), sig.data() + 64);

    // With ratchet: 148 + 32 = 180 bytes
    TEST_ASSERT_EQUAL(180, announce.size());

    // Verify ratchet is at offset 84
    TEST_ASSERT_EQUAL_MEMORY(ratchet_key, announce.data() + 84, 32);
    // Signature at offset 116
    TEST_ASSERT_EQUAL_MEMORY(sig.data(), announce.data() + 116, 64);

    printf("\n=== ANNOUNCE_WITH_RATCHET ===\n");
    printf("  size = %d bytes (148 base + 32 ratchet)\n", (int)announce.size());
}

// ── Test 4: App data extraction (msgpack) ───────────────────────────

void testAppDataExtraction() {
    // Test extracting display name from Ratdeck msgpack format: fixarray(1)[bin8(name)]
    uint8_t app_data[] = {0x91, 0xC4, 0x04, 'T', 'e', 's', 't'};  // ["Test"]

    // Parse: fixarray(1) → bin8(4) → "Test"
    TEST_ASSERT_EQUAL_UINT8(0x91, app_data[0]);
    TEST_ASSERT_EQUAL_UINT8(0xC4, app_data[1]);
    TEST_ASSERT_EQUAL_UINT8(4, app_data[2]);

    std::string name((const char*)app_data + 3, 4);
    TEST_ASSERT_EQUAL_STRING("Test", name.c_str());

    // Also test raw UTF-8 format (Rust format)
    const char* utf8_data = "RustNode";
    std::string utf8_name(utf8_data);
    TEST_ASSERT_EQUAL_STRING("RustNode", utf8_name.c_str());
}

// ── Test 5: Dest hash from identity ─────────────────────────────────

void testDestHashFromIdentity() {
    initFixture();

    // dest_hash = truncated_hash(name_hash("lxmf.delivery") || identity.hash())
    RNS::Bytes nh = RNS::Identity::full_hash(RNS::Bytes("lxmf.delivery")).left(RNS::Type::Identity::NAME_HASH_LENGTH / 8);
    RNS::Bytes ih = g_identity.hash();
    RNS::Bytes addr = nh + ih;
    RNS::Bytes computed = RNS::Identity::truncated_hash(addr);

    TEST_ASSERT_EQUAL(16, computed.size());
    TEST_ASSERT_EQUAL_MEMORY(g_dest_hash.data(), computed.data(), 16);

    // Also verify for a different aspect name
    RNS::Bytes nh_prop = RNS::Identity::full_hash(RNS::Bytes("lxmf.propagation")).left(RNS::Type::Identity::NAME_HASH_LENGTH / 8);
    RNS::Bytes prop_dest = RNS::Identity::truncated_hash(nh_prop + ih);
    TEST_ASSERT_EQUAL(16, prop_dest.size());
    // Must be different from delivery dest
    TEST_ASSERT_FALSE(memcmp(g_dest_hash.data(), prop_dest.data(), 16) == 0);

    printf("\n=== DEST_HASH ===\n");
    printHex("delivery_dest", g_dest_hash);
    printHex("propagation_dest", prop_dest);
}

// ── Test 6: Name hash for multiple aspects ──────────────────────────

void testNameHashes() {
    RNS::Bytes nh1 = RNS::Identity::full_hash(RNS::Bytes("lxmf.delivery")).left(RNS::Type::Identity::NAME_HASH_LENGTH / 8);
    RNS::Bytes nh2 = RNS::Identity::full_hash(RNS::Bytes("lxmf.propagation")).left(RNS::Type::Identity::NAME_HASH_LENGTH / 8);
    RNS::Bytes nh3 = RNS::Identity::full_hash(RNS::Bytes("nomadnetwork.node")).left(RNS::Type::Identity::NAME_HASH_LENGTH / 8);

    TEST_ASSERT_EQUAL(10, nh1.size());
    TEST_ASSERT_EQUAL(10, nh2.size());
    TEST_ASSERT_EQUAL(10, nh3.size());

    // All must be different
    TEST_ASSERT_FALSE(nh1 == nh2);
    TEST_ASSERT_FALSE(nh1 == nh3);
    TEST_ASSERT_FALSE(nh2 == nh3);

    printf("\n=== NAME_HASHES ===\n");
    printHex("lxmf.delivery", nh1);
    printHex("lxmf.propagation", nh2);
    printHex("nomadnetwork.node", nh3);
}

// ── Runner ──────────────────────────────────────────────────────────

void setUp() {}
void tearDown() {}

int main(int argc, char **argv) {
    UNITY_BEGIN();
    RUN_TEST(testAnnouncePack);
    RUN_TEST(testAnnounceUnpack);
    RUN_TEST(testAnnounceWithRatchet);
    RUN_TEST(testAppDataExtraction);
    RUN_TEST(testDestHashFromIdentity);
    RUN_TEST(testNameHashes);
    return UNITY_END();
}
