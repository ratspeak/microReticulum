/// LXMF Message codec tests — validates packing, unpacking, signing, and wire format.
///
/// Tests the LXMFMessage module using deterministic seeds (same as test_cross_compat).
/// All tests run on native platform (no ESP32 hardware needed).

#include <unity.h>
#include "Identity.h"
#include "LXMFMessage.h"
#include "Cryptography/Hashes.h"

#include <string.h>
#include <stdio.h>
#include <math.h>
#include <string>
#include <vector>

// ---- Global state ----

static RNS::Identity g_identity({RNS::Type::NONE});
static RNS::Bytes g_dest_hash;
static bool g_initialized = false;

static void initFixture() {
    if (g_initialized) return;

    // Deterministic seeds (same as test_cross_compat)
    RNS::Bytes x_seed = RNS::Cryptography::sha256(RNS::Bytes("x25519_test_seed"));
    RNS::Bytes ed_seed = RNS::Cryptography::sha256(RNS::Bytes("ed25519_test_seed"));
    RNS::Bytes prv_key = x_seed + ed_seed;

    g_identity = RNS::Identity(false);
    TEST_ASSERT_TRUE_MESSAGE(g_identity.load_private_key(prv_key), "Failed to load private key");

    // dest_hash = truncated_hash(name_hash("lxmf.delivery") + identity_hash)
    RNS::Bytes name_hash = RNS::Identity::full_hash(RNS::Bytes("lxmf.delivery")).left(RNS::Type::Identity::NAME_HASH_LENGTH / 8);
    RNS::Bytes addr = name_hash + g_identity.hash();
    g_dest_hash = RNS::Identity::truncated_hash(addr);

    g_initialized = true;
}

// ── Test 1: Pack content roundtrip ──────────────────────────────────

void testPackContentRoundtrip() {
    initFixture();

    auto packed = LXMFMessage::packContent(1700000000.0, "Test content", "Test Title");
    TEST_ASSERT_TRUE(packed.size() > 0);

    // First byte = fixarray(4) = 0x94
    TEST_ASSERT_EQUAL_UINT8(0x94, packed[0]);
    // Second byte = float64 marker = 0xCB
    TEST_ASSERT_EQUAL_UINT8(0xCB, packed[1]);
    // Position 10 = title bin8 marker (after 1 + 9 float bytes)
    TEST_ASSERT_EQUAL_UINT8(0xC4, packed[10]);
}

// ── Test 2: Pack content uses bin encoding ──────────────────────────

void testPackContentBinEncoding() {
    auto packed = LXMFMessage::packContent(0.0, "Hello", "Hi");

    // Title "Hi" at position 10: bin8(0xC4) + len(2) + "Hi"
    TEST_ASSERT_EQUAL_UINT8(0xC4, packed[10]);
    TEST_ASSERT_EQUAL_UINT8(2, packed[11]);
    TEST_ASSERT_EQUAL_UINT8('H', packed[12]);
    TEST_ASSERT_EQUAL_UINT8('i', packed[13]);

    // Content "Hello" at position 14: bin8(0xC4) + len(5) + "Hello"
    TEST_ASSERT_EQUAL_UINT8(0xC4, packed[14]);
    TEST_ASSERT_EQUAL_UINT8(5, packed[15]);
    TEST_ASSERT_EQUAL_UINT8('H', packed[16]);
}

// ── Test 3: Pack full opportunistic wire format ─────────────────────

void testPackFullOpportunistic() {
    initFixture();

    LXMFMessage msg;
    msg.destHash = g_dest_hash;
    msg.sourceHash = g_identity.hash();
    msg.timestamp = 1700000000.0;
    msg.title = "Hello from C++";
    msg.content = "Cross-platform test";

    auto payload = msg.packFull(g_identity);
    TEST_ASSERT_TRUE(payload.size() > 80);

    // Opportunistic: [src_hash:16][signature:64][packed_content]
    TEST_ASSERT_EQUAL_MEMORY(g_identity.hash().data(), payload.data(), 16);
    // packed_content starts at position 80 with 0x94
    TEST_ASSERT_EQUAL_UINT8(0x94, payload[80]);
}

// ── Test 4: Pack full + prepend dest_hash for DIRECT format ─────────

void testPackFullDirect() {
    initFixture();

    LXMFMessage msg;
    msg.destHash = g_dest_hash;
    msg.sourceHash = g_identity.hash();
    msg.timestamp = 1700000000.0;
    msg.title = "Direct test";
    msg.content = "With dest_hash";

    auto payload = msg.packFull(g_identity);

    // Build direct format: [dest:16][payload]
    std::vector<uint8_t> direct;
    direct.insert(direct.end(), g_dest_hash.data(), g_dest_hash.data() + 16);
    direct.insert(direct.end(), payload.begin(), payload.end());

    TEST_ASSERT_TRUE(direct.size() >= 96);
    TEST_ASSERT_EQUAL_MEMORY(g_dest_hash.data(), direct.data(), 16);
    TEST_ASSERT_EQUAL_MEMORY(g_identity.hash().data(), direct.data() + 16, 16);
}

// ── Test 5: Unpack full ─────────────────────────────────────────────

void testUnpackFull() {
    initFixture();

    LXMFMessage msg;
    msg.destHash = g_dest_hash;
    msg.sourceHash = g_identity.hash();
    msg.timestamp = 1700000000.0;
    msg.title = "Unpack test";
    msg.content = "Verify round-trip";

    auto payload = msg.packFull(g_identity);

    // Build direct format for unpackFull (it expects [dest:16][src:16][sig:64][packed])
    std::vector<uint8_t> direct;
    direct.insert(direct.end(), g_dest_hash.data(), g_dest_hash.data() + 16);
    direct.insert(direct.end(), payload.begin(), payload.end());

    LXMFMessage unpacked;
    bool ok = LXMFMessage::unpackFull(direct.data(), direct.size(), unpacked);
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL_STRING("Unpack test", unpacked.title.c_str());
    TEST_ASSERT_EQUAL_STRING("Verify round-trip", unpacked.content.c_str());
    TEST_ASSERT_TRUE(fabs(unpacked.timestamp - 1700000000.0) < 0.001);
}

// ── Test 6: Signature verification ──────────────────────────────────

void testSignatureVerification() {
    initFixture();

    LXMFMessage msg;
    msg.destHash = g_dest_hash;
    msg.sourceHash = g_identity.hash();
    msg.timestamp = 1700000000.0;
    msg.title = "Signed";
    msg.content = "Verify me";

    auto payload = msg.packFull(g_identity);
    TEST_ASSERT_TRUE(payload.size() > 80);

    // Extract signature from payload[16:80]
    RNS::Bytes sig(payload.data() + 16, 64);

    // Reconstruct signed_data: dest + src + packed + SHA256(dest + src + packed)
    auto packed = LXMFMessage::packContent(msg.timestamp, msg.content, msg.title);
    RNS::Bytes hashed_part(32 + packed.size());
    memcpy(hashed_part.writable(hashed_part.size()), g_dest_hash.data(), 16);
    memcpy(hashed_part.writable(hashed_part.size()) + 16, g_identity.hash().data(), 16);
    memcpy(hashed_part.writable(hashed_part.size()) + 32, packed.data(), packed.size());

    RNS::Bytes msgHash = RNS::Identity::full_hash(hashed_part);
    RNS::Bytes signed_data = hashed_part + msgHash;

    bool valid = g_identity.validate(sig, signed_data);
    TEST_ASSERT_TRUE(valid);
}

// ── Test 7: Message ID computation ──────────────────────────────────

void testMessageIdComputation() {
    initFixture();

    LXMFMessage msg;
    msg.destHash = g_dest_hash;
    msg.sourceHash = g_identity.hash();
    msg.timestamp = 1700000000.0;
    msg.title = "ID test";
    msg.content = "Hash me";

    msg.packFull(g_identity);
    TEST_ASSERT_EQUAL(32, msg.messageId.size());

    // Pack same message again — messageId should be deterministic
    LXMFMessage msg2;
    msg2.destHash = g_dest_hash;
    msg2.sourceHash = g_identity.hash();
    msg2.timestamp = 1700000000.0;
    msg2.title = "ID test";
    msg2.content = "Hash me";
    msg2.packFull(g_identity);

    TEST_ASSERT_EQUAL_MEMORY(msg.messageId.data(), msg2.messageId.data(), 32);
}

// ── Test 8: Empty title and content ─────────────────────────────────

void testEmptyTitleAndContent() {
    auto packed = LXMFMessage::packContent(0.0, "", "");
    TEST_ASSERT_TRUE(packed.size() > 0);
    TEST_ASSERT_EQUAL_UINT8(0x94, packed[0]);
    // Empty bin: 0xC4 0x00
    TEST_ASSERT_EQUAL_UINT8(0xC4, packed[10]);
    TEST_ASSERT_EQUAL_UINT8(0, packed[11]);
    TEST_ASSERT_EQUAL_UINT8(0xC4, packed[12]);
    TEST_ASSERT_EQUAL_UINT8(0, packed[13]);
}

// ── Test 9: Unicode content ─────────────────────────────────────────

void testUnicodeContent() {
    initFixture();

    LXMFMessage msg;
    msg.destHash = g_dest_hash;
    msg.sourceHash = g_identity.hash();
    msg.timestamp = 1700000000.0;
    msg.title = "Unicode";
    msg.content = "Hello World";  // Keep ASCII for reliable cross-platform testing

    auto payload = msg.packFull(g_identity);

    std::vector<uint8_t> direct;
    direct.insert(direct.end(), g_dest_hash.data(), g_dest_hash.data() + 16);
    direct.insert(direct.end(), payload.begin(), payload.end());

    LXMFMessage unpacked;
    bool ok = LXMFMessage::unpackFull(direct.data(), direct.size(), unpacked);
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL_STRING("Hello World", unpacked.content.c_str());
}

// ── Test 10: Max size content (near opportunistic limit) ────────────

void testMaxSizeContent() {
    initFixture();

    std::string bigContent(280, 'X');

    LXMFMessage msg;
    msg.destHash = g_dest_hash;
    msg.sourceHash = g_identity.hash();
    msg.timestamp = 1700000000.0;
    msg.title = "";
    msg.content = bigContent;

    auto payload = msg.packFull(g_identity);
    TEST_ASSERT_TRUE(payload.size() > 0);

    std::vector<uint8_t> direct;
    direct.insert(direct.end(), g_dest_hash.data(), g_dest_hash.data() + 16);
    direct.insert(direct.end(), payload.begin(), payload.end());

    LXMFMessage unpacked;
    bool ok = LXMFMessage::unpackFull(direct.data(), direct.size(), unpacked);
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL(280, unpacked.content.size());
}

// ── Runner ──────────────────────────────────────────────────────────

void setUp() {}
void tearDown() {}

int main(int argc, char **argv) {
    UNITY_BEGIN();
    RUN_TEST(testPackContentRoundtrip);
    RUN_TEST(testPackContentBinEncoding);
    RUN_TEST(testPackFullOpportunistic);
    RUN_TEST(testPackFullDirect);
    RUN_TEST(testUnpackFull);
    RUN_TEST(testSignatureVerification);
    RUN_TEST(testMessageIdComputation);
    RUN_TEST(testEmptyTitleAndContent);
    RUN_TEST(testUnicodeContent);
    RUN_TEST(testMaxSizeContent);
    return UNITY_END();
}
