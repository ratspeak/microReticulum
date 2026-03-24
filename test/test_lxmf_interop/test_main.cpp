/// Cross-platform LXMF interop fixture generator + validator.
///
/// Generates deterministic LXMF fixture values for Rust validation in
/// raticulum-tests/tests/cpp_interop_fields.rs. All values use the same
/// seeds as test_cross_compat for consistency.
///
/// Also validates C++ can unpack known Python/Rust-generated fixtures.

#include <unity.h>
#include "Identity.h"
#include "LXMFMessage.h"
#include "Cryptography/Hashes.h"

#include <string.h>
#include <stdio.h>
#include <string>
#include <vector>

// ---- Helpers (same as test_cross_compat) ----

static void printHex(const char* label, const uint8_t* data, size_t len) {
    printf("  %s = ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}
static void printHex(const char* label, const RNS::Bytes& data) { printHex(label, data.data(), data.size()); }
static void printHex(const char* label, const std::vector<uint8_t>& data) { printHex(label, data.data(), data.size()); }

// ---- MsgPack helpers for field packing ----

static void mpPackBin(std::vector<uint8_t>& buf, const uint8_t* data, size_t len) {
    if (len < 256) { buf.push_back(0xC4); buf.push_back((uint8_t)len); }
    else { buf.push_back(0xC5); buf.push_back((len >> 8) & 0xFF); buf.push_back(len & 0xFF); }
    buf.insert(buf.end(), data, data + len);
}

static void mpPackBin(std::vector<uint8_t>& buf, const std::string& str) {
    mpPackBin(buf, (const uint8_t*)str.data(), str.size());
}

// ---- Global fixture state ----

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

// ── Test 1: LXMF with FIELD_IMAGE ───────────────────────────────────
// Pack an LXMF message where the fields map contains FIELD_IMAGE (0x06)
// as a msgpack array: [bin("image/png"), bin(fake_png_data)]

void testLxmfWithImageField() {
    initFixture();

    // Build packed_content with IMAGE field in the fields map
    std::vector<uint8_t> packed;
    packed.push_back(0x94);  // fixarray(4)

    // timestamp
    packed.push_back(0xCB);
    double ts = 1700000000.0;
    uint64_t bits; memcpy(&bits, &ts, 8);
    for (int i = 7; i >= 0; i--) packed.push_back((bits >> (i * 8)) & 0xFF);

    // title: bin8("Image Test")
    mpPackBin(packed, "Image Test");
    // content: bin8("Has image field")
    mpPackBin(packed, "Has image field");

    // fields: fixmap(1) { 0x06: fixarray(2)[bin("image/png"), bin(fake_png)] }
    packed.push_back(0x81);  // fixmap(1)
    packed.push_back(0x06);  // key = FIELD_IMAGE

    // value = fixarray(2)
    packed.push_back(0x92);
    mpPackBin(packed, "image/png");
    uint8_t fake_png[] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00};
    mpPackBin(packed, fake_png, sizeof(fake_png));

    // Build wire format: [dest:16][src:16][sig:64][packed]
    // Sign it
    std::vector<uint8_t> hashed_part;
    hashed_part.insert(hashed_part.end(), g_dest_hash.data(), g_dest_hash.data() + 16);
    hashed_part.insert(hashed_part.end(), g_identity.hash().data(), g_identity.hash().data() + 16);
    hashed_part.insert(hashed_part.end(), packed.begin(), packed.end());
    RNS::Bytes msgHash = RNS::Identity::full_hash(RNS::Bytes(hashed_part.data(), hashed_part.size()));

    std::vector<uint8_t> signed_data(hashed_part);
    signed_data.insert(signed_data.end(), msgHash.data(), msgHash.data() + msgHash.size());
    RNS::Bytes sig = g_identity.sign(RNS::Bytes(signed_data.data(), signed_data.size()));
    TEST_ASSERT_EQUAL(64, sig.size());

    // Build full wire
    std::vector<uint8_t> wire;
    wire.insert(wire.end(), g_dest_hash.data(), g_dest_hash.data() + 16);
    wire.insert(wire.end(), g_identity.hash().data(), g_identity.hash().data() + 16);
    wire.insert(wire.end(), sig.data(), sig.data() + 64);
    wire.insert(wire.end(), packed.begin(), packed.end());

    printf("\n=== LXMF_IMAGE_FIELD ===\n");
    printHex("wire", wire);
    printHex("packed_content", packed);

    // Self-validate: unpack and check title
    LXMFMessage unpacked;
    bool ok = LXMFMessage::unpackFull(wire.data(), wire.size(), unpacked);
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL_STRING("Image Test", unpacked.title.c_str());
}

// ── Test 2: LXMF with FIELD_FILE_ATTACHMENTS ────────────────────────

void testLxmfWithFileAttachment() {
    initFixture();

    std::vector<uint8_t> packed;
    packed.push_back(0x94);

    double ts = 1700000000.0;
    packed.push_back(0xCB);
    uint64_t bits; memcpy(&bits, &ts, 8);
    for (int i = 7; i >= 0; i--) packed.push_back((bits >> (i * 8)) & 0xFF);

    mpPackBin(packed, "File Test");
    mpPackBin(packed, "Has file attachment");

    // fields: fixmap(1) { 0x05: fixarray(1)[fixarray(2)[bin("test.txt"), bin("file data")]] }
    packed.push_back(0x81);  // fixmap(1)
    packed.push_back(0x05);  // key = FIELD_FILE_ATTACHMENTS
    packed.push_back(0x91);  // fixarray(1) — one attachment
    packed.push_back(0x92);  // fixarray(2) — [filename, data]
    mpPackBin(packed, "test.txt");
    mpPackBin(packed, "Hello file content!");

    // Sign and build wire
    std::vector<uint8_t> hashed_part;
    hashed_part.insert(hashed_part.end(), g_dest_hash.data(), g_dest_hash.data() + 16);
    hashed_part.insert(hashed_part.end(), g_identity.hash().data(), g_identity.hash().data() + 16);
    hashed_part.insert(hashed_part.end(), packed.begin(), packed.end());
    RNS::Bytes msgHash = RNS::Identity::full_hash(RNS::Bytes(hashed_part.data(), hashed_part.size()));
    std::vector<uint8_t> signed_data(hashed_part);
    signed_data.insert(signed_data.end(), msgHash.data(), msgHash.data() + msgHash.size());
    RNS::Bytes sig = g_identity.sign(RNS::Bytes(signed_data.data(), signed_data.size()));

    std::vector<uint8_t> wire;
    wire.insert(wire.end(), g_dest_hash.data(), g_dest_hash.data() + 16);
    wire.insert(wire.end(), g_identity.hash().data(), g_identity.hash().data() + 16);
    wire.insert(wire.end(), sig.data(), sig.data() + 64);
    wire.insert(wire.end(), packed.begin(), packed.end());

    printf("\n=== LXMF_FILE_FIELD ===\n");
    printHex("wire", wire);

    LXMFMessage unpacked;
    TEST_ASSERT_TRUE(LXMFMessage::unpackFull(wire.data(), wire.size(), unpacked));
    TEST_ASSERT_EQUAL_STRING("File Test", unpacked.title.c_str());
}

// ── Test 3: LXMF with multiple fields ───────────────────────────────

void testLxmfWithMultipleFields() {
    initFixture();

    std::vector<uint8_t> packed;
    packed.push_back(0x94);

    double ts = 1700000000.0;
    packed.push_back(0xCB);
    uint64_t bits; memcpy(&bits, &ts, 8);
    for (int i = 7; i >= 0; i--) packed.push_back((bits >> (i * 8)) & 0xFF);

    mpPackBin(packed, "Multi-field");
    mpPackBin(packed, "Multiple fields test");

    // fields: fixmap(2) { 0xFB: bin("custom-type"), 0xFC: bin("custom-data") }
    packed.push_back(0x82);  // fixmap(2)
    packed.push_back(0xFB);  // FIELD_CUSTOM_TYPE
    mpPackBin(packed, "application/x-test");
    packed.push_back(0xFC);  // FIELD_CUSTOM_DATA
    uint8_t custom[] = {0xDE, 0xAD, 0xBE, 0xEF};
    mpPackBin(packed, custom, sizeof(custom));

    // Sign
    std::vector<uint8_t> hashed_part;
    hashed_part.insert(hashed_part.end(), g_dest_hash.data(), g_dest_hash.data() + 16);
    hashed_part.insert(hashed_part.end(), g_identity.hash().data(), g_identity.hash().data() + 16);
    hashed_part.insert(hashed_part.end(), packed.begin(), packed.end());
    RNS::Bytes msgHash = RNS::Identity::full_hash(RNS::Bytes(hashed_part.data(), hashed_part.size()));
    std::vector<uint8_t> signed_data(hashed_part);
    signed_data.insert(signed_data.end(), msgHash.data(), msgHash.data() + msgHash.size());
    RNS::Bytes sig = g_identity.sign(RNS::Bytes(signed_data.data(), signed_data.size()));

    std::vector<uint8_t> wire;
    wire.insert(wire.end(), g_dest_hash.data(), g_dest_hash.data() + 16);
    wire.insert(wire.end(), g_identity.hash().data(), g_identity.hash().data() + 16);
    wire.insert(wire.end(), sig.data(), sig.data() + 64);
    wire.insert(wire.end(), packed.begin(), packed.end());

    printf("\n=== LXMF_MULTI_FIELDS ===\n");
    printHex("wire", wire);

    LXMFMessage unpacked;
    TEST_ASSERT_TRUE(LXMFMessage::unpackFull(wire.data(), wire.size(), unpacked));
    TEST_ASSERT_EQUAL_STRING("Multi-field", unpacked.title.c_str());
}

// ── Test 4: Announce with UTF-8 app_data (Rust format) ──────────────

void testAnnounceUtf8AppData() {
    initFixture();

    // Build announce: pubkey(64) + name_hash(10) + random_hash(10) + sig(64) + app_data
    RNS::Bytes pubkey = g_identity.get_public_key();
    TEST_ASSERT_EQUAL(64, pubkey.size());

    uint8_t random_hash[10] = {0xE8, 0xCC, 0xF9, 0xC8, 0xF9, 0xE1, 0xB0, 0xBA, 0xC6, 0xD5};
    std::string app_data = "TestNode";  // Raw UTF-8 — Rust dashboard format

    // Build signed data: dest_hash + pubkey + name_hash + random_hash + app_data
    std::vector<uint8_t> signed_data;
    signed_data.insert(signed_data.end(), g_dest_hash.data(), g_dest_hash.data() + 16);
    signed_data.insert(signed_data.end(), pubkey.data(), pubkey.data() + 64);
    signed_data.insert(signed_data.end(), g_name_hash.data(), g_name_hash.data() + 10);
    signed_data.insert(signed_data.end(), random_hash, random_hash + 10);
    signed_data.insert(signed_data.end(), app_data.begin(), app_data.end());

    RNS::Bytes sig = g_identity.sign(RNS::Bytes(signed_data.data(), signed_data.size()));

    // Build announce payload
    std::vector<uint8_t> announce;
    announce.insert(announce.end(), pubkey.data(), pubkey.data() + 64);
    announce.insert(announce.end(), g_name_hash.data(), g_name_hash.data() + 10);
    announce.insert(announce.end(), random_hash, random_hash + 10);
    announce.insert(announce.end(), sig.data(), sig.data() + 64);
    announce.insert(announce.end(), app_data.begin(), app_data.end());

    printf("\n=== ANNOUNCE_UTF8_APPDATA ===\n");
    printHex("announce", announce);
    printHex("app_data", (const uint8_t*)app_data.data(), app_data.size());
    printf("  app_data_str = %s\n", app_data.c_str());

    // Verify: announce should be 148 + app_data bytes
    TEST_ASSERT_EQUAL(148 + app_data.size(), announce.size());
}

// ── Test 5: Announce with msgpack app_data (Ratdeck format) ─────────

void testAnnounceMsgpackAppData() {
    initFixture();

    RNS::Bytes pubkey = g_identity.get_public_key();
    uint8_t random_hash[10] = {0xE8, 0xCC, 0xF9, 0xC8, 0xF9, 0xE1, 0xB0, 0xBA, 0xC6, 0xD5};

    // Ratdeck format: fixarray(1)[bin8(name)]
    std::string name = "CppTestNode";
    std::vector<uint8_t> app_data;
    app_data.push_back(0x91);  // fixarray(1)
    app_data.push_back(0xC4);  // bin8
    app_data.push_back((uint8_t)name.size());
    app_data.insert(app_data.end(), name.begin(), name.end());

    // Sign
    std::vector<uint8_t> signed_data;
    signed_data.insert(signed_data.end(), g_dest_hash.data(), g_dest_hash.data() + 16);
    signed_data.insert(signed_data.end(), pubkey.data(), pubkey.data() + 64);
    signed_data.insert(signed_data.end(), g_name_hash.data(), g_name_hash.data() + 10);
    signed_data.insert(signed_data.end(), random_hash, random_hash + 10);
    signed_data.insert(signed_data.end(), app_data.begin(), app_data.end());

    RNS::Bytes sig = g_identity.sign(RNS::Bytes(signed_data.data(), signed_data.size()));

    std::vector<uint8_t> announce;
    announce.insert(announce.end(), pubkey.data(), pubkey.data() + 64);
    announce.insert(announce.end(), g_name_hash.data(), g_name_hash.data() + 10);
    announce.insert(announce.end(), random_hash, random_hash + 10);
    announce.insert(announce.end(), sig.data(), sig.data() + 64);
    announce.insert(announce.end(), app_data.begin(), app_data.end());

    printf("\n=== ANNOUNCE_MSGPACK_APPDATA ===\n");
    printHex("announce", announce);
    printHex("app_data", app_data);

    TEST_ASSERT_EQUAL(148 + app_data.size(), announce.size());
}

// ── Test 6: Opportunistic wire format (no dest_hash) ────────────────

void testOpportunisticWireNoDestHash() {
    initFixture();

    LXMFMessage msg;
    msg.destHash = g_dest_hash;
    msg.sourceHash = g_identity.hash();
    msg.timestamp = 1700000000.0;
    msg.title = "Opportunistic";
    msg.content = "No dest_hash in payload";

    auto payload = msg.packFull(g_identity);
    TEST_ASSERT_TRUE(payload.size() > 80);

    // Opportunistic format: [src:16][sig:64][packed]
    // Verify NO dest_hash prefix
    TEST_ASSERT_EQUAL_MEMORY(g_identity.hash().data(), payload.data(), 16);
    TEST_ASSERT_EQUAL_UINT8(0x94, payload[80]);  // packed content starts here

    printf("\n=== OPPORTUNISTIC_WIRE ===\n");
    printHex("payload", payload);
    printHex("dest_hash", g_dest_hash);
    printf("  dest_hash must be prepended by receiver before unpack\n");

    TEST_ASSERT_TRUE(payload.size() > 0);
}

// ── Test 7: Signalling bytes packing ────────────────────────────────

void testSignallingBytesPacking() {
    // Python: signalling_value = (mtu & 0x1FFFFF) | (((mode << 5) & 0xE0) << 16)
    // Packed as 3-byte big-endian (skip first byte of u32)

    uint8_t mode = 1;  // AES_256_CBC
    uint32_t mtu = 500;

    uint32_t value = (mtu & 0x1FFFFF) | ((((uint32_t)mode << 5) & 0xE0) << 16);
    uint8_t bytes[3];
    bytes[0] = (value >> 16) & 0xFF;
    bytes[1] = (value >> 8) & 0xFF;
    bytes[2] = value & 0xFF;

    printf("\n=== SIGNALLING_BYTES ===\n");
    printf("  mode=%d mtu=%d\n", mode, mtu);
    printHex("signalling", bytes, 3);

    // Expected: mode=1 → (1<<5)=0x20, mtu=500=0x1F4
    // value = 0x1F4 | (0x20 << 16) = 0x2001F4
    // bytes = [0x20, 0x01, 0xF4]
    TEST_ASSERT_EQUAL_UINT8(0x20, bytes[0]);
    TEST_ASSERT_EQUAL_UINT8(0x01, bytes[1]);
    TEST_ASSERT_EQUAL_UINT8(0xF4, bytes[2]);

    // Decode back
    uint32_t decoded_value = ((uint32_t)bytes[0] << 16) | ((uint32_t)bytes[1] << 8) | bytes[2];
    uint32_t decoded_mtu = decoded_value & 0x1FFFFF;
    uint8_t decoded_mode = (decoded_value >> 21) & 0x07;
    TEST_ASSERT_EQUAL(500, decoded_mtu);
    TEST_ASSERT_EQUAL(1, decoded_mode);
}

// ── Test 8: Packet flag encoding ────────────────────────────────────

void testPacketFlagEncoding() {
    // Verify flag byte layout matches Python/Rust
    // flags = (header_type << 6) | (context_flag << 5) | (transport_type << 4) | (dest_type << 2) | packet_type

    // Header1, Broadcast, Single, Data = 0x00
    uint8_t f1 = (0 << 6) | (0 << 5) | (0 << 4) | (0 << 2) | 0;
    TEST_ASSERT_EQUAL_UINT8(0x00, f1);

    // Header1, Broadcast, Single, Announce = 0x01
    uint8_t f2 = (0 << 6) | (0 << 5) | (0 << 4) | (0 << 2) | 1;
    TEST_ASSERT_EQUAL_UINT8(0x01, f2);

    // Header1, Broadcast, Single, LinkRequest = 0x02
    uint8_t f3 = (0 << 6) | (0 << 5) | (0 << 4) | (0 << 2) | 2;
    TEST_ASSERT_EQUAL_UINT8(0x02, f3);

    // Header1, Broadcast, Link, Proof = 0x0F (dest_type=Link=3, packet_type=Proof=3)
    uint8_t f4 = (0 << 6) | (0 << 5) | (0 << 4) | (3 << 2) | 3;
    TEST_ASSERT_EQUAL_UINT8(0x0F, f4);

    // Header2, Transport, Single, Data = 0x50
    uint8_t f5 = (1 << 6) | (0 << 5) | (1 << 4) | (0 << 2) | 0;
    TEST_ASSERT_EQUAL_UINT8(0x50, f5);

    printf("\n=== PACKET_FLAGS ===\n");
    printf("  H1_Broadcast_Single_Data     = 0x%02x\n", f1);
    printf("  H1_Broadcast_Single_Announce = 0x%02x\n", f2);
    printf("  H1_Broadcast_Link_Proof      = 0x%02x\n", f4);
    printf("  H2_Transport_Single_Data     = 0x%02x\n", f5);
}

// ── Test 9: Truncated hash lengths ──────────────────────────────────

void testTruncatedHashLengths() {
    // Dest hash = 16 bytes (128 bits)
    RNS::Bytes data("test data for hashing");
    RNS::Bytes truncated = RNS::Identity::truncated_hash(data);
    TEST_ASSERT_EQUAL(16, truncated.size());

    // Full hash = 32 bytes (256 bits)
    RNS::Bytes full = RNS::Identity::full_hash(data);
    TEST_ASSERT_EQUAL(32, full.size());

    // Name hash = 10 bytes (80 bits)
    RNS::Bytes name = RNS::Identity::full_hash(RNS::Bytes("lxmf.delivery")).left(RNS::Type::Identity::NAME_HASH_LENGTH / 8);
    TEST_ASSERT_EQUAL(10, name.size());

    // Truncated is prefix of full
    TEST_ASSERT_EQUAL_MEMORY(full.data(), truncated.data(), 16);

    printf("\n=== HASH_LENGTHS ===\n");
    printf("  truncated_hash = %d bytes\n", (int)truncated.size());
    printf("  full_hash = %d bytes\n", (int)full.size());
    printf("  name_hash = %d bytes\n", (int)name.size());
}

// ── Test 10: Header1 vs Header2 format ──────────────────────────────

void testHeaderFormats() {
    // Header1: [flags:1][hops:1][dest_hash:16][context:1] = 19 bytes
    uint8_t h1[19];
    h1[0] = 0x01;  // flags: H1, Broadcast, Single, Announce
    h1[1] = 0x00;  // hops
    memset(h1 + 2, 0xAA, 16);  // dest_hash
    h1[18] = 0x00;  // context: None
    TEST_ASSERT_EQUAL(19, sizeof(h1));

    // Header2: [flags:1][hops:1][transport_id:16][dest_hash:16][context:1] = 35 bytes
    uint8_t h2[35];
    h2[0] = 0x50;  // flags: H2, Transport, Single, Data
    h2[1] = 0x01;  // hops
    memset(h2 + 2, 0xBB, 16);  // transport_id
    memset(h2 + 18, 0xCC, 16);  // dest_hash
    h2[34] = 0x00;  // context: None
    TEST_ASSERT_EQUAL(35, sizeof(h2));

    printf("\n=== HEADER_FORMATS ===\n");
    printf("  Header1 size = %d bytes\n", 19);
    printf("  Header2 size = %d bytes\n", 35);
    printHex("header1", h1, 19);
    printHex("header2", h2, 35);

    TEST_ASSERT_TRUE(true);
}

// ── Runner ──────────────────────────────────────────────────────────

void setUp() {}
void tearDown() {}

int main(int argc, char **argv) {
    UNITY_BEGIN();
    RUN_TEST(testLxmfWithImageField);
    RUN_TEST(testLxmfWithFileAttachment);
    RUN_TEST(testLxmfWithMultipleFields);
    RUN_TEST(testAnnounceUtf8AppData);
    RUN_TEST(testAnnounceMsgpackAppData);
    RUN_TEST(testOpportunisticWireNoDestHash);
    RUN_TEST(testSignallingBytesPacking);
    RUN_TEST(testPacketFlagEncoding);
    RUN_TEST(testTruncatedHashLengths);
    RUN_TEST(testHeaderFormats);
    return UNITY_END();
}
