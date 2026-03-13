/// Cross-platform compatibility fixture generator for microReticulum (C++).
///
/// Computes deterministic values from known seeds and validates them.
/// These same seeds and expected values are used by the Rust test suite
/// in raticulum-tests/tests/cpp_fixture_compat.rs to prove byte-level
/// interoperability between the C++ and Rust implementations.
///
/// Seeds:
///   x25519_seed  = SHA256("x25519_test_seed")
///   ed25519_seed = SHA256("ed25519_test_seed")
///   private_key  = x25519_seed(32) || ed25519_seed(32)

#include <unity.h>

#include "Identity.h"
#include "Cryptography/Hashes.h"
#include "Cryptography/Ed25519.h"
#include "Cryptography/X25519.h"
#include "Cryptography/AES.h"
#include "Cryptography/HMAC.h"
#include "Cryptography/HKDF.h"
#include "Cryptography/PKCS7.h"
#include "Cryptography/Token.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <string>

// ---- Inline MsgPack helpers (from ratdeck/src/reticulum/LXMFMessage.cpp) ----

static void mpPackFloat64(std::vector<uint8_t>& buf, double val) {
    buf.push_back(0xCB);
    uint64_t bits;
    memcpy(&bits, &val, 8);
    for (int i = 7; i >= 0; i--) {
        buf.push_back((bits >> (i * 8)) & 0xFF);
    }
}

static void mpPackBin(std::vector<uint8_t>& buf, const std::string& str) {
    size_t len = str.size();
    if (len < 256) {
        buf.push_back(0xC4);
        buf.push_back((uint8_t)len);
    } else {
        buf.push_back(0xC5);
        buf.push_back((len >> 8) & 0xFF);
        buf.push_back(len & 0xFF);
    }
    buf.insert(buf.end(), str.begin(), str.end());
}

// ---- Helpers ----

static void printHex(const char* label, const uint8_t* data, size_t len) {
    printf("  %s = ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static void printHex(const char* label, const RNS::Bytes& data) {
    printHex(label, data.data(), data.size());
}

static void printHex(const char* label, const std::vector<uint8_t>& data) {
    printHex(label, data.data(), data.size());
}

// ---- Global state computed once in setUp ----

static RNS::Identity g_identity({RNS::Type::NONE});
static RNS::Bytes g_x_seed;
static RNS::Bytes g_ed_seed;
static RNS::Bytes g_prv_key;
static RNS::Bytes g_identity_hash;
static RNS::Bytes g_x_pub;
static RNS::Bytes g_ed_pub;
static RNS::Bytes g_name_hash;       // name_hash("lxmf.delivery")
static RNS::Bytes g_dest_hash;       // truncated_hash(name_hash + identity_hash)

// Deterministic LXMF message parts
static const double FIXTURE_TIMESTAMP = 1700000000.0;
static const std::string FIXTURE_TITLE = "Hello from C++";
static const std::string FIXTURE_CONTENT = "Cross-platform test message";

static std::vector<uint8_t> g_packed_content;
static RNS::Bytes g_signature;
static std::vector<uint8_t> g_lxmf_wire;

// ---- Fixture setup ----

static bool g_initialized = false;

static void initFixture() {
    if (g_initialized) return;

    // Deterministic seeds (same as Rust cross_compat.rs)
    g_x_seed = RNS::Cryptography::sha256(RNS::Bytes("x25519_test_seed"));
    g_ed_seed = RNS::Cryptography::sha256(RNS::Bytes("ed25519_test_seed"));

    // Private key = x25519_seed(32) || ed25519_seed(32)
    g_prv_key = g_x_seed + g_ed_seed;

    // Create identity from deterministic key
    g_identity = RNS::Identity(false);
    TEST_ASSERT_TRUE_MESSAGE(g_identity.load_private_key(g_prv_key),
        "Failed to load deterministic private key");

    g_identity_hash = g_identity.hash();
    g_x_pub = g_identity.encryptionPublicKey();
    g_ed_pub = g_identity.signingPublicKey();

    // name_hash for "lxmf.delivery" = SHA256("lxmf.delivery")[:10]
    // Manual computation (avoids Destination.h → Link.h incomplete type issue)
    g_name_hash = RNS::Identity::full_hash(RNS::Bytes("lxmf.delivery")).left(RNS::Type::Identity::NAME_HASH_LENGTH / 8);

    // dest_hash = truncated_hash(name_hash + identity_hash)
    // This is how Destination::hash() works
    RNS::Bytes addr_material = g_name_hash + g_identity_hash;
    g_dest_hash = RNS::Identity::truncated_hash(addr_material);

    // Pack LXMF content: fixarray(4) + float64(ts) + bin(title) + bin(content) + fixmap(0)
    g_packed_content.clear();
    g_packed_content.push_back(0x94);  // fixarray of 4
    mpPackFloat64(g_packed_content, FIXTURE_TIMESTAMP);
    mpPackBin(g_packed_content, FIXTURE_TITLE);
    mpPackBin(g_packed_content, FIXTURE_CONTENT);
    g_packed_content.push_back(0x80);  // empty fixmap

    // Build signed_data = dest_hash + src_hash + packed + SHA256(dest_hash + src_hash + packed)
    // src_hash = identity_hash (we use same identity as sender)
    std::vector<uint8_t> hashed_part;
    hashed_part.insert(hashed_part.end(), g_dest_hash.data(), g_dest_hash.data() + g_dest_hash.size());
    hashed_part.insert(hashed_part.end(), g_identity_hash.data(), g_identity_hash.data() + g_identity_hash.size());
    hashed_part.insert(hashed_part.end(), g_packed_content.begin(), g_packed_content.end());

    RNS::Bytes hashed_bytes(hashed_part.data(), hashed_part.size());
    RNS::Bytes message_hash = RNS::Identity::full_hash(hashed_bytes);

    std::vector<uint8_t> signed_data_vec;
    signed_data_vec.insert(signed_data_vec.end(), hashed_part.begin(), hashed_part.end());
    signed_data_vec.insert(signed_data_vec.end(), message_hash.data(), message_hash.data() + message_hash.size());

    RNS::Bytes signed_data_bytes(signed_data_vec.data(), signed_data_vec.size());
    g_signature = g_identity.sign(signed_data_bytes);

    // Build full LXMF wire: [dest_hash:16][src_hash:16][signature:64][packed_content]
    g_lxmf_wire.clear();
    g_lxmf_wire.insert(g_lxmf_wire.end(), g_dest_hash.data(), g_dest_hash.data() + g_dest_hash.size());
    g_lxmf_wire.insert(g_lxmf_wire.end(), g_identity_hash.data(), g_identity_hash.data() + g_identity_hash.size());
    g_lxmf_wire.insert(g_lxmf_wire.end(), g_signature.data(), g_signature.data() + g_signature.size());
    g_lxmf_wire.insert(g_lxmf_wire.end(), g_packed_content.begin(), g_packed_content.end());

    g_initialized = true;

    // Print all fixture values for capture
    printf("\n=== C++ CROSS-COMPAT FIXTURE VALUES ===\n");
    printHex("x25519_seed", g_x_seed);
    printHex("ed25519_seed", g_ed_seed);
    printHex("x25519_pub", g_x_pub);
    printHex("ed25519_pub", g_ed_pub);
    printHex("identity_hash", g_identity_hash);
    printHex("name_hash_lxmf_delivery", g_name_hash);
    printHex("dest_hash", g_dest_hash);
    printHex("packed_content", g_packed_content);
    printHex("signature", g_signature);
    printHex("lxmf_wire", g_lxmf_wire);
    printf("  packed_content_len = %zu\n", g_packed_content.size());
    printf("  lxmf_wire_len = %zu\n", g_lxmf_wire.size());
    printf("=== END FIXTURE VALUES ===\n\n");
}

// ---- Tests ----

void testIdentityHash() {
    initFixture();
    // Identity hash should be 16 bytes (truncated SHA256)
    TEST_ASSERT_EQUAL_INT(16, g_identity_hash.size());
    printf("  C++ identity_hash = %s\n", g_identity_hash.toHex().c_str());

    // Verify identity hash = SHA256(x_pub || ed_pub)[:16]
    RNS::Bytes pub_combined = g_x_pub + g_ed_pub;
    RNS::Bytes expected = RNS::Identity::truncated_hash(pub_combined);
    TEST_ASSERT_TRUE_MESSAGE(g_identity_hash == expected,
        "Identity hash mismatch: SHA256(x_pub||ed_pub)[:16]");
}

void testNameHash() {
    initFixture();
    // name_hash should be 10 bytes (NAME_HASH_LENGTH=80 bits)
    TEST_ASSERT_EQUAL_INT(10, g_name_hash.size());
    printf("  C++ name_hash(lxmf.delivery) = %s\n", g_name_hash.toHex().c_str());

    // Verify: SHA256("lxmf.delivery")[:10]
    RNS::Bytes name_str("lxmf.delivery");
    RNS::Bytes expected = RNS::Identity::full_hash(name_str).left(10);
    TEST_ASSERT_TRUE_MESSAGE(g_name_hash == expected,
        "name_hash mismatch for lxmf.delivery");
}

void testDestHash() {
    initFixture();
    TEST_ASSERT_EQUAL_INT(16, g_dest_hash.size());
    printf("  C++ dest_hash = %s\n", g_dest_hash.toHex().c_str());

    // Verify: truncated_hash(name_hash + identity_hash)
    RNS::Bytes material = g_name_hash + g_identity_hash;
    RNS::Bytes expected = RNS::Identity::truncated_hash(material);
    TEST_ASSERT_TRUE_MESSAGE(g_dest_hash == expected,
        "dest_hash mismatch");
}

void testPackedContent() {
    initFixture();
    // Verify packed content starts with fixarray(4) marker
    TEST_ASSERT_EQUAL_UINT8(0x94, g_packed_content[0]);
    // Followed by float64 marker
    TEST_ASSERT_EQUAL_UINT8(0xCB, g_packed_content[1]);
    // Verify title is bin-encoded (0xC4 for bin8)
    // After 1 (fixarray) + 9 (float64) = offset 10
    TEST_ASSERT_EQUAL_UINT8(0xC4, g_packed_content[10]);
    printf("  C++ packed_content_len = %zu\n", g_packed_content.size());
}

void testSignature() {
    initFixture();
    TEST_ASSERT_EQUAL_INT(64, g_signature.size());

    // Verify signature: rebuild signed_data and validate
    std::vector<uint8_t> hashed_part;
    hashed_part.insert(hashed_part.end(), g_dest_hash.data(), g_dest_hash.data() + g_dest_hash.size());
    hashed_part.insert(hashed_part.end(), g_identity_hash.data(), g_identity_hash.data() + g_identity_hash.size());
    hashed_part.insert(hashed_part.end(), g_packed_content.begin(), g_packed_content.end());

    RNS::Bytes hashed_bytes(hashed_part.data(), hashed_part.size());
    RNS::Bytes message_hash = RNS::Identity::full_hash(hashed_bytes);

    std::vector<uint8_t> signed_data_vec;
    signed_data_vec.insert(signed_data_vec.end(), hashed_part.begin(), hashed_part.end());
    signed_data_vec.insert(signed_data_vec.end(), message_hash.data(), message_hash.data() + message_hash.size());

    RNS::Bytes signed_data_bytes(signed_data_vec.data(), signed_data_vec.size());

    TEST_ASSERT_TRUE_MESSAGE(g_identity.validate(g_signature, signed_data_bytes),
        "Signature validation failed in C++");
}

void testLxmfWireFormat() {
    initFixture();
    // Wire: [dest_hash:16][src_hash:16][signature:64][packed_content]
    size_t expected_len = 16 + 16 + 64 + g_packed_content.size();
    TEST_ASSERT_EQUAL_INT(expected_len, g_lxmf_wire.size());

    // Verify dest_hash at offset 0
    TEST_ASSERT_EQUAL_INT(0, memcmp(g_lxmf_wire.data(), g_dest_hash.data(), 16));
    // Verify src_hash at offset 16
    TEST_ASSERT_EQUAL_INT(0, memcmp(g_lxmf_wire.data() + 16, g_identity_hash.data(), 16));
    // Verify signature at offset 32
    TEST_ASSERT_EQUAL_INT(0, memcmp(g_lxmf_wire.data() + 32, g_signature.data(), 64));
    // Verify packed content at offset 96
    TEST_ASSERT_EQUAL_INT(0, memcmp(g_lxmf_wire.data() + 96, g_packed_content.data(), g_packed_content.size()));
}

void testAdditionalNameHashes() {
    initFixture();
    size_t nh_len = RNS::Type::Identity::NAME_HASH_LENGTH / 8;  // 10 bytes

    // Compute name hashes for other common aspect names (manually, same as Destination::name_hash)
    RNS::Bytes nh_prop = RNS::Identity::full_hash(RNS::Bytes("lxmf.propagation")).left(nh_len);
    RNS::Bytes nh_nn = RNS::Identity::full_hash(RNS::Bytes("nomadnetwork.node")).left(nh_len);

    TEST_ASSERT_EQUAL_INT(10, nh_prop.size());
    TEST_ASSERT_EQUAL_INT(10, nh_nn.size());

    printf("  C++ name_hash(lxmf.propagation) = %s\n", nh_prop.toHex().c_str());
    printf("  C++ name_hash(nomadnetwork.node) = %s\n", nh_nn.toHex().c_str());
}

void testPacketFlagEncoding() {
    initFixture();
    // Test flag byte encoding: (header_type<<6) | (context_flag<<5) | (transport_type<<4) | (dest_type<<2) | packet_type
    // Header1, no context, broadcast, single, data = 0x00
    uint8_t flags_h1_data = (0 << 6) | (0 << 5) | (0 << 4) | (0 << 2) | 0;
    TEST_ASSERT_EQUAL_UINT8(0x00, flags_h1_data);

    // Header1, no context, broadcast, single, announce = 0x01
    uint8_t flags_h1_announce = (0 << 6) | (0 << 5) | (0 << 4) | (0 << 2) | 1;
    TEST_ASSERT_EQUAL_UINT8(0x01, flags_h1_announce);

    // Header2, no context, transport, single, data = 0x50
    uint8_t flags_h2_transport_data = (1 << 6) | (0 << 5) | (1 << 4) | (0 << 2) | 0;
    TEST_ASSERT_EQUAL_UINT8(0x50, flags_h2_transport_data);

    // Header2, context set, transport, single, data = 0x70
    uint8_t flags_h2_ctx_transport = (1 << 6) | (1 << 5) | (1 << 4) | (0 << 2) | 0;
    TEST_ASSERT_EQUAL_UINT8(0x70, flags_h2_ctx_transport);

    printf("  C++ flag encoding verified\n");
}

void testAnnounceByteLayout() {
    initFixture();
    // Announce layout: [pubkey:64][name_hash:10][random_hash:10][signature:64][app_data...]
    // We construct it manually with deterministic random_hash

    RNS::Bytes pub_key = g_identity.get_public_key();  // 64 bytes
    TEST_ASSERT_EQUAL_INT(64, pub_key.size());

    // Use deterministic "random" hash
    RNS::Bytes random_hash = RNS::Cryptography::sha256(RNS::Bytes("deterministic_random")).left(10);

    // signed_data = dest_hash + public_key + name_hash + random_hash
    RNS::Bytes signed_data;
    signed_data << g_dest_hash << pub_key << g_name_hash << random_hash;

    RNS::Bytes sig = g_identity.sign(signed_data);
    TEST_ASSERT_EQUAL_INT(64, sig.size());

    // Announce payload: pubkey(64) + name_hash(10) + random_hash(10) + signature(64) = 148 bytes minimum
    RNS::Bytes announce_data;
    announce_data << pub_key << g_name_hash << random_hash << sig;
    TEST_ASSERT_EQUAL_INT(148, announce_data.size());

    // Verify byte offsets
    TEST_ASSERT_EQUAL_INT(0, memcmp(announce_data.data(), pub_key.data(), 64));
    TEST_ASSERT_EQUAL_INT(0, memcmp(announce_data.data() + 64, g_name_hash.data(), 10));
    TEST_ASSERT_EQUAL_INT(0, memcmp(announce_data.data() + 74, random_hash.data(), 10));
    TEST_ASSERT_EQUAL_INT(0, memcmp(announce_data.data() + 84, sig.data(), 64));

    // Validate signature
    TEST_ASSERT_TRUE_MESSAGE(g_identity.validate(sig, signed_data),
        "Announce signature validation failed");

    printHex("random_hash", random_hash);
    printHex("announce_signed_data", signed_data);
    printHex("announce_signature", sig);
    printHex("announce_data", announce_data);
    printf("  announce_data_len = %zu\n", announce_data.size());
}

void testEncryptDecryptRoundtrip() {
    initFixture();
    // Encrypt a known plaintext and verify we can decrypt it
    RNS::Bytes plaintext("secret from cpp fixture");
    RNS::Bytes ciphertext = g_identity.encrypt(plaintext);

    // Verify format: ephemeral_pub(32) + token
    TEST_ASSERT_TRUE_MESSAGE(ciphertext.size() > 32 + 16 + 32,
        "Ciphertext too short");

    RNS::Bytes decrypted = g_identity.decrypt(ciphertext);
    TEST_ASSERT_TRUE_MESSAGE(decrypted == plaintext,
        "Decrypt failed to recover plaintext");

    printf("  C++ encrypt/decrypt roundtrip OK, ciphertext_len=%zu\n", ciphertext.size());
}

// ---- Cross-encryption tests: C++ encrypts, Rust decrypts (and vice versa) ----

// Second identity for cross-encryption (simulates a remote peer)
static RNS::Identity g_peer_identity({RNS::Type::NONE});
static RNS::Bytes g_peer_x_seed;
static RNS::Bytes g_peer_ed_seed;
static RNS::Bytes g_peer_x_pub;
static RNS::Bytes g_peer_identity_hash;
static RNS::Bytes g_cross_ciphertext;
static RNS::Bytes g_cross_plaintext;

// Deterministic ECDH test: use known ephemeral key to verify shared secret
static RNS::Bytes g_ecdh_ephemeral_prv_seed;
static RNS::Bytes g_ecdh_ephemeral_pub;
static RNS::Bytes g_ecdh_shared_secret;

static bool g_cross_initialized = false;

static RNS::Bytes clampX25519(const RNS::Bytes& key) {
    // RFC 7748 clamping — same as Curve25519::dh1() and x25519-dalek::mul_clamped()
    uint8_t buf[32];
    memcpy(buf, key.data(), 32);
    buf[0]  &= 0xF8;
    buf[31]  = (buf[31] & 0x7F) | 0x40;
    return RNS::Bytes(buf, 32);
}

static void initCrossFixture() {
    initFixture();
    if (g_cross_initialized) return;

    // Create a second identity (the "peer" / recipient)
    g_peer_x_seed = RNS::Cryptography::sha256(RNS::Bytes("peer_x25519_seed"));
    g_peer_ed_seed = RNS::Cryptography::sha256(RNS::Bytes("peer_ed25519_seed"));

    // Clamp the X25519 seed to match production behavior.
    // In production, dh1() clamps keys at generation time. Curve25519::eval()
    // does NOT clamp internally, so imported keys must be pre-clamped for
    // cross-platform ECDH compatibility with x25519-dalek (which clamps in DH).
    g_peer_x_seed = clampX25519(g_peer_x_seed);

    RNS::Bytes peer_prv = g_peer_x_seed + g_peer_ed_seed;

    g_peer_identity = RNS::Identity(false);
    TEST_ASSERT_TRUE_MESSAGE(g_peer_identity.load_private_key(peer_prv),
        "Failed to load peer private key");

    g_peer_x_pub = g_peer_identity.encryptionPublicKey();
    g_peer_identity_hash = g_peer_identity.hash();

    // Deterministic ephemeral key for cross-encryption
    g_ecdh_ephemeral_prv_seed = clampX25519(
        RNS::Cryptography::sha256(RNS::Bytes("deterministic_ephemeral_seed")));
    auto eph_prv = RNS::Cryptography::X25519PrivateKey::from_private_bytes(g_ecdh_ephemeral_prv_seed);
    g_ecdh_ephemeral_pub = eph_prv->public_key()->public_bytes();

    // ECDH: ephemeral × peer_x_pub → shared secret for cross-encryption
    RNS::Bytes cross_shared = eph_prv->exchange(g_peer_x_pub);

    // HKDF: derive_key_64(shared, peer_identity_hash)
    RNS::Bytes cross_derived = RNS::Cryptography::hkdf(64, cross_shared, g_peer_identity_hash);

    // Deterministic Token encrypt: manually construct with known IV
    g_cross_plaintext = RNS::Bytes("cross-platform encryption test");
    RNS::Bytes cross_iv = RNS::Cryptography::sha256(RNS::Bytes("deterministic_iv")).left(16);
    RNS::Cryptography::Token cross_token(cross_derived);
    // We use the full Token encrypt (random IV) for C++ self-test, then manually
    // construct a deterministic version for the fixture.
    // Manual construction: PKCS7 pad → AES-256-CBC → HMAC
    RNS::Bytes padded = RNS::Cryptography::PKCS7::pad(g_cross_plaintext);
    RNS::Bytes signing_key = cross_derived.left(32);
    RNS::Bytes encryption_key = cross_derived.mid(32);
    RNS::Bytes aes_ct = RNS::Cryptography::AES_256_CBC::encrypt(padded, encryption_key, cross_iv);
    RNS::Bytes signed_parts = cross_iv + aes_ct;
    RNS::Bytes hmac = RNS::Cryptography::HMAC::generate(signing_key, signed_parts)->digest();
    RNS::Bytes token_bytes = signed_parts + hmac;

    // Full ciphertext: ephemeral_pub(32) + token(IV+ct+HMAC)
    g_cross_ciphertext = g_ecdh_ephemeral_pub + token_bytes;
    TEST_ASSERT_TRUE_MESSAGE(g_cross_ciphertext.size() == 112,
        "Deterministic cross ciphertext should be 112 bytes");

    // Verify C++ can decrypt the deterministic ciphertext
    RNS::Bytes verify_pt = g_peer_identity.decrypt(g_cross_ciphertext);
    TEST_ASSERT_TRUE_MESSAGE(verify_pt == g_cross_plaintext,
        "C++ failed to decrypt deterministic cross ciphertext");

    // Also test ECDH with the main identity's public key
    g_ecdh_shared_secret = eph_prv->exchange(g_x_pub);

    // Verify commutativity
    RNS::Bytes reverse_shared = g_identity.prv()->exchange(g_ecdh_ephemeral_pub);
    TEST_ASSERT_TRUE_MESSAGE(g_ecdh_shared_secret == reverse_shared,
        "ECDH commutativity failed in C++");

    g_cross_initialized = true;

    printf("\n=== C++ CROSS-ENCRYPTION FIXTURE VALUES ===\n");
    printHex("peer_x25519_seed", g_peer_x_seed);
    printHex("peer_ed25519_seed", g_peer_ed_seed);
    printHex("peer_x25519_pub", g_peer_x_pub);
    printHex("peer_identity_hash", g_peer_identity_hash);
    printHex("cross_ciphertext", g_cross_ciphertext);
    printf("  cross_ciphertext_len = %zu\n", g_cross_ciphertext.size());
    printf("  cross_plaintext = cross-platform encryption test\n");
    printHex("ecdh_ephemeral_seed", g_ecdh_ephemeral_prv_seed);
    printHex("ecdh_ephemeral_pub", g_ecdh_ephemeral_pub);
    printHex("ecdh_shared_secret", g_ecdh_shared_secret);
    printf("=== END CROSS-ENCRYPTION VALUES ===\n\n");
}

void testCrossEncryptionFixture() {
    initCrossFixture();
    // This test just ensures the cross-encryption fixture values are generated
    // and C++ can self-roundtrip
    TEST_ASSERT_EQUAL_INT(32, g_peer_x_pub.size());
    TEST_ASSERT_EQUAL_INT(16, g_peer_identity_hash.size());
    TEST_ASSERT_TRUE_MESSAGE(g_cross_ciphertext.size() > 80,
        "Cross ciphertext should be > 80 bytes");
    printf("  C++ cross-encryption fixture generated OK\n");
}

void testEcdhDeterministic() {
    initCrossFixture();
    // Verify ECDH with known ephemeral key produces deterministic shared secret
    TEST_ASSERT_EQUAL_INT(32, g_ecdh_shared_secret.size());
    TEST_ASSERT_EQUAL_INT(32, g_ecdh_ephemeral_pub.size());

    // Re-compute to verify determinism
    auto eph_prv2 = RNS::Cryptography::X25519PrivateKey::from_private_bytes(g_ecdh_ephemeral_prv_seed);
    RNS::Bytes eph_pub2 = eph_prv2->public_key()->public_bytes();
    TEST_ASSERT_TRUE_MESSAGE(g_ecdh_ephemeral_pub == eph_pub2,
        "Ephemeral public key derivation should be deterministic");
    RNS::Bytes shared2 = eph_prv2->exchange(g_x_pub);
    TEST_ASSERT_TRUE_MESSAGE(g_ecdh_shared_secret == shared2,
        "ECDH should be deterministic");

    printf("  C++ ECDH deterministic OK\n");
}

// ---- Test runner ----

void setUp(void) {}
void tearDown(void) {}

int runUnityTests(void) {
    UNITY_BEGIN();
    RUN_TEST(testIdentityHash);
    RUN_TEST(testNameHash);
    RUN_TEST(testDestHash);
    RUN_TEST(testPackedContent);
    RUN_TEST(testSignature);
    RUN_TEST(testLxmfWireFormat);
    RUN_TEST(testAdditionalNameHashes);
    RUN_TEST(testPacketFlagEncoding);
    RUN_TEST(testAnnounceByteLayout);
    RUN_TEST(testEncryptDecryptRoundtrip);
    RUN_TEST(testCrossEncryptionFixture);
    RUN_TEST(testEcdhDeterministic);
    return UNITY_END();
}

int main(void) {
    return runUnityTests();
}

#ifdef ARDUINO
void setup() {
    delay(2000);
    runUnityTests();
}
void loop() {}
#endif

void app_main() {
    runUnityTests();
}
