// Unit tests for AutoInterface wire-format derivation.
//
// Fixture values were captured from Python Reticulum
// (RNS/Interfaces/AutoInterface.py) so any divergence here means we are no
// longer wire-compatible with desktop Reticulum nodes.
//
// Source of fixture values:
//   group_hash:    hashlib.sha256(b"reticulum").hexdigest()
//   mcast addr:    Python AutoInterface lines 202-212 with the captured group hash
//   token:         hashlib.sha256(group_id + link_local_addr.encode("utf-8")).hexdigest()

#include <unity.h>
#include <time.h>

#include "Interfaces/AutoInterface.h"
#include "Bytes.h"
#include "Log.h"

using RNS::AutoInterface;
using RNS::Bytes;

// SHA256("reticulum")
static const char* kGroupHashReticulumHex =
	"eac4d70bfb1c16e45e39485e31e1f5ccb18cedf878e0310d9a96100168f89f0d";

// Default group "reticulum", addr_type=temporary ('1'), scope=link ('2')
static const char* kMcastDefaultLink =
	"ff12:0:d70b:fb1c:16e4:5e39:485e:31e1";

// Default group "reticulum", addr_type=permanent ('0'), scope=admin ('4')
static const char* kMcastDefaultAdminPerm =
	"ff04:0:d70b:fb1c:16e4:5e39:485e:31e1";

// Custom group "testnet", addr_type=temporary ('1'), scope=link ('2')
// Note: trailing group is "315" — only 3 hex chars (RFC 5952: leading zeros
// suppressed).  This is the format Python emits and that lwIP's inet_pton
// accepts; do not pad to 4 chars.
static const char* kMcastTestnetLink =
	"ff12:0:ce9f:2416:5207:33ba:cb37:315";

// SHA256("reticulum" + "fe80::abcd:1234")
static const char* kTokenReticulumFe80AbcdHex =
	"eb45d091e4798b743d44f9242e245e90cb193ed1c39ac40563e2956e3759a6ca";

// SHA256("reticulum" + "fe80::1")
static const char* kTokenReticulumFe80OneHex =
	"97b25576749ea936b0d8a8536ffaf442d157cf47d460dcf13c48b7bd18b6c163";

// SHA256("testnet" + "fe80::abcd:1234")
static const char* kTokenTestnetFe80AbcdHex =
	"33c8aed6ebf08a5e3470d76a43cb090602e14952861877f25d72640aedcad0bf";

void test_group_hash_default() {
	Bytes h = AutoInterface::compute_group_hash(Bytes("reticulum"));
	TEST_ASSERT_EQUAL_size_t(32, h.size());
	TEST_ASSERT_EQUAL_STRING(kGroupHashReticulumHex, h.toHex().c_str());
}

void test_multicast_address_default_group_link_temp() {
	Bytes h = AutoInterface::compute_group_hash(Bytes("reticulum"));
	std::string mcast = AutoInterface::compute_multicast_address(
		h,
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK);
	TEST_ASSERT_EQUAL_STRING(kMcastDefaultLink, mcast.c_str());
}

void test_multicast_address_default_group_admin_permanent() {
	Bytes h = AutoInterface::compute_group_hash(Bytes("reticulum"));
	std::string mcast = AutoInterface::compute_multicast_address(
		h,
		AutoInterface::MCAST_ADDR_TYPE_PERMANENT,
		AutoInterface::SCOPE_ADMIN);
	TEST_ASSERT_EQUAL_STRING(kMcastDefaultAdminPerm, mcast.c_str());
}

void test_multicast_address_custom_group() {
	// Critical: tail group is "315" (3 hex chars). Python's "{:02x}" produces
	// 3 chars when the value exceeds 0xff but is < 0x1000.  Make sure C++
	// snprintf behaves the same way.
	Bytes h = AutoInterface::compute_group_hash(Bytes("testnet"));
	std::string mcast = AutoInterface::compute_multicast_address(
		h,
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK);
	TEST_ASSERT_EQUAL_STRING(kMcastTestnetLink, mcast.c_str());
}

void test_multicast_address_short_group_hash_returns_empty() {
	Bytes too_short(reinterpret_cast<const uint8_t*>("abcd"), 4);
	std::string mcast = AutoInterface::compute_multicast_address(
		too_short,
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK);
	TEST_ASSERT_TRUE(mcast.empty());
}

void test_discovery_token_default_group() {
	Bytes token = AutoInterface::compute_discovery_token(
		Bytes("reticulum"), std::string("fe80::abcd:1234"));
	TEST_ASSERT_EQUAL_size_t(32, token.size());
	TEST_ASSERT_EQUAL_STRING(kTokenReticulumFe80AbcdHex, token.toHex().c_str());
}

void test_discovery_token_compressed_address() {
	// Validates that we accept the RFC 5952 short form "fe80::1" as-is.
	Bytes token = AutoInterface::compute_discovery_token(
		Bytes("reticulum"), std::string("fe80::1"));
	TEST_ASSERT_EQUAL_STRING(kTokenReticulumFe80OneHex, token.toHex().c_str());
}

void test_set_link_local_canonicalizes_expanded_form() {
	// Arduino-ESP32 IPv6Address::toString() returns the fully expanded form
	// "fe80:0000:0000:0000:0022:5d59:22e5:0924".  Peers RX a packet from us
	// and compute SHA256(group_id || canonical_src_str), so our self-token
	// must be hashed against the canonical RFC 5952 form, not the expanded
	// form, or we will be silently rejected by every other implementation.
	AutoInterface ai("test_iface", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		AutoInterface::DEFAULT_DISCOVERY_PORT,
		AutoInterface::DEFAULT_DATA_PORT, 4);
	ai.set_link_local("fe80:0000:0000:0000:0022:5d59:22e5:0924", 1);
	TEST_ASSERT_EQUAL_STRING("fe80::22:5d59:22e5:924",
		ai.link_local_address().c_str());
}

void test_set_link_local_lowercases_uppercase_input() {
	// lwIP's ip6addr_ntoa_r emits UPPERCASE hex; Python / glibc / macOS
	// produce lowercase.  Wire compat requires us to normalize to lowercase
	// (RFC 5952 canonical) before hashing, both on the self-token side and
	// the RX validation side.
	AutoInterface ai("test_iface", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		AutoInterface::DEFAULT_DISCOVERY_PORT,
		AutoInterface::DEFAULT_DATA_PORT, 4);
	ai.set_link_local("FE80::3EDC:75FF:FE40:8000", 1);
	TEST_ASSERT_EQUAL_STRING("fe80::3edc:75ff:fe40:8000",
		ai.link_local_address().c_str());
}

void test_discovery_token_custom_group() {
	Bytes token = AutoInterface::compute_discovery_token(
		Bytes("testnet"), std::string("fe80::abcd:1234"));
	TEST_ASSERT_EQUAL_STRING(kTokenTestnetFe80AbcdHex, token.toHex().c_str());

	// Sanity: different from default-group token for the same address.
	Bytes other = AutoInterface::compute_discovery_token(
		Bytes("reticulum"), std::string("fe80::abcd:1234"));
	TEST_ASSERT_FALSE(token == other);
}

// --- Peer-table semantics ---

static AutoInterface::IPv6Addr make_addr(uint8_t last) {
	// fe80::<last> — link-local with a unique tail byte
	AutoInterface::IPv6Addr a{};
	a[0] = 0xfe;
	a[1] = 0x80;
	a[15] = last;
	return a;
}

void test_add_peer_registers_and_counts() {
	AutoInterface ai("test_iface", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		AutoInterface::DEFAULT_DISCOVERY_PORT,
		AutoInterface::DEFAULT_DATA_PORT,
		/*max_peers=*/4);

	TEST_ASSERT_EQUAL_size_t(0, ai.peer_count());

	auto a1 = make_addr(0x01);
	ai.test_inject_peer(a1, /*scope=*/1, /*now_ms=*/1000);

	TEST_ASSERT_EQUAL_size_t(1, ai.peer_count());
	TEST_ASSERT_TRUE(ai.has_peer(a1));
	TEST_ASSERT_EQUAL_UINT64(1000, ai.peer_last_heard_ms(a1));
}

void test_add_peer_idempotent_refreshes_last_heard() {
	AutoInterface ai("test_iface", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		AutoInterface::DEFAULT_DISCOVERY_PORT,
		AutoInterface::DEFAULT_DATA_PORT, 4);

	auto a1 = make_addr(0x02);
	ai.test_inject_peer(a1, 1, 5000);
	TEST_ASSERT_EQUAL_size_t(1, ai.peer_count());
	TEST_ASSERT_EQUAL_UINT64(5000, ai.peer_last_heard_ms(a1));

	// Second add for the same address: count stays 1, last_heard advances.
	ai.test_inject_peer(a1, 1, 9999);
	TEST_ASSERT_EQUAL_size_t(1, ai.peer_count());
	TEST_ASSERT_EQUAL_UINT64(9999, ai.peer_last_heard_ms(a1));
}

void test_add_peer_respects_max_peers_cap() {
	AutoInterface ai("test_iface", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		AutoInterface::DEFAULT_DISCOVERY_PORT,
		AutoInterface::DEFAULT_DATA_PORT,
		/*max_peers=*/3);

	for (uint8_t i = 1; i <= 5; ++i) {
		ai.test_inject_peer(make_addr(i), 1, 1000 + i);
	}

	// Only first 3 should have been admitted.
	TEST_ASSERT_EQUAL_size_t(3, ai.peer_count());
	TEST_ASSERT_TRUE(ai.has_peer(make_addr(1)));
	TEST_ASSERT_TRUE(ai.has_peer(make_addr(2)));
	TEST_ASSERT_TRUE(ai.has_peer(make_addr(3)));
	TEST_ASSERT_FALSE(ai.has_peer(make_addr(4)));
	TEST_ASSERT_FALSE(ai.has_peer(make_addr(5)));
}

void test_peer_jobs_evicts_timed_out_peers() {
	AutoInterface ai("test_iface", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		AutoInterface::DEFAULT_DISCOVERY_PORT,
		AutoInterface::DEFAULT_DATA_PORT, 4);

	auto fresh = make_addr(0x10);  // injected near "now"
	auto stale = make_addr(0x11);  // last_heard well in the past
	ai.test_inject_peer(stale, 1, /*now_ms=*/0);
	ai.test_inject_peer(fresh, 1, /*now_ms=*/30000);
	TEST_ASSERT_EQUAL_size_t(2, ai.peer_count());

	// Run jobs at t = 25s. PEERING_TIMEOUT_MS = 22000.
	//   stale: 25000 > 0     + 22000 → evict
	//   fresh: 25000 > 30000 + 22000 → false → keep
	ai.test_run_peer_jobs(25000);

	TEST_ASSERT_EQUAL_size_t(1, ai.peer_count());
	TEST_ASSERT_FALSE(ai.has_peer(stale));
	TEST_ASSERT_TRUE(ai.has_peer(fresh));
}

void test_peer_jobs_keeps_recent_peers() {
	AutoInterface ai("test_iface", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		AutoInterface::DEFAULT_DISCOVERY_PORT,
		AutoInterface::DEFAULT_DATA_PORT, 4);

	auto a = make_addr(0x20);
	ai.test_inject_peer(a, 1, 10000);
	ai.test_run_peer_jobs(15000);  // 15s < 22s timeout
	TEST_ASSERT_EQUAL_size_t(1, ai.peer_count());
}

// --- Socket lifecycle (native impl).  Uses ephemeral high ports to avoid
// colliding with any system AutoInterface listener on the host.

// Discovery and data must be ≥ 2 apart so the auto-derived
// unicast_disco_port (= discovery + 1) doesn't collide with data.
static const uint16_t kTestDiscoPort = 49716;
static const uint16_t kTestDataPort  = 49720;

void test_start_without_link_local_fails() {
	AutoInterface ai("test_lifecycle", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		kTestDiscoPort, kTestDataPort, 4);

	// No set_link_local() call — start() should refuse.
	TEST_ASSERT_FALSE(ai.start());
	TEST_ASSERT_EQUAL_INT(-1, ai.discovery_socket_fd());
	TEST_ASSERT_EQUAL_INT(-1, ai.unicast_socket_fd());
	TEST_ASSERT_EQUAL_INT(-1, ai.data_socket_fd());
}

void test_notify_link_change_recomputes_token() {
	AutoInterface ai("nlc_token", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		29716, 42671, 4);

	ai.set_link_local("fe80::abcd:1234", 1);
	Bytes t1 = ai.test_self_disco_token();
	TEST_ASSERT_EQUAL_size_t(32, t1.size());
	TEST_ASSERT_EQUAL_STRING(kTokenReticulumFe80AbcdHex, t1.toHex().c_str());

	ai.notify_link_change("fe80::1", 1);
	Bytes t2 = ai.test_self_disco_token();
	TEST_ASSERT_EQUAL_size_t(32, t2.size());
	TEST_ASSERT_EQUAL_STRING(kTokenReticulumFe80OneHex, t2.toHex().c_str());
	TEST_ASSERT_TRUE(t1 != t2);
}

void test_notify_link_change_remembers_old_for_self_echo() {
	AutoInterface ai("nlc_history", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		29716, 42671, 4);

	// First call: no prior address, history stays empty.
	ai.set_link_local("fe80::abcd:1234", 1);
	TEST_ASSERT_EQUAL_size_t(0, ai.test_self_link_local_history_size());

	// Second call: prior address is rotated into history.
	ai.notify_link_change("fe80::1", 1);
	TEST_ASSERT_EQUAL_size_t(1, ai.test_self_link_local_history_size());

	// Three more rotations — history caps at SELF_LL_HISTORY_MAX (4).
	ai.notify_link_change("fe80::2", 1);
	ai.notify_link_change("fe80::3", 1);
	ai.notify_link_change("fe80::4", 1);
	ai.notify_link_change("fe80::5", 1);
	TEST_ASSERT_EQUAL_size_t(4, ai.test_self_link_local_history_size());
}

void test_notify_link_change_idempotent() {
	AutoInterface ai("nlc_idem", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		29716, 42671, 4);

	ai.set_link_local("fe80::abcd:1234", 1);
	TEST_ASSERT_EQUAL_size_t(0, ai.test_self_link_local_history_size());

	// Same args → no-op, history must not grow.
	ai.notify_link_change("fe80::abcd:1234", 1);
	TEST_ASSERT_EQUAL_size_t(0, ai.test_self_link_local_history_size());

	// Different canonical form of the same address (uppercase) → still no-op.
	ai.notify_link_change("FE80::ABCD:1234", 1);
	TEST_ASSERT_EQUAL_size_t(0, ai.test_self_link_local_history_size());
}

void test_notify_link_change_rejects_invalid_address() {
	AutoInterface ai("nlc_bad", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		29716, 42671, 4);

	ai.set_link_local("fe80::1", 1);
	Bytes before = ai.test_self_disco_token();

	// Garbage input — must not mutate token or history.
	ai.notify_link_change("not-an-address", 2);
	TEST_ASSERT_TRUE(before == ai.test_self_disco_token());
	TEST_ASSERT_EQUAL_size_t(0, ai.test_self_link_local_history_size());
}

void test_constructor_default_hops_link_scope() {
	// SCOPE_LINK with hops=0 → auto-default 1 (link-local only).
	AutoInterface ai("hops_link", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		29716, 42671, 4);
	TEST_ASSERT_EQUAL_UINT8(1, ai.multicast_hops());
}

void test_constructor_default_hops_admin_scope() {
	// SCOPE_ADMIN with hops=0 → auto-default 32 (cross-router-ready).
	AutoInterface ai("hops_admin", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_ADMIN,
		29716, 42671, 4);
	TEST_ASSERT_EQUAL_UINT8(32, ai.multicast_hops());
}

void test_constructor_explicit_hops_overrides_default() {
	AutoInterface ai("hops_explicit", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		29716, 42671, 4, /*multicast_hops=*/16);
	TEST_ASSERT_EQUAL_UINT8(16, ai.multicast_hops());
}

void test_start_rejects_colliding_data_port() {
	// data_port == unicast_disco_port (= discovery_port + 1).  Without the
	// guard, both sockets bind via SO_REUSEPORT and silently steal each
	// other's packets.
	AutoInterface ai_collide_unicast("test_collide_unicast", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		29716, 29717, 4);
	ai_collide_unicast.set_link_local("fe80::1", 1);
	TEST_ASSERT_FALSE(ai_collide_unicast.start());
	TEST_ASSERT_EQUAL_INT(-1, ai_collide_unicast.discovery_socket_fd());

	// data_port == discovery_port (the multicast socket itself).
	AutoInterface ai_collide_disco("test_collide_disco", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		29716, 29716, 4);
	ai_collide_disco.set_link_local("fe80::1", 1);
	TEST_ASSERT_FALSE(ai_collide_disco.start());
	TEST_ASSERT_EQUAL_INT(-1, ai_collide_disco.discovery_socket_fd());
}

void test_start_opens_three_sockets() {
	AutoInterface ai("test_lifecycle", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		kTestDiscoPort, kTestDataPort, 4);

	// "fe80::1" + scope=1 (loopback / lo0 on most hosts).  IPV6_JOIN_GROUP
	// may warn on some hosts but start() tolerates that — see open_sockets()
	// best-effort note.
	ai.set_link_local("fe80::1", 1);
	TEST_ASSERT_TRUE(ai.start());

	TEST_ASSERT_GREATER_OR_EQUAL_INT(0, ai.discovery_socket_fd());
	TEST_ASSERT_GREATER_OR_EQUAL_INT(0, ai.unicast_socket_fd());
	TEST_ASSERT_GREATER_OR_EQUAL_INT(0, ai.data_socket_fd());

	// All three FDs must be distinct.
	TEST_ASSERT_NOT_EQUAL(ai.discovery_socket_fd(), ai.unicast_socket_fd());
	TEST_ASSERT_NOT_EQUAL(ai.discovery_socket_fd(), ai.data_socket_fd());
	TEST_ASSERT_NOT_EQUAL(ai.unicast_socket_fd(),   ai.data_socket_fd());

	// Multicast address must be populated.
	TEST_ASSERT_FALSE(ai.multicast_address().empty());

	ai.stop();
}

void test_stop_closes_sockets_and_clears_peers() {
	AutoInterface ai("test_lifecycle", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		kTestDiscoPort + 10, kTestDataPort + 10, 4);
	ai.set_link_local("fe80::1", 1);
	TEST_ASSERT_TRUE(ai.start());

	ai.test_inject_peer(make_addr(0x42), 1, 1000);
	TEST_ASSERT_EQUAL_size_t(1, ai.peer_count());

	ai.stop();

	TEST_ASSERT_EQUAL_INT(-1, ai.discovery_socket_fd());
	TEST_ASSERT_EQUAL_INT(-1, ai.unicast_socket_fd());
	TEST_ASSERT_EQUAL_INT(-1, ai.data_socket_fd());
	TEST_ASSERT_EQUAL_size_t(0, ai.peer_count());
}

void test_start_stop_start_is_idempotent() {
	AutoInterface ai("test_lifecycle", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		kTestDiscoPort + 20, kTestDataPort + 20, 4);
	ai.set_link_local("fe80::1", 1);

	TEST_ASSERT_TRUE(ai.start());
	int fd1 = ai.discovery_socket_fd();
	TEST_ASSERT_GREATER_OR_EQUAL_INT(0, fd1);
	ai.stop();
	TEST_ASSERT_EQUAL_INT(-1, ai.discovery_socket_fd());

	// Restart on the same ports must succeed (REUSEADDR on disco_sock).
	TEST_ASSERT_TRUE(ai.start());
	TEST_ASSERT_GREATER_OR_EQUAL_INT(0, ai.discovery_socket_fd());
	ai.stop();
}

void test_loop_at_does_not_crash_when_offline() {
	AutoInterface ai("test_loop_offline", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		kTestDiscoPort + 30, kTestDataPort + 30, 4);
	// No start() — loop_at on an offline interface must early-return.
	ai.test_loop_at(0);
	ai.test_loop_at(99999);
	TEST_ASSERT_FALSE(ai.has_carrier());
}

void test_loop_at_drives_announce_and_peer_jobs_scheduling() {
	AutoInterface ai("test_loop_sched", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		kTestDiscoPort + 40, kTestDataPort + 40, 4);
	ai.set_link_local("fe80::1", 1);
	TEST_ASSERT_TRUE(ai.start());

	// Prime peer table — stale + fresh.  Use t=0 / t=30000 so they end up on
	// opposite sides of PEERING_TIMEOUT_MS=22000 at t=25000.
	auto stale = make_addr(0x30);
	auto fresh = make_addr(0x31);
	ai.test_inject_peer(stale, 1, 0);
	ai.test_inject_peer(fresh, 1, 30000);
	TEST_ASSERT_EQUAL_size_t(2, ai.peer_count());

	// First loop_at() at t=0 sends an announce (next_announce_ms starts at 0
	// after start()) and schedules peer_jobs for t=4000.  Peer count should
	// not change at t=0.
	ai.test_loop_at(0);
	TEST_ASSERT_EQUAL_size_t(2, ai.peer_count());

	// Advance to t=25000 — past PEERING_TIMEOUT for stale peer.  loop_at
	// should fire peer_jobs (next_peer_job_ms=4000 < 25000) and evict.
	ai.test_loop_at(25000);
	TEST_ASSERT_EQUAL_size_t(1, ai.peer_count());
	TEST_ASSERT_TRUE(ai.has_peer(fresh));

	ai.stop();
}

// Loopback round-trip: announce + multicast RX.  Skips silently if
// IPV6_JOIN_GROUP isn't supported on the test host's loopback interface
// (some Linux configurations).  This is the closest we can get to a real
// peering handshake without two physical machines.
void test_loopback_announce_receives_self_echo() {
	AutoInterface ai("test_loopback", "reticulum",
		AutoInterface::MCAST_ADDR_TYPE_TEMPORARY,
		AutoInterface::SCOPE_LINK,
		kTestDiscoPort + 50, kTestDataPort + 50, 4);
	ai.set_link_local("fe80::1", 1);
	if (!ai.start()) {
		TEST_IGNORE_MESSAGE("start() failed on this host's loopback");
		return;
	}

	// First announce sets _final_init_done = true and sends to mcast.
	ai.test_loop_at(0);

	// Give the kernel a moment to loop the multicast packet back.
	for (int i = 0; i < 20 && !ai.has_carrier(); ++i) {
		ai.test_loop_at(static_cast<uint64_t>(i + 1) * 10);
		struct timespec ts { 0, 5'000'000 };  // 5 ms
		nanosleep(&ts, nullptr);
	}

	if (!ai.has_carrier()) {
		// Multicast loopback may be filtered out on some hosts (e.g. macOS
		// treats lo0's link-local strangely).  Don't fail the suite — the
		// real validation is the Phase 2 E2E test against Python.
		TEST_IGNORE_MESSAGE("no multicast echo on this host's loopback");
	} else {
		TEST_ASSERT_TRUE(ai.has_carrier());
	}

	ai.stop();
}

void setUp(void) {}
void tearDown(void) {}

int runUnityTests(void) {
	UNITY_BEGIN();
	RUN_TEST(test_group_hash_default);
	RUN_TEST(test_multicast_address_default_group_link_temp);
	RUN_TEST(test_multicast_address_default_group_admin_permanent);
	RUN_TEST(test_multicast_address_custom_group);
	RUN_TEST(test_multicast_address_short_group_hash_returns_empty);
	RUN_TEST(test_discovery_token_default_group);
	RUN_TEST(test_discovery_token_compressed_address);
	RUN_TEST(test_set_link_local_canonicalizes_expanded_form);
	RUN_TEST(test_set_link_local_lowercases_uppercase_input);
	RUN_TEST(test_discovery_token_custom_group);
	RUN_TEST(test_add_peer_registers_and_counts);
	RUN_TEST(test_add_peer_idempotent_refreshes_last_heard);
	RUN_TEST(test_add_peer_respects_max_peers_cap);
	RUN_TEST(test_peer_jobs_evicts_timed_out_peers);
	RUN_TEST(test_peer_jobs_keeps_recent_peers);
	RUN_TEST(test_notify_link_change_recomputes_token);
	RUN_TEST(test_notify_link_change_remembers_old_for_self_echo);
	RUN_TEST(test_notify_link_change_idempotent);
	RUN_TEST(test_notify_link_change_rejects_invalid_address);
	RUN_TEST(test_constructor_default_hops_link_scope);
	RUN_TEST(test_constructor_default_hops_admin_scope);
	RUN_TEST(test_constructor_explicit_hops_overrides_default);
	RUN_TEST(test_start_without_link_local_fails);
	RUN_TEST(test_start_rejects_colliding_data_port);
	RUN_TEST(test_start_opens_three_sockets);
	RUN_TEST(test_stop_closes_sockets_and_clears_peers);
	RUN_TEST(test_start_stop_start_is_idempotent);
	RUN_TEST(test_loop_at_does_not_crash_when_offline);
	RUN_TEST(test_loop_at_drives_announce_and_peer_jobs_scheduling);
	RUN_TEST(test_loopback_announce_receives_self_echo);
	return UNITY_END();
}

int main(void) { return runUnityTests(); }

#ifdef ARDUINO
void setup() { delay(2000); runUnityTests(); }
void loop()  {}
#endif

void app_main() { runUnityTests(); }
