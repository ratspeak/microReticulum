#include "AutoInterface.h"
#include "AutoInterfacePeer.h"

#include "../Log.h"
#include "../Transport.h"
#include "../Utilities/OS.h"

#include <cstdio>
#include <cstring>
#include <vector>

// Sockets layer — POSIX on native, lwIP on Arduino.  lwIP intentionally
// exposes a BSD-compatible API via <lwip/sockets.h> (socket/bind/recvfrom/
// sendto/setsockopt/fcntl all work as macros), so the bodies below are
// identical on both targets.
#ifdef ARDUINO
#include <lwip/opt.h>
// Defense in depth: AutoInterface needs IPv6 + MLD enabled in lwIP so
// IPV6_JOIN_GROUP works.  espressif32@6.7.0's prebuilt SDK enables both
// (LWIP_IPV6=1, LWIP_IPV6_MLD inherited from LWIP_IPV6); if a future
// platform release flips that off, fail loudly at compile time so we
// don't ship silent multicast breakage.
#if !LWIP_IPV6
#error "AutoInterface requires lwIP IPv6.  CONFIG_LWIP_IPV6 must be enabled."
#endif
#if !LWIP_IPV6_MLD
#error "AutoInterface requires lwIP MLD.  CONFIG_LWIP_IPV6_MLD must be enabled."
#endif
#include <lwip/sockets.h>
#include <lwip/inet.h>
// errno on lwIP is provided via Arduino's stdlib; <cerrno> is safe to include.
#include <cerrno>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace RNS {

	AutoInterface::AutoInterface(const char* name,
								 const char* group_id,
								 char addr_type,
								 char scope,
								 uint16_t discovery_port,
								 uint16_t data_port,
								 uint8_t max_peers)
		: _addr_type(addr_type),
		  _scope(scope),
		  _discovery_port(discovery_port),
		  _unicast_disco_port(discovery_port + 1),
		  _data_port(data_port),
		  _max_peers(max_peers)
	{
		_name = name ? name : "AutoInterface";
		_group_id_bytes = Bytes(group_id);
		_HW_MTU = HW_MTU;
		_FIXED_MTU = FIXED_MTU;
		_bitrate = BITRATE_GUESS;
		_IN = true;
		_OUT = true;
	}

	AutoInterface::~AutoInterface() {
		if (_online) {
			stop();
		}
	}

	namespace {
		// Python / glibc / macOS produce lowercase canonical IPv6 strings;
		// lwIP's ip6addr_ntoa_r produces UPPERCASE.  RFC 5952 mandates
		// lowercase, so normalize here so our SHA256 hashes wire-match
		// every other AutoInterface implementation regardless of platform.
		std::string canonicalize_ipv6(const std::string& addr_str) {
			struct in6_addr tmp;
			if (inet_pton(AF_INET6, addr_str.c_str(), &tmp) != 1) return addr_str;
			char buf[INET6_ADDRSTRLEN];
			if (inet_ntop(AF_INET6, &tmp, buf, sizeof(buf)) == nullptr) return addr_str;
			std::string out(buf);
			for (auto& c : out) {
				if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
			}
			return out;
		}
	}

	void AutoInterface::set_link_local(const std::string& addr_str, uint32_t scope_id) {
		_scope_id = scope_id;
		// Re-canonicalize so the stored form is the lowercase RFC 5952 form
		// regardless of whether the caller passed an expanded
		// "fe80:0000:..." form (Arduino IPv6Address::toString) or
		// uppercase from lwIP.  Peers compute their expected self-token by
		// hashing what they read off recvfrom + inet_ntop, which on every
		// other implementation is lowercase canonical.
		struct in6_addr tmp;
		if (inet_pton(AF_INET6, addr_str.c_str(), &tmp) == 1) {
			std::memcpy(_self_link_local_bin.data(), &tmp, 16);
		}
		_link_local_addr = canonicalize_ipv6(addr_str);
		_self_disco_token = compute_discovery_token(_group_id_bytes, _link_local_addr);
	}

	bool AutoInterface::start() {
		if (_online) return true;
		if (_link_local_addr.empty()) {
			WARNING("AutoInterface::start: no link-local address configured");
			return false;
		}

		// Compute group hash + multicast address now (cheap; idempotent).
		_group_hash       = compute_group_hash(_group_id_bytes);
		_mcast_addr_str   = compute_multicast_address(_group_hash, _addr_type, _scope);
		struct in6_addr mc_tmp;
		if (inet_pton(AF_INET6, _mcast_addr_str.c_str(), &mc_tmp) != 1) {
			WARNING("AutoInterface::start: invalid multicast address");
			return false;
		}
		std::memcpy(_mcast_addr_bin.data(), &mc_tmp, 16);

		if (!open_sockets()) {
			close_sockets();
			return false;
		}

		_online            = true;
		_final_init_done   = false;   // ignore any RX before peer_jobs first tick
		_next_announce_ms  = 0;
		_next_peer_job_ms  = PEER_JOB_INTERVAL_MS;
		_last_mcast_echo_ms = 0;
		_has_mcast_echo    = false;
		return true;
	}

	void AutoInterface::stop() {
		if (!_online) return;
		// Tear down all spawned peers — Transport must not retain stale refs.
		for (auto& kv : _peers) {
			Transport::deregister_interface(kv.second.wrapper);
			kv.second.peer_iface->stop();
		}
		_peers.clear();
		close_sockets();
		_online          = false;
		_final_init_done = false;
		_has_mcast_echo  = false;
	}

	void AutoInterface::loop() {
		loop_at(static_cast<uint64_t>(Utilities::OS::ltime()));
	}

	void AutoInterface::loop_at(uint64_t now_ms) {
		if (!_online) return;

		// Drain RX (each capped to 4 packets / call to bound CPU).
		poll_multicast();
		poll_unicast_disco();
		poll_data();

		if (now_ms >= _next_announce_ms) {
			announce_peer();
			_next_announce_ms = now_ms + ANNOUNCE_INTERVAL_MS;
			// First announce sent — RX may now process discovery packets.
			_final_init_done = true;
		}

		if (now_ms >= _next_peer_job_ms) {
			peer_jobs(now_ms);
			_next_peer_job_ms = now_ms + PEER_JOB_INTERVAL_MS;
		}
	}

	void AutoInterface::send_outgoing(const Bytes& /*data*/) {
		// No-op. Outbound goes through per-peer wrappers (matches Python).
	}

	// --- Wire-format derivation ---
	//
	// Mirrors Python AutoInterface.py:
	//   - group_hash       = SHA256(group_id)                        (lines 202-203)
	//   - mcast address    = "ff{type}{scope}:0:{g[2:4]}:..."        (lines 204-212)
	//                        each ":NN:" pair is uint16 = (g[2k]<<8)|g[2k+1],
	//                        printed with min-2 hex chars (Python "{:02x}")
	//   - discovery token  = SHA256(group_id || link_local_addr_str) (lines 491-501)
	//                        link_local_addr_str is canonical RFC 5952 (no scope suffix)

	Bytes AutoInterface::compute_group_hash(const Bytes& group_id) {
		return Identity::full_hash(group_id);
	}

	std::string AutoInterface::compute_multicast_address(const Bytes& group_hash,
														 char addr_type,
														 char scope) {
		if (group_hash.size() < 14) {
			return std::string();
		}
		const uint8_t* g = group_hash.data();
		char buf[64];
		std::snprintf(buf, sizeof(buf),
			"ff%c%c:0:%02x:%02x:%02x:%02x:%02x:%02x",
			addr_type, scope,
			(unsigned)((g[2]  << 8) | g[3]),
			(unsigned)((g[4]  << 8) | g[5]),
			(unsigned)((g[6]  << 8) | g[7]),
			(unsigned)((g[8]  << 8) | g[9]),
			(unsigned)((g[10] << 8) | g[11]),
			(unsigned)((g[12] << 8) | g[13]));
		return std::string(buf);
	}

	Bytes AutoInterface::compute_discovery_token(const Bytes& group_id,
												 const std::string& link_local_addr) {
		Bytes material;
		material.append(group_id);
		material.append(link_local_addr);
		return Identity::full_hash(material);
	}

	// --- Peer table semantics ---

	bool AutoInterface::has_peer(const IPv6Addr& addr) const {
		return _peers.find(addr_key(addr)) != _peers.end();
	}

	uint64_t AutoInterface::peer_last_heard_ms(const IPv6Addr& addr) const {
		auto it = _peers.find(addr_key(addr));
		return it == _peers.end() ? 0 : it->second.last_heard_ms;
	}

	void AutoInterface::add_peer(const IPv6Addr& addr,
								 uint32_t scope_id,
								 uint64_t now_ms) {
		const std::string key = addr_key(addr);
		auto it = _peers.find(key);
		if (it != _peers.end()) {
			// Already known — just refresh the freshness timestamp.
			it->second.last_heard_ms = now_ms;
			return;
		}
		if (_peers.size() >= _max_peers) {
			WARNING("AutoInterface: peer cap reached, ignoring new peer");
			return;
		}

		// Create the peer impl as a shared_ptr; alias it into a base
		// shared_ptr<InterfaceImpl> so the Interface wrapper shares the same
		// control block (no double-delete).  The peer ctor already sets
		// HW_MTU / FIXED_MTU / bitrate / IN / OUT.
		auto peer_impl = std::make_shared<AutoInterfacePeer>(this, addr, scope_id);
		std::shared_ptr<InterfaceImpl> base = peer_impl;

		PeerEntry entry;
		entry.addr             = addr;
		entry.scope_id         = scope_id;
		entry.last_heard_ms    = now_ms;
		entry.last_outbound_ms = now_ms;
		entry.peer_iface       = peer_impl;
		entry.wrapper          = Interface(base);

		auto inserted = _peers.emplace(key, std::move(entry));
		Interface& w = inserted.first->second.wrapper;
		w.mode(_mode);
		w.start();   // sets _online = true on the impl
		Transport::register_interface(w);
	}

	void AutoInterface::refresh_peer(const std::string& key, uint64_t now_ms) {
		auto it = _peers.find(key);
		if (it != _peers.end()) {
			it->second.last_heard_ms = now_ms;
		}
	}

	void AutoInterface::peer_jobs(uint64_t now_ms) {
		// Pass 1: collect timed-out peers (don't mutate map while iterating).
		std::vector<std::string> to_remove;
		to_remove.reserve(_peers.size());
		for (const auto& kv : _peers) {
			if (now_ms > kv.second.last_heard_ms + PEERING_TIMEOUT_MS) {
				to_remove.push_back(kv.first);
			}
		}

		// Pass 2: deregister + erase.
		for (const auto& key : to_remove) {
			auto it = _peers.find(key);
			if (it == _peers.end()) continue;
			Transport::deregister_interface(it->second.wrapper);
			it->second.peer_iface->stop();
			_peers.erase(it);
		}

		// Pass 3: reverse-peering — periodically send a unicast token to each
		// peer so they see us even when our multicast announces are dropped
		// by a hostile AP.  Mirrors Python AutoInterface lines 393-403.
		for (auto& kv : _peers) {
			if (now_ms > kv.second.last_outbound_ms + REVERSE_PEERING_INTERVAL_MS) {
				reverse_announce(kv.second.addr, kv.second.scope_id);
				kv.second.last_outbound_ms = now_ms;
			}
		}
	}

	// --- Test-only entry points ---

	void AutoInterface::test_inject_peer(const IPv6Addr& addr,
										 uint32_t scope_id,
										 uint64_t now_ms) {
		add_peer(addr, scope_id, now_ms);
	}

	void AutoInterface::test_run_peer_jobs(uint64_t now_ms) {
		peer_jobs(now_ms);
	}

	void AutoInterface::test_loop_at(uint64_t now_ms) {
		loop_at(now_ms);
	}

	// --- Socket lifecycle ---
	//
	// Three non-blocking AF_INET6 / SOCK_DGRAM sockets:
	//   _disco_sock     — RX multicast on _discovery_port + TX announces
	//   _unicast_sock   — RX reverse-peering tokens on _unicast_disco_port
	//   _data_sock      — RX peer payloads + TX peer payloads on _data_port
	//
	// Multicast group join (IPV6_JOIN_GROUP) is best-effort: failure logs a
	// warning but does not fail start().  This lets us boot without LAN
	// connectivity (or on hosts where the chosen scope id has no link-local
	// IPv6) and recover later when the network comes up — Python AutoInterface
	// has the same robustness property.

	namespace {
		// RAII helper to close a half-opened FD chain on early-return.
		void try_close(int& fd) {
			if (fd >= 0) {
				::close(fd);
				fd = -1;
			}
		}

		bool make_nonblocking(int fd) {
			int flags = ::fcntl(fd, F_GETFL, 0);
			if (flags < 0) return false;
			return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
		}

		bool bind_any(int fd, uint16_t port) {
			sockaddr_in6 a{};
			a.sin6_family = AF_INET6;
			a.sin6_port   = htons(port);
			a.sin6_addr   = in6addr_any;
			return ::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0;
		}
	}

	bool AutoInterface::open_sockets() {
		const int yes = 1;
		const int hops = 1;
		const unsigned int ifindex = static_cast<unsigned int>(_scope_id);

		// --- Multicast discovery socket (RX + TX announces) ---
		_disco_sock = ::socket(AF_INET6, SOCK_DGRAM, 0);
		if (_disco_sock < 0) {
			WARNING("AutoInterface: socket(disco) failed");
			return false;
		}
		::setsockopt(_disco_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
		::setsockopt(_disco_sock, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif
		const int v6only = 1;
		::setsockopt(_disco_sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
		// IPV6_MULTICAST_IF: outgoing multicast leaves on this interface
		::setsockopt(_disco_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
					 &ifindex, sizeof(ifindex));
		// IPV6_MULTICAST_LOOP: receive our own multicast frames so we can detect
		// the multicast echo (matches Python AutoInterface lines 451-464).
		::setsockopt(_disco_sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &yes, sizeof(yes));
		// IPV6_MULTICAST_HOPS = 1 — link-local only, never leak.
		::setsockopt(_disco_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops));
		if (!bind_any(_disco_sock, _discovery_port)) {
			WARNING("AutoInterface: bind(disco) failed");
			return false;
		}
		if (!make_nonblocking(_disco_sock)) {
			WARNING("AutoInterface: make_nonblocking(disco) failed");
			return false;
		}

		// IPV6_JOIN_GROUP: best-effort (see header note).
		struct ipv6_mreq mreq{};
		std::memcpy(&mreq.ipv6mr_multiaddr, _mcast_addr_bin.data(), 16);
		mreq.ipv6mr_interface = ifindex;
		if (::setsockopt(_disco_sock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
						 &mreq, sizeof(mreq)) != 0) {
			WARNINGF("AutoInterface: IPV6_JOIN_GROUP failed (errno=%d) — "
					 "multicast RX may not work on this interface", errno);
		}

		// --- Unicast discovery socket (port 29717) ---
		_unicast_sock = ::socket(AF_INET6, SOCK_DGRAM, 0);
		if (_unicast_sock < 0) return false;
		::setsockopt(_unicast_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
		::setsockopt(_unicast_sock, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif
		::setsockopt(_unicast_sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
		if (!bind_any(_unicast_sock, _unicast_disco_port)) {
			WARNING("AutoInterface: bind(unicast) failed");
			return false;
		}
		if (!make_nonblocking(_unicast_sock)) return false;

		// --- Data socket (port 42671) ---
		_data_sock = ::socket(AF_INET6, SOCK_DGRAM, 0);
		if (_data_sock < 0) return false;
		::setsockopt(_data_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
		::setsockopt(_data_sock, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif
		::setsockopt(_data_sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
		if (!bind_any(_data_sock, _data_port)) {
			WARNING("AutoInterface: bind(data) failed");
			return false;
		}
		if (!make_nonblocking(_data_sock)) return false;

		return true;
	}

	void AutoInterface::close_sockets() {
		if (_disco_sock >= 0) {
			// Best-effort leave group before closing.
			struct ipv6_mreq mreq{};
			std::memcpy(&mreq.ipv6mr_multiaddr, _mcast_addr_bin.data(), 16);
			mreq.ipv6mr_interface = static_cast<unsigned int>(_scope_id);
			::setsockopt(_disco_sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
						 &mreq, sizeof(mreq));
		}
		try_close(_disco_sock);
		try_close(_unicast_sock);
		try_close(_data_sock);
	}

	// --- TX / RX paths (BSD socket API; lwIP exposes the same signatures). ---

	namespace {
		constexpr int kPollBudget = 4;  // packets per poll() call

		void make_dst_sockaddr(sockaddr_in6& dst,
							   const AutoInterface::IPv6Addr& addr,
							   uint32_t scope_id,
							   uint16_t port) {
			std::memset(&dst, 0, sizeof(dst));
			dst.sin6_family   = AF_INET6;
			dst.sin6_port     = htons(port);
			dst.sin6_scope_id = scope_id;
			std::memcpy(&dst.sin6_addr, addr.data(), 16);
		}
	}

	void AutoInterface::announce_peer() {
		if (_disco_sock < 0 || _self_disco_token.size() < 32) return;
		sockaddr_in6 dst;
		make_dst_sockaddr(dst, _mcast_addr_bin, _scope_id, _discovery_port);
		ssize_t n = ::sendto(_disco_sock,
							 _self_disco_token.data(), _self_disco_token.size(),
							 0, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
		if (n < 0 && errno != ENETUNREACH && errno != EHOSTUNREACH) {
			VERBOSEF("AutoInterface::announce_peer: sendto errno=%d", errno);
		}
	}

	void AutoInterface::reverse_announce(const IPv6Addr& peer_addr,
										 uint32_t peer_scope) {
		if (_unicast_sock < 0 || _self_disco_token.size() < 32) return;
		sockaddr_in6 dst;
		make_dst_sockaddr(dst, peer_addr, peer_scope, _unicast_disco_port);
		::sendto(_unicast_sock,
				 _self_disco_token.data(), _self_disco_token.size(),
				 0, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
	}

	void AutoInterface::poll_multicast() {
		if (_disco_sock < 0) return;
		for (int i = 0; i < kPollBudget; ++i) {
			sockaddr_in6 src{};
			socklen_t sl = sizeof(src);
			ssize_t n = ::recvfrom(_disco_sock, _rx_buf, HW_MTU, 0,
								   reinterpret_cast<sockaddr*>(&src), &sl);
			if (n <= 0) break;
			if (!_final_init_done) continue;

			// Self-echo: confirms multicast loopback works (carrier).
			if (std::memcmp(&src.sin6_addr, _self_link_local_bin.data(), 16) == 0) {
				_last_mcast_echo_ms = static_cast<uint64_t>(Utilities::OS::ltime());
				_has_mcast_echo     = true;
				continue;
			}
			if (n < 32) continue;

			char src_str[64];
			::inet_ntop(AF_INET6, &src.sin6_addr, src_str, sizeof(src_str));
			std::string canon = canonicalize_ipv6(src_str);
			Bytes expected = compute_discovery_token(_group_id_bytes, canon);
			if (expected.size() < 32) continue;
			if (std::memcmp(_rx_buf, expected.data(), 32) != 0) continue;

			IPv6Addr addr;
			std::memcpy(addr.data(), &src.sin6_addr, 16);
			add_peer(addr, src.sin6_scope_id,
					 static_cast<uint64_t>(Utilities::OS::ltime()));
		}
	}

	void AutoInterface::poll_unicast_disco() {
		if (_unicast_sock < 0) return;
		for (int i = 0; i < kPollBudget; ++i) {
			sockaddr_in6 src{};
			socklen_t sl = sizeof(src);
			ssize_t n = ::recvfrom(_unicast_sock, _rx_buf, HW_MTU, 0,
								   reinterpret_cast<sockaddr*>(&src), &sl);
			if (n <= 0) break;
			if (!_final_init_done) continue;
			if (n < 32) continue;

			char src_str[64];
			::inet_ntop(AF_INET6, &src.sin6_addr, src_str, sizeof(src_str));
			std::string canon = canonicalize_ipv6(src_str);
			Bytes expected = compute_discovery_token(_group_id_bytes, canon);
			if (expected.size() < 32) continue;
			if (std::memcmp(_rx_buf, expected.data(), 32) != 0) continue;

			IPv6Addr addr;
			std::memcpy(addr.data(), &src.sin6_addr, 16);
			add_peer(addr, src.sin6_scope_id,
					 static_cast<uint64_t>(Utilities::OS::ltime()));
		}
	}

	void AutoInterface::poll_data() {
		if (_data_sock < 0) return;
		for (int i = 0; i < kPollBudget; ++i) {
			sockaddr_in6 src{};
			socklen_t sl = sizeof(src);
			ssize_t n = ::recvfrom(_data_sock, _rx_buf, HW_MTU, 0,
								   reinterpret_cast<sockaddr*>(&src), &sl);
			if (n <= 0) break;
			IPv6Addr addr;
			std::memcpy(addr.data(), &src.sin6_addr, 16);
			Bytes data(_rx_buf, static_cast<size_t>(n));
			route_inbound(data, addr);
		}
	}

	void AutoInterface::route_inbound(const Bytes& data, const IPv6Addr& src) {
		auto it = _peers.find(addr_key(src));
		if (it == _peers.end()) return;

		// MIF dedup ring — drops duplicates that arrive on multiple netifs
		// within MIF_DEDUP_TTL_MS.  Single-NIC devices rarely hit this but
		// the cost is small and it matches Python's behaviour.
		Bytes h = Identity::full_hash(data);
		const uint64_t now = static_cast<uint64_t>(Utilities::OS::ltime());
		for (const auto& d : _mif_dedup) {
			if (d.hash == h && now < d.expires_ms) return;
		}
		_mif_dedup.push_back({h, now + MIF_DEDUP_TTL_MS});
		while (_mif_dedup.size() > RNS_AUTOIFACE_MIF_DEDUP_LEN) {
			_mif_dedup.pop_front();
		}

		it->second.last_heard_ms = now;
		it->second.peer_iface->deliver_incoming(data);
	}

}  // namespace RNS
