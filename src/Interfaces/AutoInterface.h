#pragma once

#include "../Interface.h"
#include "../Bytes.h"
#include "../Identity.h"

#include <array>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <string>

// MIF (multi-interface) dedup ring length.  Override per device in
// platformio.ini build_flags for memory-tight targets (e.g. Ratcom).
#ifndef RNS_AUTOIFACE_MIF_DEDUP_LEN
#define RNS_AUTOIFACE_MIF_DEDUP_LEN 48
#endif

// Default cap on concurrent spawned peers.  Each peer costs ~280 B plus
// whatever Transport caches for its paths.  Override per device.
#ifndef RNS_AUTOIFACE_MAX_PEERS_DEFAULT
#define RNS_AUTOIFACE_MAX_PEERS_DEFAULT 8
#endif

namespace RNS {

	class AutoInterfacePeer;

	/*
	 * Reticulum AutoInterface — IPv6 link-local multicast LAN auto-discovery.
	 *
	 * Wire-compatible with the Python reference implementation
	 * (RNS/Interfaces/AutoInterface.py). Listens on a multicast group derived
	 * from SHA256(group_id) and spawns a per-peer AutoInterfacePeer Interface
	 * for each discovered node.
	 *
	 * Design notes:
	 *   - One parent AutoInterface holds the multicast/unicast/data sockets.
	 *   - One AutoInterfacePeer (registered with Transport) per peer.
	 *   - Single-threaded, cooperative: loop() polls non-blocking sockets.
	 *   - IFAC: not implemented in v1 (see plan).
	 */
	class AutoInterface : public InterfaceImpl {
	public:
		// Wire-compatible defaults — must match Python AutoInterface.py
		static constexpr uint16_t DEFAULT_DISCOVERY_PORT      = 29716;
		static constexpr uint16_t DEFAULT_UNICAST_DISCO_PORT  = 29717;  // discovery + 1
		static constexpr uint16_t DEFAULT_DATA_PORT           = 42671;
		static constexpr const char* DEFAULT_GROUP_ID         = "reticulum";
		static constexpr uint16_t HW_MTU                      = 1196;
		static constexpr bool     FIXED_MTU                   = true;
		static constexpr uint32_t BITRATE_GUESS               = 10 * 1000 * 1000;

		static constexpr uint32_t ANNOUNCE_INTERVAL_MS         = 1600;
		static constexpr uint32_t PEER_JOB_INTERVAL_MS         = 4000;
		static constexpr uint32_t PEERING_TIMEOUT_MS           = 22000;
		static constexpr uint32_t MCAST_ECHO_TIMEOUT_MS        = 6500;
		static constexpr uint32_t REVERSE_PEERING_INTERVAL_MS  = 5200;  // 1.6 * 3.25
		static constexpr uint32_t MIF_DEDUP_TTL_MS             = 750;

		static constexpr char SCOPE_LINK                     = '2';
		static constexpr char SCOPE_ADMIN                    = '4';
		static constexpr char SCOPE_SITE                     = '5';
		static constexpr char SCOPE_ORGANISATION             = '8';
		static constexpr char SCOPE_GLOBAL                   = 'e';

		static constexpr char MCAST_ADDR_TYPE_PERMANENT      = '0';
		static constexpr char MCAST_ADDR_TYPE_TEMPORARY      = '1';

		using IPv6Addr = std::array<uint8_t, 16>;

		AutoInterface(const char* name = "AutoInterface",
					  const char* group_id = DEFAULT_GROUP_ID,
					  char addr_type = MCAST_ADDR_TYPE_TEMPORARY,
					  char scope     = SCOPE_LINK,
					  uint16_t discovery_port = DEFAULT_DISCOVERY_PORT,
					  uint16_t data_port      = DEFAULT_DATA_PORT,
					  uint8_t  max_peers      = RNS_AUTOIFACE_MAX_PEERS_DEFAULT);
		virtual ~AutoInterface();

		// InterfaceImpl overrides
		virtual bool start() override;
		virtual void stop() override;
		virtual void loop() override;
		virtual void send_outgoing(const Bytes& data) override;  // no-op (mirrors Python)

		// Diagnostics / UI surface
		size_t   peer_count()    const { return _peers.size(); }
		bool     has_carrier()   const { return _has_mcast_echo; }
		const std::string& multicast_address() const { return _mcast_addr_str; }
		const std::string& link_local_address() const { return _link_local_addr; }
		bool     has_peer(const IPv6Addr& addr) const;
		uint64_t peer_last_heard_ms(const IPv6Addr& addr) const;

		// Inject the local link-local address + interface scope id.
		// Must be called before start().  Production code resolves these from
		// WiFi.linkLocalIPv6() + esp_netif_get_netif_impl_index() (Arduino) or
		// getifaddrs() + if_nametoindex() (native).
		void set_link_local(const std::string& addr_str, uint32_t scope_id);

		// Diagnostic FD accessors — returns -1 when closed.
		int  discovery_socket_fd() const { return _disco_sock; }
		int  unicast_socket_fd()   const { return _unicast_sock; }
		int  data_socket_fd()      const { return _data_sock; }

		// Test-only entry points (do not call from production code).
		// Allow driving the peer table without real sockets / real time.
		void test_inject_peer(const IPv6Addr& addr, uint32_t scope_id, uint64_t now_ms);
		void test_run_peer_jobs(uint64_t now_ms);
		void test_loop_at(uint64_t now_ms);

		// Drive a single iteration with an injected clock.  Production code
		// uses the no-arg loop() which calls this with OS::ltime().
		void loop_at(uint64_t now_ms);

		virtual std::string toString() const override {
			return "AutoInterface[" + _name + "]";
		}

		// Wire-format derivation (pure, exposed for tests / external diagnostics).
		// All match the Python reference (RNS/Interfaces/AutoInterface.py).
		static Bytes       compute_group_hash(const Bytes& group_id);
		static std::string compute_multicast_address(const Bytes& group_hash,
													 char addr_type,
													 char scope);
		static Bytes       compute_discovery_token(const Bytes& group_id,
												   const std::string& link_local_addr);

	protected:
		friend class AutoInterfacePeer;

		// Lifecycle helpers — implemented in commits 4+
		bool open_sockets();
		void close_sockets();
		void poll_multicast();
		void poll_unicast_disco();
		void poll_data();
		void announce_peer();
		void reverse_announce(const IPv6Addr& peer_addr, uint32_t scope_id);
		void peer_jobs(uint64_t now_ms);
		void add_peer(const IPv6Addr& addr, uint32_t scope_id, uint64_t now_ms);
		void refresh_peer(const std::string& key, uint64_t now_ms);
		void route_inbound(const Bytes& data, const IPv6Addr& src);

		// Map key derivation
		static std::string addr_key(const IPv6Addr& addr) {
			return std::string(reinterpret_cast<const char*>(addr.data()), addr.size());
		}

		// Configuration (immutable after start)
		Bytes        _group_id_bytes;
		Bytes        _group_hash;
		char         _addr_type;
		char         _scope;
		uint16_t     _discovery_port;
		uint16_t     _unicast_disco_port;
		uint16_t     _data_port;
		uint8_t      _max_peers;
		std::string  _mcast_addr_str;
		IPv6Addr     _mcast_addr_bin{};

		// Sockets — opaque int FDs; -1 when closed
		int          _disco_sock      = -1;
		int          _unicast_sock    = -1;
		int          _data_sock       = -1;

		// Local link-local state
		std::string  _link_local_addr;
		IPv6Addr     _self_link_local_bin{};
		uint32_t     _scope_id        = 0;
		Bytes        _self_disco_token;

		// Peer table — keyed by 16-byte address (as std::string for cheap lookup)
		struct PeerEntry {
			IPv6Addr        addr{};
			uint32_t        scope_id        = 0;
			uint64_t        last_heard_ms   = 0;
			uint64_t        last_outbound_ms = 0;
			std::shared_ptr<AutoInterfacePeer> peer_iface;
			Interface       wrapper{Type::NONE};
		};
		std::map<std::string, PeerEntry> _peers;

		// Multi-interface dedup ring
		struct DedupEntry { Bytes hash; uint64_t expires_ms = 0; };
		std::deque<DedupEntry> _mif_dedup;

		// Pacing / state
		uint64_t _next_announce_ms  = 0;
		uint64_t _next_peer_job_ms  = 0;
		uint64_t _last_mcast_echo_ms = 0;
		bool     _has_mcast_echo    = false;
		bool     _final_init_done   = false;

		// RX scratch (single, reused across all three sockets — single-threaded).
		uint8_t  _rx_buf[HW_MTU + 4]{};
	};

}  // namespace RNS
