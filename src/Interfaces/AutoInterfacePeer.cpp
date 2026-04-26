#include "AutoInterfacePeer.h"
#include "AutoInterface.h"

#include "../Log.h"

#include <cstring>

#ifdef ARDUINO
#include <lwip/sockets.h>
#include <lwip/inet.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace RNS {

	AutoInterfacePeer::AutoInterfacePeer(AutoInterface* parent,
										 const AutoInterface::IPv6Addr& addr,
										 uint32_t scope_id)
		: _parent(parent),
		  _peer_addr(addr),
		  _peer_scope(scope_id)
	{
		_HW_MTU = AutoInterface::HW_MTU;
		_FIXED_MTU = AutoInterface::FIXED_MTU;
		_bitrate = AutoInterface::BITRATE_GUESS;
		_IN = true;
		_OUT = true;
	}

	AutoInterfacePeer::~AutoInterfacePeer() {}

	bool AutoInterfacePeer::start() { _online = true; return true; }
	void AutoInterfacePeer::stop()  { _online = false; }
	void AutoInterfacePeer::loop()  {}  // RX driven by parent's poll_data()

	void AutoInterfacePeer::send_outgoing(const Bytes& data) {
		if (!_online || !_parent) return;
		const int fd = _parent->_data_sock;
		if (fd < 0) return;
		sockaddr_in6 dst{};
		dst.sin6_family   = AF_INET6;
		dst.sin6_port     = htons(_parent->_data_port);
		dst.sin6_scope_id = _peer_scope;
		std::memcpy(&dst.sin6_addr, _peer_addr.data(), 16);
		ssize_t n = sendto(fd, data.data(), data.size(), 0,
						   reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
		if (n > 0) {
			_txb         += static_cast<size_t>(n);
			_parent->_txb += static_cast<size_t>(n);
			handle_outgoing(data);
		}
	}

	void AutoInterfacePeer::deliver_incoming(const Bytes& data) {
		if (!_online) return;
		handle_incoming(data);
	}

	std::string AutoInterfacePeer::toString() const {
		// Lowercase RFC 5952 canonical form via inet_ntop, lowercased to match
		// Python (lwIP emits uppercase).  Display only — never used for hashing.
		char buf[INET6_ADDRSTRLEN];
		struct in6_addr a;
		std::memcpy(&a, _peer_addr.data(), 16);
		if (inet_ntop(AF_INET6, &a, buf, sizeof(buf)) == nullptr) {
			return "AutoInterfacePeer[invalid]";
		}
		std::string out(buf);
		for (auto& c : out) {
			if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
		}
		return std::string("AutoInterfacePeer[") + out + "]";
	}

}  // namespace RNS
