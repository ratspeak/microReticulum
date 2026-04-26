#pragma once

#include "../Interface.h"
#include "../Bytes.h"
#include "AutoInterface.h"

#include <cstdint>

namespace RNS {

	/*
	 * Per-peer Interface spawned by AutoInterface for each discovered node.
	 * Registered with Transport so per-path attached_interface routing works.
	 * Sends outbound traffic via the parent's shared _data_sock.
	 */
	class AutoInterfacePeer : public InterfaceImpl {
	public:
		AutoInterfacePeer(AutoInterface* parent,
						  const AutoInterface::IPv6Addr& addr,
						  uint32_t scope_id);
		virtual ~AutoInterfacePeer();

		virtual bool start() override;
		virtual void stop()  override;
		virtual void loop()  override;
		virtual void send_outgoing(const Bytes& data) override;

		// Called by AutoInterface::route_inbound after dedup
		void deliver_incoming(const Bytes& data);

		const AutoInterface::IPv6Addr& peer_addr() const { return _peer_addr; }
		uint32_t peer_scope() const { return _peer_scope; }

		virtual std::string toString() const override;

	protected:
		AutoInterface*               _parent;
		AutoInterface::IPv6Addr      _peer_addr{};
		uint32_t                     _peer_scope = 0;
	};

}  // namespace RNS
