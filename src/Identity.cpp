#include "Identity.h"

#include "Reticulum.h"
#include "Transport.h"
#include "Packet.h"
#include "Log.h"
#include "Utilities/OS.h"
#include "Cryptography/Ed25519.h"
#include "Cryptography/X25519.h"
#include "Cryptography/HKDF.h"
#include "Cryptography/Token.h"
#include "Cryptography/Random.h"

#include <algorithm>
#include <string.h>

using namespace RNS;
using namespace RNS::Type::Identity;
using namespace RNS::Cryptography;
using namespace RNS::Utilities;

#ifndef RNS_KNOWN_DESTINATIONS_MAX
#define RNS_KNOWN_DESTINATIONS_MAX 100
#endif

/*static*/ Identity::IdentityTable Identity::_known_destinations;
/*static*/ bool Identity::_saving_known_destinations = false;
// CBA
// CBA ACCUMULATES
/*static*/ uint16_t Identity::_known_destinations_maxsize = RNS_KNOWN_DESTINATIONS_MAX;
/*static*/ Identity::RatchetTable Identity::_known_ratchets;

Identity::Identity(bool create_keys /*= true*/) : _object(new Object()) {
	if (create_keys) {
		createKeys();
	}
	MEMF("Identity object created, this: %p, data: %p", (void*)this, (void*)_object.get());
}

void Identity::createKeys() {
	assert(_object);

	// CRYPTO: create encryption private keys
	_object->_prv           = Cryptography::X25519PrivateKey::generate();
	_object->_prv_bytes     = _object->_prv->private_bytes();
	//TRACEF("Identity::createKeys: prv bytes:     %s", _object->_prv_bytes.toHex().c_str());

	// CRYPTO: create signature private keys
	_object->_sig_prv       = Cryptography::Ed25519PrivateKey::generate();
	_object->_sig_prv_bytes = _object->_sig_prv->private_bytes();
	//TRACEF("Identity::createKeys: sig prv bytes: %s", _object->_sig_prv_bytes.toHex().c_str());

	// CRYPTO: create encryption public keys
	_object->_pub           = _object->_prv->public_key();
	_object->_pub_bytes     = _object->_pub->public_bytes();
	//TRACEF("Identity::createKeys: pub bytes:     %s", _object->_pub_bytes.toHex().c_str());

	// CRYPTO: create signature public keys
	_object->_sig_pub       = _object->_sig_prv->public_key();
	_object->_sig_pub_bytes = _object->_sig_pub->public_bytes();
	//TRACEF("Identity::createKeys: sig pub bytes: %s", _object->_sig_pub_bytes.toHex().c_str());

	update_hashes();

	VERBOSEF("Identity keys created for %s", _object->_hash.toHex().c_str());
}

/*
Load a private key into the instance.

:param prv_bytes: The private key as *bytes*.
:returns: True if the key was loaded, otherwise False.
*/
bool Identity::load_private_key(const Bytes& prv_bytes) {
	assert(_object);

	try {

		//p self.prv_bytes     = prv_bytes[:Identity.KEYSIZE//8//2]
		_object->_prv_bytes     = prv_bytes.left(Type::Identity::KEYSIZE/8/2);
		_object->_prv           = X25519PrivateKey::from_private_bytes(_object->_prv_bytes);
		//TRACEF("Identity::load_private_key: prv bytes:     %s", _object->_prv_bytes.toHex().c_str());

		//p self.sig_prv_bytes = prv_bytes[Identity.KEYSIZE//8//2:]
		_object->_sig_prv_bytes = prv_bytes.mid(Type::Identity::KEYSIZE/8/2);
		_object->_sig_prv       = Ed25519PrivateKey::from_private_bytes(_object->_sig_prv_bytes);
		//TRACEF("Identity::load_private_key: sig prv bytes: %s", _object->_sig_prv_bytes.toHex().c_str());

		_object->_pub           = _object->_prv->public_key();
		_object->_pub_bytes     = _object->_pub->public_bytes();
		//TRACEF("Identity::load_private_key: pub bytes:     %s", _object->_pub_bytes.toHex().c_str());

		_object->_sig_pub       = _object->_sig_prv->public_key();
		_object->_sig_pub_bytes = _object->_sig_pub->public_bytes();
		//TRACEF("Identity::load_private_key: sig pub bytes: %s", _object->_sig_pub_bytes.toHex().c_str());

		update_hashes();

		return true;
	}
	catch (std::exception& e) {
		//p raise e
		ERROR("Failed to load identity key");
		ERRORF("The contained exception was: %s", e.what());
		return false;
	}
}

/*
Load a public key into the instance.

:param pub_bytes: The public key as *bytes*.
:returns: True if the key was loaded, otherwise False.
*/
void Identity::load_public_key(const Bytes& pub_bytes) {
	assert(_object);

	try {

		//_pub_bytes     = pub_bytes[:Identity.KEYSIZE//8//2]
		_object->_pub_bytes     = pub_bytes.left(Type::Identity::KEYSIZE/8/2);
		//TRACEF("Identity::load_public_key: pub bytes:     ", _object->_pub_bytes.toHex().c_str());

		//_sig_pub_bytes = pub_bytes[Identity.KEYSIZE//8//2:]
		_object->_sig_pub_bytes = pub_bytes.mid(Type::Identity::KEYSIZE/8/2);
		//TRACEF("Identity::load_public_key: sig pub bytes: ", _object->_sig_pub_bytes.toHex().c_str());

		_object->_pub           = X25519PublicKey::from_public_bytes(_object->_pub_bytes);
		_object->_sig_pub       = Ed25519PublicKey::from_public_bytes(_object->_sig_pub_bytes);

		update_hashes();
	}
	catch (std::exception& e) {
		ERRORF("Error while loading public key, the contained exception was: %s", e.what());
	}
}

bool Identity::load(const char* path) {
	TRACE("Reading identity key from storage...");
#if defined(RNS_USE_FS)
	try {
		Bytes prv_bytes;
		if (OS::read_file(path, prv_bytes) > 0) {
			return load_private_key(prv_bytes);
		}
		else {
			return false;
		}
	}
	catch (std::exception& e) {
		ERRORF("Error while loading identity from %s", path);
		ERRORF("The contained exception was: %s", e.what());
	}
#endif
	return false;
}

/*
Saves the identity to a file. This will write the private key to disk,
and anyone with access to this file will be able to decrypt all
communication for the identity. Be very careful with this method.

:param path: The full path specifying where to save the identity.
:returns: True if the file was saved, otherwise False.
*/
bool Identity::to_file(const char* path) {
	TRACE("Writing identity key to storage...");
#if defined(RNS_USE_FS)
	try {
		return (OS::write_file(path, get_private_key()) == get_private_key().size());
	}
	catch (std::exception& e) {
		ERRORF("Error while saving identity to %s", path);
		ERRORF("The contained exception was: %s", e.what());
	}
#endif
	return false;
}


/*
Create a new :ref:`RNS.Identity<api-identity>` instance from a file.
Can be used to load previously created and saved identities into Reticulum.

:param path: The full path to the saved :ref:`RNS.Identity<api-identity>` data
:returns: A :ref:`RNS.Identity<api-identity>` instance, or *None* if the loaded data was invalid.
*/
/*static*/ const Identity Identity::from_file(const char* path) {
	Identity identity(false);
	if (identity.load(path)) {
		return identity;
	}
	return {Type::NONE};
}

/*static*/ void Identity::remember(const Bytes& packet_hash, const Bytes& destination_hash, const Bytes& public_key, const Bytes& app_data /*= {Bytes::NONE}*/) {
	if (public_key.size() != Type::Identity::KEYSIZE/8) {
		throw std::invalid_argument("Can't remember " + destination_hash.toHex() + ", the public key size of " + std::to_string(public_key.size()) + " is not valid.");
	}
	else {
		//p _known_destinations[destination_hash] = {OS::time(), packet_hash, public_key, app_data};
		// CBA ACCUMULATES
		try {
			// Use insert_or_assign so the timestamp is always refreshed.
			// Plain insert() is a no-op for existing keys, leaving the old
			// timestamp — cull then removes the "stale" entry we just validated.
			_known_destinations.insert_or_assign(destination_hash, IdentityEntry{OS::time(), packet_hash, public_key, app_data});
			// CBA IMMEDIATE CULL
			cull_known_destinations();
		}
		catch (const std::bad_alloc&) {
			ERRORF("remember: bad_alloc - OUT OF MEMORY, identity not stored for %s", destination_hash.toHex().c_str());
		}
		catch (const std::exception& e) {
			ERRORF("remember: exception storing identity: %s", e.what());
		}
	}
}

/*
Recall identity for a destination hash.

:param destination_hash: Destination hash as *bytes*.
:returns: An :ref:`RNS.Identity<api-identity>` instance that can be used to create an outgoing :ref:`RNS.Destination<api-destination>`, or *None* if the destination is unknown.
*/
/*static*/ Identity Identity::recall(const Bytes& destination_hash) {
	TRACE("Identity::recall...");
	auto iter = _known_destinations.find(destination_hash);
	if (iter != _known_destinations.end()) {
		TRACEF("Identity::recall: Found identity entry for destination %s", destination_hash.toHex().c_str());
		const IdentityEntry& identity_data = (*iter).second;
		Identity identity(false);
		identity.load_public_key(identity_data._public_key);
		identity.app_data(identity_data._app_data);
		return identity;
	}
	else {
		TRACEF("Identity::recall: Unable to find identity entry for destination %s, performing destination lookup...", destination_hash.toHex().c_str());
		Destination registered_destination(Transport::find_destination_from_hash(destination_hash));
		if (registered_destination) {
			TRACEF("Identity::recall: Found destination %s", destination_hash.toHex().c_str());
			Identity identity(false);
			identity.load_public_key(registered_destination.identity().get_public_key());
			identity.app_data({Bytes::NONE});
			return identity;
		}
		TRACEF("Identity::recall: Unable to find destination %s", destination_hash.toHex().c_str());
		return {Type::NONE};
	}
}

/*
Recall last heard app_data for a destination hash.

:param destination_hash: Destination hash as *bytes*.
:returns: *Bytes* containing app_data, or *None* if the destination is unknown.
*/
/*static*/ Bytes Identity::recall_app_data(const Bytes& destination_hash) {
	TRACE("Identity::recall_app_data...");
	auto iter = _known_destinations.find(destination_hash);
	if (iter != _known_destinations.end()) {
		TRACEF("Identity::recall_app_data: Found identity entry for destination %s", destination_hash.toHex().c_str());
		const IdentityEntry& identity_data = (*iter).second;
		return identity_data._app_data;
	}
	else {
		TRACEF("Identity::recall_app_data: Unable to find identity entry for destination %s", destination_hash.toHex().c_str());
		return {Bytes::NONE};
	}
}

/*
Binary format for known_destinations persistence:
  [uint16_t entry_count]
  For each entry:
    [uint16_t dest_hash_len][dest_hash bytes]
    [double   timestamp]
    [uint16_t packet_hash_len][packet_hash bytes]
    [uint16_t public_key_len][public_key bytes]
    [uint16_t app_data_len][app_data bytes]
*/

/*static*/ bool Identity::save_known_destinations() {
	bool success = false;
	try {
		if (_saving_known_destinations) {
			double wait_interval = 0.2;
			double wait_timeout = 5;
			double wait_start = OS::time();
			while (_saving_known_destinations) {
				OS::sleep(wait_interval);
				if (OS::time() > (wait_start + wait_timeout)) {
					ERROR("Could not save known destinations to storage, waiting for previous save operation timed out.");
					return false;
				}
			}
		}

		_saving_known_destinations = true;
		double save_start = OS::time();

		if (_known_destinations.empty()) {
			_saving_known_destinations = false;
			return true;
		}

		// Serialize to binary buffer
		Bytes buf(1024);
		uint16_t count = (uint16_t)_known_destinations.size();
		buf.append((const uint8_t*)&count, sizeof(count));

		for (const auto& [dest_hash, entry] : _known_destinations) {
			uint16_t len;

			len = (uint16_t)dest_hash.size();
			buf.append((const uint8_t*)&len, sizeof(len));
			buf.append(dest_hash.data(), dest_hash.size());

			buf.append((const uint8_t*)&entry._timestamp, sizeof(entry._timestamp));

			len = (uint16_t)entry._packet_hash.size();
			buf.append((const uint8_t*)&len, sizeof(len));
			if (len > 0) buf.append(entry._packet_hash.data(), entry._packet_hash.size());

			len = (uint16_t)entry._public_key.size();
			buf.append((const uint8_t*)&len, sizeof(len));
			if (len > 0) buf.append(entry._public_key.data(), entry._public_key.size());

			len = (uint16_t)entry._app_data.size();
			buf.append((const uint8_t*)&len, sizeof(len));
			if (len > 0) buf.append(entry._app_data.data(), entry._app_data.size());
		}

		char filepath[Type::Reticulum::FILEPATH_MAXSIZE];
		snprintf(filepath, Type::Reticulum::FILEPATH_MAXSIZE, "%s/known_destinations", Reticulum::_storagepath);

		if (OS::write_file(filepath, buf) == buf.size()) {
			DEBUGF("Saved %zu known destinations to storage in %.3f seconds", _known_destinations.size(), OS::round(OS::time() - save_start, 3));
			success = true;
		} else {
			ERROR("Failed to write known destinations to storage");
		}
	}
	catch (std::exception& e) {
		ERRORF("Error while saving known destinations to disk, the contained exception was: %s", e.what());
	}

	_saving_known_destinations = false;

	return success;
}

/*static*/ void Identity::load_known_destinations() {
	char filepath[Type::Reticulum::FILEPATH_MAXSIZE];
	snprintf(filepath, Type::Reticulum::FILEPATH_MAXSIZE, "%s/known_destinations", Reticulum::_storagepath);

	if (!OS::file_exists(filepath)) {
		VERBOSE("Destinations file does not exist, no known destinations loaded");
		return;
	}

	try {
		Bytes buf;
		if (OS::read_file(filepath, buf) == 0) {
			ERROR("Failed to read known destinations file");
			return;
		}

		const uint8_t* ptr = buf.data();
		size_t remaining = buf.size();

		if (remaining < sizeof(uint16_t)) return;
		uint16_t count;
		memcpy(&count, ptr, sizeof(count));
		ptr += sizeof(count);
		remaining -= sizeof(count);

		size_t loaded = 0;
		for (uint16_t i = 0; i < count && remaining > 0; i++) {
			uint16_t len;

			// dest_hash
			if (remaining < sizeof(len)) break;
			memcpy(&len, ptr, sizeof(len)); ptr += sizeof(len); remaining -= sizeof(len);
			if (remaining < len || len != Type::Reticulum::TRUNCATED_HASHLENGTH/8) break;
			Bytes dest_hash(ptr, len); ptr += len; remaining -= len;

			// timestamp
			if (remaining < sizeof(double)) break;
			double timestamp;
			memcpy(&timestamp, ptr, sizeof(timestamp)); ptr += sizeof(timestamp); remaining -= sizeof(timestamp);

			// packet_hash
			if (remaining < sizeof(len)) break;
			memcpy(&len, ptr, sizeof(len)); ptr += sizeof(len); remaining -= sizeof(len);
			if (remaining < len) break;
			Bytes packet_hash(ptr, len); ptr += len; remaining -= len;

			// public_key
			if (remaining < sizeof(len)) break;
			memcpy(&len, ptr, sizeof(len)); ptr += sizeof(len); remaining -= sizeof(len);
			if (remaining < len) break;
			Bytes public_key(ptr, len); ptr += len; remaining -= len;

			// app_data
			if (remaining < sizeof(len)) break;
			memcpy(&len, ptr, sizeof(len)); ptr += sizeof(len); remaining -= sizeof(len);
			if (remaining < len) break;
			Bytes app_data(ptr, len); ptr += len; remaining -= len;

			if (_known_destinations.find(dest_hash) == _known_destinations.end()) {
				try {
					_known_destinations.insert({dest_hash, {timestamp, packet_hash, public_key, app_data}});
					loaded++;
				}
				catch (const std::bad_alloc&) {
					ERROR("load_known_destinations: out of memory, stopping load");
					break;
				}
			}
		}

		// Normalize timestamps to current boot epoch.
		// OS::time() on Arduino returns seconds since boot, not epoch time.
		// Persisted entries carry timestamps from the previous boot session
		// (e.g., 5000.0 = device had been up 5000s when saved). On a fresh
		// boot at uptime 30s, a new announce would get timestamp 30.0 — which
		// the LRU cull considers "older" than the persisted 5000.0, causing
		// the NEW entry to be culled immediately. Fix: remap all loaded
		// timestamps into [1.0, now-1] preserving their relative order, so
		// any fresh announce at OS::time() is always "newest".
		if (loaded > 0) {
			double now = OS::time();
			double max_ts = 0, min_ts = 1e18;
			for (const auto& [key, entry] : _known_destinations) {
				if (entry._timestamp > max_ts) max_ts = entry._timestamp;
				if (entry._timestamp < min_ts) min_ts = entry._timestamp;
			}
			double range = max_ts - min_ts;
			// Map [min_ts, max_ts] → [1.0, now - 1.0]
			// All loaded entries end up before "now", preserving relative order
			double target_max = (now > 2.0) ? now - 1.0 : 1.0;
			double target_min = 1.0;
			for (auto& [key, entry] : _known_destinations) {
				if (range > 0.001) {
					double normalized = (entry._timestamp - min_ts) / range;
					entry._timestamp = target_min + normalized * (target_max - target_min);
				} else {
					entry._timestamp = target_min;
				}
			}
			VERBOSEF("Normalized %zu destination timestamps: [%.1f,%.1f] -> [%.1f,%.1f]",
				loaded, min_ts, max_ts, target_min, target_max);
		}

		cull_known_destinations();
		VERBOSEF("Loaded %zu known destinations from storage", loaded);
	}
	catch (std::exception& e) {
		ERRORF("Error loading known destinations from disk, file will be recreated on exit: %s", e.what());
	}
}

/*static*/ void Identity::cull_known_destinations() {
	TRACE("Identity::cull_known_destinations()");
	if (_known_destinations.size() > _known_destinations_maxsize) {
		try {
			// Build lightweight (timestamp, key) index to avoid copying full IdentityEntry
			// objects — prevents OOM on heap-constrained devices when the table is full.
			std::vector<std::pair<double, Bytes>> sorted_keys;
			sorted_keys.reserve(_known_destinations.size());
			for (const auto& [key, entry] : _known_destinations) {
				sorted_keys.emplace_back(entry._timestamp, key);
			}
			// Sort ascending by timestamp (oldest first)
			std::sort(sorted_keys.begin(), sorted_keys.end());

			uint16_t count = 0;
			for (const auto& [timestamp, destination_hash] : sorted_keys) {
				TRACEF("Identity::cull_known_destinations: Removing destination %s from known destinations", destination_hash.toHex().c_str());
				if (_known_destinations.erase(destination_hash) < 1) {
					WARNINGF("Failed to remove destination %s from known destinations", destination_hash.toHex().c_str());
				}
				++count;
				if (_known_destinations.size() <= _known_destinations_maxsize) {
					break;
				}
			}
			DEBUGF("Removed %d path(s) from known destinations", count);
		}
		catch (const std::bad_alloc& e) {
			ERROR("cull_known_destinations: bad_alloc - OUT OF MEMORY building sort index, falling back to single erase");
			// Fallback: std::min_element does no heap allocation — erase one oldest entry
			auto oldest = std::min_element(
				_known_destinations.begin(), _known_destinations.end(),
				[](const std::pair<const Bytes, IdentityEntry>& a,
			   const std::pair<const Bytes, IdentityEntry>& b) {
				return a.second._timestamp < b.second._timestamp;
			}
			);
			if (oldest != _known_destinations.end()) {
				_known_destinations.erase(oldest);
			}
		}
		catch (const std::exception& e) {
			ERRORF("cull_known_destinations: exception: %s", e.what());
		}
	}
}

/*static*/ bool Identity::validate_announce(const Packet& packet) {
	try {
		if (packet.packet_type() == Type::Packet::ANNOUNCE) {
			Bytes destination_hash = packet.destination_hash();

			size_t keysize       = KEYSIZE/8;
			size_t ratchetsize   = Type::Identity::RATCHETSIZE/8;
			size_t name_hash_len = NAME_HASH_LENGTH/8;
			size_t sig_len       = SIGLENGTH/8;

			Bytes public_key = packet.data().left(keysize);
			Bytes name_hash = packet.data().mid(keysize, name_hash_len);
			Bytes random_hash = packet.data().mid(keysize + name_hash_len, 10);

			Bytes ratchet;
			Bytes signature;
			Bytes app_data;

			// If the packet context flag is set, this announce contains a ratchet key
			if (packet.context_flag() == Type::Packet::FLAG_SET) {
				ratchet = packet.data().mid(keysize + name_hash_len + 10, ratchetsize);
				signature = packet.data().mid(keysize + name_hash_len + 10 + ratchetsize, sig_len);
				if (packet.data().size() > keysize + name_hash_len + 10 + ratchetsize + sig_len) {
					app_data = packet.data().mid(keysize + name_hash_len + 10 + ratchetsize + sig_len);
				}
			}
			else {
				signature = packet.data().mid(keysize + name_hash_len + 10, sig_len);
				if (packet.data().size() > keysize + name_hash_len + 10 + sig_len) {
					app_data = packet.data().mid(keysize + name_hash_len + 10 + sig_len);
				}
			}

			Bytes signed_data;
			signed_data << destination_hash << public_key << name_hash << random_hash << ratchet << app_data;

			if (!ratchet && packet.data().size() <= keysize + name_hash_len + 10 + sig_len) {
				app_data.clear();
			}
			else if (ratchet && packet.data().size() <= keysize + name_hash_len + 10 + ratchetsize + sig_len) {
				app_data.clear();
			}

			Identity announced_identity(false);
			announced_identity.load_public_key(public_key);

			if (announced_identity.pub() && announced_identity.validate(signature, signed_data)) {
				TRACEF("[DIAG] validate_announce: name_hash=%s identity_hash=%s",
					name_hash.toHex().c_str(), announced_identity.hash().toHex().c_str());
				Bytes hash_material = name_hash << announced_identity.hash();
				Bytes expected_hash = full_hash(hash_material).left(Type::Reticulum::TRUNCATED_HASHLENGTH/8);
				TRACEF("[DIAG] validate_announce: material(%d)=%s expected=%s actual=%s",
					(int)hash_material.size(), hash_material.toHex().c_str(),
					expected_hash.toHex().c_str(), packet.destination_hash().toHex().c_str());
				//TRACEF("Identity::validate_announce: destination_hash: %s", packet.destination_hash().toHex().c_str());
				//TRACEF("Identity::validate_announce: expected_hash:    %s", expected_hash.toHex().c_str());

				if (packet.destination_hash() == expected_hash) {
					// Check if we already have a public key for this destination
					// and make sure the public key is not different.
					auto iter = _known_destinations.find(packet.destination_hash());
					if (iter != _known_destinations.end()) {
						IdentityEntry& identity_entry = (*iter).second;
						if (public_key != identity_entry._public_key) {
							// In reality, this should never occur, but in the odd case
							// that someone manages a hash collision, we reject the announce.
							CRITICAL("Received announce with valid signature and destination hash, but announced public key does not match already known public key.");
							CRITICAL("This may indicate an attempt to modify network paths, or a random hash collision. The announce was rejected.");
							return false;
						}
					}

					remember(packet.get_hash(), packet.destination_hash(), public_key, app_data);

					if (ratchet) {
						remember_ratchet(packet.destination_hash(), ratchet);
					}

					std::string signal_str;
// TODO
/*
					if packet.rssi != None or packet.snr != None:
						signal_str = " ["
						if packet.rssi != None:
							signal_str += "RSSI "+str(packet.rssi)+"dBm"
							if packet.snr != None:
								signal_str += ", "
						if packet.snr != None:
							signal_str += "SNR "+str(packet.snr)+"dB"
						signal_str += "]"
					else:
						signal_str = ""
*/

					if (packet.transport_id()) {
						TRACEF("Valid announce for %s %d hops away, received via %s on %s%s", packet.destination_hash().toHex().c_str(), packet.hops(), packet.transport_id().toHex().c_str(), packet.receiving_interface().toString().c_str(), signal_str.c_str());
					}
					else {
						TRACEF("Valid announce for %s %d hops away, received on %s%s", packet.destination_hash().toHex().c_str(), packet.hops(), packet.receiving_interface().toString().c_str(), signal_str.c_str());
					}

					TRACEF("[DIAG] ANNOUNCE VALID: dest=%s hops=%d ratchet=%s",
						packet.destination_hash().toHex().c_str(), packet.hops(),
						ratchet ? "YES" : "NO");

					return true;
				}
				else {
					TRACEF("[DIAG] ANNOUNCE HASH MISMATCH: dest=%s expected=%s",
						packet.destination_hash().toHex().c_str(), expected_hash.toHex().c_str());
					DEBUGF("Received invalid announce for %s: Destination mismatch.", packet.destination_hash().toHex().c_str());
					return false;
				}
			}
			else {
				TRACEF("[DIAG] ANNOUNCE INVALID SIG: dest=%s datalen=%d ctxflag=%d",
					packet.destination_hash().toHex().c_str(), (int)packet.data().size(),
					packet.context_flag());
				DEBUGF("Received invalid announce for %s: Invalid signature.", packet.destination_hash().toHex().c_str());
				//p del announced_identity
				return false;
			}
		}
	}
	catch (std::exception& e) {
		ERRORF("Error occurred while validating announce. The contained exception was: %s", e.what());
		return false;
	}
	return false;
}

/*static*/ void Identity::remember_ratchet(const Bytes& destination_hash, const Bytes& ratchet_pub) {
	if (ratchet_pub.size() != Type::Identity::RATCHETSIZE/8) {
		WARNINGF("Cannot remember ratchet for %s, invalid ratchet size %zu", destination_hash.toHex().c_str(), ratchet_pub.size());
		return;
	}
	auto iter = _known_ratchets.find(destination_hash);
	if (iter != _known_ratchets.end() && iter->second == ratchet_pub) {
		return; // Already known, no change
	}
	TRACEF("Remembering ratchet for %s", destination_hash.toHex().c_str());
	_known_ratchets.insert_or_assign(destination_hash, ratchet_pub);
}

/*static*/ Bytes Identity::get_ratchet(const Bytes& destination_hash) {
	auto iter = _known_ratchets.find(destination_hash);
	if (iter != _known_ratchets.end()) {
		return iter->second;
	}
	return {Bytes::NONE};
}

/*static*/ void Identity::persist_data() {
	if (!Transport::reticulum() || !Transport::reticulum().is_connected_to_shared_instance()) {
		save_known_destinations();
	}
}

/*static*/ void Identity::exit_handler() {
	persist_data();
}

/*
Encrypts information for the identity.

:param plaintext: The plaintext to be encrypted as *bytes*.
:returns: Ciphertext token as *bytes*.
:raises: *KeyError* if the instance does not hold a public key.
*/
const Bytes Identity::encrypt(const Bytes& plaintext, const Bytes& ratchet_key /*= {Bytes::NONE}*/) const {
	assert(_object);
	TRACE("Identity::encrypt: encrypting data...");
	if (!_object->_pub) {
		throw std::runtime_error("Encryption failed because identity does not hold a public key");
	}
	Cryptography::X25519PrivateKey::Ptr ephemeral_key = Cryptography::X25519PrivateKey::generate();
	Bytes ephemeral_pub_bytes = ephemeral_key->public_key()->public_bytes();
	TRACEF("Identity::encrypt: ephemeral public key: %s", ephemeral_pub_bytes.toHex().c_str());

	// CRYPTO: create shared key for key exchange
	// Use ratchet public key if available for forward secrecy, otherwise identity public key
	Bytes shared_key;
	TRACEF("[DIAG] ENCRYPT: ratchet=%s ephemeral=%.16s... plaintext=%dB",
		ratchet_key ? "YES" : "NO", ephemeral_pub_bytes.toHex().c_str(), (int)plaintext.size());
	if (ratchet_key) {
		shared_key = ephemeral_key->exchange(ratchet_key);
		TRACE("Identity::encrypt: using ratchet key for ECDH");
	}
	else {
		shared_key = ephemeral_key->exchange(_object->_pub_bytes);
	}
	TRACEF("Identity::encrypt: shared key:           %s", shared_key.toHex().c_str());

	Bytes derived_key = Cryptography::hkdf(
		DERIVED_KEY_LENGTH,
		shared_key,
		get_salt(),
		get_context()
	);
	TRACEF("Identity::encrypt: derived key:          %s", derived_key.toHex().c_str());

	Cryptography::Token token(derived_key);
	TRACEF("Identity::encrypt: Token encrypting data of length %zu", plaintext.size());
	TRACEF("Identity::encrypt: plaintext:  %s", plaintext.toHex().c_str());
	Bytes ciphertext = token.encrypt(plaintext);
	TRACEF("Identity::encrypt: ciphertext: %s", ciphertext.toHex().c_str());

	return ephemeral_pub_bytes + ciphertext;
}


/*
Decrypts information for the identity.

:param ciphertext: The ciphertext to be decrypted as *bytes*.
:returns: Plaintext as *bytes*, or *None* if decryption fails.
:raises: *KeyError* if the instance does not hold a private key.
*/
const Bytes Identity::decrypt(const Bytes& ciphertext_token) const {
	assert(_object);
	TRACE("Identity::decrypt: decrypting data...");
	if (!_object->_prv) {
		throw std::runtime_error("Decryption failed because identity does not hold a private key");
	}
	if (ciphertext_token.size() <= Type::Identity::KEYSIZE/8/2) {
		DEBUGF("Decryption failed because the token size %zu was invalid.", ciphertext_token.size());
		return {Bytes::NONE};
	}
	Bytes plaintext;
	try {
		//peer_pub_bytes = ciphertext_token[:Identity.KEYSIZE//8//2]
		Bytes peer_pub_bytes = ciphertext_token.left(Type::Identity::KEYSIZE/8/2);
		//peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
		//Cryptography::X25519PublicKey::Ptr peer_pub = Cryptography::X25519PublicKey::from_public_bytes(peer_pub_bytes);
		TRACEF("Identity::decrypt: peer public key:      %s", peer_pub_bytes.toHex().c_str());

		// CRYPTO: create shared key for key exchange using peer public key
		//shared_key = _object->_prv->exchange(peer_pub);
		Bytes shared_key = _object->_prv->exchange(peer_pub_bytes);
		TRACEF("Identity::decrypt: shared key:           %s", shared_key.toHex().c_str());

		Bytes derived_key = Cryptography::hkdf(
			DERIVED_KEY_LENGTH,
			shared_key,
			get_salt(),
			get_context()
		);
		TRACEF("Identity::decrypt: derived key:          %s", derived_key.toHex().c_str());

		Cryptography::Token token(derived_key);
		//ciphertext = ciphertext_token[Identity.KEYSIZE//8//2:]
		Bytes ciphertext(ciphertext_token.mid(Type::Identity::KEYSIZE/8/2));
		TRACEF("Identity::decrypt: Token decrypting data of length %zu", ciphertext.size());
		TRACEF("Identity::decrypt: ciphertext: %s", ciphertext.toHex().c_str());
		plaintext = token.decrypt(ciphertext);
		TRACEF("Identity::decrypt: plaintext:  %s", plaintext.toHex().c_str());
		//TRACEF("Identity::decrypt: Token decrypted data of length %zu", plaintext.size());
	}
	catch (std::exception& e) {
		DEBUGF("Decryption by %s failed: %s", toString().c_str(), e.what());
	}
		
	return plaintext;
}

/*
Signs information by the identity.

:param message: The message to be signed as *bytes*.
:returns: Signature as *bytes*.
:raises: *KeyError* if the instance does not hold a private key.
*/
const Bytes Identity::sign(const Bytes& message) const {
	assert(_object);
	if (!_object->_sig_prv) {
		throw std::runtime_error("Signing failed because identity does not hold a private key");
	}
	try {
		return _object->_sig_prv->sign(message);
	}
	catch (std::exception& e) {
		ERRORF("The identity %s could not sign the requested message. The contained exception was: %s", toString().c_str(), e.what());
		throw e;
	}
}

/*
Validates the signature of a signed message.

:param signature: The signature to be validated as *bytes*.
:param message: The message to be validated as *bytes*.
:returns: True if the signature is valid, otherwise False.
:raises: *KeyError* if the instance does not hold a public key.
*/
bool Identity::validate(const Bytes& signature, const Bytes& message) const {
	assert(_object);
	if (_object->_pub) {
		try {
			TRACEF("Identity::validate: Attempting to verify signature: %s and message: %s", signature.toHex().c_str(), message.toHex().c_str());
			_object->_sig_pub->verify(signature, message);
			return true;
		}
		catch (std::exception& e) {
			return false;
		}
	}
	else {
		throw std::runtime_error("Signature validation failed because identity does not hold a public key");
	}
}

void Identity::prove(const Packet& packet, const Destination& destination /*= {Type::NONE}*/) const {
	assert(_object);
	Bytes signature(sign(packet.packet_hash()));
	Bytes proof_data;
	if (RNS::Reticulum::should_use_implicit_proof()) {
		proof_data = signature;
		TRACEF("Identity::prove: implicit proof data: %s", proof_data.toHex().c_str());
	}
	else {
		proof_data = packet.packet_hash() + signature;
		TRACEF("Identity::prove: explicit proof data: %s", proof_data.toHex().c_str());
	}
	
	if (!destination) {
		TRACE("Identity::prove: proving packet with proof destination...");
		ProofDestination proof_destination = packet.generate_proof_destination();
		Packet proof(proof_destination, packet.receiving_interface(), proof_data, Type::Packet::PROOF);
		proof.send();
	}
	else {
		TRACE("Identity::prove: proving packet with specified destination...");
		Packet proof(destination, packet.receiving_interface(), proof_data, Type::Packet::PROOF);
		proof.send();
	}
}

void Identity::prove(const Packet& packet) const {
	prove(packet, {Type::NONE});
}
