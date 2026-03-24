#pragma once

#include "Bytes.h"
#include "Identity.h"
#include <string>
#include <vector>
#include <cstdint>

enum class LXMFStatus : uint8_t {
    DRAFT = 0, QUEUED, SENDING, SENT, DELIVERED, FAILED
};

struct LXMFMessage {
    RNS::Bytes sourceHash;
    RNS::Bytes destHash;
    double timestamp = 0;
    std::string content;
    std::string title;
    RNS::Bytes signature;

    LXMFStatus status = LXMFStatus::DRAFT;
    bool incoming = false;
    bool read = false;
    int retries = 0;
    unsigned long lastRetryMs = 0;
    uint32_t savedCounter = 0;
    uint32_t receiveCounter = 0;  // Monotonic receive order (used by Ratcom)
    RNS::Bytes messageId;

    static std::vector<uint8_t> packContent(double timestamp, const std::string& content, const std::string& title);
    std::vector<uint8_t> packFull(const RNS::Identity& signingIdentity);
    static bool unpackFull(const uint8_t* data, size_t len, LXMFMessage& msg);
    const char* statusStr() const;
};
