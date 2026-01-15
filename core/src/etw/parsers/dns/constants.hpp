/// @file constants.hpp
/// @brief DNS type constants and utilities.

#pragma once

#include <cstdint>

namespace exeray::etw::dns {

/// DNS Client event IDs from Microsoft-Windows-DNS-Client provider.
enum class EventId : uint16_t {
    QueryCompleted = 3006,  ///< DNS query completed successfully
    QueryFailed = 3008      ///< DNS query failed
};

/// DNS query types (IANA).
namespace types {
    constexpr uint32_t A = 1;        ///< IPv4 address
    constexpr uint32_t AAAA = 28;    ///< IPv6 address
    constexpr uint32_t TXT = 16;     ///< Text record
    constexpr uint32_t MX = 15;      ///< Mail exchange
    constexpr uint32_t CNAME = 5;    ///< Canonical name
}  // namespace types

/// @brief Get human-readable name for DNS query type.
inline const char* query_type_name(uint32_t type) {
    switch (type) {
        case types::A: return "A";
        case types::AAAA: return "AAAA";
        case types::TXT: return "TXT";
        case types::MX: return "MX";
        case types::CNAME: return "CNAME";
        default: return "OTHER";
    }
}

}  // namespace exeray::etw::dns
