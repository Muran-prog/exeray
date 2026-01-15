#pragma once

/**
 * @file dns.hpp
 * @brief DNS operation payload.
 */

#include <cstdint>
#include "../types.hpp"

namespace exeray::event {

/**
 * @brief Payload for DNS operations.
 *
 * Contains DNS query info for C2/DGA domain detection.
 * Used for Event ID 3006 (Query Completed) and 3008 (Query Failed).
 */
struct DnsPayload {
    StringId domain;        ///< Requested domain name (interned)
    uint32_t query_type;    ///< A=1, AAAA=28, TXT=16, MX=15, CNAME=5
    uint32_t result_code;   ///< DNS response code (0=success)
    uint32_t resolved_ip;   ///< IPv4 address if type A
    uint8_t is_suspicious;  ///< 1 if DGA-like domain detected
    uint8_t _pad[3];        ///< Explicit padding for alignment
};

}  // namespace exeray::event
