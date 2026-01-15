#pragma once

/**
 * @file dns.hpp
 * @brief DNS operation types.
 */

#include <cstdint>

namespace exeray::event {

/**
 * @brief DNS operation types.
 *
 * Tracks DNS queries for C2/DGA domain detection.
 */
enum class DnsOp : std::uint8_t {
    Query,     ///< DNS query initiated
    Response,  ///< DNS response received
    Failure    ///< DNS resolution failed
};

}  // namespace exeray::event
