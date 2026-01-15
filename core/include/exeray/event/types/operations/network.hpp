#pragma once

/**
 * @file network.hpp
 * @brief Network operation types.
 */

#include <cstdint>

namespace exeray::event {

/**
 * @brief Network operation types.
 */
enum class NetworkOp : std::uint8_t {
    Connect,   ///< Outbound connection
    Listen,    ///< Start listening on port
    Send,      ///< Send data
    Receive,   ///< Receive data
    DnsQuery   ///< DNS resolution query
};

}  // namespace exeray::event
