#pragma once

/**
 * @file network.hpp
 * @brief Network operation payload.
 */

#include <cstdint>
#include "../types.hpp"

namespace exeray::event {

/**
 * @brief Payload for network operations.
 *
 * Contains local/remote addresses, ports, byte count, and protocol.
 */
struct NetworkPayload {
    uint32_t local_addr;   ///< Local IPv4 address
    uint32_t remote_addr;  ///< Remote IPv4 address
    uint16_t local_port;   ///< Local port number
    uint16_t remote_port;  ///< Remote port number
    uint32_t bytes;        ///< Number of bytes transferred
    uint8_t protocol;      ///< Protocol type (TCP=6, UDP=17)
    uint8_t _pad[3];       ///< Explicit padding for 4-byte alignment
};

}  // namespace exeray::event
