#pragma once

/**
 * @file service.hpp
 * @brief Windows service operation payload.
 */

#include <cstdint>
#include "../types.hpp"

namespace exeray::event {

/**
 * @brief Payload for Windows service operations.
 *
 * Contains service installation details for persistence detection.
 * Used for Event 4697 (Service Installation).
 */
struct ServicePayload {
    StringId service_name;   ///< Service display name
    StringId service_path;   ///< Service executable path
    uint32_t service_type;   ///< Service type (0x10=Own, 0x20=Share)
    uint32_t start_type;     ///< Start type (0x2=AUTO, 0x3=DEMAND)
    uint8_t is_suspicious;   ///< 1 if AUTO_START (persistence)
    uint8_t _pad[3];         ///< Explicit padding
};

}  // namespace exeray::event
