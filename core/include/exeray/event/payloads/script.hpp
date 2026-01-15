#pragma once

/**
 * @file script.hpp
 * @brief PowerShell script operation payload.
 */

#include <cstdint>
#include "../types.hpp"

namespace exeray::event {

/**
 * @brief Payload for PowerShell script operations.
 *
 * Contains script content and context for fileless malware detection.
 * Used for Script Block Logging (Event 4104) and Module Logging (Event 4103).
 */
struct ScriptPayload {
    StringId script_block;   ///< Interned script content
    StringId context;        ///< Host application, RunspaceId
    uint32_t sequence;       ///< Sequence number for multi-part scripts
    uint8_t is_suspicious;   ///< 1 if dangerous patterns detected
    uint8_t _pad[3];         ///< Explicit padding for alignment
};

}  // namespace exeray::event
