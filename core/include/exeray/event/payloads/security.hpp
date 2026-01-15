#pragma once

/**
 * @file security.hpp
 * @brief Security auditing event payload.
 */

#include <cstdint>
#include "../types.hpp"

namespace exeray::event {

/**
 * @brief Payload for security auditing events.
 *
 * Contains logon/privilege event details for forensics and privilege
 * escalation detection. Used for Events 4624, 4625, 4688, 4689, 4703.
 */
struct SecurityPayload {
    StringId subject_user;   ///< Account performing the action
    StringId target_user;    ///< Target account (if different)
    StringId command_line;   ///< Full command line (Event 4688)
    uint32_t logon_type;     ///< Logon type (2=Interactive, 3=Network, 10=Remote)
    uint32_t process_id;     ///< New/target process ID
    uint8_t is_suspicious;   ///< 1 if suspicious (SeDebugPrivilege, brute force)
    uint8_t _pad[3];         ///< Explicit padding
};

}  // namespace exeray::event
