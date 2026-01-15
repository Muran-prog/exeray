#pragma once

/**
 * @file security.hpp
 * @brief Security auditing operation types.
 */

#include <cstdint>

namespace exeray::event {

/**
 * @brief Security auditing operation types.
 *
 * Tracks logon attempts, privilege changes, and process creation
 * for forensics and privilege escalation detection.
 */
enum class SecurityOp : std::uint8_t {
    Logon,            ///< Successful logon (Event 4624)
    LogonFailed,      ///< Failed logon attempt (Event 4625)
    PrivilegeAdjust,  ///< Token rights adjusted (Event 4703)
    ProcessCreate,    ///< New process created (Event 4688)
    ProcessTerminate  ///< Process terminated (Event 4689)
};

}  // namespace exeray::event
