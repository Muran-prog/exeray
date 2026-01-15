#pragma once

/**
 * @file script.hpp
 * @brief PowerShell script operation types.
 */

#include <cstdint>

namespace exeray::event {

/**
 * @brief PowerShell script operation types.
 *
 * Tracks script execution for fileless malware detection.
 */
enum class ScriptOp : std::uint8_t {
    Execute,  ///< Script block executed (Event 4104)
    Module    ///< Module/cmdlet invoked (Event 4103)
};

}  // namespace exeray::event
