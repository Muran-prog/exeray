#pragma once

/**
 * @file wmi.hpp
 * @brief WMI operation types.
 */

#include <cstdint>

namespace exeray::event {

/**
 * @brief WMI operation types.
 *
 * Tracks WMI activity for lateral movement, persistence, and 
 * fileless execution detection.
 */
enum class WmiOp : std::uint8_t {
    Query,       ///< WMI/WQL query executed
    ExecMethod,  ///< Method execution (Win32_Process.Create!)
    Subscribe,   ///< Event subscription (persistence!)
    Connect      ///< Namespace connection
};

}  // namespace exeray::event
