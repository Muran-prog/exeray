#pragma once

/**
 * @file category.hpp
 * @brief Top-level event category classification.
 */

#include <cstdint>

namespace exeray::event {

/**
 * @brief Top-level event category classification.
 *
 * Each monitored operation belongs to exactly one category.
 * Categories are used for filtering, routing, and visualization.
 */
enum class Category : std::uint8_t {
    FileSystem,   ///< File and directory operations
    Registry,     ///< Windows registry operations
    Network,      ///< Network socket and DNS operations
    Process,      ///< Process and module operations
    Scheduler,    ///< Task scheduler operations
    Input,        ///< Input device hooks and blocks
    Image,        ///< DLL/EXE image load/unload operations
    Thread,       ///< Thread creation/termination operations
    Memory,       ///< Virtual memory allocation operations
    Script,       ///< PowerShell script execution operations
    Amsi,         ///< AMSI scan operations
    Dns,          ///< DNS query operations
    Security,     ///< Security auditing events (logon, privilege changes)
    Service,      ///< Windows service operations
    Wmi,          ///< WMI operations
    Clr,          ///< .NET CLR runtime operations

    Count         ///< Sentinel for iteration (not a valid category)
};

}  // namespace exeray::event
