/// @file constants.hpp
/// @brief Security event constants and enums.

#pragma once

#ifdef _WIN32

#include "exeray/etw/event_ids.hpp"

namespace exeray::etw::security {

/// Alias for centralized security event IDs.
namespace event_ids = exeray::etw::ids::security;

/// Logon type values for Event 4624/4625.
namespace logon_types {
    inline constexpr uint32_t INTERACTIVE = 2;          ///< Local keyboard logon
    inline constexpr uint32_t NETWORK = 3;              ///< Network (SMB, etc.)
    inline constexpr uint32_t BATCH = 4;                ///< Scheduled task
    inline constexpr uint32_t SERVICE = 5;              ///< Service account
    inline constexpr uint32_t UNLOCK = 7;               ///< Screen unlock
    inline constexpr uint32_t NETWORK_CLEARTEXT = 8;    ///< IIS basic auth
    inline constexpr uint32_t NEW_CREDENTIALS = 9;      ///< RunAs /netonly
    inline constexpr uint32_t REMOTE_INTERACTIVE = 10;  ///< RDP
    inline constexpr uint32_t CACHED_INTERACTIVE = 11;  ///< Cached domain credentials
}  // namespace logon_types

/// Service start types for Event 4697.
namespace service_start_types {
    inline constexpr uint32_t BOOT_START = 0x0;
    inline constexpr uint32_t SYSTEM_START = 0x1;
    inline constexpr uint32_t AUTO_START = 0x2;      ///< Persistence indicator!
    inline constexpr uint32_t DEMAND_START = 0x3;
    inline constexpr uint32_t DISABLED = 0x4;
}  // namespace service_start_types

/// Dangerous privileges that indicate privilege escalation.
inline constexpr const wchar_t* DANGEROUS_PRIVILEGES[] = {
    L"SeDebugPrivilege",           ///< Debug any process (injection)
    L"SeTcbPrivilege",             ///< Act as part of OS
    L"SeImpersonatePrivilege",     ///< Impersonate client (potato attacks)
    L"SeAssignPrimaryTokenPrivilege", ///< Assign primary token
    L"SeLoadDriverPrivilege",      ///< Load kernel drivers
    L"SeRestorePrivilege",         ///< Restore files/registry
    L"SeBackupPrivilege",          ///< Backup files/registry
    L"SeTakeOwnershipPrivilege"    ///< Take ownership of objects
};

}  // namespace exeray::etw::security

#endif  // _WIN32
