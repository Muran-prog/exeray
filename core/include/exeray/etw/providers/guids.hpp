#pragma once

/// @file guids.hpp
/// @brief Well-known ETW provider GUID declarations.

#ifdef _WIN32
#include <windows.h>
#else
// GUID struct is defined in session.hpp for non-Windows platforms
#include <cstdint>
// Forward declare types for the providers namespace
namespace exeray::etw { struct GUID; }
#endif

namespace exeray::etw::providers {

/// Microsoft-Windows-Kernel-Process provider
extern const GUID KERNEL_PROCESS;

/// Microsoft-Windows-Kernel-File provider
extern const GUID KERNEL_FILE;

/// Microsoft-Windows-Kernel-Registry provider
extern const GUID KERNEL_REGISTRY;

/// Microsoft-Windows-Kernel-Network provider
extern const GUID KERNEL_NETWORK;

/// Image Load provider (classic NT Kernel Logger)
extern const GUID KERNEL_IMAGE;

/// Thread events provider (classic NT Kernel Logger)
extern const GUID KERNEL_THREAD;

/// Virtual memory events provider (PageFault)
extern const GUID KERNEL_MEMORY;

/// Microsoft-Windows-PowerShell provider
extern const GUID POWERSHELL;

/// Microsoft-Antimalware-Scan-Interface provider
extern const GUID AMSI;

/// Microsoft-Windows-DNS-Client provider
extern const GUID DNS_CLIENT;

/// Microsoft-Windows-Security-Auditing provider
extern const GUID SECURITY_AUDITING;

/// Microsoft-Windows-WMI-Activity provider
extern const GUID WMI_ACTIVITY;

/// Microsoft-Windows-DotNETRuntime provider
extern const GUID CLR_RUNTIME;

/// PowerShell keywords for event filtering.
namespace powershell_keywords {
    constexpr uint64_t RUNSPACE = 0x10;
    constexpr uint64_t PIPELINE = 0x20;
    constexpr uint64_t CMDLETS  = 0x40;
    constexpr uint64_t ALL      = RUNSPACE | PIPELINE | CMDLETS;
}

/// CLR Runtime keywords for event filtering.
namespace clr_keywords {
    constexpr uint64_t LOADER = 0x8;
    constexpr uint64_t JIT    = 0x10;
    constexpr uint64_t ALL    = LOADER | JIT;
}

}  // namespace exeray::etw::providers
