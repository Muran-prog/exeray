/// @file event_ids.hpp
/// @brief Centralized ETW event ID definitions for all providers.
///
/// This header provides a single source of truth for all ETW event IDs used
/// across the parsers. Each provider has its own namespace.

#pragma once

#include <cstdint>

namespace exeray::etw::ids {

/// Event IDs from Microsoft-Windows-Kernel-Process provider.
namespace process {
    constexpr uint16_t START = 1;       ///< ProcessStart
    constexpr uint16_t STOP = 2;        ///< ProcessStop
    constexpr uint16_t IMAGE_LOAD = 5;  ///< ImageLoad
}  // namespace process

/// Event IDs from Microsoft-Windows-Kernel-File provider.
namespace file {
    constexpr uint16_t CREATE = 10;   ///< File create/open
    constexpr uint16_t CLEANUP = 11;  ///< File cleanup (close)
    constexpr uint16_t READ = 14;     ///< File read
    constexpr uint16_t WRITE = 15;    ///< File write
    constexpr uint16_t FILE_DELETE = 26;   ///< File delete
}  // namespace file

/// Event IDs from NT Kernel Logger Image class.
namespace image {
    constexpr uint16_t UNLOAD = 2;  ///< Image unloaded from process
    constexpr uint16_t LOAD = 10;   ///< Image loaded into process
}  // namespace image

/// Event IDs from Microsoft-Windows-Kernel-Registry provider.
namespace registry {
    constexpr uint16_t CREATE_KEY = 1;    ///< CreateKey
    constexpr uint16_t OPEN_KEY = 2;      ///< OpenKey
    constexpr uint16_t SET_VALUE = 5;     ///< SetValue
    constexpr uint16_t VALUE_DELETE = 6;  ///< DeleteValue
}  // namespace registry

/// Event IDs from Microsoft-Windows-Kernel-Network provider.
namespace network {
    constexpr uint16_t TCP_CONNECT = 10;   ///< TCP connect
    constexpr uint16_t TCP_ACCEPT = 11;    ///< TCP accept
    constexpr uint16_t TCP_SEND = 14;      ///< TCP send
    constexpr uint16_t TCP_RECEIVE = 15;   ///< TCP receive
    constexpr uint16_t UDP_SEND = 18;      ///< UDP send
    constexpr uint16_t UDP_RECEIVE = 19;   ///< UDP receive
}  // namespace network

/// Event IDs from Thread_TypeGroup1 class.
namespace thread {
    constexpr uint16_t START = 1;     ///< Thread started
    constexpr uint16_t END = 2;       ///< Thread terminated
    constexpr uint16_t DC_START = 3;  ///< Running thread enumeration at start
    constexpr uint16_t DC_END = 4;    ///< Running thread enumeration at end
}  // namespace thread

/// Event IDs from PageFault_VirtualAlloc class.
namespace memory {
    constexpr uint16_t VIRTUAL_ALLOC = 98;  ///< VirtualAlloc/VirtualAllocEx
    constexpr uint16_t VIRTUAL_FREE = 99;   ///< VirtualFree
}  // namespace memory

/// Event IDs from Microsoft-Antimalware-Scan-Interface provider.
namespace amsi {
    constexpr uint16_t SCAN_BUFFER = 1101;  ///< AmsiScanBuffer called
}  // namespace amsi

/// Event IDs from Microsoft-Windows-PowerShell provider.
namespace powershell {
    constexpr uint16_t MODULE_LOGGING = 4103;        ///< Module/Cmdlet logging
    constexpr uint16_t SCRIPT_BLOCK_LOGGING = 4104;  ///< Script Block Logging
}  // namespace powershell

/// Event IDs from Microsoft-Windows-WMI-Activity provider.
namespace wmi {
    constexpr uint16_t NAMESPACE_CONNECT = 5;          ///< ConnectServer
    constexpr uint16_t EXEC_QUERY = 11;                ///< ExecQuery
    constexpr uint16_t EXEC_NOTIFICATION_QUERY = 22;   ///< ExecNotificationQuery
    constexpr uint16_t EXEC_METHOD = 23;               ///< ExecMethod
}  // namespace wmi

/// Event IDs from Microsoft-Windows-Security-Auditing provider.
namespace security {
    constexpr uint16_t LOGON_SUCCESS = 4624;       ///< Successful logon
    constexpr uint16_t LOGON_FAILED = 4625;        ///< Failed logon attempt
    constexpr uint16_t PROCESS_CREATE = 4688;      ///< New process created
    constexpr uint16_t PROCESS_EXIT = 4689;       ///< Process terminated
    constexpr uint16_t SERVICE_INSTALLED = 4697;  ///< Service installed
    constexpr uint16_t TOKEN_RIGHTS = 4703;        ///< Token rights adjusted
}  // namespace security

/// Event IDs from Microsoft-Windows-DotNETRuntime provider.
namespace clr {
    constexpr uint16_t ASSEMBLY_LOAD_START = 152;  ///< Assembly load started
    constexpr uint16_t ASSEMBLY_LOAD_STOP = 153;   ///< Assembly load completed
    constexpr uint16_t ASSEMBLY_UNLOAD = 154;      ///< Assembly unloaded
    constexpr uint16_t METHOD_JIT_START = 155;     ///< Method JIT started
}  // namespace clr

/// Event IDs from Microsoft-Windows-DNS-Client provider.
namespace dns {
    constexpr uint16_t QUERY_COMPLETED = 3006;  ///< DNS query completed
    constexpr uint16_t QUERY_FAILED = 3008;     ///< DNS query failed
}  // namespace dns

}  // namespace exeray::etw::ids
