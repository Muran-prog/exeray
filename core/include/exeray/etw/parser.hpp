#pragma once

/// @file parser.hpp
/// @brief ETW event parsers for extracting structured data from raw events.

#ifdef _WIN32

#include <cstdint>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include "exeray/event/types.hpp"
#include "exeray/event/payload.hpp"

namespace exeray::event {
class StringPool;  // Forward declaration
}  // namespace exeray::event

namespace exeray::etw {

/// @brief Result of parsing an ETW event.
///
/// Contains the extracted event data in a normalized format suitable for
/// storage in the EventGraph. The `valid` flag indicates whether parsing
/// succeeded.
struct ParsedEvent {
    event::Category category;   ///< Event category (FileSystem, Process, etc.)
    uint8_t operation;          ///< Category-specific operation enum value
    event::Status status;       ///< Operation result status
    uint32_t pid;               ///< Source process ID
    uint64_t timestamp;         ///< Timestamp in 100-ns intervals
    event::EventPayload payload; ///< Category-specific payload data
    bool valid;                 ///< True if parsing succeeded
};

/// @brief Parse a Microsoft-Windows-Kernel-Process event.
/// @param record Pointer to the raw ETW event record.
/// @return ParsedEvent with process operation details.
///
/// Handles:
/// - Event ID 1: ProcessStart → ProcessOp::Create
/// - Event ID 2: ProcessStop → ProcessOp::Terminate
/// - Event ID 5: ImageLoad → ProcessOp::LoadLibrary
ParsedEvent parse_process_event(const EVENT_RECORD* record, event::StringPool* strings);

/// @brief Parse a Microsoft-Windows-Kernel-File event.
/// @param record Pointer to the raw ETW event record.
/// @return ParsedEvent with file operation details.
///
/// Handles:
/// - Event ID 10: Create → FileOp::Create
/// - Event ID 11: Cleanup (close)
/// - Event ID 14: Read → FileOp::Read
/// - Event ID 15: Write → FileOp::Write
/// - Event ID 26: Delete → FileOp::Delete
ParsedEvent parse_file_event(const EVENT_RECORD* record, event::StringPool* strings);

/// @brief Parse a Microsoft-Windows-Kernel-Registry event.
/// @param record Pointer to the raw ETW event record.
/// @return ParsedEvent with registry operation details.
///
/// Handles:
/// - Event ID 1: CreateKey → RegistryOp::CreateKey
/// - Event ID 2: OpenKey → RegistryOp::QueryValue
/// - Event ID 5: SetValue → RegistryOp::SetValue
/// - Event ID 6: DeleteValue → RegistryOp::DeleteValue
ParsedEvent parse_registry_event(const EVENT_RECORD* record, event::StringPool* strings);

/// @brief Parse a Microsoft-Windows-Kernel-Network event.
/// @param record Pointer to the raw ETW event record.
/// @return ParsedEvent with network operation details.
ParsedEvent parse_network_event(const EVENT_RECORD* record, event::StringPool* strings);

/// @brief Parse an Image Load/Unload event.
/// @param record Pointer to the raw ETW event record.
/// @return ParsedEvent with image operation details.
///
/// Handles:
/// - Event ID 10: Image Load
/// - Event ID 2:  Image Unload
/// Also detects suspicious DLLs loaded from temp/appdata paths.
ParsedEvent parse_image_event(const EVENT_RECORD* record, event::StringPool* strings);

/// @brief Parse a Thread event.
/// @param record Pointer to the raw ETW event record.
/// @return ParsedEvent with thread operation details.
///
/// Handles:
/// - Event ID 1: Start → ThreadOp::Start
/// - Event ID 2: End → ThreadOp::End
/// - Event ID 3: DCStart → ThreadOp::DCStart
/// - Event ID 4: DCEnd → ThreadOp::DCEnd
/// Detects remote thread injection when creator != target process.
ParsedEvent parse_thread_event(const EVENT_RECORD* record, event::StringPool* strings);

/// @brief Parse a Virtual Memory event.
/// @param record Pointer to the raw ETW event record.
/// @return ParsedEvent with memory operation details.
///
/// Handles:
/// - Event ID 98: VirtualAlloc → MemoryOp::Alloc
/// - Event ID 99: VirtualFree → MemoryOp::Free
/// Detects RWX allocations (PAGE_EXECUTE_READWRITE/WRITECOPY).
ParsedEvent parse_memory_event(const EVENT_RECORD* record, event::StringPool* strings);

/// @brief Parse a Microsoft-Windows-PowerShell event.
/// @param record Pointer to the raw ETW event record.
/// @return ParsedEvent with script operation details.
///
/// Handles:
/// - Event ID 4103: Module Logging → ScriptOp::Module
/// - Event ID 4104: Script Block Logging → ScriptOp::Execute
/// Detects suspicious patterns (IEX, EncodedCommand, download cradles).
ParsedEvent parse_powershell_event(const EVENT_RECORD* record, event::StringPool* strings);

/// @brief Dispatch an ETW event to the appropriate parser based on provider.
/// @param record Pointer to the raw ETW event record.
/// @return ParsedEvent from the matching parser, or invalid if unrecognized.
///
/// Routes events by comparing the provider GUID to known kernel providers:
/// - KERNEL_PROCESS → parse_process_event
/// - KERNEL_FILE → parse_file_event
/// - KERNEL_REGISTRY → parse_registry_event
/// - KERNEL_NETWORK → parse_network_event
/// - KERNEL_IMAGE → parse_image_event
/// - KERNEL_THREAD → parse_thread_event
/// - KERNEL_MEMORY → parse_memory_event
/// - POWERSHELL → parse_powershell_event
/// - AMSI → parse_amsi_event
/// - DNS_CLIENT → parse_dns_event
/// - SECURITY_AUDITING → parse_security_event
/// - WMI_ACTIVITY → parse_wmi_event
ParsedEvent dispatch_event(const EVENT_RECORD* record, event::StringPool* strings);

/// @brief Parse a Microsoft-Antimalware-Scan-Interface event.
/// @param record Pointer to the raw ETW event record.
/// @return ParsedEvent with AMSI scan details.
///
/// Handles:
/// - Event ID 1101: AmsiScanBuffer → AmsiOp::Scan
/// Detects bypass attempts (empty content) and malware results.
ParsedEvent parse_amsi_event(const EVENT_RECORD* record, event::StringPool* strings);

/// @brief Parse a Microsoft-Windows-DNS-Client event.
/// @param record Pointer to the raw ETW event record.
/// @return ParsedEvent with DNS query details.
///
/// Handles:
/// - Event ID 3006: Query Completed → DnsOp::Response
/// - Event ID 3008: Query Failed → DnsOp::Failure
/// Detects DGA-like suspicious domains using entropy analysis.
ParsedEvent parse_dns_event(const EVENT_RECORD* record, event::StringPool* strings);

/// @brief Parse a Microsoft-Windows-Security-Auditing event.
/// @param record Pointer to the raw ETW event record.
/// @return ParsedEvent with security/service operation details.
///
/// Handles:
/// - Event ID 4624: Logon Success → SecurityOp::Logon
/// - Event ID 4625: Logon Failed → SecurityOp::LogonFailed (brute force detection)
/// - Event ID 4688: Process Create → SecurityOp::ProcessCreate (with command line)
/// - Event ID 4689: Process Terminate → SecurityOp::ProcessTerminate
/// - Event ID 4697: Service Install → ServiceOp::Install (AUTO_START = suspicious)
/// - Event ID 4703: Token Rights → SecurityOp::PrivilegeAdjust (SeDebugPrivilege = suspicious)
ParsedEvent parse_security_event(const EVENT_RECORD* record, event::StringPool* strings);

/// @brief Parse a Microsoft-Windows-WMI-Activity event.
/// @param record Pointer to the raw ETW event record.
/// @return ParsedEvent with WMI operation details.
///
/// Handles:
/// - Event ID 5: Namespace Connect → WmiOp::Connect
/// - Event ID 11: ExecQuery → WmiOp::Query
/// - Event ID 22: ExecNotificationQuery → WmiOp::Subscribe (persistence!)
/// - Event ID 23: ExecMethod → WmiOp::ExecMethod (Win32_Process.Create!)
/// Detects remote WMI (lateral movement) and suspicious patterns.
ParsedEvent parse_wmi_event(const EVENT_RECORD* record, event::StringPool* strings);

}  // namespace exeray::etw

#else  // !_WIN32

// Stub declarations for non-Windows platforms
#include <cstdint>
#include "exeray/event/types.hpp"
#include "exeray/event/payload.hpp"

namespace exeray::event {
class StringPool;  // Forward declaration
}  // namespace exeray::event

namespace exeray::etw {

struct ParsedEvent {
    event::Category category;
    uint8_t operation;
    event::Status status;
    uint32_t pid;
    uint64_t timestamp;
    event::EventPayload payload;
    bool valid;
};

// Stub function declarations - return invalid events on non-Windows
struct EVENT_RECORD;  // Forward declaration

inline ParsedEvent parse_process_event(const EVENT_RECORD* /*record*/, event::StringPool* /*strings*/) {
    return ParsedEvent{.valid = false};
}

inline ParsedEvent parse_file_event(const EVENT_RECORD* /*record*/, event::StringPool* /*strings*/) {
    return ParsedEvent{.valid = false};
}

inline ParsedEvent parse_registry_event(const EVENT_RECORD* /*record*/, event::StringPool* /*strings*/) {
    return ParsedEvent{.valid = false};
}

inline ParsedEvent parse_network_event(const EVENT_RECORD* /*record*/, event::StringPool* /*strings*/) {
    return ParsedEvent{.valid = false};
}

inline ParsedEvent parse_image_event(const EVENT_RECORD* /*record*/, event::StringPool* /*strings*/) {
    return ParsedEvent{.valid = false};
}

inline ParsedEvent parse_thread_event(const EVENT_RECORD* /*record*/, event::StringPool* /*strings*/) {
    return ParsedEvent{.valid = false};
}

inline ParsedEvent parse_memory_event(const EVENT_RECORD* /*record*/, event::StringPool* /*strings*/) {
    return ParsedEvent{.valid = false};
}

inline ParsedEvent parse_powershell_event(const EVENT_RECORD* /*record*/, event::StringPool* /*strings*/) {
    return ParsedEvent{.valid = false};
}

inline ParsedEvent parse_amsi_event(const EVENT_RECORD* /*record*/, event::StringPool* /*strings*/) {
    return ParsedEvent{.valid = false};
}

inline ParsedEvent parse_dns_event(const EVENT_RECORD* /*record*/, event::StringPool* /*strings*/) {
    return ParsedEvent{.valid = false};
}

inline ParsedEvent parse_security_event(const EVENT_RECORD* /*record*/, event::StringPool* /*strings*/) {
    return ParsedEvent{.valid = false};
}

inline ParsedEvent parse_wmi_event(const EVENT_RECORD* /*record*/, event::StringPool* /*strings*/) {
    return ParsedEvent{.valid = false};
}

inline ParsedEvent dispatch_event(const EVENT_RECORD* /*record*/, event::StringPool* /*strings*/) {
    return ParsedEvent{.valid = false};
}

}  // namespace exeray::etw

#endif  // _WIN32
