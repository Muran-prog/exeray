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
ParsedEvent parse_process_event(const EVENT_RECORD* record);

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
ParsedEvent parse_file_event(const EVENT_RECORD* record);

/// @brief Parse a Microsoft-Windows-Kernel-Registry event.
/// @param record Pointer to the raw ETW event record.
/// @return ParsedEvent with registry operation details.
///
/// Handles:
/// - Event ID 1: CreateKey → RegistryOp::CreateKey
/// - Event ID 2: OpenKey → RegistryOp::QueryValue
/// - Event ID 5: SetValue → RegistryOp::SetValue
/// - Event ID 6: DeleteValue → RegistryOp::DeleteValue
ParsedEvent parse_registry_event(const EVENT_RECORD* record);

/// @brief Parse a Microsoft-Windows-Kernel-Network event.
/// @param record Pointer to the raw ETW event record.
/// @return ParsedEvent with network operation details.
ParsedEvent parse_network_event(const EVENT_RECORD* record);

/// @brief Dispatch an ETW event to the appropriate parser based on provider.
/// @param record Pointer to the raw ETW event record.
/// @return ParsedEvent from the matching parser, or invalid if unrecognized.
///
/// Routes events by comparing the provider GUID to known kernel providers:
/// - KERNEL_PROCESS → parse_process_event
/// - KERNEL_FILE → parse_file_event
/// - KERNEL_REGISTRY → parse_registry_event
/// - KERNEL_NETWORK → parse_network_event
ParsedEvent dispatch_event(const EVENT_RECORD* record);

}  // namespace exeray::etw

#else  // !_WIN32

// Stub declarations for non-Windows platforms
#include <cstdint>
#include "exeray/event/types.hpp"
#include "exeray/event/payload.hpp"

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

inline ParsedEvent parse_process_event(const EVENT_RECORD* /*record*/) {
    return ParsedEvent{.valid = false};
}

inline ParsedEvent parse_file_event(const EVENT_RECORD* /*record*/) {
    return ParsedEvent{.valid = false};
}

inline ParsedEvent parse_registry_event(const EVENT_RECORD* /*record*/) {
    return ParsedEvent{.valid = false};
}

inline ParsedEvent parse_network_event(const EVENT_RECORD* /*record*/) {
    return ParsedEvent{.valid = false};
}

inline ParsedEvent dispatch_event(const EVENT_RECORD* /*record*/) {
    return ParsedEvent{.valid = false};
}

}  // namespace exeray::etw

#endif  // _WIN32
