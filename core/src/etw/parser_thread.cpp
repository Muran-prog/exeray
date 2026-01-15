/// @file parser_thread.cpp
/// @brief ETW parser for Thread events with remote injection detection.

#ifdef _WIN32

#include "exeray/etw/parser.hpp"
#include "exeray/etw/parser_utils.hpp"
#include "exeray/etw/session.hpp"
#include "exeray/etw/tdh_parser.hpp"

#include <cstring>

namespace exeray::etw {

namespace {

/// Thread event IDs from Thread_TypeGroup1 class.
enum class ThreadEventId : uint16_t {
    Start = 1,    ///< Thread started
    End = 2,      ///< Thread terminated
    DCStart = 3,  ///< Running thread enumeration at session start
    DCEnd = 4     ///< Running thread enumeration at session end
};

/// @brief Check if this is a remote thread injection.
///
/// Remote thread injection occurs when a process creates a thread in another
/// process (e.g., via CreateRemoteThread or NtCreateThreadEx).
///
/// @param creator_pid Process ID of thread creator (from EVENT_RECORD header).
/// @param target_pid Process ID where thread runs (from event payload).
/// @return true if this is a cross-process thread creation.
bool is_remote_thread(uint32_t creator_pid, uint32_t target_pid) {
    // Ignore system/idle processes (PID 0 and 4)
    if (creator_pid == 0 || target_pid == 0 || creator_pid == 4 || target_pid == 4) {
        return false;
    }
    return creator_pid != target_pid;
}

/// @brief Parse Thread Start event (Event ID 1).
///
/// UserData layout (Thread_TypeGroup1, EventVersion 3):
///   ProcessId: UINT32
///   TThreadId: UINT32
///   StackBase: PVOID
///   StackLimit: PVOID
///   UserStackBase: PVOID
///   UserStackLimit: PVOID
///   Affinity: PVOID
///   Win32StartAddr: PVOID
///   TebBase: PVOID
///   SubProcessTag: UINT32
///   BasePriority: UINT8
///   PagePriority: UINT8
///   IoPriority: UINT8
///   ThreadFlags: UINT8
ParsedEvent parse_thread_start(const EVENT_RECORD* record) {
    ParsedEvent result{};
    extract_common(record, result, event::Category::Thread);
    result.operation = static_cast<uint8_t>(event::ThreadOp::Start);
    result.payload.category = event::Category::Thread;

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 8) {
        result.valid = false;
        return result;
    }

    // Determine pointer size from event flags
    const bool is64bit = (record->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0;
    const size_t ptr_size = is64bit ? 8 : 4;

    // Extract ProcessId and TThreadId (first 8 bytes)
    uint32_t process_id = 0;
    uint32_t thread_id = 0;
    std::memcpy(&process_id, data, sizeof(uint32_t));
    std::memcpy(&thread_id, data + sizeof(uint32_t), sizeof(uint32_t));

    // Calculate offset to Win32StartAddr
    // After ProcessId(4) + TThreadId(4) + StackBase + StackLimit +
    // UserStackBase + UserStackLimit + Affinity = 8 + 5*ptr_size
    const size_t start_addr_offset = 8 + (5 * ptr_size);

    uint64_t start_address = 0;
    if (start_addr_offset + ptr_size <= len) {
        if (is64bit) {
            std::memcpy(&start_address, data + start_addr_offset, sizeof(uint64_t));
        } else {
            uint32_t addr32 = 0;
            std::memcpy(&addr32, data + start_addr_offset, sizeof(uint32_t));
            start_address = addr32;
        }
    }

    // Get creator PID from event header
    const uint32_t creator_pid = record->EventHeader.ProcessId;

    // Populate payload
    result.payload.thread.thread_id = thread_id;
    result.payload.thread.process_id = process_id;
    result.payload.thread.start_address = start_address;
    result.payload.thread.creator_pid = creator_pid;

    // Detect remote thread injection
    if (is_remote_thread(creator_pid, process_id)) {
        result.payload.thread.is_remote = 1;
        result.status = event::Status::Suspicious;
    } else {
        result.payload.thread.is_remote = 0;
    }

    result.pid = creator_pid;
    result.valid = true;
    return result;
}

/// @brief Parse Thread End event (Event ID 2).
ParsedEvent parse_thread_end(const EVENT_RECORD* record) {
    ParsedEvent result{};
    extract_common(record, result, event::Category::Thread);
    result.operation = static_cast<uint8_t>(event::ThreadOp::End);
    result.payload.category = event::Category::Thread;

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 8) {
        result.valid = false;
        return result;
    }

    // Extract ProcessId and TThreadId
    uint32_t process_id = 0;
    uint32_t thread_id = 0;
    std::memcpy(&process_id, data, sizeof(uint32_t));
    std::memcpy(&thread_id, data + sizeof(uint32_t), sizeof(uint32_t));

    result.payload.thread.thread_id = thread_id;
    result.payload.thread.process_id = process_id;
    result.payload.thread.start_address = 0;
    result.payload.thread.creator_pid = 0;
    result.payload.thread.is_remote = 0;

    result.pid = record->EventHeader.ProcessId;
    result.valid = true;
    return result;
}

/// @brief Parse Thread DCStart event (Event ID 3).
/// Same structure as Start, used for enumerating existing threads.
ParsedEvent parse_thread_dcstart(const EVENT_RECORD* record) {
    ParsedEvent result = parse_thread_start(record);
    result.operation = static_cast<uint8_t>(event::ThreadOp::DCStart);
    // DCStart events are enumeration, not suspicious even if cross-process
    result.payload.thread.is_remote = 0;
    result.status = event::Status::Success;
    return result;
}

/// @brief Parse Thread DCEnd event (Event ID 4).
/// Same structure as End, used for enumerating existing threads.
ParsedEvent parse_thread_dcend(const EVENT_RECORD* record) {
    ParsedEvent result = parse_thread_end(record);
    result.operation = static_cast<uint8_t>(event::ThreadOp::DCEnd);
    return result;
}

}  // namespace

ParsedEvent parse_thread_event(const EVENT_RECORD* record, event::StringPool* strings) {
    if (record == nullptr) {
        return ParsedEvent{.valid = false};
    }

    const auto event_id = static_cast<ThreadEventId>(record->EventHeader.EventDescriptor.Id);

    switch (event_id) {
        case ThreadEventId::Start:
            return parse_thread_start(record);
        case ThreadEventId::End:
            return parse_thread_end(record);
        case ThreadEventId::DCStart:
            return parse_thread_dcstart(record);
        case ThreadEventId::DCEnd:
            return parse_thread_dcend(record);
        default:
            // Unknown event ID - try TDH fallback
            if (auto tdh_result = parse_with_tdh(record)) {
                return convert_tdh_to_thread(*tdh_result, record, strings);
            }
            return ParsedEvent{.valid = false};
    }
}

}  // namespace exeray::etw

#else  // !_WIN32

// Empty translation unit for non-Windows
namespace exeray::etw {
// Stub defined in header as inline
}  // namespace exeray::etw

#endif  // _WIN32
