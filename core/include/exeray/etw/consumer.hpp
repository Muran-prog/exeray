#pragma once

/// @file consumer.hpp
/// @brief ETW event consumer callback and context structures.
///
/// Provides the context structure and callback declarations for ETW event
/// processing. The callback is invoked by ProcessTrace for each event.

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include <atomic>
#include <cstdint>

namespace exeray {
namespace event {
class EventGraph;  // Forward declaration
}  // namespace event

namespace etw {

/// @brief Context passed to ETW callback via EVENT_TRACE_LOGFILE::Context.
///
/// This structure is stored in the UserContext field and provides the callback
/// with access to the event graph and target PID filter.
struct ConsumerContext {
    /// @brief Pointer to the event graph for pushing parsed events.
    event::EventGraph* graph = nullptr;
    
    /// @brief Atomic target PID for filtering (0 = no filter).
    std::atomic<uint32_t>* target_pid = nullptr;
};

/// @brief ETW event record callback function.
///
/// This function is called by ProcessTrace for each event record.
/// It filters by target PID, parses the event, and pushes to the EventGraph.
///
/// @param record Pointer to the ETW event record.
/// @note Must remain compatible with PEVENT_RECORD_CALLBACK signature.
void WINAPI event_record_callback(PEVENT_RECORD record);

/// @brief Start processing trace events (blocking call).
///
/// Calls ProcessTrace which blocks until the session is stopped via CloseTrace
/// or the controller calls ControlTraceW with EVENT_TRACE_CONTROL_STOP.
///
/// @param trace_handle Handle from Session::trace_handle().
/// @return ERROR_SUCCESS on success, or Windows error code on failure.
ULONG start_trace_processing(TRACEHANDLE trace_handle);

}  // namespace etw
}  // namespace exeray

#else  // !_WIN32

// Stub declarations for non-Windows platforms
#include <atomic>
#include <cstdint>

namespace exeray {
namespace event {
class EventGraph;
}  // namespace event

namespace etw {

struct ConsumerContext {
    event::EventGraph* graph = nullptr;
    std::atomic<uint32_t>* target_pid = nullptr;
};

/// @brief Stub callback for non-Windows.
void event_record_callback(void* record);

/// @brief Stub trace processing for non-Windows.
/// @return Always returns 0.
unsigned long start_trace_processing(uint64_t trace_handle);

}  // namespace etw
}  // namespace exeray

#endif  // _WIN32
