/// @file consumer.cpp
/// @brief ETW event consumer callback and utilities.
///
/// Provides the callback function invoked by ProcessTrace for each ETW event,
/// along with the consumer context structure for passing state to the callback.

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include "exeray/etw/consumer.hpp"
#include "exeray/etw/parser.hpp"
#include "exeray/event/graph.hpp"
#include "exeray/event/types.hpp"

#include <atomic>
#include <cstdint>
#include <iostream>

namespace exeray::etw {

void WINAPI event_record_callback(PEVENT_RECORD record) {
    if (record == nullptr || record->UserContext == nullptr) {
        return;
    }

    auto* ctx = static_cast<ConsumerContext*>(record->UserContext);

    // PID filter - only process events from target process
    const uint32_t event_pid = record->EventHeader.ProcessId;
    const uint32_t target = ctx->target_pid->load(std::memory_order_acquire);
    
    // If target_pid is 0, accept all events (no filter)
    // Otherwise, only accept events from the target process
    if (target != 0 && event_pid != target) {
        return;
    }

    // Parse the event using the dispatcher
    auto parsed = dispatch_event(record);
    if (!parsed.valid) {
        return;
    }

    // Push to the event graph
    ctx->graph->push(
        parsed.category,
        parsed.operation,
        parsed.status,
        event::INVALID_EVENT,
        parsed.payload
    );
}

ULONG start_trace_processing(TRACEHANDLE trace_handle) {
    if (trace_handle == INVALID_PROCESSTRACE_HANDLE) {
        return ERROR_INVALID_HANDLE;
    }

    // ProcessTrace blocks until the session is stopped via CloseTrace or
    // the BufferCallback returns FALSE
    TRACEHANDLE handles[1] = { trace_handle };
    return ProcessTrace(handles, 1, nullptr, nullptr);
}

}  // namespace exeray::etw

#else  // !_WIN32

// Stub implementations for non-Windows platforms
#include "exeray/etw/consumer.hpp"

namespace exeray::etw {

void event_record_callback(void* /*record*/) {
    // No-op on non-Windows
}

unsigned long start_trace_processing(uint64_t /*trace_handle*/) {
    // Not supported on non-Windows
    return 0;
}

}  // namespace exeray::etw

#endif  // _WIN32
