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
#include "exeray/event/correlator.hpp"
#include "exeray/event/graph.hpp"
#include "exeray/event/types.hpp"

#include <atomic>
#include <cstdint>
#include <iostream>

namespace exeray::etw {

namespace {

/// @brief Get parent event ID based on event category.
event::EventId get_parent_event(event::Correlator* correlator,
                                 const ParsedEvent& parsed) {
    if (correlator == nullptr) {
        return event::INVALID_EVENT;
    }

    switch (parsed.category) {
        case event::Category::Process:
            // For process events, parent is the parent process's create event
            return correlator->find_process_parent(parsed.payload.process.parent_pid);

        case event::Category::Thread:
            // For thread events, parent is the owning process
            return correlator->find_thread_parent(parsed.payload.thread.process_id);

        case event::Category::Memory:
            // For memory events, parent is the process doing the allocation
            return correlator->find_operation_parent(parsed.payload.memory.process_id);

        case event::Category::Image:
            // For image load events, parent is the target process
            return correlator->find_operation_parent(parsed.payload.image.process_id);

        default:
            return event::INVALID_EVENT;
    }
}

/// @brief Get PID and parent PID from parsed event for correlation.
void get_correlation_pids(const ParsedEvent& parsed,
                          uint32_t& pid, uint32_t& parent_pid) {
    switch (parsed.category) {
        case event::Category::Process:
            pid = parsed.payload.process.pid;
            parent_pid = parsed.payload.process.parent_pid;
            break;
        case event::Category::Thread:
            pid = parsed.payload.thread.process_id;
            parent_pid = 0;
            break;
        case event::Category::Memory:
            pid = parsed.payload.memory.process_id;
            parent_pid = 0;
            break;
        case event::Category::Image:
            pid = parsed.payload.image.process_id;
            parent_pid = 0;
            break;
        default:
            pid = 0;
            parent_pid = 0;
            break;
    }
}

}  // anonymous namespace

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
    auto parsed = dispatch_event(record, ctx->strings);
    if (!parsed.valid) {
        return;
    }

    // Determine parent event and correlation ID
    event::EventId parent_event = event::INVALID_EVENT;
    uint32_t correlation_id = 0;

    if (ctx->correlator != nullptr) {
        parent_event = get_parent_event(ctx->correlator, parsed);

        uint32_t pid = 0;
        uint32_t parent_pid = 0;
        get_correlation_pids(parsed, pid, parent_pid);
        correlation_id = ctx->correlator->get_correlation_id(pid, parent_pid);
    }

    // Push to the event graph
    event::EventId event_id = ctx->graph->push(
        parsed.category,
        parsed.operation,
        parsed.status,
        parent_event,
        correlation_id,
        parsed.payload
    );

    // Register the event for future correlation lookups
    if (ctx->correlator != nullptr && event_id != event::INVALID_EVENT) {
        // For process create events, register the new process
        if (parsed.category == event::Category::Process &&
            parsed.operation == static_cast<uint8_t>(event::ProcessOp::Create)) {
            ctx->correlator->register_process(parsed.payload.process.pid, event_id);
        }
    }
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
