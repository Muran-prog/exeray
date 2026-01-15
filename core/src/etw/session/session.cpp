/// @file session.cpp
/// @brief Session class constructors, destructor, and operators.

#ifdef _WIN32

#include "exeray/etw/session.hpp"
#include "helpers.hpp"

#include <vector>

namespace exeray::etw {

Session::Session(TRACEHANDLE session_handle, TRACEHANDLE trace_handle,
                 std::wstring session_name)
    : session_handle_(session_handle),
      trace_handle_(trace_handle),
      session_name_(std::move(session_name)) {}

Session::Session(Session&& other) noexcept
    : session_handle_(other.session_handle_),
      trace_handle_(other.trace_handle_),
      session_name_(std::move(other.session_name_)) {
    other.session_handle_ = 0;
    other.trace_handle_ = INVALID_PROCESSTRACE_HANDLE;
}

Session& Session::operator=(Session&& other) noexcept {
    if (this != &other) {
        // Clean up current resources if any
        if (trace_handle_ != INVALID_PROCESSTRACE_HANDLE) {
            CloseTrace(trace_handle_);
        }
        if (session_handle_ != 0) {
            std::vector<uint8_t> stop_buffer(session::properties_buffer_size(), 0);
            auto* stop_props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(stop_buffer.data());
            stop_props->Wnode.BufferSize = static_cast<ULONG>(stop_buffer.size());
            stop_props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            ControlTraceW(session_handle_, nullptr, stop_props, EVENT_TRACE_CONTROL_STOP);
        }

        session_handle_ = other.session_handle_;
        trace_handle_ = other.trace_handle_;
        session_name_ = std::move(other.session_name_);

        other.session_handle_ = 0;
        other.trace_handle_ = INVALID_PROCESSTRACE_HANDLE;
    }
    return *this;
}

Session::~Session() {
    // Close the consumer trace handle first
    if (trace_handle_ != INVALID_PROCESSTRACE_HANDLE) {
        ULONG status = CloseTrace(trace_handle_);
        if (status != ERROR_SUCCESS && status != ERROR_CTX_CLOSE_PENDING) {
            session::log_error(L"CloseTrace", status);
        }
        trace_handle_ = INVALID_PROCESSTRACE_HANDLE;
    }

    // Stop the tracing session
    if (session_handle_ != 0) {
        std::vector<uint8_t> stop_buffer(session::properties_buffer_size(), 0);
        auto* stop_props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(stop_buffer.data());
        stop_props->Wnode.BufferSize = static_cast<ULONG>(stop_buffer.size());
        stop_props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        ULONG status = ControlTraceW(session_handle_, nullptr, stop_props,
                                      EVENT_TRACE_CONTROL_STOP);
        if (status != ERROR_SUCCESS) {
            session::log_error(L"StopTrace", status);
        }
        session_handle_ = 0;
    }
}

}  // namespace exeray::etw

#endif  // _WIN32
