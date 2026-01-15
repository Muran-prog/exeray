/// @file factory.cpp
/// @brief Session::create factory method implementation.

#ifdef _WIN32

#include "exeray/etw/session.hpp"
#include "helpers.hpp"

#include <cstdio>
#include <cstring>
#include <vector>

namespace exeray::etw {

std::unique_ptr<Session> Session::create(
    std::wstring_view session_name,
    EventCallback callback,
    void* context
) {
    if (session_name.empty() || session_name.size() >= 1024) {
        std::fwprintf(stderr, L"[ETW] Invalid session name length\n");
        return nullptr;
    }

    if (callback == nullptr) {
        std::fwprintf(stderr, L"[ETW] Event callback is required\n");
        return nullptr;
    }

    // Allocate properties buffer
    std::vector<uint8_t> props_buffer(session::properties_buffer_size(), 0);
    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(props_buffer.data());

    // Configure session properties
    props->Wnode.BufferSize = static_cast<ULONG>(props_buffer.size());
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;  // QPC timestamps
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    // Copy session name
    std::wstring name_str(session_name);
    auto* name_dest = reinterpret_cast<wchar_t*>(
        props_buffer.data() + props->LoggerNameOffset);
    std::wcsncpy(name_dest, name_str.c_str(), 1023);
    name_dest[1023] = L'\0';

    // Start the trace session
    TRACEHANDLE session_handle = 0;
    ULONG status = StartTraceW(&session_handle, name_str.c_str(), props);

    if (status != ERROR_SUCCESS) {
        // If session already exists, try to stop it and restart
        if (status == ERROR_ALREADY_EXISTS) {
            std::fwprintf(stderr, L"[ETW] Session '%ls' exists, stopping...\n",
                          name_str.c_str());

            // Prepare stop properties
            std::vector<uint8_t> stop_buffer(session::properties_buffer_size(), 0);
            auto* stop_props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(stop_buffer.data());
            stop_props->Wnode.BufferSize = static_cast<ULONG>(stop_buffer.size());
            stop_props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

            ControlTraceW(0, name_str.c_str(), stop_props, EVENT_TRACE_CONTROL_STOP);

            // Retry start
            std::memset(props_buffer.data(), 0, props_buffer.size());
            props->Wnode.BufferSize = static_cast<ULONG>(props_buffer.size());
            props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            props->Wnode.ClientContext = 1;
            props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            std::wcsncpy(name_dest, name_str.c_str(), 1023);

            status = StartTraceW(&session_handle, name_str.c_str(), props);
        }

        if (status != ERROR_SUCCESS) {
            session::log_error(L"StartTraceW", status);
            return nullptr;
        }
    }

    // Open the trace for consumption with callback and context
    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = const_cast<LPWSTR>(name_str.c_str());
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = callback;
    logfile.Context = context;

    TRACEHANDLE trace_handle = OpenTraceW(&logfile);
    if (trace_handle == INVALID_PROCESSTRACE_HANDLE) {
        ULONG open_error = GetLastError();
        session::log_error(L"OpenTraceW", open_error);

        // Cleanup: stop the session we just started
        std::vector<uint8_t> stop_buffer(session::properties_buffer_size(), 0);
        auto* stop_props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(stop_buffer.data());
        stop_props->Wnode.BufferSize = static_cast<ULONG>(stop_buffer.size());
        stop_props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        ControlTraceW(session_handle, nullptr, stop_props, EVENT_TRACE_CONTROL_STOP);

        return nullptr;
    }

    return std::unique_ptr<Session>(
        new Session(session_handle, trace_handle, std::move(name_str)));
}

}  // namespace exeray::etw

#endif  // _WIN32
