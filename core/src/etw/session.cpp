/// @file session.cpp
/// @brief ETW Session Manager implementation for Windows.

#ifdef _WIN32

#include "exeray/etw/session.hpp"

#include <cstdio>
#include <cstring>
#include <vector>

namespace exeray::etw {

namespace {

/// @brief Log a Windows error to stderr.
void log_error(const wchar_t* context, ULONG error_code) {
    wchar_t* message = nullptr;
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&message), 0, nullptr);

    if (message) {
        std::fwprintf(stderr, L"[ETW] %ls: error %lu - %ls", context, error_code, message);
        LocalFree(message);
    } else {
        std::fwprintf(stderr, L"[ETW] %ls: error %lu\n", context, error_code);
    }
}

/// @brief Size of the properties buffer including session name.
constexpr size_t properties_buffer_size() {
    return sizeof(EVENT_TRACE_PROPERTIES) + (1024 * sizeof(wchar_t));
}

}  // namespace

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
    std::vector<uint8_t> props_buffer(properties_buffer_size(), 0);
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
            std::vector<uint8_t> stop_buffer(properties_buffer_size(), 0);
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
            log_error(L"StartTraceW", status);
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
        log_error(L"OpenTraceW", open_error);

        // Cleanup: stop the session we just started
        std::vector<uint8_t> stop_buffer(properties_buffer_size(), 0);
        auto* stop_props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(stop_buffer.data());
        stop_props->Wnode.BufferSize = static_cast<ULONG>(stop_buffer.size());
        stop_props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        ControlTraceW(session_handle, nullptr, stop_props, EVENT_TRACE_CONTROL_STOP);

        return nullptr;
    }

    return std::unique_ptr<Session>(
        new Session(session_handle, trace_handle, std::move(name_str)));
}

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
            std::vector<uint8_t> stop_buffer(properties_buffer_size(), 0);
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
            log_error(L"CloseTrace", status);
        }
        trace_handle_ = INVALID_PROCESSTRACE_HANDLE;
    }

    // Stop the tracing session
    if (session_handle_ != 0) {
        std::vector<uint8_t> stop_buffer(properties_buffer_size(), 0);
        auto* stop_props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(stop_buffer.data());
        stop_props->Wnode.BufferSize = static_cast<ULONG>(stop_buffer.size());
        stop_props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        ULONG status = ControlTraceW(session_handle_, nullptr, stop_props,
                                      EVENT_TRACE_CONTROL_STOP);
        if (status != ERROR_SUCCESS) {
            log_error(L"StopTrace", status);
        }
        session_handle_ = 0;
    }
}

bool Session::enable_provider(const GUID& provider_guid, uint8_t level,
                               uint64_t keywords) {
    ULONG status = EnableTraceEx2(
        session_handle_,
        &provider_guid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        level,
        keywords,
        0,  // MatchAllKeyword
        0,  // Timeout (async)
        nullptr  // EnableParameters
    );

    if (status != ERROR_SUCCESS) {
        log_error(L"EnableTraceEx2", status);
        return false;
    }
    return true;
}

void Session::disable_provider(const GUID& provider_guid) {
    ULONG status = EnableTraceEx2(
        session_handle_,
        &provider_guid,
        EVENT_CONTROL_CODE_DISABLE_PROVIDER,
        0,
        0,
        0,
        0,
        nullptr
    );

    if (status != ERROR_SUCCESS) {
        log_error(L"DisableProvider", status);
    }
}

// Well-known provider GUIDs
namespace providers {

// Microsoft-Windows-Kernel-Process
// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
const GUID KERNEL_PROCESS = {
    0x22FB2CD6, 0x0E7B, 0x422B,
    {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}
};

// Microsoft-Windows-Kernel-File
// {EDD08927-9CC4-4E65-B970-C2560FB5C289}
const GUID KERNEL_FILE = {
    0xEDD08927, 0x9CC4, 0x4E65,
    {0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89}
};

// Microsoft-Windows-Kernel-Registry
// {70EB4F03-C1DE-4F73-A051-33D13D5413BD}
const GUID KERNEL_REGISTRY = {
    0x70EB4F03, 0xC1DE, 0x4F73,
    {0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD}
};

// Microsoft-Windows-Kernel-Network
// {7DD42A49-5329-4832-8DFD-43D979153A88}
const GUID KERNEL_NETWORK = {
    0x7DD42A49, 0x5329, 0x4832,
    {0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88}
};

// Image Load provider (classic NT Kernel Logger)
// {2CB15D1D-5FC1-11D2-ABE1-00A0C911F518}
const GUID KERNEL_IMAGE = {
    0x2CB15D1D, 0x5FC1, 0x11D2,
    {0xAB, 0xE1, 0x00, 0xA0, 0xC9, 0x11, 0xF5, 0x18}
};

// Thread events provider (classic NT Kernel Logger)
// {3D6FA8D1-FE05-11D0-9DDA-00C04FD7BA7C}
const GUID KERNEL_THREAD = {
    0x3D6FA8D1, 0xFE05, 0x11D0,
    {0x9D, 0xDA, 0x00, 0xC0, 0x4F, 0xD7, 0xBA, 0x7C}
};

// Virtual memory events provider (PageFault)
// {3D6FA8D3-FE05-11D0-9DDA-00C04FD7BA7C}
const GUID KERNEL_MEMORY = {
    0x3D6FA8D3, 0xFE05, 0x11D0,
    {0x9D, 0xDA, 0x00, 0xC0, 0x4F, 0xD7, 0xBA, 0x7C}
};

// Microsoft-Windows-PowerShell
// {A0C1853B-5C40-4B15-8766-3CF1C58F985A}
const GUID POWERSHELL = {
    0xA0C1853B, 0x5C40, 0x4B15,
    {0x87, 0x66, 0x3C, 0xF1, 0xC5, 0x8F, 0x98, 0x5A}
};

// Microsoft-Antimalware-Scan-Interface
// {2A576B87-09A7-520E-C21A-4942F0271D67}
const GUID AMSI = {
    0x2A576B87, 0x09A7, 0x520E,
    {0xC2, 0x1A, 0x49, 0x42, 0xF0, 0x27, 0x1D, 0x67}
};

// Microsoft-Windows-DNS-Client
// {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
const GUID DNS_CLIENT = {
    0x1C95126E, 0x7EEA, 0x49A9,
    {0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D}
};

// Microsoft-Windows-Security-Auditing
// {54849625-5478-4994-A5BA-3E3B0328C30D}
const GUID SECURITY_AUDITING = {
    0x54849625, 0x5478, 0x4994,
    {0xA5, 0xBA, 0x3E, 0x3B, 0x03, 0x28, 0xC3, 0x0D}
};

// Microsoft-Windows-WMI-Activity
// {1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}
const GUID WMI_ACTIVITY = {
    0x1418EF04, 0xB0B4, 0x4623,
    {0xBF, 0x7E, 0xD7, 0x4A, 0xB4, 0x7B, 0xBD, 0xAA}
};

}  // namespace exeray::etw

#else  // !_WIN32

// Stub implementation for non-Windows platforms
#include "exeray/etw/session.hpp"

namespace exeray::etw::providers {

const GUID KERNEL_PROCESS = {0, 0, 0, {0}};
const GUID KERNEL_FILE = {0, 0, 0, {0}};
const GUID KERNEL_REGISTRY = {0, 0, 0, {0}};
const GUID KERNEL_NETWORK = {0, 0, 0, {0}};
const GUID KERNEL_IMAGE = {0, 0, 0, {0}};
const GUID KERNEL_THREAD = {0, 0, 0, {0}};
const GUID KERNEL_MEMORY = {0, 0, 0, {0}};
const GUID POWERSHELL = {0, 0, 0, {0}};
const GUID AMSI = {0, 0, 0, {0}};
const GUID DNS_CLIENT = {0, 0, 0, {0}};
const GUID SECURITY_AUDITING = {0, 0, 0, {0}};
const GUID WMI_ACTIVITY = {0, 0, 0, {0}};

}  // namespace exeray::etw::providers

#endif  // _WIN32
