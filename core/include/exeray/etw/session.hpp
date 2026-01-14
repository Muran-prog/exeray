#pragma once

/// @file session.hpp
/// @brief ETW Session Manager for real-time event tracing on Windows.

#ifdef _WIN32

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

// Windows headers - minimal includes
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

namespace exeray::etw {

/// @brief Manages an ETW tracing session for real-time event collection.
///
/// The Session class wraps Windows ETW APIs to create and manage event tracing
/// sessions. It handles session lifecycle, provider enabling/disabling, and
/// provides the trace handle needed for ProcessTrace consumption.
///
/// @note Requires administrator privileges to create system-wide sessions.
///
/// Usage:
/// @code
///     void WINAPI my_callback(PEVENT_RECORD record) { ... }
///     ConsumerContext ctx{&graph, &target_pid};
///     auto session = Session::create(L"MyAppTrace", my_callback, &ctx);
///     if (session) {
///         session->enable_provider(providers::KERNEL_FILE, TRACE_LEVEL_INFORMATION, 0);
///         // Start consumer thread that calls ProcessTrace
///     }
/// @endcode
class Session {
public:
    /// @brief Callback type for event records.
    using EventCallback = void(WINAPI*)(PEVENT_RECORD);

    /// @brief Create a new ETW session with callback for event consumption.
    /// @param session_name Unique name for the session (max 1024 chars).
    /// @param callback Event callback function invoked for each event.
    /// @param context User context passed to callback via EVENT_RECORD::UserContext.
    /// @return Unique pointer to the session, or nullptr on failure.
    static std::unique_ptr<Session> create(
        std::wstring_view session_name,
        EventCallback callback,
        void* context
    );

    /// @brief Destructor - stops the trace session and releases resources.
    ~Session();

    /// @brief Enable an event provider for this session.
    /// @param provider_guid GUID of the provider to enable.
    /// @param level Maximum event level (TRACE_LEVEL_*).
    /// @param keywords Keyword bitmask for event filtering.
    /// @return true if the provider was enabled successfully.
    bool enable_provider(const GUID& provider_guid, uint8_t level, uint64_t keywords);

    /// @brief Disable an event provider.
    /// @param provider_guid GUID of the provider to disable.
    void disable_provider(const GUID& provider_guid);

    /// @brief Get the trace handle for use with ProcessTrace.
    /// @return The consumer trace handle.
    [[nodiscard]] TRACEHANDLE trace_handle() const noexcept { return trace_handle_; }

    /// @brief Get the session handle.
    /// @return The session (controller) handle.
    [[nodiscard]] TRACEHANDLE session_handle() const noexcept { return session_handle_; }

    /// @brief Get the session name.
    /// @return The session name.
    [[nodiscard]] const std::wstring& session_name() const noexcept { return session_name_; }

    // Non-copyable
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    // Movable
    Session(Session&& other) noexcept;
    Session& operator=(Session&& other) noexcept;

private:
    /// @brief Private constructor - use create() factory method.
    explicit Session(TRACEHANDLE session_handle, TRACEHANDLE trace_handle,
                     std::wstring session_name);

    TRACEHANDLE session_handle_ = 0;
    TRACEHANDLE trace_handle_ = INVALID_PROCESSTRACE_HANDLE;
    std::wstring session_name_;
};

/// @brief Well-known Windows kernel provider GUIDs.
namespace providers {

/// Microsoft-Windows-Kernel-Process provider
/// Traces process creation, termination, thread events.
extern const GUID KERNEL_PROCESS;

/// Microsoft-Windows-Kernel-File provider
/// Traces file system operations (create, read, write, delete).
extern const GUID KERNEL_FILE;

/// Microsoft-Windows-Kernel-Registry provider
/// Traces registry operations (open, query, set, delete keys/values).
extern const GUID KERNEL_REGISTRY;

/// Microsoft-Windows-Kernel-Network provider
/// Traces network operations (TCP/UDP connect, send, receive).
extern const GUID KERNEL_NETWORK;

/// Image Load provider (classic NT Kernel Logger)
/// GUID: {2CB15D1D-5FC1-11D2-ABE1-00A0C911F518}
/// Traces DLL/EXE image load and unload events.
extern const GUID KERNEL_IMAGE;

/// Thread events provider (classic NT Kernel Logger)
/// GUID: {3D6FA8D1-FE05-11D0-9DDA-00C04FD7BA7C}
/// Traces thread start/end events for remote injection detection.
extern const GUID KERNEL_THREAD;

/// Virtual memory events provider (PageFault)
/// GUID: {3D6FA8D3-FE05-11D0-9DDA-00C04FD7BA7C}
/// Traces VirtualAlloc/VirtualFree for RWX shellcode detection.
extern const GUID KERNEL_MEMORY;

/// Microsoft-Windows-PowerShell provider
/// GUID: {A0C1853B-5C40-4B15-8766-3CF1C58F985A}
/// Traces PowerShell script execution for fileless malware detection.
extern const GUID POWERSHELL;

/// Microsoft-Antimalware-Scan-Interface provider
/// GUID: {2A576B87-09A7-520E-C21A-4942F0271D67}
/// Traces AMSI scan requests for bypass detection.
extern const GUID AMSI;

/// Microsoft-Windows-DNS-Client provider
/// GUID: {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
/// Traces DNS query operations for C2/DGA detection.
extern const GUID DNS_CLIENT;

/// Microsoft-Windows-Security-Auditing provider
/// GUID: {54849625-5478-4994-A5BA-3E3B0328C30D}
/// Traces security events: logon, privilege changes, service installation.
extern const GUID SECURITY_AUDITING;

/// Microsoft-Windows-WMI-Activity provider
/// GUID: {1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}
/// Traces WMI queries and method executions for attack detection.
extern const GUID WMI_ACTIVITY;

/// PowerShell keywords for event filtering.
namespace powershell_keywords {
    constexpr uint64_t RUNSPACE = 0x10;   ///< Runspace lifecycle
    constexpr uint64_t PIPELINE = 0x20;   ///< Pipeline execution
    constexpr uint64_t CMDLETS  = 0x40;   ///< Cmdlet invocation
    constexpr uint64_t ALL      = RUNSPACE | PIPELINE | CMDLETS;
}  // namespace powershell_keywords

}  // namespace providers

}  // namespace exeray::etw

#else  // !_WIN32

// Stub declarations for non-Windows platforms
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace exeray::etw {

// Forward declare a placeholder GUID type for non-Windows
struct GUID {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t Data4[8];
};

using TRACEHANDLE = uint64_t;
constexpr TRACEHANDLE INVALID_PROCESSTRACE_HANDLE = static_cast<TRACEHANDLE>(-1);

class Session {
public:
    using EventCallback = void(*)(void*);

    static std::unique_ptr<Session> create(
        std::wstring_view /*session_name*/,
        EventCallback /*callback*/ = nullptr,
        void* /*context*/ = nullptr
    ) {
        return nullptr;  // ETW not available on non-Windows
    }

    ~Session() = default;

    bool enable_provider(const GUID& /*provider_guid*/, uint8_t /*level*/,
                         uint64_t /*keywords*/) {
        return false;
    }

    void disable_provider(const GUID& /*provider_guid*/) {}

    [[nodiscard]] TRACEHANDLE trace_handle() const noexcept {
        return INVALID_PROCESSTRACE_HANDLE;
    }

    [[nodiscard]] TRACEHANDLE session_handle() const noexcept { return 0; }

    [[nodiscard]] const std::wstring& session_name() const noexcept {
        return session_name_;
    }

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

private:
    Session() = default;
    std::wstring session_name_;
};

namespace providers {
extern const GUID KERNEL_PROCESS;
extern const GUID KERNEL_FILE;
extern const GUID KERNEL_REGISTRY;
extern const GUID KERNEL_NETWORK;
extern const GUID KERNEL_IMAGE;
extern const GUID KERNEL_THREAD;
extern const GUID KERNEL_MEMORY;
extern const GUID POWERSHELL;
extern const GUID AMSI;
extern const GUID DNS_CLIENT;
extern const GUID SECURITY_AUDITING;
extern const GUID WMI_ACTIVITY;
namespace powershell_keywords {
    constexpr uint64_t RUNSPACE = 0x10;
    constexpr uint64_t PIPELINE = 0x20;
    constexpr uint64_t CMDLETS  = 0x40;
    constexpr uint64_t ALL      = RUNSPACE | PIPELINE | CMDLETS;
}
}  // namespace providers

}  // namespace exeray::etw

#endif  // _WIN32
