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
#include "exeray/platform/guid.hpp"

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

}  // namespace exeray::etw

// Include provider GUIDs - separated for modularity
#include "exeray/etw/providers/guids.hpp"

#else  // !_WIN32

// Stub declarations for non-Windows platforms
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include "exeray/platform/guid.hpp"

namespace exeray::etw {

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

}  // namespace exeray::etw

// Include provider GUIDs - separated for modularity
#include "exeray/etw/providers/guids.hpp"

#endif  // _WIN32
