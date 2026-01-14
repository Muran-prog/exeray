#pragma once

#include "exeray/engine.hpp"
#include <memory>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

// Include rust/cxx.h when building with cxx (defined by cxx-build)
#if __has_include("rust/cxx.h")
#include "rust/cxx.h"
#define EXERAY_HAS_CXX 1
#endif

namespace exeray {

/// @brief Convert UTF-8 string to std::wstring for Windows APIs.
/// @param data Pointer to UTF-8 encoded string data.
/// @param len Length in bytes.
/// @return Wide string for Windows API, empty on non-Windows or conversion failure.
inline std::wstring utf8_to_wstring(const char* data, std::size_t len) {
#ifdef _WIN32
    if (len == 0 || data == nullptr) return {};
    int wlen = MultiByteToWideChar(
        CP_UTF8, 0,
        data, static_cast<int>(len),
        nullptr, 0
    );
    if (wlen == 0) return {};
    std::wstring result(static_cast<size_t>(wlen), L'\0');
    MultiByteToWideChar(
        CP_UTF8, 0,
        data, static_cast<int>(len),
        result.data(), wlen
    );
    return result;
#else
    (void)data;
    (void)len;
    return {};
#endif
}

/// @brief Overload for std::string.
inline std::wstring utf8_to_wstring(const std::string& s) {
    return utf8_to_wstring(s.data(), s.size());
}

class Handle {
public:
    Handle(std::size_t arena_mb, std::size_t threads)
        : engine_(EngineConfig{arena_mb * 1024 * 1024, threads}) {}

    void submit() { engine_.submit(); }

    std::uint64_t generation() const { return engine_.generation(); }
    std::uint64_t timestamp_ns() const { return engine_.timestamp_ns(); }
    std::uint64_t flags() const { return engine_.flags(); }
    float progress() const { return engine_.progress(); }

    bool idle() const { return engine_.idle(); }
    std::size_t threads() const { return engine_.threads(); }

    // Event graph access
    event::EventGraph& graph() { return engine_.graph(); }
    const event::EventGraph& graph() const { return engine_.graph(); }

    // -------------------------------------------------------------------------
    // Monitoring Control
    // -------------------------------------------------------------------------

#ifdef EXERAY_HAS_CXX
    /// @brief Start monitoring a target process (FFI version with rust::Str).
    /// @param exe_path UTF-8 encoded path from Rust &str.
    /// @return true if monitoring started successfully.
    bool start_monitoring(rust::Str exe_path) {
        return engine_.start_monitoring(utf8_to_wstring(exe_path.data(), exe_path.length()));
    }
#endif

    /// @brief Start monitoring a target process (std::string version).
    /// @param exe_path UTF-8 encoded path to the executable.
    /// @return true if monitoring started successfully.
    bool start_monitoring(const std::string& exe_path) {
        return engine_.start_monitoring(utf8_to_wstring(exe_path));
    }

    /// @brief Stop monitoring and terminate the target process.
    void stop_monitoring() { engine_.stop_monitoring(); }

    // -------------------------------------------------------------------------
    // Target Process Control
    // -------------------------------------------------------------------------

    /// @brief Freeze (suspend) the target process.
    void freeze_target() { engine_.freeze_target(); }

    /// @brief Unfreeze (resume) the target process.
    void unfreeze_target() { engine_.unfreeze_target(); }

    /// @brief Terminate the target process.
    void kill_target() { engine_.kill_target(); }

    // -------------------------------------------------------------------------
    // Target State
    // -------------------------------------------------------------------------

    /// @brief Get the target process ID.
    /// @return PID of the target, or 0 if not monitoring.
    std::uint32_t target_pid() const noexcept { return engine_.target_pid(); }

    /// @brief Check if the target process is still running.
    /// @return true if monitoring and target is running.
    bool target_running() const noexcept { return engine_.is_monitoring(); }

private:
    Engine engine_;
};

inline std::unique_ptr<Handle> create(std::size_t arena_mb, std::size_t threads) {
    return std::make_unique<Handle>(arena_mb, threads);
}

// Event accessor functions for FFI
inline std::size_t event_count(const Handle& h) {
    return h.graph().count();
}

inline std::uint64_t event_get_id(const Handle& h, std::size_t index) {
    if (index >= h.graph().count()) return 0;
    // IDs are 1-indexed, so we need id = index + 1
    return h.graph().get(static_cast<event::EventId>(index + 1)).id();
}

inline std::uint64_t event_get_parent(const Handle& h, std::size_t index) {
    if (index >= h.graph().count()) return 0;
    return h.graph().get(static_cast<event::EventId>(index + 1)).parent_id();
}

inline std::uint64_t event_get_timestamp(const Handle& h, std::size_t index) {
    if (index >= h.graph().count()) return 0;
    return h.graph().get(static_cast<event::EventId>(index + 1)).timestamp();
}

inline std::uint8_t event_get_category(const Handle& h, std::size_t index) {
    if (index >= h.graph().count()) return 0;
    return static_cast<std::uint8_t>(
        h.graph().get(static_cast<event::EventId>(index + 1)).category());
}

inline std::uint8_t event_get_status(const Handle& h, std::size_t index) {
    if (index >= h.graph().count()) return 0;
    return static_cast<std::uint8_t>(
        h.graph().get(static_cast<event::EventId>(index + 1)).status());
}

inline std::uint8_t event_get_operation(const Handle& h, std::size_t index) {
    if (index >= h.graph().count()) return 0;
    return h.graph().get(static_cast<event::EventId>(index + 1)).operation();
}

}

