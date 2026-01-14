#pragma once

/// @file controller.hpp
/// @brief Process Controller for launching and controlling target executables.
///
/// Uses Windows APIs: CreateProcessW, Job Objects for process isolation.
/// On non-Windows platforms, provides stub implementations.

#include <cstdint>
#include <memory>
#include <string_view>

namespace exeray::process {

/// @brief Controls a launched process with suspend/resume/terminate capabilities.
///
/// Processes are launched in suspended mode and must be explicitly resumed.
/// Job Objects provide resource isolation and limits.
///
/// @note This class is Windows-specific. On other platforms, launch() returns nullptr.
class Controller {
public:
    /// @brief Launch a process in suspended mode.
    /// @param exe_path Path to the executable.
    /// @param args Command-line arguments (optional).
    /// @param working_dir Working directory (optional, defaults to current).
    /// @return Unique pointer to Controller, or nullptr on failure.
    [[nodiscard]] static std::unique_ptr<Controller> launch(
        std::wstring_view exe_path,
        std::wstring_view args = L"",
        std::wstring_view working_dir = L""
    );

    /// @brief Destructor terminates process and closes handles.
    ~Controller();

    // Non-copyable, non-movable (handle ownership)
    Controller(const Controller&) = delete;
    Controller& operator=(const Controller&) = delete;
    Controller(Controller&&) = delete;
    Controller& operator=(Controller&&) = delete;

    // -------------------------------------------------------------------------
    // Process Control
    // -------------------------------------------------------------------------

    /// @brief Resume the primary thread (start execution).
    void resume();

    /// @brief Suspend the primary thread (pause execution).
    void suspend();

    /// @brief Terminate the process.
    /// @param exit_code Exit code to set for the process.
    void terminate(std::uint32_t exit_code = 1);

    // -------------------------------------------------------------------------
    // State Queries
    // -------------------------------------------------------------------------

    /// @brief Get the process ID.
    [[nodiscard]] std::uint32_t pid() const noexcept { return pid_; }

    /// @brief Check if the process is still running.
    [[nodiscard]] bool is_running() const;

    /// @brief Get the exit code (only valid if !is_running()).
    [[nodiscard]] std::uint32_t exit_code() const;

    // -------------------------------------------------------------------------
    // Job Object Control (Resource Limits)
    // -------------------------------------------------------------------------

    /// @brief Set memory limit for the process.
    /// @param bytes Maximum memory in bytes.
    void set_memory_limit(std::size_t bytes);

    /// @brief Set CPU usage limit.
    /// @param percent CPU rate limit (1-100).
    void set_cpu_limit(std::uint32_t percent);

    /// @brief Deny the process from creating child processes.
    void deny_child_processes();

private:
    /// @brief Private constructor, use launch() factory.
    Controller() = default;

    // Use void* to avoid Windows header pollution in public header.
    // These are HANDLE types on Windows.
#ifdef _WIN32
    void* process_handle_{nullptr};
    void* thread_handle_{nullptr};
    void* job_handle_{nullptr};
#endif
    std::uint32_t pid_{0};
};

}  // namespace exeray::process
