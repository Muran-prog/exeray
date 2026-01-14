#pragma once

/// @file engine.hpp
/// @brief Core Engine class integrating ETW tracing and process control.
///
/// The Engine provides a unified interface for:
/// - Launching and controlling target processes
/// - Real-time ETW event capture and filtering
/// - Thread-safe event storage in EventGraph

#include "exeray/arena.hpp"
#include "exeray/event/graph.hpp"
#include "exeray/event/string_pool.hpp"
#include "exeray/etw/consumer.hpp"
#include "exeray/etw/session.hpp"
#include "exeray/process/controller.hpp"
#include "exeray/thread_pool.hpp"
#include "exeray/types.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>
#include <thread>

namespace exeray {

/// @brief Engine configuration parameters.
struct EngineConfig {
    std::size_t arena_size;   ///< Size of the memory arena in bytes.
    std::size_t num_threads;  ///< Number of worker threads.
};

/// @brief Core engine integrating ETW tracing and process control.
///
/// Thread-safety model:
/// - EventGraph access is thread-safe (atomic push, shared mutex for iteration)
/// - target_pid_ and monitoring_ are atomic for cross-thread access
/// - ETW thread joins gracefully on stop_monitoring()
class Engine {
public:
    explicit Engine(EngineConfig config);
    ~Engine();

    // Non-copyable, non-movable (owns threads and handles)
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
    Engine(Engine&&) = delete;
    Engine& operator=(Engine&&) = delete;

    // -------------------------------------------------------------------------
    // Process Monitoring
    // -------------------------------------------------------------------------

    /// @brief Start monitoring a target process.
    ///
    /// Launches the executable in suspended mode, creates an ETW session,
    /// enables kernel providers, starts the ETW consumer thread, then resumes
    /// the target process.
    ///
    /// @param exe_path Path to the executable to launch and monitor.
    /// @return true if monitoring started successfully, false on failure.
    bool start_monitoring(std::wstring_view exe_path);

    /// @brief Stop monitoring and terminate the target process.
    ///
    /// Stops the ETW session (unblocks ProcessTrace), joins the consumer
    /// thread, and terminates the target process if still running.
    void stop_monitoring();

    /// @brief Check if currently monitoring a process.
    [[nodiscard]] bool is_monitoring() const noexcept;

    // -------------------------------------------------------------------------
    // Process Control (forwarded to Controller)
    // -------------------------------------------------------------------------

    /// @brief Freeze (suspend) the target process.
    void freeze_target();

    /// @brief Unfreeze (resume) the target process.
    void unfreeze_target();

    /// @brief Terminate the target process.
    void kill_target();

    /// @brief Get the target process ID.
    /// @return PID of the target, or 0 if not monitoring.
    [[nodiscard]] uint32_t target_pid() const noexcept;

    // -------------------------------------------------------------------------
    // Legacy Task API (for compatibility)
    // -------------------------------------------------------------------------

    void submit();
    [[nodiscard]] std::uint64_t generation() const;
    [[nodiscard]] std::uint64_t timestamp_ns() const;
    [[nodiscard]] std::uint64_t flags() const;
    [[nodiscard]] float progress() const;
    [[nodiscard]] bool idle() const;
    [[nodiscard]] std::size_t threads() const;

    // -------------------------------------------------------------------------
    // Event Graph Access
    // -------------------------------------------------------------------------

    /// @brief Get mutable reference to the event graph.
    event::EventGraph& graph() { return graph_; }

    /// @brief Get const reference to the event graph.
    [[nodiscard]] const event::EventGraph& graph() const { return graph_; }

private:
    /// @brief Legacy background processing task.
    void process();

    /// @brief ETW consumer thread function.
    ///
    /// Calls start_trace_processing() which blocks until the session is stopped.
    void etw_thread_func();

    // Core components
    Arena arena_;
    event::StringPool strings_;
    event::EventGraph graph_;
    ThreadPool pool_;

    // Legacy task state
    std::atomic<std::uint64_t> generation_{0};
    std::atomic<std::uint64_t> flags_{StatusFlags::IDLE};
    std::atomic<float> progress_{0.0f};

    // ETW monitoring state
    std::unique_ptr<etw::Session> etw_session_;
    std::unique_ptr<process::Controller> target_;
    std::thread etw_thread_;
    std::atomic<bool> monitoring_{false};
    std::atomic<uint32_t> target_pid_{0};
    etw::ConsumerContext consumer_ctx_;
};

}  // namespace exeray
