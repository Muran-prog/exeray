#pragma once

/// @file engine.hpp
/// @brief Core Engine class integrating ETW tracing and process control.
///
/// The Engine provides a unified interface for:
/// - Launching and controlling target processes
/// - Real-time ETW event capture and filtering
/// - Thread-safe event storage in EventGraph

#include "exeray/arena.hpp"
#include "exeray/event/correlator.hpp"
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
#include <mutex>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace exeray {

/// @brief Configuration for a single ETW provider.
struct ProviderConfig {
    bool enabled = true;           ///< Whether the provider is enabled.
    uint8_t level = 4;             ///< Trace level (4 = TRACE_LEVEL_INFORMATION).
    uint64_t keywords = 0;         ///< Keyword bitmask (0 = all keywords).
};

/// @brief Engine configuration parameters.
struct EngineConfig {
    std::size_t arena_size;   ///< Size of the memory arena in bytes.
    std::size_t num_threads;  ///< Number of worker threads.
    int log_level = 2;        ///< Log level: 0=trace, 1=debug, 2=info, 3=warn, 4=error.
    std::string log_file;     ///< Optional log file path (empty = stderr only).

    /// @brief Provider configurations (name → config).
    ///
    /// Default configuration enables core providers, disables optional ones.
    std::unordered_map<std::string, ProviderConfig> providers = {
        {"Process", {true, 4, 0}},
        {"File", {true, 4, 0}},
        {"Registry", {true, 4, 0}},
        {"Network", {true, 4, 0}},
        {"Image", {true, 4, 0}},
        {"Thread", {true, 4, 0}},
        {"Memory", {true, 5, 0}},      // VERBOSE for detailed info
        {"PowerShell", {true, 5, 0}},
        {"AMSI", {true, 4, 0}},
        {"DNS", {false, 4, 0}},        // Disabled by default
        {"WMI", {false, 4, 0}},
        {"CLR", {false, 4, 0}},
        {"Security", {false, 4, 0}},
    };
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

    // -------------------------------------------------------------------------
    // Event Correlation API
    // -------------------------------------------------------------------------

    /// @brief Get process tree (ancestors) for a PID.
    ///
    /// Walks up the parent chain from the most recent ProcessCreate event
    /// for the given PID, collecting all ancestor process events.
    ///
    /// @param pid Process ID to start from.
    /// @return Vector of EventViews representing the process ancestry.
    [[nodiscard]] std::vector<event::EventView> get_process_tree(uint32_t pid);

    /// @brief Get all events with a specific correlation ID.
    ///
    /// Returns all events (Process, Thread, Memory, Image, etc.) that share
    /// the same correlation ID, representing a related execution chain.
    ///
    /// @param correlation_id Correlation ID to filter by.
    /// @return Vector of EventViews matching the correlation ID.
    [[nodiscard]] std::vector<event::EventView> get_event_chain(uint32_t correlation_id);

    // -------------------------------------------------------------------------
    // Provider Configuration API
    // -------------------------------------------------------------------------

    /// @brief Enable a provider by name.
    ///
    /// The change takes effect on the next start_monitoring() call.
    /// Unknown provider names are ignored with a warning.
    ///
    /// @param name Provider name (e.g., "Process", "File", "DNS").
    void enable_provider(std::string_view name);

    /// @brief Disable a provider by name.
    ///
    /// The change takes effect on the next start_monitoring() call.
    /// Unknown provider names are ignored with a warning.
    ///
    /// @param name Provider name (e.g., "Process", "File", "DNS").
    void disable_provider(std::string_view name);

    /// @brief Check if a provider is enabled.
    ///
    /// @param name Provider name.
    /// @return true if the provider exists and is enabled, false otherwise.
    [[nodiscard]] bool is_provider_enabled(std::string_view name) const;

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
    event::Correlator correlator_;
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

    // Provider configuration
    EngineConfig config_;
    mutable std::mutex providers_mutex_;
};

}  // namespace exeray
