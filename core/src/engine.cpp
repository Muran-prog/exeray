/// @file engine.cpp
/// @brief Engine implementation with ETW monitoring and process control.

#include "exeray/engine.hpp"
#include "exeray/etw/session.hpp"
#include "exeray/logging.hpp"
#include "exeray/process/controller.hpp"

namespace exeray {

Engine::Engine(EngineConfig config)
    : arena_(config.arena_size),
      strings_(arena_),
      graph_(arena_, strings_),
      correlator_(),
      pool_(config.num_threads) {
    // Initialize consumer context with graph, correlator, and target_pid
    consumer_ctx_.graph = &graph_;
    consumer_ctx_.target_pid = &target_pid_;
    consumer_ctx_.strings = &strings_;
    consumer_ctx_.correlator = &correlator_;
}

Engine::~Engine() {
    // Ensure cleanup on destruction
    if (monitoring_.load(std::memory_order_acquire)) {
        stop_monitoring();
    }
}

// =============================================================================
// Process Monitoring
// =============================================================================

bool Engine::start_monitoring(std::wstring_view exe_path) {
    // Don't start if already monitoring
    if (monitoring_.load(std::memory_order_acquire)) {
        EXERAY_ERROR("Engine: Already monitoring a process");
        return false;
    }

#ifdef _WIN32
    // Step 1: Launch target process in suspended mode
    target_ = process::Controller::launch(exe_path);
    if (!target_) {
        EXERAY_ERROR("Engine: Failed to launch target process");
        return false;
    }

    // Store target PID for event filtering
    target_pid_.store(target_->pid(), std::memory_order_release);

    // Step 2: Create ETW session with callback and context
    etw_session_ = etw::Session::create(
        L"ExeRayMonitor",
        etw::event_record_callback,
        &consumer_ctx_
    );
    if (!etw_session_) {
        EXERAY_ERROR("Engine: Failed to create ETW session");
        target_.reset();
        target_pid_.store(0, std::memory_order_release);
        return false;
    }

    // Step 3: Enable kernel providers for comprehensive monitoring
    constexpr uint8_t trace_level = 4;  // TRACE_LEVEL_INFORMATION
    constexpr uint64_t all_keywords = 0xFFFFFFFFFFFFFFFF;

    etw_session_->enable_provider(etw::providers::KERNEL_PROCESS, trace_level, all_keywords);
    etw_session_->enable_provider(etw::providers::KERNEL_FILE, trace_level, all_keywords);
    etw_session_->enable_provider(etw::providers::KERNEL_REGISTRY, trace_level, all_keywords);
    etw_session_->enable_provider(etw::providers::KERNEL_NETWORK, trace_level, all_keywords);
    etw_session_->enable_provider(etw::providers::KERNEL_IMAGE, trace_level, all_keywords);
    etw_session_->enable_provider(
        etw::providers::POWERSHELL,
        trace_level,
        etw::providers::powershell_keywords::ALL
    );
    etw_session_->enable_provider(etw::providers::AMSI, trace_level, all_keywords);
    etw_session_->enable_provider(etw::providers::DNS_CLIENT, trace_level, all_keywords);
    etw_session_->enable_provider(etw::providers::SECURITY_AUDITING, trace_level, all_keywords);
    etw_session_->enable_provider(etw::providers::WMI_ACTIVITY, trace_level, all_keywords);
    etw_session_->enable_provider(
        etw::providers::CLR_RUNTIME,
        trace_level,
        etw::providers::clr_keywords::ALL
    );

    // Step 4: Set monitoring flag before starting thread
    monitoring_.store(true, std::memory_order_release);

    // Step 5: Start ETW consumer thread
    etw_thread_ = std::thread(&Engine::etw_thread_func, this);

    // Step 6: Resume the target process to start execution
    target_->resume();

    return true;
#else
    // ETW not available on non-Windows platforms
    (void)exe_path;
    EXERAY_ERROR("Engine: ETW monitoring not available on this platform");
    return false;
#endif
}

void Engine::stop_monitoring() {
    if (!monitoring_.load(std::memory_order_acquire)) {
        return;
    }

    // Clear monitoring flag first
    monitoring_.store(false, std::memory_order_release);

#ifdef _WIN32
    // Step 1: Stop ETW session - this will cause ProcessTrace to return
    // The Session destructor handles StopTrace/CloseTrace
    etw_session_.reset();

    // Step 2: Wait for ETW thread to finish
    if (etw_thread_.joinable()) {
        etw_thread_.join();
    }

    // Step 3: Terminate target process if still running
    if (target_ && target_->is_running()) {
        target_->terminate();
    }
    target_.reset();
#endif

    // Clear target PID
    target_pid_.store(0, std::memory_order_release);
}

bool Engine::is_monitoring() const noexcept {
    return monitoring_.load(std::memory_order_acquire);
}

// =============================================================================
// Process Control
// =============================================================================

void Engine::freeze_target() {
    if (target_ && target_->is_running()) {
        target_->suspend();
    }
}

void Engine::unfreeze_target() {
    if (target_ && target_->is_running()) {
        target_->resume();
    }
}

void Engine::kill_target() {
    if (target_) {
        target_->terminate();
    }
}

uint32_t Engine::target_pid() const noexcept {
    return target_pid_.load(std::memory_order_acquire);
}

// =============================================================================
// Legacy Task API
// =============================================================================

void Engine::submit() {
    flags_.store(StatusFlags::PENDING, std::memory_order_release);
    pool_.submit([this] { process(); });
}

std::uint64_t Engine::generation() const {
    return generation_.load(std::memory_order_acquire);
}

std::uint64_t Engine::timestamp_ns() const {
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
}

std::uint64_t Engine::flags() const {
    return flags_.load(std::memory_order_acquire);
}

float Engine::progress() const {
    return progress_.load(std::memory_order_relaxed);
}

bool Engine::idle() const {
    return flags_.load(std::memory_order_acquire) == StatusFlags::IDLE;
}

std::size_t Engine::threads() const {
    return pool_.size();
}

// =============================================================================
// Private Methods
// =============================================================================

void Engine::process() {
    for (int i = 0; i <= 100; ++i) {
        progress_.store(static_cast<float>(i) / 100.0f, std::memory_order_relaxed);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    generation_.fetch_add(1, std::memory_order_release);
    flags_.store(StatusFlags::COMPLETE | StatusFlags::READY, std::memory_order_release);
}

void Engine::etw_thread_func() {
#ifdef _WIN32
    if (etw_session_) {
        // ProcessTrace blocks until session is stopped
        etw::start_trace_processing(etw_session_->trace_handle());
    }
#endif
}

// =============================================================================
// Event Correlation API
// =============================================================================

std::vector<event::EventView> Engine::get_process_tree(uint32_t pid) {
    std::vector<event::EventView> result;

    // Find the process's most recent ProcessCreate event
    event::EventId current_id = correlator_.find_thread_parent(pid);
    if (current_id == event::INVALID_EVENT) {
        return result;
    }

    // Walk up the parent chain, collecting process events
    constexpr std::size_t max_depth = 100;  // Prevent infinite loops
    std::size_t depth = 0;

    while (current_id != event::INVALID_EVENT && depth < max_depth) {
        if (!graph_.exists(current_id)) {
            break;
        }

        auto view = graph_.get(current_id);
        result.push_back(view);

        // Move to parent
        current_id = view.parent_id();
        ++depth;
    }

    return result;
}

std::vector<event::EventView> Engine::get_event_chain(uint32_t correlation_id) {
    std::vector<event::EventView> result;

    if (correlation_id == 0) {
        return result;
    }

    // Collect all events with matching correlation ID
    graph_.for_each_correlation(correlation_id, [&result](event::EventView view) {
        result.push_back(view);
    });

    return result;
}

}  // namespace exeray

