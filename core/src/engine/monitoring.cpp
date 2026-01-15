/// @file engine/monitoring.cpp
/// @brief Process monitoring implementation: start, stop, status.

#include "exeray/engine.hpp"
#include "exeray/etw/session.hpp"
#include "exeray/logging.hpp"
#include "exeray/process/controller.hpp"

#include <optional>

namespace exeray {

namespace {

#ifdef _WIN32
/// @brief Map provider name to GUID (Windows implementation).
std::optional<GUID> get_provider_guid(std::string_view name) {
    if (name == "Process") return etw::providers::KERNEL_PROCESS;
    if (name == "File") return etw::providers::KERNEL_FILE;
    if (name == "Registry") return etw::providers::KERNEL_REGISTRY;
    if (name == "Network") return etw::providers::KERNEL_NETWORK;
    if (name == "Image") return etw::providers::KERNEL_IMAGE;
    if (name == "Thread") return etw::providers::KERNEL_THREAD;
    if (name == "Memory") return etw::providers::KERNEL_MEMORY;
    if (name == "PowerShell") return etw::providers::POWERSHELL;
    if (name == "AMSI") return etw::providers::AMSI;
    if (name == "DNS") return etw::providers::DNS_CLIENT;
    if (name == "WMI") return etw::providers::WMI_ACTIVITY;
    if (name == "CLR") return etw::providers::CLR_RUNTIME;
    if (name == "Security") return etw::providers::SECURITY_AUDITING;
    return std::nullopt;
}
#endif

}  // namespace

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

    // Step 3: Enable providers based on configuration
    {
        std::lock_guard lock(providers_mutex_);
        for (const auto& [name, cfg] : config_.providers) {
            if (!cfg.enabled) {
                EXERAY_DEBUG("Provider {} is disabled, skipping", name);
                continue;
            }

            auto guid = get_provider_guid(name);
            if (!guid) {
                EXERAY_WARN("Unknown provider: {}", name);
                continue;
            }

            // Use configured keywords, or all keywords if 0
            uint64_t keywords = (cfg.keywords == 0) ? 0xFFFFFFFFFFFFFFFF : cfg.keywords;
            etw_session_->enable_provider(*guid, cfg.level, keywords);
            EXERAY_DEBUG("Enabled provider {} (level={}, keywords=0x{:x})",
                         name, cfg.level, keywords);
        }
    }

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

}  // namespace exeray
