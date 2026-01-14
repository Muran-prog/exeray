/// @file logging.cpp
/// @brief Structured logging implementation using spdlog.

#include "exeray/logging.hpp"

#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <vector>

namespace exeray::log {

namespace {

/// Logger name used for registration
constexpr const char* kLoggerName = "exeray";

/// Async queue size (power of 2)
constexpr std::size_t kQueueSize = 8192;

/// Async thread count
constexpr std::size_t kThreadCount = 1;

/// Rotating file max size (5 MB)
constexpr std::size_t kMaxFileSize = 5 * 1024 * 1024;

/// Number of rotating files to keep
constexpr std::size_t kMaxFiles = 3;

/// Global logger pointer
std::shared_ptr<spdlog::logger> g_logger;

/// Initialization mutex
std::mutex g_init_mutex;

/// Initialization flag
std::atomic<bool> g_initialized{false};

/// Create a default synchronous stderr logger
std::shared_ptr<spdlog::logger> create_default_logger() {
    auto console_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
    auto logger = std::make_shared<spdlog::logger>(kLoggerName, console_sink);
    logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%n] %v");
    logger->set_level(spdlog::level::info);
    return logger;
}

}  // namespace

void init(spdlog::level::level_enum level, const std::string& log_file) {
    std::lock_guard<std::mutex> lock(g_init_mutex);
    
    // Skip if already initialized
    if (g_initialized.load(std::memory_order_acquire)) {
        return;
    }
    
    // Initialize async thread pool
    spdlog::init_thread_pool(kQueueSize, kThreadCount);
    
    // Build sink list
    std::vector<spdlog::sink_ptr> sinks;
    
    // Always add stderr console sink
    auto console_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
    console_sink->set_level(level);
    sinks.push_back(console_sink);
    
    // Optionally add rotating file sink
    if (!log_file.empty()) {
        try {
            auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                log_file, kMaxFileSize, kMaxFiles);
            file_sink->set_level(level);
            sinks.push_back(file_sink);
        } catch (const spdlog::spdlog_ex& ex) {
            // Log to console if file sink creation fails, but continue
            console_sink->log(spdlog::details::log_msg(
                spdlog::source_loc{}, kLoggerName, spdlog::level::warn,
                std::string("Failed to create log file: ") + ex.what()));
        }
    }
    
    // Create async logger with all sinks
    g_logger = std::make_shared<spdlog::async_logger>(
        kLoggerName,
        sinks.begin(),
        sinks.end(),
        spdlog::thread_pool(),
        spdlog::async_overflow_policy::block);
    
    // Set format: [timestamp] [level] [logger] message
    g_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%n] %v");
    g_logger->set_level(level);
    
    // Flush on warning and above for important messages
    g_logger->flush_on(spdlog::level::warn);
    
    // Register logger globally
    spdlog::register_logger(g_logger);
    
    g_initialized.store(true, std::memory_order_release);
}

spdlog::logger& get() {
    // Fast path: already initialized
    if (g_initialized.load(std::memory_order_acquire)) {
        return *g_logger;
    }
    
    // Slow path: need to initialize with defaults
    std::lock_guard<std::mutex> lock(g_init_mutex);
    
    if (!g_initialized.load(std::memory_order_relaxed)) {
        // Create a simple synchronous logger as fallback
        g_logger = create_default_logger();
        spdlog::register_logger(g_logger);
        g_initialized.store(true, std::memory_order_release);
    }
    
    return *g_logger;
}

void shutdown() {
    std::lock_guard<std::mutex> lock(g_init_mutex);
    
    if (g_initialized.load(std::memory_order_acquire)) {
        spdlog::shutdown();
        g_logger.reset();
        g_initialized.store(false, std::memory_order_release);
    }
}

}  // namespace exeray::log
