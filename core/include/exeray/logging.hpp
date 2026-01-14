/// @file logging.hpp
/// @brief Structured logging wrapper using spdlog.
///
/// Provides production-ready logging with:
/// - Async logging (non-blocking for ETW hot path)
/// - Console and optional rotating file sinks
/// - Configurable log levels
/// - Automatic flush on error/critical

#pragma once

#include <spdlog/spdlog.h>
#include <string>

namespace exeray::log {

/// @brief Initialize the logging system.
///
/// Must be called once before using any logging macros.
/// Safe to call multiple times (subsequent calls are no-ops).
///
/// @param level Minimum log level (default: info).
/// @param log_file Optional path for rotating file output.
///                 If empty, logs only to stderr.
void init(spdlog::level::level_enum level = spdlog::level::info,
          const std::string& log_file = "");

/// @brief Get the global logger instance.
///
/// Thread-safe. If init() hasn't been called, returns a default logger.
///
/// @return Reference to the exeray logger.
spdlog::logger& get();

/// @brief Shutdown the logging system.
///
/// Flushes all pending messages and releases resources.
/// Should be called before program exit.
void shutdown();

}  // namespace exeray::log

// =============================================================================
// Convenience Macros
// =============================================================================

/// @brief Log trace-level message (verbose debug).
/// @param ... Format string and arguments using fmt syntax.
#define EXERAY_TRACE(...) ::exeray::log::get().trace(__VA_ARGS__)

/// @brief Log debug-level message.
/// @param ... Format string and arguments using fmt syntax.
#define EXERAY_DEBUG(...) ::exeray::log::get().debug(__VA_ARGS__)

/// @brief Log info-level message.
/// @param ... Format string and arguments using fmt syntax.
#define EXERAY_INFO(...)  ::exeray::log::get().info(__VA_ARGS__)

/// @brief Log warning-level message.
/// @param ... Format string and arguments using fmt syntax.
#define EXERAY_WARN(...)  ::exeray::log::get().warn(__VA_ARGS__)

/// @brief Log error-level message.
/// @param ... Format string and arguments using fmt syntax.
#define EXERAY_ERROR(...) ::exeray::log::get().error(__VA_ARGS__)

/// @brief Log critical-level message.
/// @param ... Format string and arguments using fmt syntax.
#define EXERAY_CRITICAL(...) ::exeray::log::get().critical(__VA_ARGS__)
