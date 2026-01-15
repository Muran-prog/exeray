#pragma once

/**
 * @file wmi.hpp
 * @brief WMI operation payload.
 */

#include <cstdint>
#include "../types.hpp"

namespace exeray::event {

/**
 * @brief Payload for WMI operations.
 *
 * Contains WMI activity details for attack detection including
 * lateral movement, persistence via Event Subscriptions, and
 * fileless execution via Win32_Process.Create.
 */
struct WmiPayload {
    StringId wmi_namespace;  ///< root\cimv2, etc.
    StringId query;          ///< WQL query or method name
    StringId target_host;    ///< Remote host if any
    uint8_t is_remote;       ///< 1 if not localhost
    uint8_t is_suspicious;   ///< 1 if dangerous pattern
    uint8_t _pad[2];         ///< Explicit padding
};

}  // namespace exeray::event
