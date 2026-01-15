#pragma once

/**
 * @file scheduler.hpp
 * @brief Task scheduler operation payload.
 */

#include <cstdint>
#include "../types.hpp"

namespace exeray::event {

/**
 * @brief Payload for task scheduler operations.
 *
 * Contains scheduled task name, action, and trigger type.
 */
struct SchedulerPayload {
    StringId task_name;    ///< Interned task name
    StringId action;       ///< Interned action description
    uint32_t trigger_type; ///< Task trigger type
    uint32_t _pad;         ///< Explicit padding for alignment
};

}  // namespace exeray::event
