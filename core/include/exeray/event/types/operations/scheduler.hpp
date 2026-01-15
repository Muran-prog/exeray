#pragma once

/**
 * @file scheduler.hpp
 * @brief Task scheduler operation types.
 */

#include <cstdint>

namespace exeray::event {

/**
 * @brief Task scheduler operation types.
 */
enum class SchedulerOp : std::uint8_t {
    CreateTask, ///< Create scheduled task
    DeleteTask, ///< Delete scheduled task
    ModifyTask, ///< Modify existing task
    RunTask     ///< Manually trigger task execution
};

}  // namespace exeray::event
