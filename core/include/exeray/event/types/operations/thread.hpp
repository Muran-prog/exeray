#pragma once

/**
 * @file thread.hpp
 * @brief Thread operation types.
 */

#include <cstdint>

namespace exeray::event {

/**
 * @brief Thread operation types.
 *
 * Tracks thread creation/termination for remote injection detection.
 */
enum class ThreadOp : std::uint8_t {
    Start,    ///< Thread started
    End,      ///< Thread terminated
    DCStart,  ///< Running thread enumeration (session start)
    DCEnd     ///< Running thread enumeration (session end)
};

}  // namespace exeray::event
