#pragma once

/**
 * @file input.hpp
 * @brief Input device operation types.
 */

#include <cstdint>

namespace exeray::event {

/**
 * @brief Input device operation types.
 *
 * These operations are often associated with malicious activity.
 */
enum class InputOp : std::uint8_t {
    BlockKeyboard, ///< Block keyboard input
    BlockMouse,    ///< Block mouse input
    InstallHook    ///< Install input hook
};

}  // namespace exeray::event
