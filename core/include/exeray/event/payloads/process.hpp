#pragma once

/**
 * @file process.hpp
 * @brief Process operation payload.
 */

#include <cstdint>
#include "../types.hpp"

namespace exeray::event {

/**
 * @brief Payload for process operations.
 *
 * Contains process IDs and executable information.
 */
struct ProcessPayload {
    uint32_t pid;          ///< Process ID
    uint32_t parent_pid;   ///< Parent process ID
    StringId image_path;   ///< Interned executable path
    StringId command_line; ///< Interned command line arguments
};

}  // namespace exeray::event
