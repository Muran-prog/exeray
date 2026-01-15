#pragma once

/**
 * @file thread.hpp
 * @brief Thread operation payload.
 */

#include <cstdint>
#include "../types.hpp"

namespace exeray::event {

/**
 * @brief Payload for thread operations.
 *
 * Contains thread ID, process IDs, and start address for injection detection.
 * Used for detecting remote thread injection (CreateRemoteThread).
 */
struct ThreadPayload {
    uint32_t thread_id;      ///< Thread ID
    uint32_t process_id;     ///< Target process ID (thread owner)
    uint64_t start_address;  ///< Thread entry point address
    uint32_t creator_pid;    ///< Creator process ID (who created the thread)
    uint8_t is_remote;       ///< 1 if remote thread injection detected
    uint8_t _pad[3];         ///< Explicit padding for alignment
};

}  // namespace exeray::event
