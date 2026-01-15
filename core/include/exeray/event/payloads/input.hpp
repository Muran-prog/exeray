#pragma once

/**
 * @file input.hpp
 * @brief Input device hook operation payload.
 */

#include <cstdint>
#include "../types.hpp"

namespace exeray::event {

/**
 * @brief Payload for input device hook operations.
 *
 * Contains hook type and target thread information.
 */
struct InputPayload {
    uint32_t hook_type;    ///< Type of input hook
    uint32_t target_tid;   ///< Target thread ID
    uint64_t _pad;         ///< Explicit padding for alignment
};

}  // namespace exeray::event
