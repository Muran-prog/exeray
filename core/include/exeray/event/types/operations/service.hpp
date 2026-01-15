#pragma once

/**
 * @file service.hpp
 * @brief Windows service operation types.
 */

#include <cstdint>

namespace exeray::event {

/**
 * @brief Windows service operation types.
 *
 * Tracks service installation for persistence detection.
 */
enum class ServiceOp : std::uint8_t {
    Install,  ///< Service installed (Event 4697)
    Start,    ///< Service started
    Stop,     ///< Service stopped
    Delete    ///< Service deleted
};

}  // namespace exeray::event
