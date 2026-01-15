#pragma once

/**
 * @file amsi.hpp
 * @brief AMSI scan operation types.
 */

#include <cstdint>

namespace exeray::event {

/**
 * @brief AMSI scan operation types.
 *
 * Tracks AMSI scans for bypass detection.
 */
enum class AmsiOp : std::uint8_t {
    Scan,     ///< AmsiScanBuffer/String called
    Session   ///< AmsiOpenSession/CloseSession
};

}  // namespace exeray::event
