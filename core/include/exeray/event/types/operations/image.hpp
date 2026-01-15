#pragma once

/**
 * @file image.hpp
 * @brief Image load/unload operation types.
 */

#include <cstdint>

namespace exeray::event {

/**
 * @brief Image load/unload operation types.
 *
 * Tracks DLL and EXE loading for process injection detection.
 */
enum class ImageOp : std::uint8_t {
    Load,   ///< Image loaded into process
    Unload  ///< Image unloaded from process
};

}  // namespace exeray::event
