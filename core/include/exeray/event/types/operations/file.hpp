#pragma once

/**
 * @file file.hpp
 * @brief File system operation types.
 */

#include <cstdint>

namespace exeray::event {

/**
 * @brief File system operation types.
 */
enum class FileOp : std::uint8_t {
    Create,        ///< Create file or directory
    Delete,        ///< Delete file or directory
    Read,          ///< Read from file
    Write,         ///< Write to file
    Rename,        ///< Rename file or directory
    SetAttributes  ///< Modify file attributes
};

}  // namespace exeray::event
