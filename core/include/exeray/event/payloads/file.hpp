#pragma once

/**
 * @file file.hpp
 * @brief File system operation payload.
 */

#include <cstdint>
#include "../types.hpp"

namespace exeray::event {

/**
 * @brief Payload for file system operations.
 *
 * Contains file path, size, and attributes for file/directory events.
 */
struct FilePayload {
    StringId path;         ///< Interned file/directory path
    uint64_t size;         ///< File size in bytes
    uint32_t attributes;   ///< File attributes (platform-specific)
    uint32_t _pad;         ///< Explicit padding for 8-byte alignment
};

}  // namespace exeray::event
