#pragma once

/**
 * @file image.hpp
 * @brief Image load/unload operation payload.
 */

#include <cstdint>
#include "../types.hpp"

namespace exeray::event {

/**
 * @brief Payload for image load/unload operations.
 *
 * Contains image path, load address, size, and suspicious flag.
 * Used for detecting process injection via LoadLibrary/LdrLoadDll.
 */
struct ImagePayload {
    StringId image_path;     ///< Interned DLL/EXE path
    uint32_t process_id;     ///< Target process ID
    uint64_t base_address;   ///< Load address in target process
    uint32_t size;           ///< Image size in bytes (max 4GB)
    uint8_t is_suspicious;   ///< 1 if loaded from temp/appdata
    uint8_t _pad[3];         ///< Explicit padding for alignment
};

}  // namespace exeray::event
