#pragma once

/**
 * @file registry.hpp
 * @brief Windows registry operation payload.
 */

#include <cstdint>
#include "../types.hpp"

namespace exeray::event {

/**
 * @brief Payload for Windows registry operations.
 *
 * Contains registry key path, value name, type, and data size.
 */
struct RegistryPayload {
    StringId key_path;     ///< Interned registry key path
    StringId value_name;   ///< Interned value name
    uint32_t value_type;   ///< Registry value type (REG_SZ, REG_DWORD, etc.)
    uint32_t data_size;    ///< Size of value data in bytes
};

}  // namespace exeray::event
