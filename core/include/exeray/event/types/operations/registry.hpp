#pragma once

/**
 * @file registry.hpp
 * @brief Windows registry operation types.
 */

#include <cstdint>

namespace exeray::event {

/**
 * @brief Windows registry operation types.
 */
enum class RegistryOp : std::uint8_t {
    CreateKey,   ///< Create registry key
    DeleteKey,   ///< Delete registry key
    SetValue,    ///< Set registry value
    DeleteValue, ///< Delete registry value
    QueryValue   ///< Query registry value
};

}  // namespace exeray::event
