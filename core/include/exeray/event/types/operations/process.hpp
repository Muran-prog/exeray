#pragma once

/**
 * @file process.hpp
 * @brief Process operation types.
 */

#include <cstdint>

namespace exeray::event {

/**
 * @brief Process operation types.
 */
enum class ProcessOp : std::uint8_t {
    Create,      ///< Create child process
    Terminate,   ///< Terminate process
    Inject,      ///< Inject code/memory into process
    LoadLibrary  ///< Load DLL/module
};

}  // namespace exeray::event
