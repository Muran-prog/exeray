#pragma once

/**
 * @file status.hpp
 * @brief Operation result status enum.
 */

#include <cstdint>

namespace exeray::event {

/**
 * @brief Operation result status.
 */
enum class Status : std::uint8_t {
    Success,    ///< Operation completed successfully
    Denied,     ///< Operation was denied (access/permission)
    Pending,    ///< Operation is in progress
    Error,      ///< Operation failed with error
    Suspicious  ///< Operation flagged as potentially malicious
};

}  // namespace exeray::event
