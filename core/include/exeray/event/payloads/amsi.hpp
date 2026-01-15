#pragma once

/**
 * @file amsi.hpp
 * @brief AMSI scan operation payload.
 */

#include <cstdint>
#include "../types.hpp"

namespace exeray::event {

/**
 * @brief Payload for AMSI scan operations.
 *
 * Contains scanned content info for bypass/malware detection.
 * Used for detecting AMSI bypass attempts (empty content after PowerShell).
 */
struct AmsiPayload {
    StringId content;        ///< Interned scanned content (truncated)
    StringId app_name;       ///< Interned requesting application name
    uint32_t scan_result;    ///< AMSI_RESULT_* value
    uint32_t content_size;   ///< Original content size in bytes
};

}  // namespace exeray::event
