#pragma once

/**
 * @file clr.hpp
 * @brief CLR runtime operation payload.
 */

#include <cstdint>
#include "../types.hpp"

namespace exeray::event {

/**
 * @brief Payload for CLR runtime operations.
 *
 * Contains .NET assembly and method info for malware detection.
 * Used for detecting in-memory assembly loading and obfuscated methods.
 */
struct ClrPayload {
    StringId assembly_name;  ///< Full assembly name (interned)
    StringId method_name;    ///< Method name for JIT events (interned)
    uint64_t load_address;   ///< Base load address in process
    uint8_t is_dynamic;      ///< 1 if loaded from memory (no file!)
    uint8_t is_suspicious;   ///< 1 if suspicious pattern detected
    uint8_t _pad[2];         ///< Explicit padding for alignment
};

}  // namespace exeray::event
