/// @file jit_parser.hpp
/// @brief CLR JIT compilation event parser declaration.

#pragma once

#ifdef _WIN32

#include "exeray/etw/parser.hpp"
#include "exeray/event/string_pool.hpp"

namespace exeray::etw::clr {

/// @brief Parse JIT compilation event.
ParsedEvent parse_jit_event(const EVENT_RECORD* record, event::StringPool* strings);

}  // namespace exeray::etw::clr

#endif  // _WIN32
