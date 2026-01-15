/// @file assembly_parser.hpp
/// @brief CLR assembly event parser declaration.

#pragma once

#ifdef _WIN32

#include "exeray/etw/parser.hpp"
#include "exeray/event/string_pool.hpp"

namespace exeray::etw::clr {

/// @brief Parse assembly load/unload event.
ParsedEvent parse_assembly_event(const EVENT_RECORD* record,
                                  event::StringPool* strings,
                                  event::ClrOp op);

}  // namespace exeray::etw::clr

#endif  // _WIN32
