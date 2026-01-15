/// @file query_parser.hpp
/// @brief DNS query parser declarations.

#pragma once

#ifdef _WIN32
#include <windows.h>
#include <evntrace.h>
#endif

#include "exeray/etw/parser.hpp"
#include "exeray/event/string_pool.hpp"

namespace exeray::etw::dns {

/// @brief Parse DNS Query Completed event (Event ID 3006).
ParsedEvent parse_query_completed(const EVENT_RECORD* record,
                                   event::StringPool* strings);

/// @brief Parse DNS Query Failed event (Event ID 3008).
ParsedEvent parse_query_failed(const EVENT_RECORD* record,
                                event::StringPool* strings);

}  // namespace exeray::etw::dns
