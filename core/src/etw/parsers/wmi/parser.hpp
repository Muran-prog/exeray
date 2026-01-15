/// @file parser.hpp
/// @brief WMI operation parser declaration.

#pragma once

#include "exeray/etw/parser.hpp"
#include "exeray/event/string_pool.hpp"
#include "exeray/event/types.hpp"

namespace exeray::etw::wmi {

/// @brief Parse WMI operation event.
ParsedEvent parse_wmi_operation(const EVENT_RECORD* record,
                                 event::StringPool* strings,
                                 event::WmiOp op);

}  // namespace exeray::etw::wmi
