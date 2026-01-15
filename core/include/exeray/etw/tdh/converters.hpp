/// @file converters.hpp
/// @brief TDH event converter function declarations.

#pragma once

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include "exeray/etw/tdh/internal.hpp"
#include "exeray/etw/parser.hpp"

namespace exeray::event {
class StringPool;
}

namespace exeray::etw {

ParsedEvent convert_tdh_to_process(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

ParsedEvent convert_tdh_to_file(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

ParsedEvent convert_tdh_to_registry(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

ParsedEvent convert_tdh_to_network(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

ParsedEvent convert_tdh_to_image(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

ParsedEvent convert_tdh_to_thread(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

ParsedEvent convert_tdh_to_memory(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

ParsedEvent convert_tdh_to_script(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

ParsedEvent convert_tdh_to_amsi(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

ParsedEvent convert_tdh_to_dns(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

ParsedEvent convert_tdh_to_security(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

ParsedEvent convert_tdh_to_wmi(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

ParsedEvent convert_tdh_to_clr(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
);

}  // namespace exeray::etw

#endif  // _WIN32
