/// @file parser.cpp
/// @brief parse_with_tdh and global_tdh_cache implementation.

#ifdef _WIN32

#include "exeray/etw/tdh/parser.hpp"
#include "exeray/etw/tdh/internal.hpp"
#include "exeray/logging.hpp"

namespace exeray::etw {

TdhSchemaCache& global_tdh_cache() {
    static TdhSchemaCache cache;
    return cache;
}

std::optional<TdhParsedEvent> parse_with_tdh(
    const EVENT_RECORD* record,
    TdhSchemaCache* cache
) {
    if (record == nullptr) {
        return std::nullopt;
    }
    
    // Use provided cache or global cache
    TdhSchemaCache* actual_cache = cache ? cache : &global_tdh_cache();
    PTRACE_EVENT_INFO info = actual_cache->get_schema(record);
    
    if (info == nullptr) {
        EXERAY_TRACE("TDH: Failed to get schema for event ID {}", 
                     record->EventHeader.EventDescriptor.Id);
        return std::nullopt;
    }
    
    TdhParsedEvent result;
    result.event_id = record->EventHeader.EventDescriptor.Id;
    result.event_version = record->EventHeader.EventDescriptor.Version;
    
    // Set up user data pointers
    PBYTE user_data = static_cast<PBYTE>(record->UserData);
    ULONG user_data_length = record->UserDataLength;
    
    // Extract all top-level properties
    for (ULONG i = 0; i < info->TopLevelPropertyCount && user_data_length > 0; ++i) {
        std::wstring name = tdh::detail::get_property_name(info, i);
        if (name.empty()) {
            continue;
        }
        
        auto value = tdh::detail::extract_property(info, record, i, user_data, user_data_length);
        if (value) {
            result.properties[name] = std::move(*value);
        }
    }
    
    EXERAY_TRACE("TDH: Parsed event ID {} with {} properties",
                 result.event_id, result.properties.size());
    
    return result;
}

}  // namespace exeray::etw

#else  // !_WIN32

namespace exeray::etw {
// Empty translation unit for non-Windows
}

#endif  // _WIN32
