/// @file tdh_parser.cpp
/// @brief TDH (Trace Data Helper) fallback parser implementation.

#ifdef _WIN32

#include "exeray/etw/tdh_parser.hpp"
#include "exeray/event/string_pool.hpp"
#include "exeray/logging.hpp"

#include <algorithm>
#include <cwchar>

#pragma comment(lib, "tdh.lib")

namespace exeray::etw {

namespace {

/// @brief Get pointer size from event header flags.
inline ULONG get_pointer_size(const EVENT_RECORD* record) {
    return (record->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;
}

/// @brief Extract property name from TRACE_EVENT_INFO.
std::wstring get_property_name(PTRACE_EVENT_INFO info, ULONG property_index) {
    if (property_index >= info->TopLevelPropertyCount) {
        return L"";
    }
    const auto& prop = info->EventPropertyInfoArray[property_index];
    if (prop.NameOffset == 0) {
        return L"";
    }
    return std::wstring(reinterpret_cast<PWCHAR>(
        reinterpret_cast<PBYTE>(info) + prop.NameOffset
    ));
}

/// @brief Get property size from event info.
ULONG get_property_size(
    PTRACE_EVENT_INFO info,
    const EVENT_RECORD* record,
    ULONG property_index
) {
    const auto& prop = info->EventPropertyInfoArray[property_index];
    
    // Fixed size property
    if ((prop.Flags & PropertyParamLength) == 0) {
        return prop.length;
    }
    
    // Variable length - need to use TdhGetPropertySize
    PROPERTY_DATA_DESCRIPTOR descriptor{};
    descriptor.PropertyName = reinterpret_cast<ULONGLONG>(
        reinterpret_cast<PBYTE>(info) + prop.NameOffset
    );
    descriptor.ArrayIndex = ULONG_MAX;
    
    ULONG size = 0;
    ULONG status = TdhGetPropertySize(
        const_cast<PEVENT_RECORD>(record),
        0, nullptr,
        1, &descriptor,
        &size
    );
    
    return (status == ERROR_SUCCESS) ? size : 0;
}

/// @brief Extract a single property value from event data.
std::optional<TdhPropertyValue> extract_property(
    PTRACE_EVENT_INFO info,
    const EVENT_RECORD* record,
    ULONG property_index,
    PBYTE& user_data,
    ULONG& user_data_length
) {
    if (property_index >= info->TopLevelPropertyCount) {
        return std::nullopt;
    }
    
    const auto& prop = info->EventPropertyInfoArray[property_index];
    
    // Skip struct/array properties for now
    if (prop.Flags & PropertyStruct) {
        return std::nullopt;
    }
    
    ULONG buffer_size = 0;
    USHORT consumed = 0;
    
    // First call to get required buffer size
    ULONG status = TdhFormatProperty(
        info,
        nullptr,  // MapInfo
        get_pointer_size(record),
        prop.nonStructType.InType,
        prop.nonStructType.OutType,
        static_cast<USHORT>(prop.length),
        static_cast<USHORT>(user_data_length),
        user_data,
        &buffer_size,
        nullptr,
        &consumed
    );
    
    if (status == ERROR_INSUFFICIENT_BUFFER && buffer_size > 0) {
        std::vector<WCHAR> buffer(buffer_size / sizeof(WCHAR) + 1);
        
        status = TdhFormatProperty(
            info,
            nullptr,
            get_pointer_size(record),
            prop.nonStructType.InType,
            prop.nonStructType.OutType,
            static_cast<USHORT>(prop.length),
            static_cast<USHORT>(user_data_length),
            user_data,
            &buffer_size,
            buffer.data(),
            &consumed
        );
        
        if (status == ERROR_SUCCESS) {
            user_data += consumed;
            user_data_length -= consumed;
            
            // Convert based on InType
            switch (prop.nonStructType.InType) {
                case TDH_INTYPE_UINT32:
                case TDH_INTYPE_HEXINT32:
                    return static_cast<uint32_t>(wcstoul(buffer.data(), nullptr, 0));
                    
                case TDH_INTYPE_UINT64:
                case TDH_INTYPE_HEXINT64:
                case TDH_INTYPE_POINTER:
                    return static_cast<uint64_t>(wcstoull(buffer.data(), nullptr, 0));
                    
                case TDH_INTYPE_INT32:
                    return static_cast<int32_t>(wcstol(buffer.data(), nullptr, 0));
                    
                case TDH_INTYPE_UNICODESTRING:
                case TDH_INTYPE_ANSISTRING:
                case TDH_INTYPE_COUNTEDSTRING:
                case TDH_INTYPE_SID:
                case TDH_INTYPE_GUID:
                    return std::wstring(buffer.data());
                    
                default:
                    return std::wstring(buffer.data());
            }
        }
    }
    
    // If TdhFormatProperty fails, try raw extraction for common types
    if (user_data_length >= 4) {
        switch (prop.nonStructType.InType) {
            case TDH_INTYPE_UINT32:
            case TDH_INTYPE_HEXINT32: {
                uint32_t val = *reinterpret_cast<uint32_t*>(user_data);
                user_data += 4;
                user_data_length -= 4;
                return val;
            }
            case TDH_INTYPE_INT32: {
                int32_t val = *reinterpret_cast<int32_t*>(user_data);
                user_data += 4;
                user_data_length -= 4;
                return val;
            }
            default:
                break;
        }
    }
    
    if (user_data_length >= 8) {
        switch (prop.nonStructType.InType) {
            case TDH_INTYPE_UINT64:
            case TDH_INTYPE_HEXINT64:
            case TDH_INTYPE_POINTER: {
                uint64_t val = *reinterpret_cast<uint64_t*>(user_data);
                user_data += 8;
                user_data_length -= 8;
                return val;
            }
            default:
                break;
        }
    }
    
    return std::nullopt;
}

/// @brief Extract common fields from EVENT_RECORD header.
void extract_common(const EVENT_RECORD* record, ParsedEvent& out) {
    out.pid = record->EventHeader.ProcessId;
    out.timestamp = static_cast<uint64_t>(record->EventHeader.TimeStamp.QuadPart);
    out.status = event::Status::Success;
}

/// @brief Get wide string property or empty.
std::wstring get_wstring_prop(
    const TdhParsedEvent& event,
    const std::wstring& name
) {
    auto it = event.properties.find(name);
    if (it != event.properties.end()) {
        if (auto* str = std::get_if<std::wstring>(&it->second)) {
            return *str;
        }
    }
    return L"";
}

/// @brief Get uint32 property or 0.
uint32_t get_uint32_prop(const TdhParsedEvent& event, const std::wstring& name) {
    auto it = event.properties.find(name);
    if (it != event.properties.end()) {
        if (auto* val = std::get_if<uint32_t>(&it->second)) {
            return *val;
        }
        if (auto* val = std::get_if<uint64_t>(&it->second)) {
            return static_cast<uint32_t>(*val);
        }
        if (auto* val = std::get_if<int32_t>(&it->second)) {
            return static_cast<uint32_t>(*val);
        }
    }
    return 0;
}

/// @brief Get uint64 property or 0.
uint64_t get_uint64_prop(const TdhParsedEvent& event, const std::wstring& name) {
    auto it = event.properties.find(name);
    if (it != event.properties.end()) {
        if (auto* val = std::get_if<uint64_t>(&it->second)) {
            return *val;
        }
        if (auto* val = std::get_if<uint32_t>(&it->second)) {
            return static_cast<uint64_t>(*val);
        }
    }
    return 0;
}

}  // namespace

// ----------------------------------------------------------------------------
// TdhSchemaCache implementation
// ----------------------------------------------------------------------------

bool TdhSchemaCache::EventKey::operator==(const EventKey& other) const {
    return event_id == other.event_id &&
           event_version == other.event_version &&
           memcmp(&provider_guid, &other.provider_guid, sizeof(GUID)) == 0;
}

size_t TdhSchemaCache::EventKeyHash::operator()(const EventKey& key) const {
    // Simple hash combining provider GUID parts with event id/version
    size_t h = std::hash<uint32_t>{}(key.provider_guid.Data1);
    h ^= std::hash<uint16_t>{}(key.provider_guid.Data2) << 1;
    h ^= std::hash<uint16_t>{}(key.provider_guid.Data3) << 2;
    h ^= std::hash<uint16_t>{}(key.event_id) << 3;
    h ^= std::hash<uint8_t>{}(key.event_version) << 4;
    return h;
}

PTRACE_EVENT_INFO TdhSchemaCache::get_schema(const EVENT_RECORD* record) {
    if (record == nullptr) {
        return nullptr;
    }
    
    EventKey key{
        record->EventHeader.ProviderId,
        record->EventHeader.EventDescriptor.Id,
        record->EventHeader.EventDescriptor.Version
    };
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check cache first
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        return reinterpret_cast<PTRACE_EVENT_INFO>(it->second.data());
    }
    
    // Not in cache, fetch from TDH
    ULONG buffer_size = 0;
    ULONG status = TdhGetEventInformation(
        const_cast<PEVENT_RECORD>(record),
        0, nullptr,
        nullptr,
        &buffer_size
    );
    
    if (status != ERROR_INSUFFICIENT_BUFFER || buffer_size == 0) {
        return nullptr;
    }
    
    std::vector<BYTE> buffer(buffer_size);
    status = TdhGetEventInformation(
        const_cast<PEVENT_RECORD>(record),
        0, nullptr,
        reinterpret_cast<PTRACE_EVENT_INFO>(buffer.data()),
        &buffer_size
    );
    
    if (status != ERROR_SUCCESS) {
        return nullptr;
    }
    
    // Store in cache and return
    auto [insert_it, inserted] = cache_.emplace(key, std::move(buffer));
    return reinterpret_cast<PTRACE_EVENT_INFO>(insert_it->second.data());
}

void TdhSchemaCache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();
}

size_t TdhSchemaCache::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cache_.size();
}

// ----------------------------------------------------------------------------
// Global cache singleton
// ----------------------------------------------------------------------------

TdhSchemaCache& global_tdh_cache() {
    static TdhSchemaCache cache;
    return cache;
}

// ----------------------------------------------------------------------------
// Main TDH parsing function
// ----------------------------------------------------------------------------

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
        std::wstring name = get_property_name(info, i);
        if (name.empty()) {
            continue;
        }
        
        auto value = extract_property(info, record, i, user_data, user_data_length);
        if (value) {
            result.properties[name] = std::move(*value);
        }
    }
    
    EXERAY_TRACE("TDH: Parsed event ID {} with {} properties",
                 result.event_id, result.properties.size());
    
    return result;
}

// ----------------------------------------------------------------------------
// Converter functions for each category
// ----------------------------------------------------------------------------

ParsedEvent convert_tdh_to_process(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
) {
    ParsedEvent result{};
    extract_common(record, result);
    result.category = event::Category::Process;
    result.payload.category = event::Category::Process;
    
    // Map event ID to operation
    switch (tdh_event.event_id) {
        case 1: result.operation = static_cast<uint8_t>(event::ProcessOp::Create); break;
        case 2: result.operation = static_cast<uint8_t>(event::ProcessOp::Terminate); break;
        case 5: result.operation = static_cast<uint8_t>(event::ProcessOp::LoadLibrary); break;
        default: 
            result.valid = false;
            return result;
    }
    
    // Extract ProcessId (try various property names)
    result.payload.process.pid = get_uint32_prop(tdh_event, L"ProcessId");
    if (result.payload.process.pid == 0) {
        result.payload.process.pid = get_uint32_prop(tdh_event, L"ProcessID");
    }
    
    // Extract ParentId
    result.payload.process.parent_pid = get_uint32_prop(tdh_event, L"ParentId");
    if (result.payload.process.parent_pid == 0) {
        result.payload.process.parent_pid = get_uint32_prop(tdh_event, L"ParentProcessId");
    }
    
    // Extract ImageFileName
    std::wstring image_name = get_wstring_prop(tdh_event, L"ImageFileName");
    if (image_name.empty()) {
        image_name = get_wstring_prop(tdh_event, L"ImageName");
    }
    if (!image_name.empty() && strings != nullptr) {
        result.payload.process.image_path = strings->intern_wide(image_name);
    } else {
        result.payload.process.image_path = event::INVALID_STRING;
    }
    
    // Extract CommandLine
    std::wstring cmd_line = get_wstring_prop(tdh_event, L"CommandLine");
    if (!cmd_line.empty() && strings != nullptr) {
        result.payload.process.command_line = strings->intern_wide(cmd_line);
    } else {
        result.payload.process.command_line = event::INVALID_STRING;
    }
    
    result.valid = true;
    return result;
}

ParsedEvent convert_tdh_to_file(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
) {
    ParsedEvent result{};
    extract_common(record, result);
    result.category = event::Category::FileSystem;
    result.payload.category = event::Category::FileSystem;
    
    // Map event ID to operation
    switch (tdh_event.event_id) {
        case 10: result.operation = static_cast<uint8_t>(event::FileOp::Create); break;
        case 11: result.operation = static_cast<uint8_t>(event::FileOp::Create); break; // Cleanup
        case 14: result.operation = static_cast<uint8_t>(event::FileOp::Read); break;
        case 15: result.operation = static_cast<uint8_t>(event::FileOp::Write); break;
        case 26: result.operation = static_cast<uint8_t>(event::FileOp::Delete); break;
        default:
            result.valid = false;
            return result;
    }
    
    // Extract file path
    std::wstring path = get_wstring_prop(tdh_event, L"FileName");
    if (path.empty()) {
        path = get_wstring_prop(tdh_event, L"OpenPath");
    }
    if (!path.empty() && strings != nullptr) {
        result.payload.file.path = strings->intern_wide(path);
    } else {
        result.payload.file.path = event::INVALID_STRING;
    }
    
    result.valid = true;
    return result;
}

ParsedEvent convert_tdh_to_registry(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
) {
    ParsedEvent result{};
    extract_common(record, result);
    result.category = event::Category::Registry;
    result.payload.category = event::Category::Registry;
    
    // Map event ID to operation
    switch (tdh_event.event_id) {
        case 1: result.operation = static_cast<uint8_t>(event::RegistryOp::CreateKey); break;
        case 2: result.operation = static_cast<uint8_t>(event::RegistryOp::QueryValue); break;
        case 5: result.operation = static_cast<uint8_t>(event::RegistryOp::SetValue); break;
        case 6: result.operation = static_cast<uint8_t>(event::RegistryOp::DeleteValue); break;
        default:
            result.valid = false;
            return result;
    }
    
    // Extract key name
    std::wstring key_name = get_wstring_prop(tdh_event, L"KeyName");
    if (key_name.empty()) {
        key_name = get_wstring_prop(tdh_event, L"RelativeName");
    }
    if (!key_name.empty() && strings != nullptr) {
        result.payload.registry.key_path = strings->intern_wide(key_name);
    } else {
        result.payload.registry.key_path = event::INVALID_STRING;
    }
    
    // Extract value name
    std::wstring value_name = get_wstring_prop(tdh_event, L"ValueName");
    if (!value_name.empty() && strings != nullptr) {
        result.payload.registry.value_name = strings->intern_wide(value_name);
    } else {
        result.payload.registry.value_name = event::INVALID_STRING;
    }
    
    result.valid = true;
    return result;
}

ParsedEvent convert_tdh_to_network(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* /*strings*/
) {
    ParsedEvent result{};
    extract_common(record, result);
    result.category = event::Category::Network;
    result.payload.category = event::Category::Network;
    
    // Map event ID to operation (TCPIPv4/v6 events)
    switch (tdh_event.event_id) {
        case 10: // Send
        case 26: // SendIPV6
            result.operation = static_cast<uint8_t>(event::NetworkOp::Send);
            break;
        case 11: // Recv
        case 27: // RecvIPV6
            result.operation = static_cast<uint8_t>(event::NetworkOp::Receive);
            break;
        case 12: // Connect
        case 28: // ConnectIPV6
            result.operation = static_cast<uint8_t>(event::NetworkOp::Connect);
            break;
        case 13: // Disconnect
        case 29: // DisconnectIPV6
            result.operation = static_cast<uint8_t>(event::NetworkOp::Disconnect);
            break;
        default:
            result.valid = false;
            return result;
    }
    
    // Extract network fields
    result.payload.network.src_port = static_cast<uint16_t>(
        get_uint32_prop(tdh_event, L"sport"));
    result.payload.network.dst_port = static_cast<uint16_t>(
        get_uint32_prop(tdh_event, L"dport"));
    result.payload.network.src_addr = get_uint32_prop(tdh_event, L"saddr");
    result.payload.network.dst_addr = get_uint32_prop(tdh_event, L"daddr");
    
    result.valid = true;
    return result;
}

ParsedEvent convert_tdh_to_image(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
) {
    ParsedEvent result{};
    extract_common(record, result);
    result.category = event::Category::Image;
    result.payload.category = event::Category::Image;
    
    switch (tdh_event.event_id) {
        case 10: result.operation = static_cast<uint8_t>(event::ImageOp::Load); break;
        case 2: result.operation = static_cast<uint8_t>(event::ImageOp::Unload); break;
        default:
            result.valid = false;
            return result;
    }
    
    // Extract image base and size
    result.payload.image.base_address = get_uint64_prop(tdh_event, L"ImageBase");
    result.payload.image.size = get_uint64_prop(tdh_event, L"ImageSize");
    result.payload.image.target_pid = get_uint32_prop(tdh_event, L"ProcessId");
    
    // Extract image path
    std::wstring path = get_wstring_prop(tdh_event, L"FileName");
    if (path.empty()) {
        path = get_wstring_prop(tdh_event, L"ImageFileName");
    }
    if (!path.empty() && strings != nullptr) {
        result.payload.image.image_path = strings->intern_wide(path);
    } else {
        result.payload.image.image_path = event::INVALID_STRING;
    }
    
    result.payload.image.is_suspicious = false;
    result.valid = true;
    return result;
}

ParsedEvent convert_tdh_to_thread(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* /*strings*/
) {
    ParsedEvent result{};
    extract_common(record, result);
    result.category = event::Category::Thread;
    result.payload.category = event::Category::Thread;
    
    switch (tdh_event.event_id) {
        case 1: result.operation = static_cast<uint8_t>(event::ThreadOp::Start); break;
        case 2: result.operation = static_cast<uint8_t>(event::ThreadOp::End); break;
        case 3: result.operation = static_cast<uint8_t>(event::ThreadOp::DCStart); break;
        case 4: result.operation = static_cast<uint8_t>(event::ThreadOp::DCEnd); break;
        default:
            result.valid = false;
            return result;
    }
    
    result.payload.thread.thread_id = get_uint32_prop(tdh_event, L"TThreadId");
    if (result.payload.thread.thread_id == 0) {
        result.payload.thread.thread_id = get_uint32_prop(tdh_event, L"ThreadId");
    }
    result.payload.thread.target_pid = get_uint32_prop(tdh_event, L"ProcessId");
    result.payload.thread.creator_pid = get_uint32_prop(tdh_event, L"StackProcess");
    result.payload.thread.start_address = get_uint64_prop(tdh_event, L"Win32StartAddr");
    
    // Detect remote thread injection
    result.payload.thread.is_remote = 
        (result.payload.thread.creator_pid != 0 &&
         result.payload.thread.target_pid != result.payload.thread.creator_pid);
    
    result.valid = true;
    return result;
}

ParsedEvent convert_tdh_to_memory(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* /*strings*/
) {
    ParsedEvent result{};
    extract_common(record, result);
    result.category = event::Category::Memory;
    result.payload.category = event::Category::Memory;
    
    switch (tdh_event.event_id) {
        case 98: result.operation = static_cast<uint8_t>(event::MemoryOp::Alloc); break;
        case 99: result.operation = static_cast<uint8_t>(event::MemoryOp::Free); break;
        default:
            result.valid = false;
            return result;
    }
    
    result.payload.memory.base_address = get_uint64_prop(tdh_event, L"BaseAddress");
    result.payload.memory.region_size = get_uint64_prop(tdh_event, L"RegionSize");
    result.payload.memory.target_pid = get_uint32_prop(tdh_event, L"ProcessId");
    result.payload.memory.protection = get_uint32_prop(tdh_event, L"Flags");
    
    // Detect RWX allocations
    constexpr uint32_t PAGE_EXECUTE_READWRITE = 0x40;
    constexpr uint32_t PAGE_EXECUTE_WRITECOPY = 0x80;
    result.payload.memory.is_rwx = 
        (result.payload.memory.protection == PAGE_EXECUTE_READWRITE ||
         result.payload.memory.protection == PAGE_EXECUTE_WRITECOPY);
    
    result.valid = true;
    return result;
}

ParsedEvent convert_tdh_to_script(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
) {
    ParsedEvent result{};
    extract_common(record, result);
    result.category = event::Category::Script;
    result.payload.category = event::Category::Script;
    
    switch (tdh_event.event_id) {
        case 4103: result.operation = static_cast<uint8_t>(event::ScriptOp::Module); break;
        case 4104: result.operation = static_cast<uint8_t>(event::ScriptOp::Execute); break;
        default:
            result.valid = false;
            return result;
    }
    
    // Extract script content
    std::wstring content = get_wstring_prop(tdh_event, L"ScriptBlockText");
    if (content.empty()) {
        content = get_wstring_prop(tdh_event, L"ContextInfo");
    }
    if (!content.empty() && strings != nullptr) {
        result.payload.script.content = strings->intern_wide(content);
    } else {
        result.payload.script.content = event::INVALID_STRING;
    }
    
    result.payload.script.script_path = event::INVALID_STRING;
    result.payload.script.is_suspicious = false;
    
    result.valid = true;
    return result;
}

ParsedEvent convert_tdh_to_amsi(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
) {
    ParsedEvent result{};
    extract_common(record, result);
    result.category = event::Category::Amsi;
    result.payload.category = event::Category::Amsi;
    result.operation = static_cast<uint8_t>(event::AmsiOp::Scan);
    
    // Extract app name
    std::wstring app_name = get_wstring_prop(tdh_event, L"appname");
    if (!app_name.empty() && strings != nullptr) {
        result.payload.amsi.app_name = strings->intern_wide(app_name);
    } else {
        result.payload.amsi.app_name = event::INVALID_STRING;
    }
    
    // Extract content
    std::wstring content = get_wstring_prop(tdh_event, L"content");
    if (!content.empty() && strings != nullptr) {
        result.payload.amsi.content = strings->intern_wide(content);
    } else {
        result.payload.amsi.content = event::INVALID_STRING;
    }
    
    result.payload.amsi.scan_result = get_uint32_prop(tdh_event, L"scanResult");
    result.payload.amsi.content_size = get_uint32_prop(tdh_event, L"contentSize");
    
    // Detect bypass (empty content but success) or malware
    result.payload.amsi.is_bypass = 
        (result.payload.amsi.content_size == 0 && 
         result.payload.amsi.scan_result == 0);
    result.payload.amsi.is_malware = (result.payload.amsi.scan_result >= 32768);
    
    result.valid = true;
    return result;
}

ParsedEvent convert_tdh_to_dns(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
) {
    ParsedEvent result{};
    extract_common(record, result);
    result.category = event::Category::Dns;
    result.payload.category = event::Category::Dns;
    
    switch (tdh_event.event_id) {
        case 3006: result.operation = static_cast<uint8_t>(event::DnsOp::Response); break;
        case 3008: 
            result.operation = static_cast<uint8_t>(event::DnsOp::Failure);
            result.status = event::Status::Failure;
            break;
        default:
            result.valid = false;
            return result;
    }
    
    // Extract query name
    std::wstring query_name = get_wstring_prop(tdh_event, L"QueryName");
    if (!query_name.empty() && strings != nullptr) {
        result.payload.dns.query_name = strings->intern_wide(query_name);
    } else {
        result.payload.dns.query_name = event::INVALID_STRING;
    }
    
    result.payload.dns.query_type = static_cast<uint16_t>(
        get_uint32_prop(tdh_event, L"QueryType"));
    result.payload.dns.resolved_ip = get_uint32_prop(tdh_event, L"QueryResults");
    result.payload.dns.is_suspicious = false; // Would need entropy calc
    
    result.valid = true;
    return result;
}

ParsedEvent convert_tdh_to_security(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
) {
    ParsedEvent result{};
    extract_common(record, result);
    result.payload.category = event::Category::Security;
    
    switch (tdh_event.event_id) {
        case 4624:
            result.category = event::Category::Security;
            result.operation = static_cast<uint8_t>(event::SecurityOp::Logon);
            break;
        case 4625:
            result.category = event::Category::Security;
            result.operation = static_cast<uint8_t>(event::SecurityOp::LogonFailed);
            result.status = event::Status::Failure;
            break;
        case 4688:
            result.category = event::Category::Security;
            result.operation = static_cast<uint8_t>(event::SecurityOp::ProcessCreate);
            break;
        case 4689:
            result.category = event::Category::Security;
            result.operation = static_cast<uint8_t>(event::SecurityOp::ProcessTerminate);
            break;
        case 4697:
            result.category = event::Category::Service;
            result.payload.category = event::Category::Service;
            result.operation = static_cast<uint8_t>(event::ServiceOp::Install);
            break;
        case 4703:
            result.category = event::Category::Security;
            result.operation = static_cast<uint8_t>(event::SecurityOp::PrivilegeAdjust);
            break;
        default:
            result.valid = false;
            return result;
    }
    
    // Extract account info
    std::wstring account = get_wstring_prop(tdh_event, L"TargetUserName");
    if (account.empty()) {
        account = get_wstring_prop(tdh_event, L"SubjectUserName");
    }
    if (!account.empty() && strings != nullptr) {
        result.payload.security.account_name = strings->intern_wide(account);
    } else {
        result.payload.security.account_name = event::INVALID_STRING;
    }
    
    std::wstring domain = get_wstring_prop(tdh_event, L"TargetDomainName");
    if (domain.empty()) {
        domain = get_wstring_prop(tdh_event, L"SubjectDomainName");
    }
    if (!domain.empty() && strings != nullptr) {
        result.payload.security.domain_name = strings->intern_wide(domain);
    } else {
        result.payload.security.domain_name = event::INVALID_STRING;
    }
    
    result.payload.security.logon_type = get_uint32_prop(tdh_event, L"LogonType");
    result.payload.security.is_suspicious = false;
    
    result.valid = true;
    return result;
}

ParsedEvent convert_tdh_to_wmi(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
) {
    ParsedEvent result{};
    extract_common(record, result);
    result.category = event::Category::Wmi;
    result.payload.category = event::Category::Wmi;
    
    switch (tdh_event.event_id) {
        case 5: result.operation = static_cast<uint8_t>(event::WmiOp::Connect); break;
        case 11: result.operation = static_cast<uint8_t>(event::WmiOp::Query); break;
        case 22: result.operation = static_cast<uint8_t>(event::WmiOp::Subscribe); break;
        case 23: result.operation = static_cast<uint8_t>(event::WmiOp::ExecMethod); break;
        default:
            result.valid = false;
            return result;
    }
    
    // Extract namespace
    std::wstring ns = get_wstring_prop(tdh_event, L"NamespaceName");
    if (!ns.empty() && strings != nullptr) {
        result.payload.wmi.wmi_namespace = strings->intern_wide(ns);
    } else {
        result.payload.wmi.wmi_namespace = event::INVALID_STRING;
    }
    
    // Extract query/operation
    std::wstring query = get_wstring_prop(tdh_event, L"Query");
    if (query.empty()) {
        query = get_wstring_prop(tdh_event, L"ClassName");
    }
    if (!query.empty() && strings != nullptr) {
        result.payload.wmi.query = strings->intern_wide(query);
    } else {
        result.payload.wmi.query = event::INVALID_STRING;
    }
    
    result.payload.wmi.is_remote = false;  // Would need machine name check
    result.payload.wmi.is_suspicious = (tdh_event.event_id == 22); // Subscription
    
    result.valid = true;
    return result;
}

ParsedEvent convert_tdh_to_clr(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
) {
    ParsedEvent result{};
    extract_common(record, result);
    result.category = event::Category::Clr;
    result.payload.category = event::Category::Clr;
    
    switch (tdh_event.event_id) {
        case 152:
        case 153:
            result.operation = static_cast<uint8_t>(event::ClrOp::AssemblyLoad);
            break;
        case 154:
            result.operation = static_cast<uint8_t>(event::ClrOp::AssemblyUnload);
            break;
        case 155:
            result.operation = static_cast<uint8_t>(event::ClrOp::MethodJit);
            break;
        default:
            result.valid = false;
            return result;
    }
    
    // Extract assembly name
    std::wstring assembly_name = get_wstring_prop(tdh_event, L"AssemblyName");
    if (assembly_name.empty()) {
        assembly_name = get_wstring_prop(tdh_event, L"FullyQualifiedAssemblyName");
    }
    if (!assembly_name.empty() && strings != nullptr) {
        result.payload.clr.assembly_name = strings->intern_wide(assembly_name);
    } else {
        result.payload.clr.assembly_name = event::INVALID_STRING;
    }
    
    result.payload.clr.clr_instance_id = static_cast<uint16_t>(
        get_uint32_prop(tdh_event, L"ClrInstanceID"));
    
    // Detect dynamic assembly (no file path)
    result.payload.clr.is_dynamic = (assembly_name.find(L"\\") == std::wstring::npos &&
                                      assembly_name.find(L"/") == std::wstring::npos);
    result.payload.clr.is_suspicious = result.payload.clr.is_dynamic;
    
    result.valid = true;
    return result;
}

}  // namespace exeray::etw

#else  // !_WIN32

// Empty translation unit for non-Windows
namespace exeray::etw {
// Stubs defined in header as inline
}  // namespace exeray::etw

#endif  // _WIN32
