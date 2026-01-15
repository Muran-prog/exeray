/// @file service.cpp
/// @brief Service installation event parser (4697).

#ifdef _WIN32

#include "helpers.hpp"
#include "constants.hpp"
#include "exeray/event/string_pool.hpp"
#include "exeray/logging.hpp"

#include <cstring>

namespace exeray::etw::security {

ParsedEvent parse_service_install(const EVENT_RECORD* record, event::StringPool* strings) {
    ParsedEvent result{};
    exeray::etw::extract_common(record, result, event::Category::Service);
    result.category = event::Category::Service;
    result.operation = static_cast<uint8_t>(event::ServiceOp::Install);
    result.payload.category = event::Category::Service;
    
    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;
    
    if (data == nullptr || len < 16) {
        result.valid = false;
        return result;
    }
    
    size_t offset = 0;
    
    std::wstring_view service_name = extract_wstring(data + offset, len - offset);
    offset += (service_name.size() + 1) * sizeof(wchar_t);
    
    std::wstring_view service_path = extract_wstring(data + offset, len - offset);
    offset += (service_path.size() + 1) * sizeof(wchar_t);
    
    uint32_t service_type = 0;
    uint32_t start_type = 0;
    
    if (offset + sizeof(uint32_t) <= len) {
        std::memcpy(&service_type, data + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
    }
    if (offset + sizeof(uint32_t) <= len) {
        std::memcpy(&start_type, data + offset, sizeof(uint32_t));
    }
    
    bool suspicious = (start_type == service_start_types::AUTO_START);
    
    if (strings != nullptr) {
        result.payload.service.service_name = service_name.empty() ?
            event::INVALID_STRING : strings->intern_wide(service_name);
        result.payload.service.service_path = service_path.empty() ?
            event::INVALID_STRING : strings->intern_wide(service_path);
    } else {
        result.payload.service.service_name = event::INVALID_STRING;
        result.payload.service.service_path = event::INVALID_STRING;
    }
    result.payload.service.service_type = service_type;
    result.payload.service.start_type = start_type;
    result.payload.service.is_suspicious = suspicious ? 1 : 0;
    std::memset(result.payload.service._pad, 0, sizeof(result.payload.service._pad));
    
    if (suspicious) {
        result.status = event::Status::Suspicious;
    }
    
    std::string name_str = wstring_to_narrow(service_name);
    std::string path_str = wstring_to_narrow(service_path, 80);
    if (suspicious) {
        EXERAY_WARN("Service Install (AUTO_START - Persistence!): name={}, path={}",
                    name_str, path_str);
    } else {
        EXERAY_TRACE("Service Install: name={}, path={}", name_str, path_str);
    }
    
    result.valid = true;
    return result;
}

}  // namespace exeray::etw::security

#endif  // _WIN32
