/// @file security.cpp
/// @brief TDH to Security event converter.

#ifdef _WIN32

#include "exeray/etw/tdh/converters.hpp"
#include "exeray/etw/tdh/internal.hpp"
#include "exeray/event/string_pool.hpp"

namespace exeray::etw {

using namespace tdh::detail;

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
            result.status = event::Status::Error;
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
    
    std::wstring subject = get_wstring_prop(tdh_event, L"SubjectUserName");
    if (!subject.empty() && strings != nullptr) {
        result.payload.security.subject_user = strings->intern_wide(subject);
    } else {
        result.payload.security.subject_user = event::INVALID_STRING;
    }
    
    std::wstring target = get_wstring_prop(tdh_event, L"TargetUserName");
    if (!target.empty() && strings != nullptr) {
        result.payload.security.target_user = strings->intern_wide(target);
    } else {
        result.payload.security.target_user = event::INVALID_STRING;
    }
    
    std::wstring cmd = get_wstring_prop(tdh_event, L"CommandLine");
    if (!cmd.empty() && strings != nullptr) {
        result.payload.security.command_line = strings->intern_wide(cmd);
    } else {
        result.payload.security.command_line = event::INVALID_STRING;
    }
    
    result.payload.security.logon_type = get_uint32_prop(tdh_event, L"LogonType");
    result.payload.security.process_id = get_uint32_prop(tdh_event, L"NewProcessId");
    result.payload.security.is_suspicious = 0;
    
    result.valid = true;
    return result;
}

}  // namespace exeray::etw

#else

namespace exeray::etw {}

#endif
