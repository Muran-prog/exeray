/// @file clr.cpp
/// @brief TDH to CLR event converter.

#ifdef _WIN32

#include "exeray/etw/tdh/converters.hpp"
#include "exeray/etw/tdh/internal.hpp"
#include "exeray/etw/parser_utils.hpp"
#include "exeray/event/string_pool.hpp"

namespace exeray::etw {

using namespace tdh::detail;

ParsedEvent convert_tdh_to_clr(
    const TdhParsedEvent& tdh_event,
    const EVENT_RECORD* record,
    event::StringPool* strings
) {
    ParsedEvent result{};
    extract_common(record, result, event::Category::Clr);
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
    
    std::wstring assembly_name = get_wstring_prop(tdh_event, L"AssemblyName");
    if (assembly_name.empty()) {
        assembly_name = get_wstring_prop(tdh_event, L"FullyQualifiedAssemblyName");
    }
    if (!assembly_name.empty() && strings != nullptr) {
        result.payload.clr.assembly_name = strings->intern_wide(assembly_name);
    } else {
        result.payload.clr.assembly_name = event::INVALID_STRING;
    }
    
    std::wstring method_name = get_wstring_prop(tdh_event, L"MethodName");
    if (!method_name.empty() && strings != nullptr) {
        result.payload.clr.method_name = strings->intern_wide(method_name);
    } else {
        result.payload.clr.method_name = event::INVALID_STRING;
    }
    
    result.payload.clr.load_address = get_uint64_prop(tdh_event, L"ModuleILPath");
    
    result.payload.clr.is_dynamic = (assembly_name.find(L"\\") == std::wstring::npos &&
                                      assembly_name.find(L"/") == std::wstring::npos) ? 1 : 0;
    result.payload.clr.is_suspicious = result.payload.clr.is_dynamic;
    
    result.valid = true;
    return result;
}

}  // namespace exeray::etw

#else

namespace exeray::etw {}

#endif
