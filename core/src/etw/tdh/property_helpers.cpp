/// @file property_helpers.cpp
/// @brief TDH property helper functions.

#ifdef _WIN32

#include "exeray/etw/tdh/internal.hpp"

#pragma comment(lib, "tdh.lib")

namespace exeray::etw::tdh::detail {

ULONG get_pointer_size(const EVENT_RECORD* record) {
    return (record->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;
}

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

}  // namespace exeray::etw::tdh::detail

#else  // !_WIN32

namespace exeray::etw::tdh::detail {
// Empty translation unit for non-Windows
}

#endif  // _WIN32
