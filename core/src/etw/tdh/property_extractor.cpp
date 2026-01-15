/// @file property_extractor.cpp
/// @brief TDH property extraction functions.

#ifdef _WIN32

#include "exeray/etw/tdh/internal.hpp"
#include <cwchar>

namespace exeray::etw::tdh::detail {

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

}  // namespace exeray::etw::tdh::detail

#else  // !_WIN32

namespace exeray::etw::tdh::detail {
// Empty translation unit for non-Windows
}

#endif  // _WIN32
