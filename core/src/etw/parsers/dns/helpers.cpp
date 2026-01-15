/// @file helpers.cpp
/// @brief DNS parser helper implementations.

#ifdef _WIN32

#include "helpers.hpp"
#include "constants.hpp"
#include "exeray/logging.hpp"

namespace exeray::etw::dns {

void extract_common(const EVENT_RECORD* record, ParsedEvent& out) {
    out.timestamp = static_cast<uint64_t>(record->EventHeader.TimeStamp.QuadPart);
    out.status = event::Status::Success;
    out.category = event::Category::Dns;
    out.pid = record->EventHeader.ProcessId;
}

std::wstring_view extract_wstring(const uint8_t* data, size_t max_len) {
    if (data == nullptr || max_len < 2) {
        return {};
    }

    const auto* wdata = reinterpret_cast<const wchar_t*>(data);
    size_t max_chars = max_len / sizeof(wchar_t);
    size_t len = 0;
    while (len < max_chars && wdata[len] != L'\0') {
        ++len;
    }
    return {wdata, len};
}

std::string wstring_to_narrow(std::wstring_view wstr) {
    std::string result;
    result.reserve(wstr.size());
    for (wchar_t c : wstr) {
        result.push_back(static_cast<char>(c & 0x7F));
    }
    return result;
}

void log_dns_query(uint32_t pid, std::wstring_view domain, uint32_t query_type,
                   uint32_t result_code, bool is_suspicious) {
    std::string narrow_domain = wstring_to_narrow(domain);
    if (is_suspicious) {
        EXERAY_WARN("Suspicious DNS query (DGA-like): pid={}, domain={}, type={}",
                    pid, narrow_domain, query_type_name(query_type));
    } else {
        EXERAY_TRACE("DNS query: pid={}, domain={}, type={}, result={}",
                     pid, narrow_domain, query_type_name(query_type), result_code);
    }
}

}  // namespace exeray::etw::dns

#endif  // _WIN32
