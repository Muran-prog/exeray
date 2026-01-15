/// @file query_parser.cpp
/// @brief DNS query event parsers.

#ifdef _WIN32

#include "query_parser.hpp"
#include "constants.hpp"
#include "dga_detector.hpp"
#include "helpers.hpp"

#include <cstring>

#include "exeray/logging.hpp"

namespace exeray::etw::dns {

ParsedEvent parse_query_completed(const EVENT_RECORD* record,
                                   event::StringPool* strings) {
    ParsedEvent result{};
    exeray::etw::extract_common(record, result, event::Category::Dns);
    result.operation = static_cast<uint8_t>(event::DnsOp::Response);
    result.payload.category = event::Category::Dns;

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 4) {
        result.valid = false;
        return result;
    }

    size_t offset = 0;

    // Extract domain name (wide string)
    std::wstring_view domain = extract_wstring(data + offset, len - offset);
    offset += (domain.size() + 1) * sizeof(wchar_t);

    // Extract query type (2 bytes)
    uint16_t query_type = 0;
    if (offset + 2 <= len) {
        std::memcpy(&query_type, data + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
    }

    // Extract query status/result code (4 bytes)
    uint32_t result_code = 0;
    if (offset + 4 <= len) {
        std::memcpy(&result_code, data + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
    }

    // Extract resolved IP from results string (if A record)
    uint32_t resolved_ip = 0;
    if (query_type == types::A && offset < len) {
        std::wstring_view results = extract_wstring(data + offset, len - offset);
        // Parse first IP from results (format: "x.x.x.x;...")
        if (!results.empty()) {
            unsigned int a = 0, b = 0, c = 0, d = 0;
            int parsed = 0;
            // Simple parsing - convert to narrow string first
            char narrow[64] = {0};
            size_t i = 0;
            for (wchar_t wc : results) {
                if (i >= sizeof(narrow) - 1) break;
                if (wc == L';') break;  // Stop at delimiter
                narrow[i++] = static_cast<char>(wc & 0x7F);
            }
            parsed = std::sscanf(narrow, "%u.%u.%u.%u", &a, &b, &c, &d);
            if (parsed == 4 && a < 256 && b < 256 && c < 256 && d < 256) {
                resolved_ip = (a << 24) | (b << 16) | (c << 8) | d;
            }
        }
    }

    // Check for DGA-like domain
    bool suspicious = is_dga_suspicious(domain);

    // Set payload with interned strings
    if (strings != nullptr && !domain.empty()) {
        result.payload.dns.domain = strings->intern_wide(domain);
    } else {
        result.payload.dns.domain = event::INVALID_STRING;
    }
    result.payload.dns.query_type = query_type;
    result.payload.dns.result_code = result_code;
    result.payload.dns.resolved_ip = resolved_ip;
    result.payload.dns.is_suspicious = suspicious ? 1 : 0;
    std::memset(result.payload.dns._pad, 0, sizeof(result.payload.dns._pad));

    // Set status
    if (suspicious) {
        result.status = event::Status::Suspicious;
    } else if (result_code != 0) {
        result.status = event::Status::Error;
    } else {
        result.status = event::Status::Success;
    }

    // Log the query
    log_dns_query(result.pid, domain, query_type, result_code, suspicious);

    result.valid = true;
    return result;
}

ParsedEvent parse_query_failed(const EVENT_RECORD* record,
                                event::StringPool* strings) {
    ParsedEvent result{};
    exeray::etw::extract_common(record, result, event::Category::Dns);
    result.operation = static_cast<uint8_t>(event::DnsOp::Failure);
    result.payload.category = event::Category::Dns;

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 4) {
        result.valid = false;
        return result;
    }

    size_t offset = 0;

    // Extract domain name
    std::wstring_view domain = extract_wstring(data + offset, len - offset);
    offset += (domain.size() + 1) * sizeof(wchar_t);

    // Extract query type
    uint16_t query_type = 0;
    if (offset + 2 <= len) {
        std::memcpy(&query_type, data + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
    }

    // Extract error code
    uint32_t error_code = 0;
    if (offset + 4 <= len) {
        std::memcpy(&error_code, data + offset, sizeof(uint32_t));
    }

    // Check for DGA-like domain (failed queries to random domains = suspicious)
    bool suspicious = is_dga_suspicious(domain);

    // Set payload
    if (strings != nullptr && !domain.empty()) {
        result.payload.dns.domain = strings->intern_wide(domain);
    } else {
        result.payload.dns.domain = event::INVALID_STRING;
    }
    result.payload.dns.query_type = query_type;
    result.payload.dns.result_code = error_code;
    result.payload.dns.resolved_ip = 0;
    result.payload.dns.is_suspicious = suspicious ? 1 : 0;
    std::memset(result.payload.dns._pad, 0, sizeof(result.payload.dns._pad));

    // Failed DNS queries are errors, or suspicious if DGA
    result.status = suspicious ? event::Status::Suspicious : event::Status::Error;

    // Log failed query
    std::string narrow_domain = wstring_to_narrow(domain);
    if (suspicious) {
        EXERAY_WARN("DNS query failed (SUSPICIOUS): pid={}, domain={}, type={}, error={}",
                    result.pid, narrow_domain, query_type_name(query_type), error_code);
    } else {
        EXERAY_WARN("DNS query failed: pid={}, domain={}, type={}, error={}",
                    result.pid, narrow_domain, query_type_name(query_type), error_code);
    }

    result.valid = true;
    return result;
}

}  // namespace exeray::etw::dns

#endif  // _WIN32
