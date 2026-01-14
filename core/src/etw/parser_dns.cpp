/// @file parser_dns.cpp
/// @brief ETW parser for Microsoft-Windows-DNS-Client events.
///
/// Parses DNS Query events for C2/DGA domain detection using
/// Shannon entropy analysis and heuristic pattern matching.

#ifdef _WIN32

#include "exeray/etw/parser.hpp"
#include "exeray/etw/session.hpp"
#include "exeray/etw/tdh_parser.hpp"
#include "exeray/event/string_pool.hpp"

#include <cmath>
#include <cstring>
#include <string>
#include <string_view>

#include "exeray/logging.hpp"

namespace exeray::etw {

namespace {

/// DNS Client event IDs from Microsoft-Windows-DNS-Client provider.
enum class DnsEventId : uint16_t {
    QueryCompleted = 3006,  ///< DNS query completed successfully
    QueryFailed = 3008      ///< DNS query failed
};

/// DNS query types (IANA).
namespace dns_types {
    constexpr uint32_t A = 1;        ///< IPv4 address
    constexpr uint32_t AAAA = 28;    ///< IPv6 address
    constexpr uint32_t TXT = 16;     ///< Text record
    constexpr uint32_t MX = 15;      ///< Mail exchange
    constexpr uint32_t CNAME = 5;    ///< Canonical name
}  // namespace dns_types

/// @brief Get human-readable name for DNS query type.
const char* query_type_name(uint32_t type) {
    switch (type) {
        case dns_types::A: return "A";
        case dns_types::AAAA: return "AAAA";
        case dns_types::TXT: return "TXT";
        case dns_types::MX: return "MX";
        case dns_types::CNAME: return "CNAME";
        default: return "OTHER";
    }
}

/// @brief Extract common fields from EVENT_RECORD header.
void extract_common(const EVENT_RECORD* record, ParsedEvent& out) {
    out.timestamp = static_cast<uint64_t>(record->EventHeader.TimeStamp.QuadPart);
    out.status = event::Status::Success;
    out.category = event::Category::Dns;
    out.pid = record->EventHeader.ProcessId;
}

/// @brief Extract wide string from event data.
/// @param data Pointer to start of string.
/// @param max_len Maximum bytes to read.
/// @return String view (empty if null or invalid).
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

/// @brief Calculate Shannon entropy of a domain name.
///
/// Higher entropy indicates more randomness, typical of DGA domains.
/// Normal domains: 2.5-3.5, DGA domains: 3.8+
///
/// @param domain The domain name to analyze.
/// @return Entropy value (0.0 to ~4.7 for lowercase alphanumeric).
float calculate_entropy(std::wstring_view domain) {
    if (domain.empty()) {
        return 0.0f;
    }

    // Count character frequencies
    int freq[256] = {0};
    size_t count = 0;

    for (wchar_t c : domain) {
        if (c == L'.') continue;  // Skip dots in entropy calc
        // Fold to lowercase ASCII for frequency counting
        unsigned char ch = static_cast<unsigned char>(c & 0xFF);
        if (c > 255) ch = 'x';  // Treat unicode as 'x'
        if (ch >= 'A' && ch <= 'Z') ch = ch - 'A' + 'a';
        freq[ch]++;
        count++;
    }

    if (count == 0) {
        return 0.0f;
    }

    // Calculate entropy
    float entropy = 0.0f;
    for (int f : freq) {
        if (f > 0) {
            float p = static_cast<float>(f) / static_cast<float>(count);
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

/// @brief Check if domain appears to be a DGA-generated domain.
///
/// DGA detection heuristics:
/// - Domain length > 20 chars (excluding TLD)
/// - High Shannon entropy (> 3.8)
/// - High digit ratio in subdomain (> 30%)
/// - Absence of common word patterns
///
/// @param domain The domain name to check.
/// @return true if domain appears suspicious.
bool is_dga_suspicious(std::wstring_view domain) {
    if (domain.empty()) {
        return false;
    }

    // Find the subdomain (part before first dot or entire domain)
    size_t dot_pos = domain.find(L'.');
    std::wstring_view subdomain = (dot_pos != std::wstring_view::npos)
        ? domain.substr(0, dot_pos)
        : domain;

    // Heuristic 1: Long subdomain (> 20 chars)
    if (subdomain.size() > 20) {
        return true;
    }

    // Heuristic 2: High entropy (> 3.8)
    float entropy = calculate_entropy(subdomain);
    if (entropy > 3.8f) {
        return true;
    }

    // Heuristic 3: High digit ratio in subdomain (> 30%)
    size_t digit_count = 0;
    for (wchar_t c : subdomain) {
        if (c >= L'0' && c <= L'9') {
            digit_count++;
        }
    }
    if (subdomain.size() > 5 &&
        static_cast<float>(digit_count) / static_cast<float>(subdomain.size()) > 0.3f) {
        return true;
    }

    // Heuristic 4: No vowels (common in random strings)
    bool has_vowel = false;
    for (wchar_t c : subdomain) {
        wchar_t lower = (c >= L'A' && c <= L'Z') ? (c - L'A' + L'a') : c;
        if (lower == L'a' || lower == L'e' || lower == L'i' ||
            lower == L'o' || lower == L'u') {
            has_vowel = true;
            break;
        }
    }
    if (subdomain.size() > 8 && !has_vowel) {
        return true;
    }

    return false;
}

/// @brief Convert wide string to narrow for logging.
std::string wstring_to_narrow(std::wstring_view wstr) {
    std::string result;
    result.reserve(wstr.size());
    for (wchar_t c : wstr) {
        result.push_back(static_cast<char>(c & 0x7F));
    }
    return result;
}

/// @brief Log DNS query event.
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

/// @brief Parse DNS Query Completed event (Event ID 3006).
///
/// Event Data Layout (approximate):
///   QueryName: WSTRING - Domain being queried
///   QueryType: UINT16 - DNS record type
///   QueryStatus: UINT32 - Result code
///   QueryResults: WSTRING - IP addresses (semicolon-separated)
ParsedEvent parse_query_completed(const EVENT_RECORD* record,
                                   event::StringPool* strings) {
    ParsedEvent result{};
    extract_common(record, result);
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
    if (query_type == dns_types::A && offset < len) {
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

/// @brief Parse DNS Query Failed event (Event ID 3008).
ParsedEvent parse_query_failed(const EVENT_RECORD* record,
                                event::StringPool* strings) {
    ParsedEvent result{};
    extract_common(record, result);
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

}  // namespace

ParsedEvent parse_dns_event(const EVENT_RECORD* record, event::StringPool* strings) {
    if (record == nullptr) {
        return ParsedEvent{.valid = false};
    }

    const auto event_id = static_cast<DnsEventId>(
        record->EventHeader.EventDescriptor.Id);

    switch (event_id) {
        case DnsEventId::QueryCompleted:
            return parse_query_completed(record, strings);
        case DnsEventId::QueryFailed:
            return parse_query_failed(record, strings);
        default:
            // Unknown event ID - try TDH fallback
            if (auto tdh_result = parse_with_tdh(record)) {
                return convert_tdh_to_dns(*tdh_result, record, strings);
            }
            return ParsedEvent{.valid = false};
    }
}

}  // namespace exeray::etw

#else  // !_WIN32

// Empty translation unit for non-Windows
namespace exeray::etw {
// Stub defined in header as inline
}  // namespace exeray::etw

#endif  // _WIN32
