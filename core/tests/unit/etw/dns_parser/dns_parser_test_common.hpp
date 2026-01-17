/// @file dns_parser_test_common.hpp
/// @brief Shared test fixture and helpers for DNS ETW parser tests.

#pragma once

#include <gtest/gtest.h>

#ifdef _WIN32

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include "exeray/arena.hpp"
#include "exeray/etw/event_ids.hpp"
#include "exeray/etw/parser.hpp"
#include "exeray/event/string_pool.hpp"
#include "exeray/event/types.hpp"

namespace exeray::etw {

/// DNS query types (IANA).
namespace dns_types {
    constexpr uint16_t A = 1;        ///< IPv4 address
    constexpr uint16_t AAAA = 28;    ///< IPv6 address
    constexpr uint16_t MX = 15;      ///< Mail exchange
    constexpr uint16_t TXT = 16;     ///< Text record
    constexpr uint16_t CNAME = 5;    ///< Canonical name
    constexpr uint16_t ANY = 255;    ///< Any record type
}  // namespace dns_types

class DnsParserTest : public ::testing::Test {
protected:
    static constexpr std::size_t kArenaSize = 1024 * 1024;  // 1MB

    void SetUp() override {
        arena_ = std::make_unique<Arena>(kArenaSize);
        strings_ = std::make_unique<event::StringPool>(*arena_);
    }

    /// Create a minimal valid EVENT_RECORD for DNS events.
    EVENT_RECORD make_record(uint16_t event_id) {
        EVENT_RECORD record{};
        record.EventHeader.EventDescriptor.Id = event_id;
        record.EventHeader.ProcessId = 1234;
        record.EventHeader.TimeStamp.QuadPart = 0x123456789ABCDEF0LL;
        return record;
    }

    /// Build DNS Query Completed (Event 3006) user data.
    /// Layout:
    ///   domain: WSTRING (null-terminated wide string)
    ///   query_type: UINT16
    ///   result_code: UINT32
    ///   results: WSTRING (optional, IP addresses separated by ';')
    std::vector<uint8_t> build_query_completed_data(
        const std::wstring& domain,
        uint16_t query_type,
        uint32_t result_code,
        const std::wstring& results = L""
    ) {
        const size_t domain_bytes = (domain.size() + 1) * sizeof(wchar_t);
        const size_t results_bytes = (results.size() + 1) * sizeof(wchar_t);
        const size_t total_size = domain_bytes +
                                  sizeof(uint16_t) +    // query_type
                                  sizeof(uint32_t) +    // result_code
                                  results_bytes;

        std::vector<uint8_t> buffer(total_size, 0);
        size_t offset = 0;

        // domain (null-terminated wide string)
        std::memcpy(buffer.data() + offset, domain.c_str(), domain_bytes);
        offset += domain_bytes;

        // query_type (2 bytes)
        std::memcpy(buffer.data() + offset, &query_type, sizeof(uint16_t));
        offset += sizeof(uint16_t);

        // result_code (4 bytes)
        std::memcpy(buffer.data() + offset, &result_code, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // results (null-terminated wide string)
        std::memcpy(buffer.data() + offset, results.c_str(), results_bytes);

        return buffer;
    }

    /// Build DNS Query Failed (Event 3008) user data.
    /// Layout:
    ///   domain: WSTRING (null-terminated wide string)
    ///   query_type: UINT16
    ///   error_code: UINT32
    std::vector<uint8_t> build_query_failed_data(
        const std::wstring& domain,
        uint16_t query_type,
        uint32_t error_code
    ) {
        const size_t domain_bytes = (domain.size() + 1) * sizeof(wchar_t);
        const size_t total_size = domain_bytes +
                                  sizeof(uint16_t) +    // query_type
                                  sizeof(uint32_t);     // error_code

        std::vector<uint8_t> buffer(total_size, 0);
        size_t offset = 0;

        // domain (null-terminated wide string)
        std::memcpy(buffer.data() + offset, domain.c_str(), domain_bytes);
        offset += domain_bytes;

        // query_type (2 bytes)
        std::memcpy(buffer.data() + offset, &query_type, sizeof(uint16_t));
        offset += sizeof(uint16_t);

        // error_code (4 bytes)
        std::memcpy(buffer.data() + offset, &error_code, sizeof(uint32_t));

        return buffer;
    }

    /// Convert IPv4 octets to 32-bit integer (network byte order: big-endian).
    static uint32_t make_ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
        return (static_cast<uint32_t>(a) << 24) |
               (static_cast<uint32_t>(b) << 16) |
               (static_cast<uint32_t>(c) << 8) |
               static_cast<uint32_t>(d);
    }

    std::unique_ptr<Arena> arena_;
    std::unique_ptr<event::StringPool> strings_;
};

}  // namespace exeray::etw

#endif  // _WIN32
