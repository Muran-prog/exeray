/// @file dns_parser_test.cpp
/// @brief Unit tests for DNS ETW parser.

#include "dns_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

// =============================================================================
// 1. Query Completed Parsing
// =============================================================================

TEST_F(DnsParserTest, ParseQueryCompleted_ExtractsDomain) {
    auto data = build_query_completed_data(L"example.com", dns_types::A, 0, L"93.184.216.34");

    EVENT_RECORD record = make_record(ids::dns::QUERY_COMPLETED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::Dns);
    EXPECT_NE(result.payload.dns.domain, event::INVALID_STRING);
}

TEST_F(DnsParserTest, ParseQueryCompleted_ExtractsQueryType) {
    auto data = build_query_completed_data(L"example.com", dns_types::AAAA, 0, L"");

    EVENT_RECORD record = make_record(ids::dns::QUERY_COMPLETED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.dns.query_type, dns_types::AAAA);
}

TEST_F(DnsParserTest, ParseQueryCompleted_ExtractsResultCode) {
    // Result code 0 = success
    auto data_success = build_query_completed_data(L"example.com", dns_types::A, 0, L"93.184.216.34");

    EVENT_RECORD record_success = make_record(ids::dns::QUERY_COMPLETED);
    record_success.UserData = data_success.data();
    record_success.UserDataLength = static_cast<USHORT>(data_success.size());

    auto result_success = parse_dns_event(&record_success, strings_.get());

    EXPECT_TRUE(result_success.valid);
    EXPECT_EQ(result_success.payload.dns.result_code, 0u);
    EXPECT_EQ(result_success.status, event::Status::Success);

    // Non-zero result code = error
    auto data_error = build_query_completed_data(L"example.com", dns_types::A, 9003, L"");

    EVENT_RECORD record_error = make_record(ids::dns::QUERY_COMPLETED);
    record_error.UserData = data_error.data();
    record_error.UserDataLength = static_cast<USHORT>(data_error.size());

    auto result_error = parse_dns_event(&record_error, strings_.get());

    EXPECT_TRUE(result_error.valid);
    EXPECT_EQ(result_error.payload.dns.result_code, 9003u);
    EXPECT_EQ(result_error.status, event::Status::Error);
}

TEST_F(DnsParserTest, ParseQueryCompleted_ExtractsResolvedIP) {
    // A record with IP address
    auto data = build_query_completed_data(L"google.com", dns_types::A, 0, L"142.250.80.14");

    EVENT_RECORD record = make_record(ids::dns::QUERY_COMPLETED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.dns.resolved_ip, make_ipv4(142, 250, 80, 14));
}

// =============================================================================
// 2. IP Address Parsing
// =============================================================================

TEST_F(DnsParserTest, ParseQueryCompleted_IPv4FromResults) {
    // Multiple IPs separated by semicolons - first IP extracted
    auto data = build_query_completed_data(L"example.com", dns_types::A, 0, L"192.168.1.1;10.0.0.1");

    EVENT_RECORD record = make_record(ids::dns::QUERY_COMPLETED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.dns.resolved_ip, make_ipv4(192, 168, 1, 1));
}

TEST_F(DnsParserTest, ParseQueryCompleted_SingleIP_Extracted) {
    auto data = build_query_completed_data(L"test.com", dns_types::A, 0, L"8.8.8.8");

    EVENT_RECORD record = make_record(ids::dns::QUERY_COMPLETED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.dns.resolved_ip, make_ipv4(8, 8, 8, 8));
}

TEST_F(DnsParserTest, ParseQueryCompleted_InvalidIPFormat_ZeroIP) {
    // Malformed IP address
    auto data = build_query_completed_data(L"example.com", dns_types::A, 0, L"not.an.ip.address");

    EVENT_RECORD record = make_record(ids::dns::QUERY_COMPLETED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.dns.resolved_ip, 0u);
}

TEST_F(DnsParserTest, ParseQueryCompleted_NonARecord_NoIPExtraction) {
    // AAAA record - IPv4 extraction skipped
    auto data_aaaa = build_query_completed_data(L"ipv6.example.com", dns_types::AAAA, 0, L"2001:db8::1");

    EVENT_RECORD record_aaaa = make_record(ids::dns::QUERY_COMPLETED);
    record_aaaa.UserData = data_aaaa.data();
    record_aaaa.UserDataLength = static_cast<USHORT>(data_aaaa.size());

    auto result_aaaa = parse_dns_event(&record_aaaa, strings_.get());

    EXPECT_TRUE(result_aaaa.valid);
    EXPECT_EQ(result_aaaa.payload.dns.resolved_ip, 0u);

    // MX record - no IP extraction
    auto data_mx = build_query_completed_data(L"example.com", dns_types::MX, 0, L"mail.example.com");

    EVENT_RECORD record_mx = make_record(ids::dns::QUERY_COMPLETED);
    record_mx.UserData = data_mx.data();
    record_mx.UserDataLength = static_cast<USHORT>(data_mx.size());

    auto result_mx = parse_dns_event(&record_mx, strings_.get());

    EXPECT_TRUE(result_mx.valid);
    EXPECT_EQ(result_mx.payload.dns.resolved_ip, 0u);
}

// =============================================================================
// 3. DGA Detection (CRITICAL SECURITY)
// =============================================================================

TEST_F(DnsParserTest, ParseQueryCompleted_DGALikeDomain_Suspicious) {
    // Random character domain typical of DGA (long enough to trigger entropy check)
    auto data = build_query_completed_data(L"xkqjhwertplmznb.com", dns_types::A, 0, L"1.2.3.4");

    EVENT_RECORD record = make_record(ids::dns::QUERY_COMPLETED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.dns.is_suspicious, 1u);
    EXPECT_EQ(result.status, event::Status::Suspicious);
}

TEST_F(DnsParserTest, ParseQueryCompleted_NormalDomain_NotSuspicious) {
    auto data = build_query_completed_data(L"google.com", dns_types::A, 0, L"142.250.80.14");

    EVENT_RECORD record = make_record(ids::dns::QUERY_COMPLETED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.dns.is_suspicious, 0u);
    EXPECT_NE(result.status, event::Status::Suspicious);
}

TEST_F(DnsParserTest, ParseQueryCompleted_LongRandomSubdomain_Suspicious) {
    // Long random subdomain with high entropy
    auto data = build_query_completed_data(L"asdfjkl1234qwerty.malware.com", dns_types::A, 0, L"1.2.3.4");

    EVENT_RECORD record = make_record(ids::dns::QUERY_COMPLETED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.dns.is_suspicious, 1u);
    EXPECT_EQ(result.status, event::Status::Suspicious);
}

TEST_F(DnsParserTest, ParseQueryFailed_DGADomain_Suspicious) {
    // DGA domain that fails resolution (common malware pattern)
    auto data = build_query_failed_data(L"qzxwvuts9876.net", dns_types::A, 9003);

    EVENT_RECORD record = make_record(ids::dns::QUERY_FAILED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.dns.is_suspicious, 1u);
    EXPECT_EQ(result.status, event::Status::Suspicious);
}

// =============================================================================
// 4. Query Failed Parsing
// =============================================================================

TEST_F(DnsParserTest, ParseQueryFailed_ExtractsErrorCode) {
    // NXDOMAIN error
    auto data = build_query_failed_data(L"nonexistent.example.com", dns_types::A, 9003);

    EVENT_RECORD record = make_record(ids::dns::QUERY_FAILED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.dns.result_code, 9003u);
}

TEST_F(DnsParserTest, ParseQueryFailed_SetsStatusError) {
    // Normal domain that fails - status Error
    auto data = build_query_failed_data(L"example.com", dns_types::A, 9002);

    EVENT_RECORD record = make_record(ids::dns::QUERY_FAILED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.status, event::Status::Error);
}

TEST_F(DnsParserTest, ParseQueryFailed_DGA_SetsStatusSuspicious) {
    // DGA-like domain failure -> Suspicious status
    auto data = build_query_failed_data(L"kxjzqwrty1234.com", dns_types::A, 9003);

    EVENT_RECORD record = make_record(ids::dns::QUERY_FAILED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.status, event::Status::Suspicious);
}

// =============================================================================
// 5. Query Type Handling
// =============================================================================

TEST_F(DnsParserTest, ParseQueryCompleted_TypeA_Value1) {
    auto data = build_query_completed_data(L"example.com", dns_types::A, 0, L"1.2.3.4");

    EVENT_RECORD record = make_record(ids::dns::QUERY_COMPLETED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.dns.query_type, 1u);
}

TEST_F(DnsParserTest, ParseQueryCompleted_TypeAAAA_Value28) {
    auto data = build_query_completed_data(L"example.com", dns_types::AAAA, 0, L"2001:db8::1");

    EVENT_RECORD record = make_record(ids::dns::QUERY_COMPLETED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.dns.query_type, 28u);
}

TEST_F(DnsParserTest, ParseQueryCompleted_TypeMX_Value15) {
    auto data = build_query_completed_data(L"example.com", dns_types::MX, 0, L"mail.example.com");

    EVENT_RECORD record = make_record(ids::dns::QUERY_COMPLETED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.dns.query_type, 15u);
}

TEST_F(DnsParserTest, ParseQueryCompleted_TypeTXT_Value16) {
    auto data = build_query_completed_data(L"example.com", dns_types::TXT, 0, L"v=spf1 include:_spf.google.com");

    EVENT_RECORD record = make_record(ids::dns::QUERY_COMPLETED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.dns.query_type, 16u);
}

TEST_F(DnsParserTest, ParseQueryCompleted_TypeANY_Value255) {
    auto data = build_query_completed_data(L"example.com", dns_types::ANY, 0, L"");

    EVENT_RECORD record = make_record(ids::dns::QUERY_COMPLETED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.dns.query_type, 255u);
}

// =============================================================================
// 6. Invalid Input
// =============================================================================

TEST_F(DnsParserTest, ParseDnsEvent_NullRecord_ReturnsInvalid) {
    auto result = parse_dns_event(nullptr, strings_.get());

    EXPECT_FALSE(result.valid);
}

TEST_F(DnsParserTest, ParseQueryCompleted_TruncatedData_ReturnsInvalid) {
    // Less than 4 bytes minimum
    std::vector<uint8_t> data(3, 0);

    EVENT_RECORD record = make_record(ids::dns::QUERY_COMPLETED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_FALSE(result.valid);
}

// =============================================================================
// 7. Unicode Domain Names
// =============================================================================

TEST_F(DnsParserTest, ParseQueryCompleted_IDNDomain_Extracted) {
    // Internationalized domain name (Punycode)
    auto data = build_query_completed_data(L"xn--n3h.com", dns_types::A, 0, L"1.2.3.4");

    EVENT_RECORD record = make_record(ids::dns::QUERY_COMPLETED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_NE(result.payload.dns.domain, event::INVALID_STRING);
}

TEST_F(DnsParserTest, ParseQueryCompleted_LongDomain_FullExtraction) {
    // 253-character domain (max DNS length)
    std::wstring long_domain;
    // Build subdomain.subdomain.subdomain... pattern up to 253 chars
    for (int i = 0; i < 10; ++i) {
        if (i > 0) long_domain += L'.';
        long_domain += L"subdomain" + std::to_wstring(i);
    }
    long_domain += L".example.com";
    // Ensure it's within DNS limit
    if (long_domain.length() > 253) {
        long_domain = long_domain.substr(0, 253);
    }

    auto data = build_query_completed_data(long_domain, dns_types::A, 0, L"1.2.3.4");

    EVENT_RECORD record = make_record(ids::dns::QUERY_COMPLETED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_NE(result.payload.dns.domain, event::INVALID_STRING);

    // Verify the domain was interned
    auto interned = strings_->get(result.payload.dns.domain);
    EXPECT_FALSE(interned.empty());
}

// =============================================================================
// 8. String Pool Integration
// =============================================================================

TEST_F(DnsParserTest, ParseQueryCompleted_NullStringPool_DomainINVALID) {
    auto data = build_query_completed_data(L"example.com", dns_types::A, 0, L"1.2.3.4");

    EVENT_RECORD record = make_record(ids::dns::QUERY_COMPLETED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, nullptr);

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.dns.domain, event::INVALID_STRING);
}

TEST_F(DnsParserTest, ParseQueryCompleted_ValidStringPool_InternsDomain) {
    auto data = build_query_completed_data(L"example.com", dns_types::A, 0, L"1.2.3.4");

    EVENT_RECORD record = make_record(ids::dns::QUERY_COMPLETED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_NE(result.payload.dns.domain, event::INVALID_STRING);

    // Verify interned string is retrievable
    auto interned = strings_->get(result.payload.dns.domain);
    EXPECT_FALSE(interned.empty());
}

// =============================================================================
// 9. Payload Initialization
// =============================================================================

TEST_F(DnsParserTest, ParseQueryCompleted_InitializesPadding) {
    auto data = build_query_completed_data(L"example.com", dns_types::A, 0, L"1.2.3.4");

    EVENT_RECORD record = make_record(ids::dns::QUERY_COMPLETED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    // Verify _pad is zeroed
    EXPECT_EQ(result.payload.dns._pad[0], 0);
    EXPECT_EQ(result.payload.dns._pad[1], 0);
    EXPECT_EQ(result.payload.dns._pad[2], 0);
}

TEST_F(DnsParserTest, ParseQueryFailed_InitializesResolvedIPToZero) {
    auto data = build_query_failed_data(L"example.com", dns_types::A, 9003);

    EVENT_RECORD record = make_record(ids::dns::QUERY_FAILED);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_dns_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.dns.resolved_ip, 0u);
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(DnsParserTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
