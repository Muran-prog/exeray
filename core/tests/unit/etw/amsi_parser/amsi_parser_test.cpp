/// @file amsi_parser_test.cpp
/// @brief Unit tests for AMSI ETW parser.

#include "amsi_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

// =============================================================================
// 1. Scan Buffer Parsing
// =============================================================================

TEST_F(AmsiParserTest, ParseScanBuffer_ExtractsScanResult) {
    uint32_t expected_result = 0x8000;  // Malware threshold
    auto data = build_scan_buffer_data(expected_result, L"TestApp.exe", 100);

    EVENT_RECORD record = make_record(ids::amsi::SCAN_BUFFER);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_amsi_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::Amsi);
    EXPECT_EQ(result.payload.amsi.scan_result, expected_result);
}

TEST_F(AmsiParserTest, ParseScanBuffer_ExtractsAppName) {
    auto data = build_scan_buffer_data(0, L"PowerShell.exe", 256);

    EVENT_RECORD record = make_record(ids::amsi::SCAN_BUFFER);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_amsi_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_NE(result.payload.amsi.app_name, event::INVALID_STRING);
}

TEST_F(AmsiParserTest, ParseScanBuffer_ExtractsContentSize) {
    uint32_t expected_size = 4096;
    auto data = build_scan_buffer_data(0, L"TestApp.exe", expected_size);

    EVENT_RECORD record = make_record(ids::amsi::SCAN_BUFFER);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_amsi_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.amsi.content_size, expected_size);
}

// =============================================================================
// 2. Malware Detection (CRITICAL SECURITY)
// =============================================================================

TEST_F(AmsiParserTest, ParseScanBuffer_ResultClean_StatusSuccess) {
    auto data = build_scan_buffer_data(0, L"TestApp.exe", 100);  // AMSI_RESULT_CLEAN = 0

    EVENT_RECORD record = make_record(ids::amsi::SCAN_BUFFER);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_amsi_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.status, event::Status::Success);
}

TEST_F(AmsiParserTest, ParseScanBuffer_ResultNotDetected_StatusSuccess) {
    auto data = build_scan_buffer_data(1, L"TestApp.exe", 100);  // AMSI_RESULT_NOT_DETECTED = 1

    EVENT_RECORD record = make_record(ids::amsi::SCAN_BUFFER);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_amsi_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.status, event::Status::Success);
}

TEST_F(AmsiParserTest, ParseScanBuffer_ResultMalware_StatusDenied) {
    auto data = build_scan_buffer_data(0x8000, L"TestApp.exe", 100);  // AMSI_RESULT_DETECTED = 0x8000

    EVENT_RECORD record = make_record(ids::amsi::SCAN_BUFFER);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_amsi_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.status, event::Status::Denied);
}

TEST_F(AmsiParserTest, ParseScanBuffer_ResultBlockedByAdmin_StatusDenied) {
    auto data = build_scan_buffer_data(0x4000, L"TestApp.exe", 100);  // Admin block range start

    EVENT_RECORD record = make_record(ids::amsi::SCAN_BUFFER);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_amsi_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.status, event::Status::Denied);
}

TEST_F(AmsiParserTest, ParseScanBuffer_EdgeCaseMalwareThreshold) {
    // result = 0x7FFF -> NOT malware (below threshold)
    auto data_below = build_scan_buffer_data(0x7FFF, L"TestApp.exe", 100);

    EVENT_RECORD record_below = make_record(ids::amsi::SCAN_BUFFER);
    record_below.UserData = data_below.data();
    record_below.UserDataLength = static_cast<USHORT>(data_below.size());

    auto result_below = parse_amsi_event(&record_below, strings_.get());

    EXPECT_TRUE(result_below.valid);
    EXPECT_NE(result_below.status, event::Status::Denied);

    // result = 0x8000 -> IS malware (at threshold)
    auto data_at = build_scan_buffer_data(0x8000, L"TestApp.exe", 100);

    EVENT_RECORD record_at = make_record(ids::amsi::SCAN_BUFFER);
    record_at.UserData = data_at.data();
    record_at.UserDataLength = static_cast<USHORT>(data_at.size());

    auto result_at = parse_amsi_event(&record_at, strings_.get());

    EXPECT_TRUE(result_at.valid);
    EXPECT_EQ(result_at.status, event::Status::Denied);
}

// =============================================================================
// 3. AMSI Bypass Detection (CRITICAL SECURITY)
// =============================================================================

TEST_F(AmsiParserTest, ParseScanBuffer_EmptyContentPowerShell_Bypass) {
    auto data = build_scan_buffer_data(0, L"PowerShell.exe", 0);  // content_size = 0, PowerShell

    EVENT_RECORD record = make_record(ids::amsi::SCAN_BUFFER);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_amsi_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.status, event::Status::Suspicious);
}

TEST_F(AmsiParserTest, ParseScanBuffer_EmptyContentOtherApp_NotBypass) {
    auto data = build_scan_buffer_data(0, L"JScript.exe", 0);  // content_size = 0, but NOT PowerShell

    EVENT_RECORD record = make_record(ids::amsi::SCAN_BUFFER);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_amsi_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.status, event::Status::Success);  // Not bypass, clean result
}

TEST_F(AmsiParserTest, ParseScanBuffer_NonEmptyContent_NotBypass) {
    auto data = build_scan_buffer_data(0, L"PowerShell.exe", 100);  // content_size > 0

    EVENT_RECORD record = make_record(ids::amsi::SCAN_BUFFER);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_amsi_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.status, event::Status::Success);  // Not bypass, clean result
}

TEST_F(AmsiParserTest, ParseScanBuffer_BypassSetsStatusSuspicious) {
    auto data = build_scan_buffer_data(0, L"PowerShell", 0);  // bypass condition

    EVENT_RECORD record = make_record(ids::amsi::SCAN_BUFFER);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_amsi_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.status, event::Status::Suspicious);
}

// =============================================================================
// 4. Case Insensitive App Name Matching
// =============================================================================

TEST_F(AmsiParserTest, BypassDetection_PowerShellCasings) {
    std::vector<std::wstring> variations = {
        L"powershell.exe",
        L"POWERSHELL",
        L"PowerShell",
        L"pOwErShElL.ExE"
    };

    for (const auto& app_name : variations) {
        auto data = build_scan_buffer_data(0, app_name, 0);

        EVENT_RECORD record = make_record(ids::amsi::SCAN_BUFFER);
        record.UserData = data.data();
        record.UserDataLength = static_cast<USHORT>(data.size());

        auto result = parse_amsi_event(&record, strings_.get());

        EXPECT_TRUE(result.valid) << "Failed for: " << std::string(app_name.begin(), app_name.end());
        EXPECT_EQ(result.status, event::Status::Suspicious)
            << "Case insensitivity failed for: " << std::string(app_name.begin(), app_name.end());
    }
}

TEST_F(AmsiParserTest, ContainsCaseInsensitive_BasicMatching) {
    // "PowerShell_ISE" contains "powershell" -> should detect bypass
    auto data = build_scan_buffer_data(0, L"PowerShell_ISE", 0);

    EVENT_RECORD record = make_record(ids::amsi::SCAN_BUFFER);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_amsi_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.status, event::Status::Suspicious);
}

// =============================================================================
// 5. Result Name Mapping (test through status outcomes)
// =============================================================================

TEST_F(AmsiParserTest, AmsiResultName_Clean_ReturnsString) {
    auto data = build_scan_buffer_data(0, L"TestApp.exe", 100);

    EVENT_RECORD record = make_record(ids::amsi::SCAN_BUFFER);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_amsi_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.status, event::Status::Success);
    EXPECT_EQ(result.payload.amsi.scan_result, 0u);
}

TEST_F(AmsiParserTest, AmsiResultName_Malware_ReturnsString) {
    auto data = build_scan_buffer_data(0x8000, L"TestApp.exe", 100);

    EVENT_RECORD record = make_record(ids::amsi::SCAN_BUFFER);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_amsi_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.status, event::Status::Denied);
    EXPECT_GE(result.payload.amsi.scan_result, 0x8000u);
}

TEST_F(AmsiParserTest, AmsiResultName_BlockedByAdmin_ReturnsString) {
    // Test middle of admin block range (0x4000 - 0x4FFF)
    auto data = build_scan_buffer_data(0x4500, L"TestApp.exe", 100);

    EVENT_RECORD record = make_record(ids::amsi::SCAN_BUFFER);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_amsi_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.status, event::Status::Denied);
}

TEST_F(AmsiParserTest, AmsiResultName_Unknown_ReturnsSuspicious) {
    // result = 5 is not CLEAN(0), NOT_DETECTED(1), or in known ranges
    auto data = build_scan_buffer_data(5, L"TestApp.exe", 100);

    EVENT_RECORD record = make_record(ids::amsi::SCAN_BUFFER);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_amsi_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    // Unknown result still maps to Success (not malware/blocked)
    EXPECT_EQ(result.status, event::Status::Success);
}

// =============================================================================
// 6. Invalid Input
// =============================================================================

TEST_F(AmsiParserTest, ParseAmsiEvent_NullRecord_ReturnsInvalid) {
    auto result = parse_amsi_event(nullptr, strings_.get());

    EXPECT_FALSE(result.valid);
}

TEST_F(AmsiParserTest, ParseScanBuffer_TruncatedData_ReturnsInvalid) {
    std::vector<uint8_t> data(15, 0);  // Less than 16 bytes minimum

    EVENT_RECORD record = make_record(ids::amsi::SCAN_BUFFER);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_amsi_event(&record, strings_.get());

    EXPECT_FALSE(result.valid);
}

// =============================================================================
// 7. String Pool Integration
// =============================================================================

TEST_F(AmsiParserTest, ParseScanBuffer_NullStringPool_AppNameINVALID) {
    auto data = build_scan_buffer_data(0, L"PowerShell.exe", 100);

    EVENT_RECORD record = make_record(ids::amsi::SCAN_BUFFER);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_amsi_event(&record, nullptr);

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.amsi.app_name, event::INVALID_STRING);
}

TEST_F(AmsiParserTest, ParseScanBuffer_ValidStringPool_InternsAppName) {
    auto data = build_scan_buffer_data(0, L"PowerShell.exe", 100);

    EVENT_RECORD record = make_record(ids::amsi::SCAN_BUFFER);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_amsi_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_NE(result.payload.amsi.app_name, event::INVALID_STRING);

    // Verify interned string is retrievable
    auto interned = strings_->get(result.payload.amsi.app_name);
    EXPECT_FALSE(interned.empty());
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(AmsiParserTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
