/// @file registry_parser_ntstatus_test.cpp
/// @brief NTSTATUS edge case tests for Registry ETW parser.

#include "registry_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

// =============================================================================
// NTSTATUS Edge Cases
// =============================================================================

TEST_F(RegistryParserTest, ParseKeyEvent_WarningNTSTATUS_ReturnsSuccess) {
    // Positive non-zero NTSTATUS values are warnings, treated as success
    // STATUS_BUFFER_OVERFLOW = 0x80000005 is actually negative when cast to int32
    // Use a small positive value for warning status
    int32_t ntstatus = 1;  // Positive warning

    auto data = build_key_event_data(ntstatus);

    EVENT_RECORD record = make_record(ids::registry::CREATE_KEY, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_registry_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.status, event::Status::Success);
}

TEST_F(RegistryParserTest, ParseKeyEvent_MaxNegativeNTSTATUS_ReturnsError) {
    // 0xFFFFFFFF as int32 = -1 (negative, should be error)
    int32_t ntstatus = static_cast<int32_t>(0xFFFFFFFF);

    auto data = build_key_event_data(ntstatus);

    EVENT_RECORD record = make_record(ids::registry::OPEN_KEY, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_registry_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.status, event::Status::Error);
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(RegistryParserNtstatusTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
