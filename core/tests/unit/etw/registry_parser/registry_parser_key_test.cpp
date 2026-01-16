/// @file registry_parser_key_test.cpp
/// @brief Key operation tests for Registry ETW parser.

#include "registry_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

// =============================================================================
// Key Operations
// =============================================================================

TEST_F(RegistryParserTest, ParseCreateKey_ValidEvent_SetsOperation) {
    auto data = build_key_event_data(0);  // STATUS_SUCCESS

    EVENT_RECORD record = make_record(ids::registry::CREATE_KEY, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_registry_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::Registry);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::RegistryOp::CreateKey));
}

TEST_F(RegistryParserTest, ParseOpenKey_ValidEvent_SetsOperation) {
    auto data = build_key_event_data(0);  // STATUS_SUCCESS

    EVENT_RECORD record = make_record(ids::registry::OPEN_KEY, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_registry_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::Registry);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::RegistryOp::QueryValue));
}

TEST_F(RegistryParserTest, ParseKeyEvent_SuccessNTSTATUS_ReturnsSuccess) {
    auto data = build_key_event_data(0);  // STATUS_SUCCESS = 0

    EVENT_RECORD record = make_record(ids::registry::CREATE_KEY, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_registry_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.status, event::Status::Success);
}

TEST_F(RegistryParserTest, ParseKeyEvent_ErrorNTSTATUS_ReturnsError) {
    // STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
    int32_t ntstatus = static_cast<int32_t>(0xC0000034);
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

TEST(RegistryParserKeyTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
