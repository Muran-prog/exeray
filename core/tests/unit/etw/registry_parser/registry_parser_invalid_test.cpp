/// @file registry_parser_invalid_test.cpp
/// @brief Invalid input tests for Registry ETW parser.

#include "registry_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

// =============================================================================
// Invalid Input
// =============================================================================

TEST_F(RegistryParserTest, ParseRegistryEvent_NullRecord_ReturnsInvalid) {
    auto result = parse_registry_event(nullptr, strings_.get());
    EXPECT_FALSE(result.valid);
}

TEST_F(RegistryParserTest, ParseKeyEvent_InsufficientLength_ReturnsInvalid) {
    // Key event requires at least 12 bytes minimum
    std::vector<uint8_t> data(11, 0);  // < 12 bytes

    EVENT_RECORD record = make_record(ids::registry::CREATE_KEY, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_registry_event(&record, strings_.get());

    EXPECT_FALSE(result.valid);
}

TEST_F(RegistryParserTest, ParseValueEvent_InsufficientLength_ReturnsInvalid) {
    // Value event requires at least 8 bytes minimum
    std::vector<uint8_t> data(7, 0);  // < 8 bytes

    EVENT_RECORD record = make_record(ids::registry::SET_VALUE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_registry_event(&record, strings_.get());

    EXPECT_FALSE(result.valid);
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(RegistryParserInvalidTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
