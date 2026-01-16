/// @file registry_parser_defaults_test.cpp
/// @brief Payload initialization tests for Registry ETW parser.

#include "registry_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

// =============================================================================
// Payload Initialization
// =============================================================================

TEST_F(RegistryParserTest, ParseRegistryEvent_InitializesDefaults) {
    auto data = build_key_event_data(0);

    EVENT_RECORD record = make_record(ids::registry::CREATE_KEY, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_registry_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.registry.key_path, event::INVALID_STRING);
    EXPECT_EQ(result.payload.registry.value_name, event::INVALID_STRING);
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(RegistryParserDefaultsTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
