/// @file registry_parser_pointer_test.cpp
/// @brief Pointer size handling tests for Registry ETW parser.

#include "registry_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

// =============================================================================
// Pointer Size Handling
// =============================================================================

TEST_F(RegistryParserTest, ParseKeyEvent_64bit_BaseObjectKeyObject8Bytes) {
    // In 64-bit mode: BaseObject(8) + KeyObject(8) + Status(4) = offset 16 for status
    constexpr size_t ptr_size_64 = 8;
    constexpr size_t expected_offset = ptr_size_64 * 2;  // 16 bytes

    auto data = build_key_event_data(0, true);  // 64-bit

    // Verify buffer layout: should have at least ptr*2 + 4 bytes
    EXPECT_GE(data.size(), expected_offset + sizeof(int32_t));

    EVENT_RECORD record = make_record(ids::registry::CREATE_KEY, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_registry_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.status, event::Status::Success);
}

TEST_F(RegistryParserTest, ParseValueEvent_32bit_KeyObject4Bytes) {
    // In 32-bit mode: KeyObject(4) + Status(4) = offset 4 for status
    constexpr size_t ptr_size_32 = 4;
    constexpr size_t expected_offset = ptr_size_32;  // 4 bytes

    auto data = build_value_event_data(0, 4, 4, false);  // 32-bit, REG_DWORD

    // Verify buffer layout: should have at least ptr + 4 + 4 + 4 bytes
    EXPECT_GE(data.size(), expected_offset + sizeof(int32_t) * 3);

    EVENT_RECORD record = make_record(ids::registry::SET_VALUE, false);  // 32-bit
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_registry_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.status, event::Status::Success);
    EXPECT_EQ(result.payload.registry.value_type, 4u);  // REG_DWORD
    EXPECT_EQ(result.payload.registry.data_size, 4u);
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(RegistryParserPointerTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
