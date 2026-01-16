/// @file registry_parser_value_test.cpp
/// @brief Value operation tests for Registry ETW parser.

#include "registry_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

// Registry value type constants (avoid Windows macro conflicts)
constexpr uint32_t kRegSz = 1;
constexpr uint32_t kRegExpandSz = 2;
constexpr uint32_t kRegBinary = 3;
constexpr uint32_t kRegDword = 4;
constexpr uint32_t kRegMultiSz = 7;
constexpr uint32_t kRegQword = 11;

// =============================================================================
// Value Operations
// =============================================================================

TEST_F(RegistryParserTest, ParseSetValue_ExtractsTypeAndSize) {
    auto data = build_value_event_data(0, kRegDword, 4);  // type=4 (REG_DWORD), size=4

    EVENT_RECORD record = make_record(ids::registry::SET_VALUE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_registry_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::RegistryOp::SetValue));
    EXPECT_EQ(result.payload.registry.value_type, kRegDword);
    EXPECT_EQ(result.payload.registry.data_size, 4u);
}

TEST_F(RegistryParserTest, ParseSetValue_AllRegistryTypes) {
    struct TestCase {
        uint32_t type;
        uint32_t size;
        const char* name;
    };

    TestCase test_cases[] = {
        {kRegSz, 100, "REG_SZ"},
        {kRegExpandSz, 256, "REG_EXPAND_SZ"},
        {kRegBinary, 1024, "REG_BINARY"},
        {kRegDword, 4, "REG_DWORD"},
        {kRegQword, 8, "REG_QWORD"},
        {kRegMultiSz, 512, "REG_MULTI_SZ"},
    };

    for (const auto& tc : test_cases) {
        SCOPED_TRACE(tc.name);

        auto data = build_value_event_data(0, tc.type, tc.size);

        EVENT_RECORD record = make_record(ids::registry::SET_VALUE, true);
        record.UserData = data.data();
        record.UserDataLength = static_cast<USHORT>(data.size());

        auto result = parse_registry_event(&record, strings_.get());

        EXPECT_TRUE(result.valid);
        EXPECT_EQ(result.payload.registry.value_type, tc.type);
        EXPECT_EQ(result.payload.registry.data_size, tc.size);
    }
}

TEST_F(RegistryParserTest, ParseDeleteValue_NoTypeOrSize) {
    auto data = build_value_event_data(0, 0, 0);

    EVENT_RECORD record = make_record(ids::registry::VALUE_DELETE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_registry_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::RegistryOp::DeleteValue));
    EXPECT_EQ(result.payload.registry.value_type, 0u);
    EXPECT_EQ(result.payload.registry.data_size, 0u);
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(RegistryParserValueTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
