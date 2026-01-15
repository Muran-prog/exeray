/// @file process_parser_null_input_test.cpp
/// @brief Null and invalid input tests for Process ETW parser.

#include "process_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

TEST_F(ProcessParserTest, ParseProcessEvent_NullRecord_ReturnsInvalid) {
    auto result = parse_process_event(nullptr, strings_.get());
    EXPECT_FALSE(result.valid);
}

TEST_F(ProcessParserTest, ParseProcessEvent_NullUserData_ReturnsInvalid) {
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = nullptr;
    record.UserDataLength = 100;
    
    auto result = parse_process_event(&record, strings_.get());
    EXPECT_FALSE(result.valid);
}

TEST_F(ProcessParserTest, ParseProcessStart_InsufficientLength_ReturnsInvalid) {
    std::vector<uint8_t> data(20, 0);
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    EXPECT_FALSE(result.valid);
}

TEST_F(ProcessParserTest, ParseProcessStop_InsufficientLength_ReturnsInvalid) {
    std::vector<uint8_t> data(12, 0);
    
    EVENT_RECORD record = make_record(ids::process::STOP, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    EXPECT_FALSE(result.valid);
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(ProcessParserNullInputTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
