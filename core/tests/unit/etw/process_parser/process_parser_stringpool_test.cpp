/// @file process_parser_stringpool_test.cpp
/// @brief StringPool integration tests for Process ETW parser.

#include "process_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

TEST_F(ProcessParserTest, ParseProcessStart_NullStringPool_NoIntern) {
    auto data = build_process_start_data(1234, 5678, 1, "test.exe", L"test");
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, nullptr);
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.process.image_path, event::INVALID_STRING);
    EXPECT_EQ(result.payload.process.command_line, event::INVALID_STRING);
}

TEST_F(ProcessParserTest, ParseProcessStart_ValidStringPool_InternsStrings) {
    auto data = build_process_start_data(1234, 5678, 1, "interned.exe", L"-arg1 --arg2");
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_NE(result.payload.process.image_path, event::INVALID_STRING);
    EXPECT_NE(result.payload.process.command_line, event::INVALID_STRING);
    
    auto image = strings_->get(result.payload.process.image_path);
    auto cmdline = strings_->get(result.payload.process.command_line);
    
    EXPECT_EQ(image, "interned.exe");
    EXPECT_EQ(cmdline, "-arg1 --arg2");
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(ProcessParserStringPoolTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
