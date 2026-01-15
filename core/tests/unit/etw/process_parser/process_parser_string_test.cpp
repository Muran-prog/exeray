/// @file process_parser_string_test.cpp
/// @brief String parsing tests for Process ETW parser.

#include "process_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

TEST_F(ProcessParserTest, ParseProcessStart_EmptyImageFileName_ReturnsInvalidString) {
    auto data = build_process_start_data(1234, 5678, 1, "", L"cmd");
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.process.image_path, event::INVALID_STRING);
}

TEST_F(ProcessParserTest, ParseProcessStart_EmptyCommandLine_ReturnsInvalidString) {
    auto data = build_process_start_data(1234, 5678, 1, "app.exe", L"");
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.process.command_line, event::INVALID_STRING);
}

TEST_F(ProcessParserTest, ParseProcessStart_LongImageFileName_FullExtraction) {
    std::string long_path(255, 'x');
    long_path[0] = 'C';
    long_path[1] = ':';
    long_path[2] = '\\';
    
    auto data = build_process_start_data(1234, 5678, 1, long_path, L"cmd");
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    auto image_path = strings_->get(result.payload.process.image_path);
    EXPECT_EQ(image_path.size(), 255u);
    EXPECT_EQ(image_path, long_path);
}

TEST_F(ProcessParserTest, ParseProcessStart_LongCommandLine_FullExtraction) {
    std::wstring long_cmd(4096, L'x');
    long_cmd[0] = L'c';
    long_cmd[1] = L'm';
    long_cmd[2] = L'd';
    long_cmd[3] = L' ';
    
    auto data = build_process_start_data(1234, 5678, 1, "cmd.exe", long_cmd);
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    auto cmd_line = strings_->get(result.payload.process.command_line);
    EXPECT_GE(cmd_line.size(), 4000u);
}

TEST_F(ProcessParserTest, ParseProcessStart_NonAsciiCommandLine_UTF16Preserved) {
    std::wstring unicode_cmd = L"powershell.exe -c \"Привет мир 🎉\"";
    
    auto data = build_process_start_data(1234, 5678, 1, "powershell.exe", unicode_cmd);
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    auto cmd_line = strings_->get(result.payload.process.command_line);
    
    EXPECT_NE(cmd_line.find("powershell.exe"), std::string::npos);
    EXPECT_GT(cmd_line.size(), 20u);
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(ProcessParserStringTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
