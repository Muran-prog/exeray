/// @file process_parser_sid_test.cpp
/// @brief SID parsing edge case tests for Process ETW parser.

#include "process_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

TEST_F(ProcessParserTest, ParseProcessStart_LargeSID_SkipsCorrectly) {
    auto data = build_process_start_data(
        9999, 8888, 15, "largesid.exe", L"largesid --flag"
    );
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.process.pid, 9999u);
    
    auto image_path = strings_->get(result.payload.process.image_path);
    EXPECT_EQ(image_path, "largesid.exe");
}

TEST_F(ProcessParserTest, ParseProcessStart_ZeroSID_HandlesGracefully) {
    auto data = build_process_start_data(
        5555, 4444, 0, "zerosid.exe", L"zerosid"
    );
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.process.pid, 5555u);
    
    auto image_path = strings_->get(result.payload.process.image_path);
    EXPECT_EQ(image_path, "zerosid.exe");
}

TEST_F(ProcessParserTest, ParseProcessStart_CorruptedSID_NoBufferOverread) {
    auto data = build_process_start_data(
        7777, 6666, 1, "test.exe", L"test"
    );
    
    const size_t ptr_size = 8;
    size_t sid_offset = ptr_size + 4*sizeof(uint32_t) + ptr_size + sizeof(uint32_t);
    data[sid_offset + 1] = 255;  // Corrupt SubAuthorityCount
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    SUCCEED();  // If we got here without ASAN/MSAN errors, we passed
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(ProcessParserSidTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
