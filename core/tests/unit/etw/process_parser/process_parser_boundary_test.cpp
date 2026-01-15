/// @file process_parser_boundary_test.cpp
/// @brief Boundary condition tests for Process ETW parser.

#include "process_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

TEST_F(ProcessParserTest, ParseProcessStart_ExactMinimumLength_Succeeds) {
    const size_t ptr_size = 8;
    const size_t sid_size = 8;  // SubAuthorityCount = 0
    const size_t min_size = ptr_size + 4*sizeof(uint32_t) + ptr_size 
                          + sizeof(uint32_t) + sid_size + 1 + sizeof(wchar_t);
    
    std::vector<uint8_t> data(min_size, 0);
    
    size_t offset = ptr_size;
    uint32_t pid = 42;
    uint32_t ppid = 84;
    std::memcpy(data.data() + offset, &pid, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    std::memcpy(data.data() + offset, &ppid, sizeof(uint32_t));
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.process.pid, 42u);
    EXPECT_EQ(result.payload.process.parent_pid, 84u);
}

TEST_F(ProcessParserTest, ParseProcessStart_StringAtBufferEnd_NoOverread) {
    auto data = build_process_start_data(1234, 5678, 1, "end.exe", L"x");
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    auto image = strings_->get(result.payload.process.image_path);
    EXPECT_EQ(image, "end.exe");
}

TEST_F(ProcessParserTest, ParseProcessStart_MissingNullTerminator_SafeHandling) {
    auto data = build_process_start_data(1234, 5678, 1, "test.exe", L"test");
    
    const size_t ptr_size = 8;
    const size_t sid_size = 8 + 4;  // SubAuthorityCount = 1
    size_t image_offset = ptr_size + 4*sizeof(uint32_t) + ptr_size + sizeof(uint32_t) + sid_size;
    
    size_t truncate_at = image_offset + 5;
    data.resize(truncate_at);
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    SUCCEED();
}

TEST_F(ProcessParserTest, ParseImageLoad_InsufficientLength_ReturnsInvalid) {
    std::vector<uint8_t> data(16, 0);
    
    EVENT_RECORD record = make_record(ids::process::IMAGE_LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    EXPECT_FALSE(result.valid);
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(ProcessParserBoundaryTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
