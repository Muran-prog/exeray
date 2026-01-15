/// @file process_parser_dispatch_test.cpp
/// @brief Event ID dispatch tests for Process ETW parser.

#include "process_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

TEST_F(ProcessParserTest, ParseProcessEvent_UnknownEventId_ReturnsInvalid) {
    std::vector<uint8_t> data(64, 0);
    
    EVENT_RECORD record = make_record(999, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_FALSE(result.valid);
}

TEST_F(ProcessParserTest, ParseProcessEvent_EventId1_DispatchesToStart) {
    auto data = build_process_start_data(100, 200, 1, "start.exe", L"start");
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::ProcessOp::Create));
}

TEST_F(ProcessParserTest, ParseProcessEvent_EventId2_DispatchesToStop) {
    auto data = build_process_stop_data(300);
    
    EVENT_RECORD record = make_record(ids::process::STOP, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::ProcessOp::Terminate));
    EXPECT_EQ(result.payload.process.pid, 300u);
}

TEST_F(ProcessParserTest, ParseProcessEvent_EventId5_DispatchesToImageLoad) {
    auto data = build_image_load_data(400);
    
    EVENT_RECORD record = make_record(ids::process::IMAGE_LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::ProcessOp::LoadLibrary));
    EXPECT_EQ(result.payload.process.pid, 400u);
}

TEST_F(ProcessParserTest, ParseProcessStop_ValidEvent_ExtractsPID) {
    auto data = build_process_stop_data(9876);
    
    EVENT_RECORD record = make_record(ids::process::STOP, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::Process);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::ProcessOp::Terminate));
    EXPECT_EQ(result.payload.process.pid, 9876u);
    EXPECT_EQ(result.payload.process.parent_pid, 0u);
}

TEST_F(ProcessParserTest, ParseImageLoad_ValidEvent_ExtractsPID) {
    auto data = build_image_load_data(5432);
    
    EVENT_RECORD record = make_record(ids::process::IMAGE_LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::Process);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::ProcessOp::LoadLibrary));
    EXPECT_EQ(result.payload.process.pid, 5432u);
}

TEST_F(ProcessParserTest, ParseImageLoad_32bit_CorrectPointerHandling) {
    auto data = build_image_load_data(7890, false);
    
    EVENT_RECORD record = make_record(ids::process::IMAGE_LOAD, false);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.process.pid, 7890u);
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(ProcessParserDispatchTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
