/// @file thread_parser_test.cpp
/// @brief Unit tests for Thread ETW parser.

#include "thread_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

// =============================================================================
// 1. Basic Thread Events
// =============================================================================

TEST_F(ThreadParserTest, ParseThreadStart_ExtractsProcessIdThreadId) {
    uint32_t process_id = 4567;
    uint32_t thread_id = 8901;

    auto data = build_thread_start_data(process_id, thread_id, 0x7FFE0000, true);

    EVENT_RECORD record = make_record(ids::thread::START, true, 4567);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_thread_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::Thread);
    EXPECT_EQ(result.payload.thread.process_id, process_id);
    EXPECT_EQ(result.payload.thread.thread_id, thread_id);
}

TEST_F(ThreadParserTest, ParseThreadStart_ExtractsWin32StartAddr) {
    uint64_t start_address = 0x00007FFE12340000ULL;

    auto data = build_thread_start_data(1234, 5678, start_address, true);

    EVENT_RECORD record = make_record(ids::thread::START, true, 1234);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_thread_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.thread.start_address, start_address);
}

TEST_F(ThreadParserTest, ParseThreadEnd_ExtractsBasicInfo) {
    uint32_t process_id = 1111;
    uint32_t thread_id = 2222;

    auto data = build_thread_end_data(process_id, thread_id);

    EVENT_RECORD record = make_record(ids::thread::END, true, 1111);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_thread_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::Thread);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::ThreadOp::End));
    EXPECT_EQ(result.payload.thread.process_id, process_id);
    EXPECT_EQ(result.payload.thread.thread_id, thread_id);
    EXPECT_EQ(result.payload.thread.start_address, 0u);
}

// =============================================================================
// 2. Remote Thread Injection Detection (CRITICAL)
// =============================================================================

TEST_F(ThreadParserTest, ParseThreadStart_SameProcess_NotRemote) {
    uint32_t pid = 5000;

    auto data = build_thread_start_data(pid, 100, 0x400000, true);

    EVENT_RECORD record = make_record(ids::thread::START, true, pid);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_thread_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.thread.is_remote, 0u);
    EXPECT_NE(result.status, event::Status::Suspicious);
}

TEST_F(ThreadParserTest, ParseThreadStart_CrossProcess_IsRemote) {
    uint32_t creator_pid = 1000;
    uint32_t target_pid = 2000;

    auto data = build_thread_start_data(target_pid, 100, 0x400000, true);

    EVENT_RECORD record = make_record(ids::thread::START, true, creator_pid);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_thread_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.thread.is_remote, 1u);
    EXPECT_EQ(result.status, event::Status::Suspicious);
}

TEST_F(ThreadParserTest, ParseThreadStart_SystemProcess_NotRemote) {
    uint32_t system_pid = 4;
    uint32_t target_pid = 2000;

    auto data = build_thread_start_data(target_pid, 100, 0x400000, true);

    EVENT_RECORD record = make_record(ids::thread::START, true, system_pid);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_thread_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.thread.is_remote, 0u);
}

TEST_F(ThreadParserTest, ParseThreadStart_IdleProcess_NotRemote) {
    uint32_t idle_pid = 0;
    uint32_t target_pid = 2000;

    auto data = build_thread_start_data(target_pid, 100, 0x400000, true);

    EVENT_RECORD record = make_record(ids::thread::START, true, idle_pid);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_thread_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.thread.is_remote, 0u);
}

TEST_F(ThreadParserTest, ParseThreadStart_TargetSystemProcess_NotRemote) {
    uint32_t creator_pid = 1000;
    uint32_t system_pid = 4;

    auto data = build_thread_start_data(system_pid, 100, 0x400000, true);

    EVENT_RECORD record = make_record(ids::thread::START, true, creator_pid);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_thread_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.thread.is_remote, 0u);
}

// =============================================================================
// 3. DCStart/DCEnd Events
// =============================================================================

TEST_F(ThreadParserTest, ParseThreadDCStart_NotSuspicious) {
    uint32_t creator_pid = 1000;
    uint32_t target_pid = 2000;

    auto data = build_thread_start_data(target_pid, 100, 0x400000, true);

    EVENT_RECORD record = make_record(ids::thread::DC_START, true, creator_pid);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_thread_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::ThreadOp::DCStart));
    EXPECT_EQ(result.payload.thread.is_remote, 0u);
    EXPECT_EQ(result.status, event::Status::Success);
}

TEST_F(ThreadParserTest, ParseThreadDCEnd_BasicParsing) {
    uint32_t process_id = 3333;
    uint32_t thread_id = 4444;

    auto data = build_thread_end_data(process_id, thread_id);

    EVENT_RECORD record = make_record(ids::thread::DC_END, true, 3333);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_thread_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::ThreadOp::DCEnd));
    EXPECT_EQ(result.payload.thread.process_id, process_id);
    EXPECT_EQ(result.payload.thread.thread_id, thread_id);
}

// =============================================================================
// 4. Pointer Size Handling
// =============================================================================

TEST_F(ThreadParserTest, ParseThreadStart_64bit_StartAddressOffset) {
    uint64_t start_address = 0xDEADBEEFCAFEBABEULL;

    auto data = build_thread_start_data(1234, 5678, start_address, true);

    EVENT_RECORD record = make_record(ids::thread::START, true, 1234);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_thread_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.thread.start_address, start_address);
}

TEST_F(ThreadParserTest, ParseThreadStart_32bit_StartAddressOffset) {
    uint32_t start_address = 0x77E00000;

    auto data = build_thread_start_data(1234, 5678, start_address, false);

    EVENT_RECORD record = make_record(ids::thread::START, false, 1234);
    record.EventHeader.Flags = 0;  // Clear 64-bit flag
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_thread_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.thread.start_address, static_cast<uint64_t>(start_address));
}

// =============================================================================
// 5. Invalid Input
// =============================================================================

TEST_F(ThreadParserTest, ParseThreadEvent_NullRecord_ReturnsInvalid) {
    auto result = parse_thread_event(nullptr, strings_.get());

    EXPECT_FALSE(result.valid);
}

TEST_F(ThreadParserTest, ParseThreadStart_InsufficientLength_ReturnsInvalid) {
    std::vector<uint8_t> data(7, 0);  // Less than 8 bytes minimum

    EVENT_RECORD record = make_record(ids::thread::START, true, 1234);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_thread_event(&record, strings_.get());

    EXPECT_FALSE(result.valid);
}

// =============================================================================
// 6. Edge Cases
// =============================================================================

TEST_F(ThreadParserTest, ParseThreadStart_StartAddressZero_Valid) {
    uint64_t start_address = 0;

    auto data = build_thread_start_data(1234, 5678, start_address, true);

    EVENT_RECORD record = make_record(ids::thread::START, true, 1234);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_thread_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.thread.start_address, 0u);
}

TEST_F(ThreadParserTest, ParseThreadStart_MaxStartAddress_NoOverflow) {
    uint64_t start_address = 0xFFFFFFFFFFFFFFFFULL;

    auto data = build_thread_start_data(1234, 5678, start_address, true);

    EVENT_RECORD record = make_record(ids::thread::START, true, 1234);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_thread_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.thread.start_address, start_address);
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(ThreadParserTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
