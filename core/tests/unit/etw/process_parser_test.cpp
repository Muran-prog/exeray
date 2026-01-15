/// @file process_parser_test.cpp
/// @brief Unit tests for Microsoft-Windows-Kernel-Process ETW parser.

#include <gtest/gtest.h>

#ifdef _WIN32

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include "exeray/arena.hpp"
#include "exeray/etw/event_ids.hpp"
#include "exeray/etw/parser.hpp"
#include "exeray/event/string_pool.hpp"
#include "exeray/event/types.hpp"

namespace exeray::etw {
namespace {

// ============================================================================
// Test Fixture
// ============================================================================

class ProcessParserTest : public ::testing::Test {
protected:
    static constexpr std::size_t kArenaSize = 1024 * 1024;  // 1MB
    
    void SetUp() override {
        arena_ = std::make_unique<Arena>(kArenaSize);
        strings_ = std::make_unique<event::StringPool>(*arena_);
    }

    /// Create a minimal valid EVENT_RECORD
    EVENT_RECORD make_record(uint16_t event_id, bool is64bit = true) {
        EVENT_RECORD record{};
        record.EventHeader.EventDescriptor.Id = event_id;
        if (is64bit) {
            record.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER;
        }
        record.EventHeader.ProcessId = 1234;
        record.EventHeader.TimeStamp.QuadPart = 0x123456789ABCDEF0LL;
        return record;
    }

    /// Build ProcessStart user data (Event ID 1)
    /// Layout:
    ///   UniqueProcessKey: PVOID (ptr_size)
    ///   ProcessId: UINT32
    ///   ParentId: UINT32
    ///   SessionId: UINT32
    ///   ExitStatus: INT32
    ///   DirectoryTableBase: PVOID (ptr_size)
    ///   Flags: UINT32
    ///   UserSID: variable (8 + 4*SubAuthorityCount)
    ///   ImageFileName: ANSI null-terminated
    ///   CommandLine: Unicode null-terminated
    std::vector<uint8_t> build_process_start_data(
        uint32_t pid,
        uint32_t parent_pid,
        uint8_t sub_authority_count,
        const std::string& image_name,
        const std::wstring& command_line,
        bool is64bit = true
    ) {
        const size_t ptr_size = is64bit ? 8 : 4;
        
        // Calculate SID size: 8 bytes header + 4 bytes per SubAuthority
        const size_t sid_size = 8 + 4 * sub_authority_count;
        
        // Total size
        size_t total_size = ptr_size                   // UniqueProcessKey
                          + sizeof(uint32_t)           // ProcessId
                          + sizeof(uint32_t)           // ParentId
                          + sizeof(uint32_t)           // SessionId
                          + sizeof(int32_t)            // ExitStatus
                          + ptr_size                   // DirectoryTableBase
                          + sizeof(uint32_t)           // Flags
                          + sid_size                   // SID
                          + image_name.size() + 1      // ImageFileName + null
                          + (command_line.size() + 1) * sizeof(wchar_t);  // CommandLine + null
        
        std::vector<uint8_t> buffer(total_size, 0);
        size_t offset = 0;
        
        // UniqueProcessKey (skip)
        offset += ptr_size;
        
        // ProcessId
        std::memcpy(buffer.data() + offset, &pid, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        
        // ParentId
        std::memcpy(buffer.data() + offset, &parent_pid, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        
        // SessionId
        uint32_t session_id = 1;
        std::memcpy(buffer.data() + offset, &session_id, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        
        // ExitStatus
        offset += sizeof(int32_t);
        
        // DirectoryTableBase (skip)
        offset += ptr_size;
        
        // Flags
        offset += sizeof(uint32_t);
        
        // SID: Revision(1), SubAuthorityCount(1), Authority(6), SubAuthorities(4*count)
        buffer[offset] = 1;  // Revision
        buffer[offset + 1] = sub_authority_count;
        // Authority bytes: 0,0,0,0,0,5 (NT AUTHORITY)
        buffer[offset + 7] = 5;
        offset += sid_size;
        
        // ImageFileName (ANSI null-terminated)
        std::memcpy(buffer.data() + offset, image_name.c_str(), image_name.size() + 1);
        offset += image_name.size() + 1;
        
        // CommandLine (Unicode null-terminated)
        std::memcpy(buffer.data() + offset, command_line.c_str(), 
                    (command_line.size() + 1) * sizeof(wchar_t));
        
        return buffer;
    }

    /// Build ProcessStop user data (Event ID 2)
    /// Layout:
    ///   UniqueProcessKey: PVOID
    ///   ProcessId: UINT32
    ///   ParentId: UINT32  
    ///   SessionId: UINT32
    ///   ExitStatus: INT32
    std::vector<uint8_t> build_process_stop_data(uint32_t pid, bool is64bit = true) {
        const size_t ptr_size = is64bit ? 8 : 4;
        size_t total_size = ptr_size + 4 * sizeof(uint32_t);
        
        std::vector<uint8_t> buffer(total_size, 0);
        size_t offset = ptr_size;  // Skip UniqueProcessKey
        
        std::memcpy(buffer.data() + offset, &pid, sizeof(uint32_t));
        
        return buffer;
    }

    /// Build ImageLoad user data (Event ID 5)
    /// Layout:
    ///   ImageBase: PVOID
    ///   ImageSize: PVOID
    ///   ProcessId: UINT32
    ///   ...rest is optional
    std::vector<uint8_t> build_image_load_data(uint32_t pid, bool is64bit = true) {
        const size_t ptr_size = is64bit ? 8 : 4;
        size_t total_size = ptr_size * 2 + sizeof(uint32_t) * 4;  // Enough for minimum
        
        std::vector<uint8_t> buffer(total_size, 0);
        size_t offset = ptr_size * 2;  // Skip ImageBase and ImageSize
        
        std::memcpy(buffer.data() + offset, &pid, sizeof(uint32_t));
        
        return buffer;
    }

    std::unique_ptr<Arena> arena_;
    std::unique_ptr<event::StringPool> strings_;
};

// ============================================================================
// 1. Basic Event Parsing
// ============================================================================

TEST_F(ProcessParserTest, ParseProcessStart_ValidEvent_ExtractsAllFields) {
    auto data = build_process_start_data(
        1234,       // PID
        5678,       // ParentPID
        2,          // SubAuthorityCount
        "notepad.exe",
        L"notepad.exe C:\\test.txt"
    );
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::Process);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::ProcessOp::Create));
    EXPECT_EQ(result.payload.process.pid, 1234u);
    EXPECT_EQ(result.payload.process.parent_pid, 5678u);
    EXPECT_NE(result.payload.process.image_path, event::INVALID_STRING);
    EXPECT_NE(result.payload.process.command_line, event::INVALID_STRING);
    
    // Verify interned strings
    auto image_path = strings_->get(result.payload.process.image_path);
    auto cmd_line = strings_->get(result.payload.process.command_line);
    EXPECT_EQ(image_path, "notepad.exe");
    EXPECT_EQ(cmd_line, "notepad.exe C:\\test.txt");
}

TEST_F(ProcessParserTest, ParseProcessStart_64bit_CorrectPointerHandling) {
    auto data = build_process_start_data(
        4321, 8765, 1, "test64.exe", L"test64", true /* is64bit */
    );
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER;
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.process.pid, 4321u);
    EXPECT_EQ(result.payload.process.parent_pid, 8765u);
}

TEST_F(ProcessParserTest, ParseProcessStart_32bit_CorrectPointerHandling) {
    auto data = build_process_start_data(
        1111, 2222, 1, "test32.exe", L"test32", false /* is32bit */
    );
    
    EVENT_RECORD record = make_record(ids::process::START, false);
    record.EventHeader.Flags = 0;  // No 64-bit flag
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.process.pid, 1111u);
    EXPECT_EQ(result.payload.process.parent_pid, 2222u);
}

// ============================================================================
// 2. Null and Invalid Input
// ============================================================================

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
    std::vector<uint8_t> data(20, 0);  // Less than 24 bytes minimum
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    EXPECT_FALSE(result.valid);
}

TEST_F(ProcessParserTest, ParseProcessStop_InsufficientLength_ReturnsInvalid) {
    std::vector<uint8_t> data(12, 0);  // Less than 16 bytes minimum
    
    EVENT_RECORD record = make_record(ids::process::STOP, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    EXPECT_FALSE(result.valid);
}

// ============================================================================
// 3. SID Parsing Edge Cases
// ============================================================================

TEST_F(ProcessParserTest, ParseProcessStart_LargeSID_SkipsCorrectly) {
    // SubAuthorityCount = 15 (max), SID = 8 + 60 = 68 bytes
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
    // SubAuthorityCount = 0, SID = 8 bytes only
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
    // Build data normally but then corrupt the SID SubAuthorityCount
    auto data = build_process_start_data(
        7777, 6666, 1, "test.exe", L"test"
    );
    
    // Set SubAuthorityCount to 255 (way beyond buffer)
    const size_t ptr_size = 8;
    size_t sid_offset = ptr_size + 4*sizeof(uint32_t) + ptr_size + sizeof(uint32_t);
    data[sid_offset + 1] = 255;  // Corrupt SubAuthorityCount
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    // Should not crash - parser should detect overread
    auto result = parse_process_event(&record, strings_.get());
    
    // May be valid=false or may parse with INVALID_STRING - just no crash
    // The key test is that we don't crash or read beyond buffer
    SUCCEED();  // If we got here without ASAN/MSAN errors, we passed
}

// ============================================================================
// 4. String Parsing
// ============================================================================

TEST_F(ProcessParserTest, ParseProcessStart_EmptyImageFileName_ReturnsInvalidString) {
    // Empty ImageFileName (just null terminator)
    auto data = build_process_start_data(1234, 5678, 1, "", L"cmd");
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.process.image_path, event::INVALID_STRING);
}

TEST_F(ProcessParserTest, ParseProcessStart_EmptyCommandLine_ReturnsInvalidString) {
    // Empty CommandLine
    auto data = build_process_start_data(1234, 5678, 1, "app.exe", L"");
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.process.command_line, event::INVALID_STRING);
}

TEST_F(ProcessParserTest, ParseProcessStart_LongImageFileName_FullExtraction) {
    // 255-character path
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
    // 4KB command line
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
    EXPECT_GE(cmd_line.size(), 4000u);  // Should be close to 4KB
}

TEST_F(ProcessParserTest, ParseProcessStart_NonAsciiCommandLine_UTF16Preserved) {
    // Unicode command line with Cyrillic and emoji
    std::wstring unicode_cmd = L"powershell.exe -c \"Привет мир 🎉\"";
    
    auto data = build_process_start_data(1234, 5678, 1, "powershell.exe", unicode_cmd);
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    auto cmd_line = strings_->get(result.payload.process.command_line);
    
    // Should contain the Cyrillic characters (as UTF-8)
    EXPECT_NE(cmd_line.find("powershell.exe"), std::string::npos);
    // UTF-8 encoding should preserve the content
    EXPECT_GT(cmd_line.size(), 20u);
}

// ============================================================================
// 5. Boundary Conditions
// ============================================================================

TEST_F(ProcessParserTest, ParseProcessStart_ExactMinimumLength_Succeeds) {
    // Build minimal valid data with empty strings
    const size_t ptr_size = 8;
    const size_t sid_size = 8;  // SubAuthorityCount = 0
    const size_t min_size = ptr_size      // UniqueProcessKey
                          + 4*sizeof(uint32_t)  // PIDs, SessionId, ExitStatus
                          + ptr_size      // DirectoryTableBase
                          + sizeof(uint32_t)    // Flags
                          + sid_size      // SID
                          + 1             // null terminator for ImageFileName
                          + sizeof(wchar_t);    // null terminator for CommandLine
    
    std::vector<uint8_t> data(min_size, 0);
    
    // Set ProcessId at correct offset
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
    // Create data where string ends exactly at buffer boundary
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
    // Build normal data first
    auto data = build_process_start_data(1234, 5678, 1, "test.exe", L"test");
    
    // Truncate before the null terminators - find ImageFileName position
    const size_t ptr_size = 8;
    const size_t sid_size = 8 + 4;  // SubAuthorityCount = 1
    size_t image_offset = ptr_size + 4*sizeof(uint32_t) + ptr_size + sizeof(uint32_t) + sid_size;
    
    // Truncate after "test." but before null and rest
    size_t truncate_at = image_offset + 5;
    data.resize(truncate_at);
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    // Should handle gracefully - either valid with partial string or invalid
    // Key is no crash or buffer overread
    SUCCEED();
}

// ============================================================================
// 6. Event ID Dispatch
// ============================================================================

TEST_F(ProcessParserTest, ParseProcessEvent_UnknownEventId_ReturnsInvalid) {
    std::vector<uint8_t> data(64, 0);
    
    EVENT_RECORD record = make_record(999, true);  // Unknown ID
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    // Unknown event should return invalid (no TDH available in tests)
    EXPECT_FALSE(result.valid);
}

TEST_F(ProcessParserTest, ParseProcessEvent_EventId1_DispatchesToStart) {
    auto data = build_process_start_data(100, 200, 1, "start.exe", L"start");
    
    EVENT_RECORD record = make_record(ids::process::START, true);  // ID = 1
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::ProcessOp::Create));
}

TEST_F(ProcessParserTest, ParseProcessEvent_EventId2_DispatchesToStop) {
    auto data = build_process_stop_data(300);
    
    EVENT_RECORD record = make_record(ids::process::STOP, true);  // ID = 2
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::ProcessOp::Terminate));
    EXPECT_EQ(result.payload.process.pid, 300u);
}

TEST_F(ProcessParserTest, ParseProcessEvent_EventId5_DispatchesToImageLoad) {
    auto data = build_image_load_data(400);
    
    EVENT_RECORD record = make_record(ids::process::IMAGE_LOAD, true);  // ID = 5
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::ProcessOp::LoadLibrary));
    EXPECT_EQ(result.payload.process.pid, 400u);
}

// ============================================================================
// 7. StringPool Integration
// ============================================================================

TEST_F(ProcessParserTest, ParseProcessStart_NullStringPool_NoIntern) {
    auto data = build_process_start_data(1234, 5678, 1, "test.exe", L"test");
    
    EVENT_RECORD record = make_record(ids::process::START, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    // Pass nullptr for StringPool
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
    
    // Verify strings are actually retrievable
    auto image = strings_->get(result.payload.process.image_path);
    auto cmdline = strings_->get(result.payload.process.command_line);
    
    EXPECT_EQ(image, "interned.exe");
    EXPECT_EQ(cmdline, "-arg1 --arg2");
}

// ============================================================================
// Additional Edge Cases
// ============================================================================

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
    EXPECT_EQ(result.payload.process.parent_pid, 0u);  // Not available in stop event
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
    auto data = build_image_load_data(7890, false /* is32bit */);
    
    EVENT_RECORD record = make_record(ids::process::IMAGE_LOAD, false);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.process.pid, 7890u);
}

TEST_F(ProcessParserTest, ParseImageLoad_InsufficientLength_ReturnsInvalid) {
    std::vector<uint8_t> data(16, 0);  // Less than 20 bytes minimum
    
    EVENT_RECORD record = make_record(ids::process::IMAGE_LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());
    
    auto result = parse_process_event(&record, strings_.get());
    EXPECT_FALSE(result.valid);
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

// Empty test on non-Windows to allow compilation
TEST(ProcessParserTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
