/// @file file_parser_test.cpp
/// @brief Unit tests for Microsoft-Windows-Kernel-File ETW parser.

#include <gtest/gtest.h>

#ifdef _WIN32

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
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

class FileParserTest : public ::testing::Test {
protected:
    static constexpr std::size_t kArenaSize = 1024 * 1024;  // 1MB

    void SetUp() override {
        arena_ = std::make_unique<Arena>(kArenaSize);
        strings_ = std::make_unique<event::StringPool>(*arena_);
    }

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

    /// Build FileCreate user data (Event ID 10).
    /// Layout: Irp(PTR), FileObject(PTR), TTID(4), CreateOptions(4),
    ///         FileAttributes(4), ShareAccess(4), OpenPath(wchar_t[])
    std::vector<uint8_t> build_file_create_data(
        const std::wstring& path,
        uint32_t attributes = 0,
        bool is64bit = true
    ) {
        const size_t ptr_size = is64bit ? 8 : 4;
        // Irp + FileObject + TTID + CreateOptions + FileAttributes + ShareAccess + path
        size_t total_size = ptr_size * 2 + sizeof(uint32_t) * 4 +
                            (path.size() + 1) * sizeof(wchar_t);

        std::vector<uint8_t> buffer(total_size, 0);
        size_t offset = 0;

        // Skip Irp, FileObject
        offset += ptr_size * 2;
        // Skip TTID
        offset += sizeof(uint32_t);
        // Skip CreateOptions
        offset += sizeof(uint32_t);
        // FileAttributes
        std::memcpy(buffer.data() + offset, &attributes, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        // Skip ShareAccess
        offset += sizeof(uint32_t);
        // OpenPath
        std::memcpy(buffer.data() + offset, path.c_str(),
                    (path.size() + 1) * sizeof(wchar_t));

        return buffer;
    }

    /// Build FileRead/FileWrite user data (Event ID 14/15).
    /// Layout: Offset(8), Irp(PTR), FileObject(PTR), FileKey(PTR),
    ///         TTID(4), IoSize(4), IoFlags(4)
    std::vector<uint8_t> build_file_read_write_data(
        uint32_t io_size,
        bool is64bit = true
    ) {
        const size_t ptr_size = is64bit ? 8 : 4;
        // Offset(8) + Irp + FileObject + FileKey + TTID + IoSize + IoFlags
        size_t total_size = 8 + ptr_size * 3 + sizeof(uint32_t) * 3;

        std::vector<uint8_t> buffer(total_size, 0);
        // Skip Offset(8) + Irp + FileObject + FileKey + TTID
        size_t offset = 8 + ptr_size * 3 + sizeof(uint32_t);
        // IoSize
        std::memcpy(buffer.data() + offset, &io_size, sizeof(uint32_t));

        return buffer;
    }

    std::unique_ptr<Arena> arena_;
    std::unique_ptr<event::StringPool> strings_;
};

// =============================================================================
// 1. Create Operations
// =============================================================================

TEST_F(FileParserTest, ParseFileCreate_ValidEvent_ExtractsPath) {
    auto data = build_file_create_data(L"C:\\Windows\\System32\\notepad.exe");

    EVENT_RECORD record = make_record(ids::file::CREATE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::FileSystem);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::FileOp::Create));
    EXPECT_NE(result.payload.file.path, event::INVALID_STRING);

    auto path = strings_->get(result.payload.file.path);
    EXPECT_EQ(path, "C:\\Windows\\System32\\notepad.exe");
}

TEST_F(FileParserTest, ParseFileCreate_ExtractsFileAttributes) {
    constexpr uint32_t HIDDEN_READONLY = 0x03;  // FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN
    auto data = build_file_create_data(L"C:\\test.txt", HIDDEN_READONLY);

    EVENT_RECORD record = make_record(ids::file::CREATE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.file.attributes, HIDDEN_READONLY);
}

TEST_F(FileParserTest, ParseFileCreate_LongPath_MaxPath32K) {
    // Build a long path (limited by USHORT UserDataLength max 65535)
    // Header is ~32 bytes, so max path is ~32750 wchars
    // Use 16000 chars as a safe long path test
    std::wstring long_path = L"\\\\?\\C:\\";
    long_path.append(16000 - long_path.size(), L'a');

    auto data = build_file_create_data(long_path);

    EVENT_RECORD record = make_record(ids::file::CREATE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_NE(result.payload.file.path, event::INVALID_STRING);

    auto path = strings_->get(result.payload.file.path);
    EXPECT_EQ(path.size(), 16000u);
}

// =============================================================================
// 2. Read/Write Operations
// =============================================================================

TEST_F(FileParserTest, ParseFileRead_ExtractsIoSize) {
    auto data = build_file_read_write_data(65536);

    EVENT_RECORD record = make_record(ids::file::READ, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::FileOp::Read));
    EXPECT_EQ(result.payload.file.size, 65536u);
}

TEST_F(FileParserTest, ParseFileWrite_ExtractsIoSize) {
    auto data = build_file_read_write_data(65536);

    EVENT_RECORD record = make_record(ids::file::WRITE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::FileOp::Write));
    EXPECT_EQ(result.payload.file.size, 65536u);
}

TEST_F(FileParserTest, ParseFileRead_ZeroIoSize_Valid) {
    auto data = build_file_read_write_data(0);

    EVENT_RECORD record = make_record(ids::file::READ, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.file.size, 0u);
}

TEST_F(FileParserTest, ParseFileRead_MaxIoSize_NoOverflow) {
    auto data = build_file_read_write_data(0xFFFFFFFF);

    EVENT_RECORD record = make_record(ids::file::READ, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.file.size, 0xFFFFFFFFu);
}

// =============================================================================
// 3. Pointer Size Handling
// =============================================================================

TEST_F(FileParserTest, ParseFileCreate_64bit_CorrectOffsets) {
    // 64-bit: Irp(8), FileObject(8), FileKey(8)
    auto data = build_file_create_data(L"C:\\test64.txt", 0, true);

    EVENT_RECORD record = make_record(ids::file::CREATE, true);
    record.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER;
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    auto path = strings_->get(result.payload.file.path);
    EXPECT_EQ(path, "C:\\test64.txt");
}

TEST_F(FileParserTest, ParseFileCreate_32bit_CorrectOffsets) {
    // 32-bit: Irp(4), FileObject(4), FileKey(4)
    auto data = build_file_create_data(L"C:\\test32.txt", 0, false);

    EVENT_RECORD record = make_record(ids::file::CREATE, false);
    record.EventHeader.Flags = 0;
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    auto path = strings_->get(result.payload.file.path);
    EXPECT_EQ(path, "C:\\test32.txt");
}

TEST_F(FileParserTest, ParseFileRead_64bit_Offset8Bytes) {
    // Offset field is always UINT64 (8 bytes) regardless of pointer size
    auto data = build_file_read_write_data(4096, true);

    EVENT_RECORD record = make_record(ids::file::READ, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.file.size, 4096u);
}

// =============================================================================
// 4. Invalid Input
// =============================================================================

TEST_F(FileParserTest, ParseFileEvent_NullRecord_ReturnsInvalid) {
    auto result = parse_file_event(nullptr, strings_.get());
    EXPECT_FALSE(result.valid);
}

TEST_F(FileParserTest, ParseFileCreate_TruncatedUserData_ReturnsInvalid) {
    std::vector<uint8_t> data(15, 0);  // < 16 bytes minimum

    EVENT_RECORD record = make_record(ids::file::CREATE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_FALSE(result.valid);
}

TEST_F(FileParserTest, ParseFileRead_TruncatedUserData_ReturnsInvalid) {
    std::vector<uint8_t> data(23, 0);  // < 24 bytes minimum

    EVENT_RECORD record = make_record(ids::file::READ, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_FALSE(result.valid);
}

// =============================================================================
// 5. Payload Initialization
// =============================================================================

TEST_F(FileParserTest, ParseFileCreate_InitializesDefaultValues) {
    // Create a record with path only, no attributes
    auto data = build_file_create_data(L"C:\\default.txt", 0);

    EVENT_RECORD record = make_record(ids::file::CREATE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    // Default initialization: size = 0, attributes = 0 (from our build func)
    EXPECT_EQ(result.payload.file.size, 0u);
    EXPECT_EQ(result.payload.file.attributes, 0u);
}

// =============================================================================
// 6. Unicode Path Edge Cases
// =============================================================================

TEST_F(FileParserTest, ParseFileCreate_EmptyPath_ReturnsINVALID_STRING) {
    auto data = build_file_create_data(L"");

    EVENT_RECORD record = make_record(ids::file::CREATE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.file.path, event::INVALID_STRING);
}

TEST_F(FileParserTest, ParseFileCreate_PathWithNullChars_TruncatesAtFirst) {
    // Build path with embedded null: "C:\test" + NULL + "extra"
    std::wstring path_with_null = L"C:\\test";
    path_with_null += L'\0';
    path_with_null += L"extra";

    // Manually build the buffer to include embedded null
    const size_t ptr_size = 8;
    size_t total_size = ptr_size * 2 + sizeof(uint32_t) * 4 +
                        (path_with_null.size() + 1) * sizeof(wchar_t);
    std::vector<uint8_t> buffer(total_size, 0);

    size_t offset = ptr_size * 2 + sizeof(uint32_t) * 4;
    std::memcpy(buffer.data() + offset, path_with_null.data(),
                (path_with_null.size() + 1) * sizeof(wchar_t));

    EVENT_RECORD record = make_record(ids::file::CREATE, true);
    record.UserData = buffer.data();
    record.UserDataLength = static_cast<USHORT>(buffer.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    auto path = strings_->get(result.payload.file.path);
    EXPECT_EQ(path, "C:\\test");  // Truncated at first null
}

TEST_F(FileParserTest, ParseFileCreate_DeviceNtPath_ExtractsCorrectly) {
    auto data = build_file_create_data(L"\\Device\\HarddiskVolume1\\Windows\\System32\\cmd.exe");

    EVENT_RECORD record = make_record(ids::file::CREATE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_file_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    auto path = strings_->get(result.payload.file.path);
    EXPECT_EQ(path, "\\Device\\HarddiskVolume1\\Windows\\System32\\cmd.exe");
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(FileParserTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
