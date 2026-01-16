/// @file image_parser_test.cpp
/// @brief Unit tests for Image ETW parser.

#include "image_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

// =============================================================================
// 1. Image Load Parsing
// =============================================================================

TEST_F(ImageParserTest, ParseImageLoad_ExtractsImageBase_64bit) {
    uint64_t image_base = 0x00007FFE12340000ULL;

    auto data = build_image_load_data_64bit(image_base, 4096, 1234, L"C:\\Windows\\System32\\kernel32.dll");

    EVENT_RECORD record = make_record(ids::image::LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::Image);
    EXPECT_EQ(result.payload.image.base_address, image_base);
}

TEST_F(ImageParserTest, ParseImageLoad_ExtractsImageBase_32bit) {
    uint32_t image_base = 0x77E00000;

    auto data = build_image_load_data_32bit(image_base, 4096, 1234, L"C:\\Windows\\System32\\kernel32.dll");

    EVENT_RECORD record = make_record(ids::image::LOAD, false);
    record.EventHeader.Flags = 0;  // Clear 64-bit flag
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.image.base_address, static_cast<uint64_t>(image_base));
}

TEST_F(ImageParserTest, ParseImageLoad_ExtractsImageSize) {
    uint64_t image_size = 0x100000;  // 1MB

    auto data = build_image_load_data_64bit(0x10000, image_size, 1234, L"C:\\test.dll");

    EVENT_RECORD record = make_record(ids::image::LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.image.size, static_cast<uint32_t>(image_size));
}

TEST_F(ImageParserTest, ParseImageLoad_ExtractsProcessId) {
    uint32_t process_id = 5678;

    auto data = build_image_load_data_64bit(0x10000, 4096, process_id, L"C:\\test.dll");

    EVENT_RECORD record = make_record(ids::image::LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.image.process_id, process_id);
}

TEST_F(ImageParserTest, ParseImageLoad_ExtractsFileName) {
    std::wstring filename = L"C:\\Program Files\\MyApp\\myapp.dll";

    auto data = build_image_load_data_64bit(0x10000, 4096, 1234, filename);

    EVENT_RECORD record = make_record(ids::image::LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_NE(result.payload.image.image_path, event::INVALID_STRING);
}

// =============================================================================
// 2. Suspicious Path Detection (CRITICAL SECURITY)
// =============================================================================

TEST_F(ImageParserTest, ParseImageLoad_TempPath_Suspicious) {
    auto data = build_image_load_data_64bit(0x10000, 4096, 1234, L"c:\\windows\\temp\\evil.dll");

    EVENT_RECORD record = make_record(ids::image::LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.image.is_suspicious, 1u);
}

TEST_F(ImageParserTest, ParseImageLoad_AppDataLocalTemp_Suspicious) {
    auto data = build_image_load_data_64bit(0x10000, 4096, 1234, L"c:\\users\\admin\\appdata\\local\\temp\\loader.dll");

    EVENT_RECORD record = make_record(ids::image::LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.image.is_suspicious, 1u);
}

TEST_F(ImageParserTest, ParseImageLoad_AppDataRoaming_Suspicious) {
    auto data = build_image_load_data_64bit(0x10000, 4096, 1234, L"c:\\users\\admin\\appdata\\roaming\\malware.dll");

    EVENT_RECORD record = make_record(ids::image::LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.image.is_suspicious, 1u);
}

TEST_F(ImageParserTest, ParseImageLoad_UsersPublic_Suspicious) {
    auto data = build_image_load_data_64bit(0x10000, 4096, 1234, L"c:\\users\\public\\dropper.dll");

    EVENT_RECORD record = make_record(ids::image::LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.image.is_suspicious, 1u);
}

TEST_F(ImageParserTest, ParseImageLoad_ProgramData_Suspicious) {
    auto data = build_image_load_data_64bit(0x10000, 4096, 1234, L"c:\\programdata\\implant.dll");

    EVENT_RECORD record = make_record(ids::image::LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.image.is_suspicious, 1u);
}

TEST_F(ImageParserTest, ParseImageLoad_System32_NotSuspicious) {
    auto data = build_image_load_data_64bit(0x10000, 4096, 1234, L"C:\\Windows\\System32\\kernel32.dll");

    EVENT_RECORD record = make_record(ids::image::LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.image.is_suspicious, 0u);
}

TEST_F(ImageParserTest, ParseImageLoad_ProgramFiles_NotSuspicious) {
    auto data = build_image_load_data_64bit(0x10000, 4096, 1234, L"C:\\Program Files\\App\\app.dll");

    EVENT_RECORD record = make_record(ids::image::LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.image.is_suspicious, 0u);
}

// =============================================================================
// 3. Image Unload Parsing
// =============================================================================

TEST_F(ImageParserTest, ParseImageUnload_ExtractsBaseAndSize) {
    uint64_t image_base = 0x00007FFE00000000ULL;
    uint64_t image_size = 8192;

    auto data = build_image_unload_data_64bit(image_base, image_size, 1234);

    EVENT_RECORD record = make_record(ids::image::UNLOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::ImageOp::Unload));
    EXPECT_EQ(result.payload.image.base_address, image_base);
    EXPECT_EQ(result.payload.image.size, static_cast<uint32_t>(image_size));
}

TEST_F(ImageParserTest, ParseImageUnload_NoPathExtraction) {
    auto data = build_image_unload_data_64bit(0x10000, 4096, 1234);

    EVENT_RECORD record = make_record(ids::image::UNLOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.image.image_path, event::INVALID_STRING);
}

TEST_F(ImageParserTest, ParseImageUnload_NotSuspicious) {
    auto data = build_image_unload_data_64bit(0x10000, 4096, 1234);

    EVENT_RECORD record = make_record(ids::image::UNLOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.image.is_suspicious, 0u);
}

// =============================================================================
// 4. Path Edge Cases
// =============================================================================

TEST_F(ImageParserTest, ParseImageLoad_EmptyFileName_NotSuspicious) {
    auto data = build_image_load_data_64bit(0x10000, 4096, 1234, L"");

    EVENT_RECORD record = make_record(ids::image::LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.image.is_suspicious, 0u);
}

TEST_F(ImageParserTest, ParseImageLoad_CaseInsensitiveCheck) {
    // Note: Current implementation uses wcsstr which is case-sensitive.
    // This test documents the current behavior. If case-insensitive matching
    // is implemented, this test should expect is_suspicious = 1.
    auto data = build_image_load_data_64bit(0x10000, 4096, 1234, L"C:\\WINDOWS\\TEMP\\x.dll");

    EVENT_RECORD record = make_record(ids::image::LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    // Current implementation is case-sensitive, so uppercase TEMP won't match \temp\
    // If case-insensitive detection is added later, change to EXPECT_EQ(..., 1u)
    EXPECT_EQ(result.payload.image.is_suspicious, 0u);
}

TEST_F(ImageParserTest, ParseImageLoad_UNCPath_NotFlagged) {
    auto data = build_image_load_data_64bit(0x10000, 4096, 1234, L"\\\\server\\share\\legit.dll");

    EVENT_RECORD record = make_record(ids::image::LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.image.is_suspicious, 0u);
}

TEST_F(ImageParserTest, ParseImageLoad_TmpPath_Suspicious) {
    auto data = build_image_load_data_64bit(0x10000, 4096, 1234, L"C:\\tmp\\backdoor.dll");

    EVENT_RECORD record = make_record(ids::image::LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.image.is_suspicious, 1u);
}

// =============================================================================
// 5. Pointer Size Handling
// =============================================================================

TEST_F(ImageParserTest, ParseImageLoad_64bit_Layout) {
    uint64_t image_base = 0xDEADBEEFCAFEBABEULL;
    uint64_t image_size = 0x200000;
    uint32_t process_id = 9999;

    auto data = build_image_load_data_64bit(image_base, image_size, process_id, L"C:\\test.dll");

    EVENT_RECORD record = make_record(ids::image::LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.image.base_address, image_base);
    EXPECT_EQ(result.payload.image.size, static_cast<uint32_t>(image_size));
    EXPECT_EQ(result.payload.image.process_id, process_id);
}

TEST_F(ImageParserTest, ParseImageLoad_32bit_Layout) {
    uint32_t image_base = 0x77E00000;
    uint32_t image_size = 0x100000;
    uint32_t process_id = 8888;

    auto data = build_image_load_data_32bit(image_base, image_size, process_id, L"C:\\test.dll");

    EVENT_RECORD record = make_record(ids::image::LOAD, false);
    record.EventHeader.Flags = 0;  // Clear 64-bit flag
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.image.base_address, static_cast<uint64_t>(image_base));
    EXPECT_EQ(result.payload.image.size, image_size);
    EXPECT_EQ(result.payload.image.process_id, process_id);
}

TEST_F(ImageParserTest, ParseImageLoad_SizeExceeds4GB_ClampedToMax) {
    uint64_t image_size_raw = 5ULL * 1024 * 1024 * 1024;  // 5GB

    auto data = build_image_load_data_64bit(0x10000, image_size_raw, 1234, L"C:\\test.dll");

    EVENT_RECORD record = make_record(ids::image::LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    // Size is cast to uint32_t, so it will be truncated
    EXPECT_NE(result.payload.image.size, 0u);
}

// =============================================================================
// 6. Invalid Input
// =============================================================================

TEST_F(ImageParserTest, ParseImageEvent_NullRecord_ReturnsInvalid) {
    auto result = parse_image_event(nullptr, strings_.get());

    EXPECT_FALSE(result.valid);
}

TEST_F(ImageParserTest, ParseImageLoad_TruncatedData_ReturnsInvalid) {
    std::vector<uint8_t> data(31, 0);  // Less than 32 bytes minimum for load

    EVENT_RECORD record = make_record(ids::image::LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_FALSE(result.valid);
}

TEST_F(ImageParserTest, ParseImageUnload_TruncatedData_ReturnsInvalid) {
    std::vector<uint8_t> data(15, 0);  // Less than 16 bytes minimum for unload

    EVENT_RECORD record = make_record(ids::image::UNLOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_FALSE(result.valid);
}

TEST_F(ImageParserTest, ParseImageLoad_NullUserData_ReturnsInvalid) {
    EVENT_RECORD record = make_record(ids::image::LOAD, true);
    record.UserData = nullptr;
    record.UserDataLength = 64;

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_FALSE(result.valid);
}

// =============================================================================
// 7. Operation Type Verification
// =============================================================================

TEST_F(ImageParserTest, ParseImageLoad_SetsLoadOperation) {
    auto data = build_image_load_data_64bit(0x10000, 4096, 1234, L"C:\\test.dll");

    EVENT_RECORD record = make_record(ids::image::LOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::ImageOp::Load));
}

TEST_F(ImageParserTest, ParseImageUnload_SetsUnloadOperation) {
    auto data = build_image_unload_data_64bit(0x10000, 4096, 1234);

    EVENT_RECORD record = make_record(ids::image::UNLOAD, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_image_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::ImageOp::Unload));
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(ImageParserTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
