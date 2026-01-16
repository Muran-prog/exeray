/// @file memory_parser_test.cpp
/// @brief Unit tests for Memory ETW parser.

#include "memory_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

// =============================================================================
// 1. Virtual Alloc Parsing
// =============================================================================

TEST_F(MemoryParserTest, ParseVirtualAlloc_ExtractsBaseAddress) {
    uint64_t base_address = 0x00007FFE12340000ULL;

    auto data = build_memory_data_64bit(base_address, 4096, 1234, PAGE_READWRITE_VAL);

    EVENT_RECORD record = make_record(ids::memory::VIRTUAL_ALLOC, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_memory_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::Memory);
    EXPECT_EQ(result.payload.memory.base_address, base_address);
}

TEST_F(MemoryParserTest, ParseVirtualAlloc_ExtractsRegionSize) {
    uint64_t region_size = 65536;

    auto data = build_memory_data_64bit(0x10000, region_size, 1234, PAGE_READWRITE_VAL);

    EVENT_RECORD record = make_record(ids::memory::VIRTUAL_ALLOC, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_memory_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.memory.region_size, static_cast<uint32_t>(region_size));
}

TEST_F(MemoryParserTest, ParseVirtualAlloc_ExtractsProcessId) {
    uint32_t process_id = 5678;

    auto data = build_memory_data_64bit(0x10000, 4096, process_id, PAGE_READWRITE_VAL);

    EVENT_RECORD record = make_record(ids::memory::VIRTUAL_ALLOC, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_memory_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.memory.process_id, process_id);
    EXPECT_EQ(result.pid, process_id);
}

TEST_F(MemoryParserTest, ParseVirtualAlloc_ExtractsProtectionFlags) {
    uint32_t protection = PAGE_READWRITE_VAL;

    auto data = build_memory_data_64bit(0x10000, 4096, 1234, protection);

    EVENT_RECORD record = make_record(ids::memory::VIRTUAL_ALLOC, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_memory_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.memory.protection, protection);
}

// =============================================================================
// 2. RWX Detection (CRITICAL SECURITY)
// =============================================================================

TEST_F(MemoryParserTest, ParseVirtualAlloc_PAGE_EXECUTE_READWRITE_Suspicious) {
    auto data = build_memory_data_64bit(0x10000, 4096, 1234, PAGE_EXECUTE_READWRITE_VAL);

    EVENT_RECORD record = make_record(ids::memory::VIRTUAL_ALLOC, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_memory_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.memory.is_suspicious, 1u);
    EXPECT_EQ(result.status, event::Status::Suspicious);
}

TEST_F(MemoryParserTest, ParseVirtualAlloc_PAGE_EXECUTE_WRITECOPY_Suspicious) {
    auto data = build_memory_data_64bit(0x10000, 4096, 1234, PAGE_EXECUTE_WRITECOPY_VAL);

    EVENT_RECORD record = make_record(ids::memory::VIRTUAL_ALLOC, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_memory_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.memory.is_suspicious, 1u);
}

TEST_F(MemoryParserTest, ParseVirtualAlloc_PAGE_READWRITE_NotSuspicious) {
    auto data = build_memory_data_64bit(0x10000, 4096, 1234, PAGE_READWRITE_VAL);

    EVENT_RECORD record = make_record(ids::memory::VIRTUAL_ALLOC, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_memory_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.memory.is_suspicious, 0u);
}

TEST_F(MemoryParserTest, ParseVirtualAlloc_PAGE_EXECUTE_READ_NotSuspicious) {
    auto data = build_memory_data_64bit(0x10000, 4096, 1234, PAGE_EXECUTE_READ_VAL);

    EVENT_RECORD record = make_record(ids::memory::VIRTUAL_ALLOC, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_memory_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.memory.is_suspicious, 0u);
}

// =============================================================================
// 3. Large Allocation Detection
// =============================================================================

TEST_F(MemoryParserTest, ParseVirtualAlloc_LargeRWX_WarningLogged) {
    uint64_t large_size = LARGE_ALLOC_THRESHOLD + 1;  // > 1MB

    auto data = build_memory_data_64bit(0x10000, large_size, 1234, PAGE_EXECUTE_READWRITE_VAL);

    EVENT_RECORD record = make_record(ids::memory::VIRTUAL_ALLOC, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_memory_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.memory.is_suspicious, 1u);
    EXPECT_EQ(result.status, event::Status::Suspicious);
}

TEST_F(MemoryParserTest, ParseVirtualAlloc_SmallRWX_NoWarning) {
    uint64_t small_size = LARGE_ALLOC_THRESHOLD - 1;  // < 1MB

    auto data = build_memory_data_64bit(0x10000, small_size, 1234, PAGE_EXECUTE_READWRITE_VAL);

    EVENT_RECORD record = make_record(ids::memory::VIRTUAL_ALLOC, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_memory_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.memory.is_suspicious, 1u);
    EXPECT_EQ(result.status, event::Status::Suspicious);
}

// =============================================================================
// 4. Virtual Free Parsing
// =============================================================================

TEST_F(MemoryParserTest, ParseVirtualFree_ExtractsBaseAndSize) {
    uint64_t base_address = 0x00007FFE00000000ULL;
    uint64_t region_size = 8192;

    auto data = build_memory_data_64bit(base_address, region_size, 1234, 0);

    EVENT_RECORD record = make_record(ids::memory::VIRTUAL_FREE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_memory_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::MemoryOp::Free));
    EXPECT_EQ(result.payload.memory.base_address, base_address);
    EXPECT_EQ(result.payload.memory.region_size, static_cast<uint32_t>(region_size));
}

TEST_F(MemoryParserTest, ParseVirtualFree_NoProtectionCheck) {
    auto data = build_memory_data_64bit(0x10000, 4096, 1234, 0);

    EVENT_RECORD record = make_record(ids::memory::VIRTUAL_FREE, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_memory_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.memory.protection, 0u);
    EXPECT_EQ(result.payload.memory.is_suspicious, 0u);
}

// =============================================================================
// 5. Pointer Size Handling
// =============================================================================

TEST_F(MemoryParserTest, ParseVirtualAlloc_64bit_Offsets) {
    uint64_t base_address = 0xDEADBEEFCAFEBABEULL;
    uint64_t region_size = 0x123456789ABCULL;
    uint32_t process_id = 9999;
    uint32_t flags = PAGE_READWRITE_VAL;

    auto data = build_memory_data_64bit(base_address, region_size, process_id, flags);

    EVENT_RECORD record = make_record(ids::memory::VIRTUAL_ALLOC, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_memory_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.memory.base_address, base_address);
    EXPECT_EQ(result.payload.memory.process_id, process_id);
    EXPECT_EQ(result.payload.memory.protection, flags);
}

TEST_F(MemoryParserTest, ParseVirtualAlloc_32bit_Offsets) {
    uint32_t base_address = 0x77E00000;
    uint32_t region_size = 0x10000;
    uint32_t process_id = 8888;
    uint32_t flags = PAGE_READWRITE_VAL;

    auto data = build_memory_data_32bit(base_address, region_size, process_id, flags);

    EVENT_RECORD record = make_record(ids::memory::VIRTUAL_ALLOC, false);
    record.EventHeader.Flags = 0;  // Clear 64-bit flag
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_memory_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.memory.base_address, static_cast<uint64_t>(base_address));
    EXPECT_EQ(result.payload.memory.region_size, region_size);
    EXPECT_EQ(result.payload.memory.process_id, process_id);
    EXPECT_EQ(result.payload.memory.protection, flags);
}

// =============================================================================
// 6. Region Size Clamping
// =============================================================================

TEST_F(MemoryParserTest, ParseVirtualAlloc_SizeExceeds4GB_ClampedToMax) {
    uint64_t region_size_raw = 5ULL * 1024 * 1024 * 1024;  // 5GB

    auto data = build_memory_data_64bit(0x10000, region_size_raw, 1234, PAGE_READWRITE_VAL);

    EVENT_RECORD record = make_record(ids::memory::VIRTUAL_ALLOC, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_memory_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.memory.region_size, UINT32_MAX);
}

TEST_F(MemoryParserTest, ParseVirtualAlloc_SizeExactly4GB_Preserved) {
    uint64_t region_size_raw = 0xFFFFFFFFULL;  // Exactly UINT32_MAX

    auto data = build_memory_data_64bit(0x10000, region_size_raw, 1234, PAGE_READWRITE_VAL);

    EVENT_RECORD record = make_record(ids::memory::VIRTUAL_ALLOC, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_memory_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.memory.region_size, UINT32_MAX);
}

// =============================================================================
// 7. Invalid Input
// =============================================================================

TEST_F(MemoryParserTest, ParseMemoryEvent_NullRecord_ReturnsInvalid) {
    auto result = parse_memory_event(nullptr, strings_.get());

    EXPECT_FALSE(result.valid);
}

TEST_F(MemoryParserTest, ParseVirtualAlloc_TruncatedData_ReturnsInvalid) {
    std::vector<uint8_t> data(15, 0);  // Less than 16 bytes minimum

    EVENT_RECORD record = make_record(ids::memory::VIRTUAL_ALLOC, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_memory_event(&record, strings_.get());

    EXPECT_FALSE(result.valid);
}

TEST_F(MemoryParserTest, ParseVirtualAlloc_MinLenNotMet_ReturnsInvalid) {
    // For 64-bit: min_len = 2*8 + 8 = 24 bytes
    // Provide 23 bytes (less than minimum)
    std::vector<uint8_t> data(23, 0);

    EVENT_RECORD record = make_record(ids::memory::VIRTUAL_ALLOC, true);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_memory_event(&record, strings_.get());

    EXPECT_FALSE(result.valid);
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(MemoryParserTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
