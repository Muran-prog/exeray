/// @file memory_parser_test_common.hpp
/// @brief Shared test fixture and helpers for Memory ETW parser tests.

#pragma once

#include <gtest/gtest.h>

#ifdef _WIN32

#include <cstdint>
#include <cstring>
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

// Memory protection constants
constexpr uint32_t PAGE_EXECUTE_READWRITE_VAL = 0x40;
constexpr uint32_t PAGE_EXECUTE_WRITECOPY_VAL = 0x80;
constexpr uint32_t PAGE_READWRITE_VAL = 0x04;
constexpr uint32_t PAGE_EXECUTE_READ_VAL = 0x20;

// Large allocation threshold (1MB)
constexpr uint64_t LARGE_ALLOC_THRESHOLD = 1024 * 1024;

class MemoryParserTest : public ::testing::Test {
protected:
    static constexpr std::size_t kArenaSize = 1024 * 1024;  // 1MB

    void SetUp() override {
        arena_ = std::make_unique<Arena>(kArenaSize);
        strings_ = std::make_unique<event::StringPool>(*arena_);
    }

    /// Create a minimal valid EVENT_RECORD for memory events.
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

    /// Build VirtualAlloc/VirtualFree user data for 64-bit.
    /// Layout (PageFault_VirtualAlloc):
    ///   BaseAddress: PVOID (ptr_size)
    ///   RegionSize:  SIZE_T (ptr_size)
    ///   ProcessId:   UINT32
    ///   Flags:       UINT32 (protection/allocation type)
    std::vector<uint8_t> build_memory_data_64bit(
        uint64_t base_address,
        uint64_t region_size,
        uint32_t process_id,
        uint32_t flags
    ) {
        const size_t ptr_size = 8;
        const size_t total_size = 2 * ptr_size + 2 * sizeof(uint32_t);

        std::vector<uint8_t> buffer(total_size, 0);
        size_t offset = 0;

        // BaseAddress (8 bytes)
        std::memcpy(buffer.data() + offset, &base_address, sizeof(uint64_t));
        offset += sizeof(uint64_t);

        // RegionSize (8 bytes)
        std::memcpy(buffer.data() + offset, &region_size, sizeof(uint64_t));
        offset += sizeof(uint64_t);

        // ProcessId (4 bytes)
        std::memcpy(buffer.data() + offset, &process_id, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // Flags (4 bytes)
        std::memcpy(buffer.data() + offset, &flags, sizeof(uint32_t));

        return buffer;
    }

    /// Build VirtualAlloc/VirtualFree user data for 32-bit.
    std::vector<uint8_t> build_memory_data_32bit(
        uint32_t base_address,
        uint32_t region_size,
        uint32_t process_id,
        uint32_t flags
    ) {
        const size_t ptr_size = 4;
        const size_t total_size = 2 * ptr_size + 2 * sizeof(uint32_t);

        std::vector<uint8_t> buffer(total_size, 0);
        size_t offset = 0;

        // BaseAddress (4 bytes)
        std::memcpy(buffer.data() + offset, &base_address, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // RegionSize (4 bytes)
        std::memcpy(buffer.data() + offset, &region_size, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // ProcessId (4 bytes)
        std::memcpy(buffer.data() + offset, &process_id, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // Flags (4 bytes)
        std::memcpy(buffer.data() + offset, &flags, sizeof(uint32_t));

        return buffer;
    }

    std::unique_ptr<Arena> arena_;
    std::unique_ptr<event::StringPool> strings_;
};

}  // namespace exeray::etw

#endif  // _WIN32
