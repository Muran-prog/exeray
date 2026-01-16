/// @file thread_parser_test_common.hpp
/// @brief Shared test fixture and helpers for Thread ETW parser tests.

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

class ThreadParserTest : public ::testing::Test {
protected:
    static constexpr std::size_t kArenaSize = 1024 * 1024;  // 1MB

    void SetUp() override {
        arena_ = std::make_unique<Arena>(kArenaSize);
        strings_ = std::make_unique<event::StringPool>(*arena_);
    }

    /// Create a minimal valid EVENT_RECORD for thread events.
    EVENT_RECORD make_record(uint16_t event_id, bool is64bit = true, uint32_t creator_pid = 1234) {
        EVENT_RECORD record{};
        record.EventHeader.EventDescriptor.Id = event_id;
        if (is64bit) {
            record.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER;
        }
        record.EventHeader.ProcessId = creator_pid;
        record.EventHeader.TimeStamp.QuadPart = 0x123456789ABCDEF0LL;
        return record;
    }

    /// Build Thread Start/DCStart user data.
    /// Layout (Thread_TypeGroup1, EventVersion 3):
    ///   ProcessId: UINT32 (4)
    ///   TThreadId: UINT32 (4)
    ///   StackBase: PVOID (ptr_size)
    ///   StackLimit: PVOID (ptr_size)
    ///   UserStackBase: PVOID (ptr_size)
    ///   UserStackLimit: PVOID (ptr_size)
    ///   Affinity: PVOID (ptr_size)
    ///   Win32StartAddr: PVOID (ptr_size)
    ///   TebBase: PVOID (ptr_size)
    ///   SubProcessTag: UINT32 (4)
    ///   BasePriority: UINT8 (1)
    ///   PagePriority: UINT8 (1)
    ///   IoPriority: UINT8 (1)
    ///   ThreadFlags: UINT8 (1)
    std::vector<uint8_t> build_thread_start_data(
        uint32_t process_id,
        uint32_t thread_id,
        uint64_t start_address,
        bool is64bit = true
    ) {
        const size_t ptr_size = is64bit ? 8 : 4;
        // Total: 8 + 7*ptr_size + 4 + 4 = 16 + 7*ptr_size
        const size_t total_size = 8 + 7 * ptr_size + 4 + 4;

        std::vector<uint8_t> buffer(total_size, 0);
        size_t offset = 0;

        // ProcessId
        std::memcpy(buffer.data() + offset, &process_id, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // TThreadId
        std::memcpy(buffer.data() + offset, &thread_id, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // StackBase, StackLimit, UserStackBase, UserStackLimit, Affinity (5 pointers)
        offset += 5 * ptr_size;

        // Win32StartAddr
        if (is64bit) {
            std::memcpy(buffer.data() + offset, &start_address, sizeof(uint64_t));
        } else {
            uint32_t addr32 = static_cast<uint32_t>(start_address);
            std::memcpy(buffer.data() + offset, &addr32, sizeof(uint32_t));
        }
        offset += ptr_size;

        // TebBase
        offset += ptr_size;

        // SubProcessTag (4), BasePriority (1), PagePriority (1), IoPriority (1), ThreadFlags (1)
        // Already zeroed

        return buffer;
    }

    /// Build Thread End/DCEnd user data.
    /// Layout: ProcessId (4) + TThreadId (4) = 8 bytes minimum
    std::vector<uint8_t> build_thread_end_data(uint32_t process_id, uint32_t thread_id) {
        std::vector<uint8_t> buffer(8, 0);

        std::memcpy(buffer.data(), &process_id, sizeof(uint32_t));
        std::memcpy(buffer.data() + sizeof(uint32_t), &thread_id, sizeof(uint32_t));

        return buffer;
    }

    std::unique_ptr<Arena> arena_;
    std::unique_ptr<event::StringPool> strings_;
};

}  // namespace exeray::etw

#endif  // _WIN32
