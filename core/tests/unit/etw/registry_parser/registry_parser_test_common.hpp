/// @file registry_parser_test_common.hpp
/// @brief Shared test fixture and helpers for Registry ETW parser tests.

#pragma once

#include <gtest/gtest.h>

#ifdef _WIN32

#include <cstdint>
#include <cstring>
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

class RegistryParserTest : public ::testing::Test {
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

    /// Build registry key event user data (CreateKey, OpenKey).
    /// Layout: BaseObject(PTR), KeyObject(PTR), Status(4), Disposition(4),
    ///         BaseName(4), RelativeName(wchar_t[])
    std::vector<uint8_t> build_key_event_data(
        int32_t ntstatus,
        bool is64bit = true
    ) {
        const size_t ptr_size = is64bit ? 8 : 4;
        // BaseObject + KeyObject + Status + Disposition + BaseName offset
        size_t total_size = ptr_size * 2 + sizeof(int32_t) * 3;

        std::vector<uint8_t> buffer(total_size, 0);
        size_t offset = ptr_size * 2;  // Skip BaseObject, KeyObject

        // Status (NTSTATUS)
        std::memcpy(buffer.data() + offset, &ntstatus, sizeof(int32_t));

        return buffer;
    }

    /// Build registry value event user data (SetValue, DeleteValue).
    /// Layout: KeyObject(PTR), Status(4), Type(4), DataSize(4),
    ///         KeyName(wchar_t[]), ValueName(wchar_t[])
    std::vector<uint8_t> build_value_event_data(
        int32_t ntstatus,
        uint32_t value_type = 0,
        uint32_t data_size = 0,
        bool is64bit = true
    ) {
        const size_t ptr_size = is64bit ? 8 : 4;
        // KeyObject + Status + Type + DataSize
        size_t total_size = ptr_size + sizeof(int32_t) + sizeof(uint32_t) * 2;

        std::vector<uint8_t> buffer(total_size, 0);
        size_t offset = ptr_size;  // Skip KeyObject

        // Status (NTSTATUS)
        std::memcpy(buffer.data() + offset, &ntstatus, sizeof(int32_t));
        offset += sizeof(int32_t);

        // Type
        std::memcpy(buffer.data() + offset, &value_type, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // DataSize
        std::memcpy(buffer.data() + offset, &data_size, sizeof(uint32_t));

        return buffer;
    }

    std::unique_ptr<Arena> arena_;
    std::unique_ptr<event::StringPool> strings_;
};

}  // namespace exeray::etw

#endif  // _WIN32
