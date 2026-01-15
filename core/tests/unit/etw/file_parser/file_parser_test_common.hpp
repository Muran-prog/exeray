/// @file file_parser_test_common.hpp
/// @brief Shared test fixture and helpers for File ETW parser tests.

#pragma once

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

}  // namespace exeray::etw

#endif  // _WIN32
