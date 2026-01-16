/// @file image_parser_test_common.hpp
/// @brief Shared test fixture and helpers for Image ETW parser tests.

#pragma once

#include <gtest/gtest.h>

#ifdef _WIN32

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

class ImageParserTest : public ::testing::Test {
protected:
    static constexpr std::size_t kArenaSize = 1024 * 1024;  // 1MB

    void SetUp() override {
        arena_ = std::make_unique<Arena>(kArenaSize);
        strings_ = std::make_unique<event::StringPool>(*arena_);
    }

    /// Create a minimal valid EVENT_RECORD for image events.
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

    /// Build Image Load user data for 64-bit.
    /// Layout:
    ///   ImageBase: PVOID (8 bytes)
    ///   ImageSize: PVOID (8 bytes)
    ///   ProcessId: UINT32 (4 bytes)
    ///   ImageChecksum: UINT32 (4 bytes)
    ///   TimeDateStamp: UINT32 (4 bytes)
    ///   Reserved0: UINT32 (4 bytes)
    ///   DefaultBase: PVOID (8 bytes)
    ///   Reserved1-4: UINT32 * 4 (16 bytes)
    ///   FileName: Unicode string (null-terminated)
    std::vector<uint8_t> build_image_load_data_64bit(
        uint64_t image_base,
        uint64_t image_size,
        uint32_t process_id,
        const std::wstring& filename
    ) {
        const size_t ptr_size = 8;
        const size_t header_size = 2 * ptr_size + 4 * sizeof(uint32_t) + ptr_size + 4 * sizeof(uint32_t);
        const size_t filename_bytes = (filename.size() + 1) * sizeof(wchar_t);
        const size_t total_size = header_size + filename_bytes;

        std::vector<uint8_t> buffer(total_size, 0);
        size_t offset = 0;

        // ImageBase (8 bytes)
        std::memcpy(buffer.data() + offset, &image_base, sizeof(uint64_t));
        offset += sizeof(uint64_t);

        // ImageSize (8 bytes)
        std::memcpy(buffer.data() + offset, &image_size, sizeof(uint64_t));
        offset += sizeof(uint64_t);

        // ProcessId (4 bytes)
        std::memcpy(buffer.data() + offset, &process_id, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // ImageChecksum (4 bytes)
        uint32_t checksum = 0x12345678;
        std::memcpy(buffer.data() + offset, &checksum, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // TimeDateStamp (4 bytes)
        uint32_t timestamp = 0x5F000000;
        std::memcpy(buffer.data() + offset, &timestamp, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // Reserved0 (4 bytes)
        offset += sizeof(uint32_t);

        // DefaultBase (8 bytes)
        offset += sizeof(uint64_t);

        // Reserved1-4 (16 bytes)
        offset += 4 * sizeof(uint32_t);

        // FileName (null-terminated wide string)
        std::memcpy(buffer.data() + offset, filename.c_str(), filename_bytes);

        return buffer;
    }

    /// Build Image Load user data for 32-bit.
    std::vector<uint8_t> build_image_load_data_32bit(
        uint32_t image_base,
        uint32_t image_size,
        uint32_t process_id,
        const std::wstring& filename
    ) {
        const size_t ptr_size = 4;
        const size_t header_size = 2 * ptr_size + 4 * sizeof(uint32_t) + ptr_size + 4 * sizeof(uint32_t);
        const size_t filename_bytes = (filename.size() + 1) * sizeof(wchar_t);
        const size_t total_size = header_size + filename_bytes;

        std::vector<uint8_t> buffer(total_size, 0);
        size_t offset = 0;

        // ImageBase (4 bytes)
        std::memcpy(buffer.data() + offset, &image_base, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // ImageSize (4 bytes)
        std::memcpy(buffer.data() + offset, &image_size, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // ProcessId (4 bytes)
        std::memcpy(buffer.data() + offset, &process_id, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // ImageChecksum (4 bytes)
        uint32_t checksum = 0x12345678;
        std::memcpy(buffer.data() + offset, &checksum, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // TimeDateStamp (4 bytes)
        uint32_t timestamp = 0x5F000000;
        std::memcpy(buffer.data() + offset, &timestamp, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // Reserved0 (4 bytes)
        offset += sizeof(uint32_t);

        // DefaultBase (4 bytes)
        offset += sizeof(uint32_t);

        // Reserved1-4 (16 bytes)
        offset += 4 * sizeof(uint32_t);

        // FileName (null-terminated wide string)
        std::memcpy(buffer.data() + offset, filename.c_str(), filename_bytes);

        return buffer;
    }

    /// Build Image Unload user data for 64-bit (no filename).
    /// Layout:
    ///   ImageBase: PVOID (8 bytes)
    ///   ImageSize: PVOID (8 bytes)
    ///   ProcessId: UINT32 (4 bytes)
    std::vector<uint8_t> build_image_unload_data_64bit(
        uint64_t image_base,
        uint64_t image_size,
        uint32_t process_id
    ) {
        const size_t ptr_size = 8;
        const size_t total_size = 2 * ptr_size + sizeof(uint32_t);

        std::vector<uint8_t> buffer(total_size, 0);
        size_t offset = 0;

        // ImageBase (8 bytes)
        std::memcpy(buffer.data() + offset, &image_base, sizeof(uint64_t));
        offset += sizeof(uint64_t);

        // ImageSize (8 bytes)
        std::memcpy(buffer.data() + offset, &image_size, sizeof(uint64_t));
        offset += sizeof(uint64_t);

        // ProcessId (4 bytes)
        std::memcpy(buffer.data() + offset, &process_id, sizeof(uint32_t));

        return buffer;
    }

    /// Build Image Unload user data for 32-bit (no filename).
    std::vector<uint8_t> build_image_unload_data_32bit(
        uint32_t image_base,
        uint32_t image_size,
        uint32_t process_id
    ) {
        const size_t ptr_size = 4;
        const size_t total_size = 2 * ptr_size + sizeof(uint32_t);

        std::vector<uint8_t> buffer(total_size, 0);
        size_t offset = 0;

        // ImageBase (4 bytes)
        std::memcpy(buffer.data() + offset, &image_base, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // ImageSize (4 bytes)
        std::memcpy(buffer.data() + offset, &image_size, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // ProcessId (4 bytes)
        std::memcpy(buffer.data() + offset, &process_id, sizeof(uint32_t));

        return buffer;
    }

    std::unique_ptr<Arena> arena_;
    std::unique_ptr<event::StringPool> strings_;
};

}  // namespace exeray::etw

#endif  // _WIN32
