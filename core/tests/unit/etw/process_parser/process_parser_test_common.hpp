/// @file process_parser_test_common.hpp
/// @brief Shared test fixture and helpers for Process ETW parser tests.

#pragma once

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
    std::vector<uint8_t> build_process_start_data(
        uint32_t pid,
        uint32_t parent_pid,
        uint8_t sub_authority_count,
        const std::string& image_name,
        const std::wstring& command_line,
        bool is64bit = true
    ) {
        const size_t ptr_size = is64bit ? 8 : 4;
        const size_t sid_size = 8 + 4 * sub_authority_count;
        
        size_t total_size = ptr_size + sizeof(uint32_t) + sizeof(uint32_t) 
                          + sizeof(uint32_t) + sizeof(int32_t) + ptr_size 
                          + sizeof(uint32_t) + sid_size + image_name.size() + 1
                          + (command_line.size() + 1) * sizeof(wchar_t);
        
        std::vector<uint8_t> buffer(total_size, 0);
        size_t offset = 0;
        
        offset += ptr_size;  // UniqueProcessKey
        std::memcpy(buffer.data() + offset, &pid, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        std::memcpy(buffer.data() + offset, &parent_pid, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        uint32_t session_id = 1;
        std::memcpy(buffer.data() + offset, &session_id, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        offset += sizeof(int32_t);  // ExitStatus
        offset += ptr_size;         // DirectoryTableBase
        offset += sizeof(uint32_t); // Flags
        
        buffer[offset] = 1;  // SID Revision
        buffer[offset + 1] = sub_authority_count;
        buffer[offset + 7] = 5;  // NT AUTHORITY
        offset += sid_size;
        
        std::memcpy(buffer.data() + offset, image_name.c_str(), image_name.size() + 1);
        offset += image_name.size() + 1;
        std::memcpy(buffer.data() + offset, command_line.c_str(), 
                    (command_line.size() + 1) * sizeof(wchar_t));
        
        return buffer;
    }

    /// Build ProcessStop user data (Event ID 2)
    std::vector<uint8_t> build_process_stop_data(uint32_t pid, bool is64bit = true) {
        const size_t ptr_size = is64bit ? 8 : 4;
        size_t total_size = ptr_size + 4 * sizeof(uint32_t);
        
        std::vector<uint8_t> buffer(total_size, 0);
        std::memcpy(buffer.data() + ptr_size, &pid, sizeof(uint32_t));
        
        return buffer;
    }

    /// Build ImageLoad user data (Event ID 5)
    std::vector<uint8_t> build_image_load_data(uint32_t pid, bool is64bit = true) {
        const size_t ptr_size = is64bit ? 8 : 4;
        size_t total_size = ptr_size * 2 + sizeof(uint32_t) * 4;
        
        std::vector<uint8_t> buffer(total_size, 0);
        std::memcpy(buffer.data() + ptr_size * 2, &pid, sizeof(uint32_t));
        
        return buffer;
    }

    std::unique_ptr<Arena> arena_;
    std::unique_ptr<event::StringPool> strings_;
};

}  // namespace exeray::etw

#endif  // _WIN32
