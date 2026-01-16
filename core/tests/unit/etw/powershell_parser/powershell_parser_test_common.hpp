/// @file powershell_parser_test_common.hpp
/// @brief Shared test fixture and helpers for PowerShell ETW parser tests.

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

class PowerShellParserTest : public ::testing::Test {
protected:
    static constexpr std::size_t kArenaSize = 1024 * 1024;  // 1MB

    void SetUp() override {
        arena_ = std::make_unique<Arena>(kArenaSize);
        strings_ = std::make_unique<event::StringPool>(*arena_);
    }

    /// Create a minimal valid EVENT_RECORD for PowerShell events.
    EVENT_RECORD make_record(uint16_t event_id) {
        EVENT_RECORD record{};
        record.EventHeader.EventDescriptor.Id = event_id;
        record.EventHeader.ProcessId = 1234;
        record.EventHeader.TimeStamp.QuadPart = 0x123456789ABCDEF0LL;
        return record;
    }

    /// Build Script Block Logging (Event 4104) user data.
    /// Layout:
    ///   MessageNumber: UINT32 (sequence number)
    ///   MessageTotal:  UINT32 (total parts)
    ///   ScriptBlockText: WSTRING (script content)
    ///   ScriptBlockId: GUID (optional, not always present)
    ///   Path: WSTRING (optional script file path)
    std::vector<uint8_t> build_script_block_data(
        uint32_t message_number,
        uint32_t message_total,
        const std::wstring& script_text,
        const std::wstring& path = L""
    ) {
        const size_t script_bytes = (script_text.size() + 1) * sizeof(wchar_t);
        const size_t path_bytes = path.empty() ? 0 : (path.size() + 1) * sizeof(wchar_t);
        const size_t guid_size = 16;  // GUID size
        const size_t total_size = sizeof(uint32_t) * 2 + script_bytes + guid_size + path_bytes;

        std::vector<uint8_t> buffer(total_size, 0);
        size_t offset = 0;

        // MessageNumber (4 bytes)
        std::memcpy(buffer.data() + offset, &message_number, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // MessageTotal (4 bytes)
        std::memcpy(buffer.data() + offset, &message_total, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // ScriptBlockText (null-terminated wide string)
        std::memcpy(buffer.data() + offset, script_text.c_str(), script_bytes);
        offset += script_bytes;

        // ScriptBlockId (GUID - 16 bytes of zeros for test)
        offset += guid_size;

        // Path (null-terminated wide string, if present)
        if (!path.empty()) {
            std::memcpy(buffer.data() + offset, path.c_str(), path_bytes);
        }

        return buffer;
    }

    /// Build Module Logging (Event 4103) user data.
    /// Less detailed than Script Block Logging.
    std::vector<uint8_t> build_module_data(
        const std::wstring& context = L""
    ) {
        const size_t context_bytes = context.empty() ? 2 : (context.size() + 1) * sizeof(wchar_t);
        const size_t total_size = sizeof(uint32_t) * 2 + context_bytes;

        std::vector<uint8_t> buffer(total_size, 0);
        size_t offset = 0;

        // Some context data
        uint32_t zero = 0;
        std::memcpy(buffer.data() + offset, &zero, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        std::memcpy(buffer.data() + offset, &zero, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // Context string
        if (!context.empty()) {
            std::memcpy(buffer.data() + offset, context.c_str(), context_bytes);
        }

        return buffer;
    }

    /// Build large script data for stress testing.
    std::vector<uint8_t> build_large_script_data(size_t script_size_chars) {
        std::wstring script(script_size_chars, L'A');
        return build_script_block_data(1, 1, script);
    }

    std::unique_ptr<Arena> arena_;
    std::unique_ptr<event::StringPool> strings_;
};

}  // namespace exeray::etw

#endif  // _WIN32
