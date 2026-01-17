/// @file amsi_parser_test_common.hpp
/// @brief Shared test fixture and helpers for AMSI ETW parser tests.

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

class AmsiParserTest : public ::testing::Test {
protected:
    static constexpr std::size_t kArenaSize = 1024 * 1024;  // 1MB

    void SetUp() override {
        arena_ = std::make_unique<Arena>(kArenaSize);
        strings_ = std::make_unique<event::StringPool>(*arena_);
    }

    /// Create a minimal valid EVENT_RECORD for AMSI events.
    EVENT_RECORD make_record(uint16_t event_id) {
        EVENT_RECORD record{};
        record.EventHeader.EventDescriptor.Id = event_id;
        record.EventHeader.ProcessId = 1234;
        record.EventHeader.TimeStamp.QuadPart = 0x123456789ABCDEF0LL;
        return record;
    }

    /// Build AmsiScanBuffer (Event 1101) user data.
    /// Layout:
    ///   session: UINT64 (AMSI session handle)
    ///   scanStatus: UINT32 (HRESULT)
    ///   scanResult: UINT32 (AMSI_RESULT_*)
    ///   appName: WSTRING (requesting application)
    ///   contentName: WSTRING (optional, e.g., script name)
    ///   contentSize: UINT32
    std::vector<uint8_t> build_scan_buffer_data(
        uint32_t scan_result,
        const std::wstring& app_name,
        uint32_t content_size,
        const std::wstring& content_name = L""
    ) {
        const size_t app_name_bytes = (app_name.size() + 1) * sizeof(wchar_t);
        const size_t content_name_bytes = (content_name.size() + 1) * sizeof(wchar_t);
        const size_t total_size = sizeof(uint64_t) +  // session
                                  sizeof(uint32_t) +  // scanStatus
                                  sizeof(uint32_t) +  // scanResult
                                  app_name_bytes +
                                  content_name_bytes +
                                  sizeof(uint32_t);   // contentSize

        std::vector<uint8_t> buffer(total_size, 0);
        size_t offset = 0;

        // session (8 bytes)
        uint64_t session = 0x1234567890ABCDEFULL;
        std::memcpy(buffer.data() + offset, &session, sizeof(uint64_t));
        offset += sizeof(uint64_t);

        // scanStatus (4 bytes) - HRESULT S_OK
        uint32_t scan_status = 0;
        std::memcpy(buffer.data() + offset, &scan_status, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // scanResult (4 bytes)
        std::memcpy(buffer.data() + offset, &scan_result, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        // appName (null-terminated wide string)
        std::memcpy(buffer.data() + offset, app_name.c_str(), app_name_bytes);
        offset += app_name_bytes;

        // contentName (null-terminated wide string)
        std::memcpy(buffer.data() + offset, content_name.c_str(), content_name_bytes);
        offset += content_name_bytes;

        // contentSize (4 bytes)
        std::memcpy(buffer.data() + offset, &content_size, sizeof(uint32_t));

        return buffer;
    }

    std::unique_ptr<Arena> arena_;
    std::unique_ptr<event::StringPool> strings_;
};

}  // namespace exeray::etw

#endif  // _WIN32
