/// @file network_parser_test_common.hpp
/// @brief Shared test fixture and helpers for Network ETW parser tests.

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

/// Protocol numbers (IANA).
constexpr uint8_t PROTO_TCP = 6;
constexpr uint8_t PROTO_UDP = 17;

/// Address families (using TEST_ prefix to avoid conflict with winsock).
constexpr uint16_t TEST_AF_INET = 2;
constexpr uint16_t TEST_AF_INET6 = 23;

class NetworkParserTest : public ::testing::Test {
protected:
    static constexpr std::size_t kArenaSize = 1024 * 1024;  // 1MB

    void SetUp() override {
        arena_ = std::make_unique<Arena>(kArenaSize);
        strings_ = std::make_unique<event::StringPool>(*arena_);
    }

    /// Create a minimal valid EVENT_RECORD for network events.
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

    /// Build TCP connect user data for IPv4.
    /// Layout: pid(4) + af(2) + local_addr(4) + local_port(2) + remote_addr(4) + remote_port(2) = 18 bytes
    std::vector<uint8_t> build_tcp_connect_ipv4_data(
        uint32_t pid,
        uint32_t local_addr,
        uint16_t local_port,
        uint32_t remote_addr,
        uint16_t remote_port
    ) {
        std::vector<uint8_t> buffer(18, 0);
        size_t offset = 0;

        std::memcpy(buffer.data() + offset, &pid, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        uint16_t af = TEST_AF_INET;
        std::memcpy(buffer.data() + offset, &af, sizeof(uint16_t));
        offset += sizeof(uint16_t);

        std::memcpy(buffer.data() + offset, &local_addr, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        std::memcpy(buffer.data() + offset, &local_port, sizeof(uint16_t));
        offset += sizeof(uint16_t);

        std::memcpy(buffer.data() + offset, &remote_addr, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        std::memcpy(buffer.data() + offset, &remote_port, sizeof(uint16_t));

        return buffer;
    }

    /// Build TCP connect user data for IPv6.
    /// Layout: pid(4) + af(2) + local_addr(16) + local_port(2) + remote_addr(16) + remote_port(2) = 42 bytes
    std::vector<uint8_t> build_tcp_connect_ipv6_data(
        uint32_t pid,
        const uint8_t local_addr[16],
        uint16_t local_port,
        const uint8_t remote_addr[16],
        uint16_t remote_port
    ) {
        std::vector<uint8_t> buffer(42, 0);
        size_t offset = 0;

        std::memcpy(buffer.data() + offset, &pid, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        uint16_t af = TEST_AF_INET6;
        std::memcpy(buffer.data() + offset, &af, sizeof(uint16_t));
        offset += sizeof(uint16_t);

        std::memcpy(buffer.data() + offset, local_addr, 16);
        offset += 16;

        std::memcpy(buffer.data() + offset, &local_port, sizeof(uint16_t));
        offset += sizeof(uint16_t);

        std::memcpy(buffer.data() + offset, remote_addr, 16);
        offset += 16;

        std::memcpy(buffer.data() + offset, &remote_port, sizeof(uint16_t));

        return buffer;
    }

    /// Build TCP transfer (send/receive) user data.
    /// Layout: pid(4) + bytes(4) = 8 bytes minimum
    std::vector<uint8_t> build_tcp_transfer_data(uint32_t pid, uint32_t bytes) {
        std::vector<uint8_t> buffer(8, 0);

        std::memcpy(buffer.data(), &pid, sizeof(uint32_t));
        std::memcpy(buffer.data() + 4, &bytes, sizeof(uint32_t));

        return buffer;
    }

    /// Build minimal UDP event data (empty, just valid record).
    std::vector<uint8_t> build_udp_event_data() {
        return std::vector<uint8_t>(8, 0);
    }

    std::unique_ptr<Arena> arena_;
    std::unique_ptr<event::StringPool> strings_;
};

}  // namespace exeray::etw

#endif  // _WIN32
