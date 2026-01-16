/// @file network_parser_test.cpp
/// @brief Unit tests for Network ETW parser.

#include "network_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

// =============================================================================
// 1. TCP Connect
// =============================================================================

TEST_F(NetworkParserTest, ParseTcpConnect_IPv4_ExtractsAddresses) {
    uint32_t local_addr = 0xC0A80001;   // 192.168.0.1
    uint32_t remote_addr = 0x08080808;  // 8.8.8.8

    auto data = build_tcp_connect_ipv4_data(1234, local_addr, 12345, remote_addr, 80);

    EVENT_RECORD record = make_record(ids::network::TCP_CONNECT);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_network_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::Network);
    EXPECT_EQ(result.payload.network.local_addr, local_addr);
    EXPECT_EQ(result.payload.network.remote_addr, remote_addr);
}

TEST_F(NetworkParserTest, ParseTcpConnect_IPv4_ExtractsPorts) {
    uint16_t local_port = 54321;
    uint16_t remote_port = 443;

    auto data = build_tcp_connect_ipv4_data(1234, 0x7F000001, local_port, 0x08080808, remote_port);

    EVENT_RECORD record = make_record(ids::network::TCP_CONNECT);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_network_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.network.local_port, local_port);
    EXPECT_EQ(result.payload.network.remote_port, remote_port);
}

TEST_F(NetworkParserTest, ParseTcpConnect_IPv6_SkipsCorrectly) {
    uint8_t local_addr[16] = {0};
    uint8_t remote_addr[16] = {0};
    // ::1 (loopback)
    local_addr[15] = 1;
    // 2001:4860:4860::8888 (Google DNS IPv6)
    remote_addr[0] = 0x20;
    remote_addr[1] = 0x01;
    remote_addr[2] = 0x48;
    remote_addr[3] = 0x60;
    remote_addr[15] = 0x88;

    auto data = build_tcp_connect_ipv6_data(1234, local_addr, 12345, remote_addr, 443);

    EVENT_RECORD record = make_record(ids::network::TCP_CONNECT);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_network_event(&record, strings_.get());

    // IPv6 parsing: addresses remain 0 since only IPv4 is fully extracted
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.network.protocol, PROTO_TCP);
    // IPv6 addresses are not stored in local_addr/remote_addr (they are 32-bit)
    EXPECT_EQ(result.payload.network.local_addr, 0u);
    EXPECT_EQ(result.payload.network.remote_addr, 0u);
}

TEST_F(NetworkParserTest, ParseTcpConnect_SetsProtocolTcp) {
    auto data = build_tcp_connect_ipv4_data(1234, 0x7F000001, 12345, 0x08080808, 80);

    EVENT_RECORD record = make_record(ids::network::TCP_CONNECT);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_network_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.network.protocol, PROTO_TCP);
}

// =============================================================================
// 2. TCP Transfer
// =============================================================================

TEST_F(NetworkParserTest, ParseTcpSend_ExtractsBytes) {
    uint32_t bytes = 1500;
    auto data = build_tcp_transfer_data(1234, bytes);

    EVENT_RECORD record = make_record(ids::network::TCP_SEND);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_network_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.network.bytes, bytes);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::NetworkOp::Send));
}

TEST_F(NetworkParserTest, ParseTcpReceive_ExtractsBytes) {
    uint32_t bytes = 65535;
    auto data = build_tcp_transfer_data(1234, bytes);

    EVENT_RECORD record = make_record(ids::network::TCP_RECEIVE);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_network_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.network.bytes, bytes);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::NetworkOp::Receive));
}

TEST_F(NetworkParserTest, ParseTcpTransfer_ZeroBytes_Valid) {
    uint32_t bytes = 0;
    auto data = build_tcp_transfer_data(1234, bytes);

    EVENT_RECORD record = make_record(ids::network::TCP_SEND);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_network_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.network.bytes, 0u);
}

// =============================================================================
// 3. UDP Operations
// =============================================================================

TEST_F(NetworkParserTest, ParseUdpSend_SetsProtocolUdp) {
    auto data = build_udp_event_data();

    EVENT_RECORD record = make_record(ids::network::UDP_SEND);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_network_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.network.protocol, PROTO_UDP);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::NetworkOp::Send));
}

TEST_F(NetworkParserTest, ParseUdpReceive_MinimalParsing) {
    auto data = build_udp_event_data();

    EVENT_RECORD record = make_record(ids::network::UDP_RECEIVE);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_network_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.network.protocol, PROTO_UDP);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::NetworkOp::Receive));
}

// =============================================================================
// 4. Address Edge Cases
// =============================================================================

TEST_F(NetworkParserTest, ParseTcpConnect_LoopbackAddress_ExtractsCorrectly) {
    uint32_t loopback = 0x7F000001;  // 127.0.0.1

    auto data = build_tcp_connect_ipv4_data(1234, loopback, 8080, loopback, 80);

    EVENT_RECORD record = make_record(ids::network::TCP_CONNECT);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_network_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.network.local_addr, loopback);
    EXPECT_EQ(result.payload.network.remote_addr, loopback);
}

TEST_F(NetworkParserTest, ParseTcpConnect_BroadcastAddress_ExtractsCorrectly) {
    uint32_t broadcast = 0xFFFFFFFF;  // 255.255.255.255

    auto data = build_tcp_connect_ipv4_data(1234, 0xC0A80001, 12345, broadcast, 80);

    EVENT_RECORD record = make_record(ids::network::TCP_CONNECT);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_network_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.network.remote_addr, broadcast);
}

TEST_F(NetworkParserTest, ParseTcpConnect_ZeroAddress_Valid) {
    uint32_t any_addr = 0x00000000;  // 0.0.0.0 - binding to any

    auto data = build_tcp_connect_ipv4_data(1234, any_addr, 8080, 0x08080808, 80);

    EVENT_RECORD record = make_record(ids::network::TCP_CONNECT);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_network_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.network.local_addr, any_addr);
}

// =============================================================================
// 5. Port Edge Cases
// =============================================================================

TEST_F(NetworkParserTest, ParseTcpConnect_PortZero_Valid) {
    uint16_t ephemeral_port = 0;  // Not yet assigned

    auto data = build_tcp_connect_ipv4_data(1234, 0x7F000001, ephemeral_port, 0x08080808, 80);

    EVENT_RECORD record = make_record(ids::network::TCP_CONNECT);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_network_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.network.local_port, ephemeral_port);
}

TEST_F(NetworkParserTest, ParseTcpConnect_Port65535_Valid) {
    uint16_t max_port = 65535;

    auto data = build_tcp_connect_ipv4_data(1234, 0x7F000001, max_port, 0x08080808, max_port);

    EVENT_RECORD record = make_record(ids::network::TCP_CONNECT);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_network_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.network.local_port, max_port);
    EXPECT_EQ(result.payload.network.remote_port, max_port);
}

// =============================================================================
// 6. Invalid Input
// =============================================================================

TEST_F(NetworkParserTest, ParseNetworkEvent_NullRecord_ReturnsInvalid) {
    auto result = parse_network_event(nullptr, strings_.get());

    EXPECT_FALSE(result.valid);
}

TEST_F(NetworkParserTest, ParseTcpConnect_TruncatedData_ReturnsInvalid) {
    // Minimum for IPv4 TCP connect is 18 bytes, provide only 17
    std::vector<uint8_t> data(17, 0);

    EVENT_RECORD record = make_record(ids::network::TCP_CONNECT);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_network_event(&record, strings_.get());

    EXPECT_FALSE(result.valid);
}

TEST_F(NetworkParserTest, ParseTcpTransfer_TruncatedData_ReturnsInvalid) {
    // Minimum for TCP transfer is 8 bytes, provide only 7
    std::vector<uint8_t> data(7, 0);

    EVENT_RECORD record = make_record(ids::network::TCP_SEND);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_network_event(&record, strings_.get());

    EXPECT_FALSE(result.valid);
}

// =============================================================================
// 7. Payload Initialization
// =============================================================================

TEST_F(NetworkParserTest, ParseNetworkEvent_InitializesDefaults) {
    auto data = build_udp_event_data();

    EVENT_RECORD record = make_record(ids::network::UDP_SEND);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_network_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::Network);
    EXPECT_EQ(result.payload.network.local_addr, 0u);
    EXPECT_EQ(result.payload.network.remote_addr, 0u);
    EXPECT_EQ(result.payload.network.local_port, 0u);
    EXPECT_EQ(result.payload.network.remote_port, 0u);
    EXPECT_EQ(result.payload.network.bytes, 0u);

    // Verify _pad is zeroed
    EXPECT_EQ(result.payload.network._pad[0], 0);
    EXPECT_EQ(result.payload.network._pad[1], 0);
    EXPECT_EQ(result.payload.network._pad[2], 0);
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(NetworkParserTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32
