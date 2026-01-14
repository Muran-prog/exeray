/// @file parser_network.cpp
/// @brief ETW parser for Microsoft-Windows-Kernel-Network events.

#ifdef _WIN32

#include "exeray/etw/parser.hpp"
#include "exeray/etw/session.hpp"

#include <cstring>

namespace exeray::etw {

namespace {

/// Network event IDs from Microsoft-Windows-Kernel-Network provider.
/// Note: Actual event IDs may vary by Windows version.
enum class NetworkEventId : uint16_t {
    TcpConnect = 10,
    TcpAccept = 11,
    TcpSend = 14,
    TcpReceive = 15,
    UdpSend = 18,
    UdpReceive = 19
};

/// Protocol numbers (IANA).
constexpr uint8_t PROTO_TCP = 6;
constexpr uint8_t PROTO_UDP = 17;

/// @brief Extract common fields from EVENT_RECORD header.
void extract_common(const EVENT_RECORD* record, ParsedEvent& out) {
    out.pid = record->EventHeader.ProcessId;
    out.timestamp = static_cast<uint64_t>(record->EventHeader.TimeStamp.QuadPart);
    out.status = event::Status::Success;
    out.category = event::Category::Network;
}

/// @brief Initialize network payload with defaults.
void init_network_payload(ParsedEvent& result) {
    result.payload.category = event::Category::Network;
    result.payload.network.local_addr = 0;
    result.payload.network.remote_addr = 0;
    result.payload.network.local_port = 0;
    result.payload.network.remote_port = 0;
    result.payload.network.bytes = 0;
    result.payload.network.protocol = 0;
    std::memset(result.payload.network._pad, 0, sizeof(result.payload.network._pad));
}

/// @brief Parse TCP connection event.
///
/// Common UserData layout for TCP events:
///   ProcessId: UINT32
///   AddressFamily: UINT16
///   LocalAddr: 4 bytes (IPv4) or 16 bytes (IPv6)
///   LocalPort: UINT16
///   RemoteAddr: 4 bytes (IPv4) or 16 bytes (IPv6)
///   RemotePort: UINT16
ParsedEvent parse_tcp_connect(const EVENT_RECORD* record) {
    ParsedEvent result{};
    extract_common(record, result);
    result.operation = static_cast<uint8_t>(event::NetworkOp::Connect);
    init_network_payload(result);
    result.payload.network.protocol = PROTO_TCP;

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    // Minimum size for IPv4: pid(4) + af(2) + laddr(4) + lport(2) + raddr(4) + rport(2) = 18
    if (data == nullptr || len < 18) {
        result.valid = false;
        return result;
    }

    size_t offset = 0;

    // PID
    uint32_t pid = 0;
    std::memcpy(&pid, data + offset, sizeof(uint32_t));
    result.payload.network.local_addr = 0;  // Will be populated below
    offset += sizeof(uint32_t);

    // Address family
    uint16_t af = 0;
    std::memcpy(&af, data + offset, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    // IPv4 only (af == 2)
    if (af == 2 && offset + 12 <= len) {
        uint32_t local_addr = 0;
        uint16_t local_port = 0;
        uint32_t remote_addr = 0;
        uint16_t remote_port = 0;

        std::memcpy(&local_addr, data + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        std::memcpy(&local_port, data + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        std::memcpy(&remote_addr, data + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        std::memcpy(&remote_port, data + offset, sizeof(uint16_t));

        result.payload.network.local_addr = local_addr;
        result.payload.network.local_port = local_port;
        result.payload.network.remote_addr = remote_addr;
        result.payload.network.remote_port = remote_port;
    }

    result.valid = true;
    return result;
}

/// @brief Parse TCP data transfer event (send/receive).
ParsedEvent parse_tcp_transfer(const EVENT_RECORD* record, event::NetworkOp op) {
    ParsedEvent result{};
    extract_common(record, result);
    result.operation = static_cast<uint8_t>(op);
    init_network_payload(result);
    result.payload.network.protocol = PROTO_TCP;

    const auto* data = static_cast<const uint8_t*>(record->UserData);
    const auto len = record->UserDataLength;

    if (data == nullptr || len < 8) {
        result.valid = false;
        return result;
    }

    // Transfer events typically have: pid, size, connection info
    // Extract size from common position
    uint32_t bytes = 0;
    if (len >= 8) {
        std::memcpy(&bytes, data + 4, sizeof(uint32_t));
        result.payload.network.bytes = bytes;
    }

    result.valid = true;
    return result;
}

/// @brief Parse UDP event.
ParsedEvent parse_udp_event(const EVENT_RECORD* record, event::NetworkOp op) {
    ParsedEvent result{};
    extract_common(record, result);
    result.operation = static_cast<uint8_t>(op);
    init_network_payload(result);
    result.payload.network.protocol = PROTO_UDP;
    result.valid = true;
    return result;
}

}  // namespace

ParsedEvent parse_network_event(const EVENT_RECORD* record, event::StringPool* /*strings*/) {
    if (record == nullptr) {
        return ParsedEvent{.valid = false};
    }

    const auto event_id = static_cast<NetworkEventId>(record->EventHeader.EventDescriptor.Id);

    switch (event_id) {
        case NetworkEventId::TcpConnect:
        case NetworkEventId::TcpAccept:
            return parse_tcp_connect(record);
        case NetworkEventId::TcpSend:
            return parse_tcp_transfer(record, event::NetworkOp::Send);
        case NetworkEventId::TcpReceive:
            return parse_tcp_transfer(record, event::NetworkOp::Receive);
        case NetworkEventId::UdpSend:
            return parse_udp_event(record, event::NetworkOp::Send);
        case NetworkEventId::UdpReceive:
            return parse_udp_event(record, event::NetworkOp::Receive);
        default:
            return ParsedEvent{.valid = false};
    }
}

}  // namespace exeray::etw

#else  // !_WIN32

namespace exeray::etw {
// Stub defined in header as inline
}  // namespace exeray::etw

#endif  // _WIN32
