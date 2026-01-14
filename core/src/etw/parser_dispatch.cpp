/// @file parser_dispatch.cpp
/// @brief ETW event dispatcher routing events to appropriate parsers.

#ifdef _WIN32

#include "exeray/etw/parser.hpp"
#include "exeray/etw/session.hpp"

#include <cstring>

namespace exeray::etw {

namespace {

/// @brief Compare two GUIDs for equality.
bool guid_equal(const GUID& a, const GUID& b) {
    return std::memcmp(&a, &b, sizeof(GUID)) == 0;
}

}  // namespace

ParsedEvent dispatch_event(const EVENT_RECORD* record, event::StringPool* strings) {
    if (record == nullptr) {
        return ParsedEvent{.valid = false};
    }

    const GUID& provider = record->EventHeader.ProviderId;

    // Route to appropriate parser based on provider GUID
    if (guid_equal(provider, providers::KERNEL_PROCESS)) {
        return parse_process_event(record, strings);
    }
    if (guid_equal(provider, providers::KERNEL_FILE)) {
        return parse_file_event(record, strings);
    }
    if (guid_equal(provider, providers::KERNEL_REGISTRY)) {
        return parse_registry_event(record, strings);
    }
    if (guid_equal(provider, providers::KERNEL_NETWORK)) {
        return parse_network_event(record, strings);
    }
    if (guid_equal(provider, providers::KERNEL_IMAGE)) {
        return parse_image_event(record, strings);
    }
    if (guid_equal(provider, providers::KERNEL_THREAD)) {
        return parse_thread_event(record, strings);
    }
    if (guid_equal(provider, providers::KERNEL_MEMORY)) {
        return parse_memory_event(record, strings);
    }
    if (guid_equal(provider, providers::POWERSHELL)) {
        return parse_powershell_event(record, strings);
    }
    if (guid_equal(provider, providers::AMSI)) {
        return parse_amsi_event(record, strings);
    }
    if (guid_equal(provider, providers::DNS_CLIENT)) {
        return parse_dns_event(record, strings);
    }
    if (guid_equal(provider, providers::SECURITY_AUDITING)) {
        return parse_security_event(record, strings);
    }

    // Unknown provider - return invalid
    return ParsedEvent{.valid = false};
}

}  // namespace exeray::etw

#else  // !_WIN32

namespace exeray::etw {
// Stub defined in header as inline
}  // namespace exeray::etw

#endif  // _WIN32
