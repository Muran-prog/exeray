/// @file parser_dispatch.cpp
/// @brief ETW event dispatcher routing events to appropriate parsers.

#ifdef _WIN32

#include "exeray/etw/parser.hpp"
#include "exeray/etw/session.hpp"

#include <cstring>
#include <unordered_map>

namespace exeray::etw {

namespace {

/// @brief Hash functor for GUID keys in unordered_map.
struct GuidHash {
    std::size_t operator()(const GUID& g) const noexcept {
        // Combine Data1, Data2, Data3, and Data4 into a single hash
        std::size_t h = std::hash<uint32_t>{}(g.Data1);
        h ^= std::hash<uint16_t>{}(g.Data2) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(g.Data3) + 0x9e3779b9 + (h << 6) + (h >> 2);
        for (int i = 0; i < 8; ++i) {
            h ^= std::hash<uint8_t>{}(g.Data4[i]) + 0x9e3779b9 + (h << 6) + (h >> 2);
        }
        return h;
    }
};

/// @brief Equality functor for GUID keys in unordered_map.
struct GuidEqual {
    bool operator()(const GUID& a, const GUID& b) const noexcept {
        return std::memcmp(&a, &b, sizeof(GUID)) == 0;
    }
};

/// @brief Function pointer type for parser functions.
using ParseFunc = ParsedEvent(*)(const EVENT_RECORD*, event::StringPool*);

/// @brief Static dispatch table mapping provider GUIDs to parser functions.
static const std::unordered_map<GUID, ParseFunc, GuidHash, GuidEqual> dispatch_table = {
    {providers::KERNEL_PROCESS,    parse_process_event},
    {providers::KERNEL_FILE,       parse_file_event},
    {providers::KERNEL_REGISTRY,   parse_registry_event},
    {providers::KERNEL_NETWORK,    parse_network_event},
    {providers::KERNEL_IMAGE,      parse_image_event},
    {providers::KERNEL_THREAD,     parse_thread_event},
    {providers::KERNEL_MEMORY,     parse_memory_event},
    {providers::POWERSHELL,        parse_powershell_event},
    {providers::AMSI,              parse_amsi_event},
    {providers::DNS_CLIENT,        parse_dns_event},
    {providers::SECURITY_AUDITING, parse_security_event},
    {providers::WMI_ACTIVITY,      parse_wmi_event},
    {providers::CLR_RUNTIME,       parse_clr_event},
};

}  // namespace

ParsedEvent dispatch_event(const EVENT_RECORD* record, event::StringPool* strings) {
    if (record == nullptr) {
        return ParsedEvent{.valid = false};
    }

    const GUID& provider = record->EventHeader.ProviderId;

    auto it = dispatch_table.find(provider);
    return (it != dispatch_table.end()) ? it->second(record, strings)
                                        : ParsedEvent{.valid = false};
}

}  // namespace exeray::etw

#else  // !_WIN32

namespace exeray::etw {
// Stub defined in header as inline
}  // namespace exeray::etw

#endif  // _WIN32
