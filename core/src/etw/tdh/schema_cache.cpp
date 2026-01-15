/// @file schema_cache.cpp
/// @brief TdhSchemaCache implementation.

#ifdef _WIN32

#include "exeray/etw/tdh/schema_cache.hpp"
#include <cstring>
#include <functional>

namespace exeray::etw {

bool TdhSchemaCache::EventKey::operator==(const EventKey& other) const {
    return event_id == other.event_id &&
           event_version == other.event_version &&
           memcmp(&provider_guid, &other.provider_guid, sizeof(GUID)) == 0;
}

size_t TdhSchemaCache::EventKeyHash::operator()(const EventKey& key) const {
    size_t h = std::hash<uint32_t>{}(key.provider_guid.Data1);
    h ^= std::hash<uint16_t>{}(key.provider_guid.Data2) << 1;
    h ^= std::hash<uint16_t>{}(key.provider_guid.Data3) << 2;
    h ^= std::hash<uint16_t>{}(key.event_id) << 3;
    h ^= std::hash<uint8_t>{}(key.event_version) << 4;
    return h;
}

PTRACE_EVENT_INFO TdhSchemaCache::get_schema(const EVENT_RECORD* record) {
    if (record == nullptr) {
        return nullptr;
    }
    
    EventKey key{
        record->EventHeader.ProviderId,
        record->EventHeader.EventDescriptor.Id,
        record->EventHeader.EventDescriptor.Version
    };
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check cache first
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        return reinterpret_cast<PTRACE_EVENT_INFO>(it->second.data());
    }
    
    // Not in cache, fetch from TDH
    ULONG buffer_size = 0;
    ULONG status = TdhGetEventInformation(
        const_cast<PEVENT_RECORD>(record),
        0, nullptr,
        nullptr,
        &buffer_size
    );
    
    if (status != ERROR_INSUFFICIENT_BUFFER || buffer_size == 0) {
        return nullptr;
    }
    
    std::vector<BYTE> buffer(buffer_size);
    status = TdhGetEventInformation(
        const_cast<PEVENT_RECORD>(record),
        0, nullptr,
        reinterpret_cast<PTRACE_EVENT_INFO>(buffer.data()),
        &buffer_size
    );
    
    if (status != ERROR_SUCCESS) {
        return nullptr;
    }
    
    // Store in cache and return
    auto [insert_it, inserted] = cache_.emplace(key, std::move(buffer));
    return reinterpret_cast<PTRACE_EVENT_INFO>(insert_it->second.data());
}

void TdhSchemaCache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();
}

size_t TdhSchemaCache::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cache_.size();
}

}  // namespace exeray::etw

#else  // !_WIN32

namespace exeray::etw {
// Empty translation unit for non-Windows
}

#endif  // _WIN32
