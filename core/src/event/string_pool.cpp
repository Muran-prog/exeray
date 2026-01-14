#include "exeray/event/string_pool.hpp"

#include <cstring>
#include <mutex>

namespace exeray::event {

StringPool::StringPool(Arena& arena, std::size_t initial_capacity)
    : arena_(arena), strings_(initial_capacity) {}

StringId StringPool::intern(std::string_view str) {
    // Fast path: read-only lookup
    {
        std::shared_lock lock(mutex_);
        auto it = strings_.find(str);
        if (it != strings_.end()) {
            return it->second;
        }
    }

    // Slow path: need to insert
    std::unique_lock lock(mutex_);

    // Double-check after acquiring exclusive lock
    auto it = strings_.find(str);
    if (it != strings_.end()) {
        return it->second;
    }

    // Allocate: [len:u32][chars...]
    const auto len = static_cast<std::uint32_t>(str.size());
    const std::size_t total_size = sizeof(std::uint32_t) + str.size();

    auto* storage = arena_.allocate<std::uint8_t>(total_size);
    if (storage == nullptr) {
        return INVALID_STRING;
    }

    // StringId = offset + 1 (so offset 0 maps to ID 1, never returning 0)
    const auto id = static_cast<StringId>(
        static_cast<std::size_t>(storage - arena_.base()) + 1);

    // Write length prefix
    std::memcpy(storage, &len, sizeof(len));

    // Write string data
    if (len > 0) {
        std::memcpy(storage + sizeof(len), str.data(), len);
    }

    // Create stable string_view pointing to arena memory
    std::string_view stored{
        reinterpret_cast<const char*>(storage + sizeof(len)), len};

    strings_.emplace(stored, id);
    bytes_used_ += total_size;

    return id;
}

StringId StringPool::intern_wide(std::wstring_view wstr) {
    if (wstr.empty()) {
        return intern("");
    }

    // Convert wide string to UTF-8 (simplified - handles ASCII range)
    // For full Unicode support, use WideCharToMultiByte on Windows
    std::string utf8;
    utf8.reserve(wstr.size());
    for (wchar_t wc : wstr) {
        if (wc < 0x80) {
            utf8.push_back(static_cast<char>(wc));
        } else if (wc < 0x800) {
            utf8.push_back(static_cast<char>(0xC0 | (wc >> 6)));
            utf8.push_back(static_cast<char>(0x80 | (wc & 0x3F)));
        } else {
            utf8.push_back(static_cast<char>(0xE0 | (wc >> 12)));
            utf8.push_back(static_cast<char>(0x80 | ((wc >> 6) & 0x3F)));
            utf8.push_back(static_cast<char>(0x80 | (wc & 0x3F)));
        }
    }

    return intern(utf8);
}

std::string_view StringPool::get(StringId id) const noexcept {
    if (id == INVALID_STRING) {
        return {};
    }

    // ID = offset + 1, so offset = ID - 1
    const auto* storage = arena_.base() + (id - 1);

    std::uint32_t len = 0;
    std::memcpy(&len, storage, sizeof(len));

    return {reinterpret_cast<const char*>(storage + sizeof(len)), len};
}

std::size_t StringPool::count() const noexcept {
    std::shared_lock lock(mutex_);
    return strings_.size();
}

std::size_t StringPool::bytes_used() const noexcept {
    std::shared_lock lock(mutex_);
    return bytes_used_;
}

}  // namespace exeray::event
