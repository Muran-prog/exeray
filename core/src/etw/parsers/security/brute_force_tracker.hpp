/// @file brute_force_tracker.hpp
/// @brief Brute force attack detection state tracker.

#pragma once

#ifdef _WIN32

#include <chrono>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace exeray::etw::security {

/// Brute force detection state.
struct BruteForceTracker {
    std::mutex mutex;
    std::unordered_map<std::wstring, std::vector<std::chrono::steady_clock::time_point>> failures;
    
    static constexpr size_t THRESHOLD = 5;
    static constexpr std::chrono::seconds WINDOW{60};
    
    /// @brief Check if this represents a brute force attempt.
    /// @param user Username that failed login.
    /// @return True if threshold exceeded within the time window.
    bool check_and_record(std::wstring_view user);
};

/// Global brute force tracker instance.
BruteForceTracker& get_brute_force_tracker();

}  // namespace exeray::etw::security

#endif  // _WIN32
