/// @file brute_force_tracker.cpp
/// @brief Brute force attack detection implementation.

#ifdef _WIN32

#include "brute_force_tracker.hpp"

#include <algorithm>

namespace exeray::etw::security {

bool BruteForceTracker::check_and_record(std::wstring_view user) {
    std::lock_guard<std::mutex> lock(mutex);
    
    auto now = std::chrono::steady_clock::now();
    std::wstring key(user);
    auto& times = failures[key];
    
    // Remove old entries outside the window
    auto cutoff = now - WINDOW;
    times.erase(std::remove_if(times.begin(), times.end(),
        [cutoff](auto& t) { return t < cutoff; }), times.end());
    
    // Add current failure
    times.push_back(now);
    
    // Check if threshold exceeded
    return times.size() >= THRESHOLD;
}

/// Global brute force tracker instance.
static BruteForceTracker g_brute_force_tracker;

BruteForceTracker& get_brute_force_tracker() {
    return g_brute_force_tracker;
}

}  // namespace exeray::etw::security

#endif  // _WIN32
