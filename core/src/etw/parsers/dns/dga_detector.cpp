/// @file dga_detector.cpp
/// @brief DGA detection implementation.

#ifdef _WIN32

#include "dga_detector.hpp"
#include <cmath>

namespace exeray::etw::dns {

float calculate_entropy(std::wstring_view domain) {
    if (domain.empty()) {
        return 0.0f;
    }

    // Count character frequencies
    int freq[256] = {0};
    size_t count = 0;

    for (wchar_t c : domain) {
        if (c == L'.') continue;  // Skip dots in entropy calc
        // Fold to lowercase ASCII for frequency counting
        unsigned char ch = static_cast<unsigned char>(c & 0xFF);
        if (c > 255) ch = 'x';  // Treat unicode as 'x'
        if (ch >= 'A' && ch <= 'Z') ch = ch - 'A' + 'a';
        freq[ch]++;
        count++;
    }

    if (count == 0) {
        return 0.0f;
    }

    // Calculate entropy
    float entropy = 0.0f;
    for (int f : freq) {
        if (f > 0) {
            float p = static_cast<float>(f) / static_cast<float>(count);
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

bool is_dga_suspicious(std::wstring_view domain) {
    if (domain.empty()) {
        return false;
    }

    // Find the subdomain (part before first dot or entire domain)
    size_t dot_pos = domain.find(L'.');
    std::wstring_view subdomain = (dot_pos != std::wstring_view::npos)
        ? domain.substr(0, dot_pos)
        : domain;

    // Heuristic 1: Long subdomain (> 20 chars)
    if (subdomain.size() > 20) {
        return true;
    }

    // Heuristic 2: High entropy (> 3.8)
    float entropy = calculate_entropy(subdomain);
    if (entropy > 3.8f) {
        return true;
    }

    // Heuristic 3: High digit ratio in subdomain (> 30%)
    size_t digit_count = 0;
    for (wchar_t c : subdomain) {
        if (c >= L'0' && c <= L'9') {
            digit_count++;
        }
    }
    if (subdomain.size() > 5 &&
        static_cast<float>(digit_count) / static_cast<float>(subdomain.size()) > 0.3f) {
        return true;
    }

    // Heuristic 4: No vowels (common in random strings)
    bool has_vowel = false;
    for (wchar_t c : subdomain) {
        wchar_t lower = (c >= L'A' && c <= L'Z') ? (c - L'A' + L'a') : c;
        if (lower == L'a' || lower == L'e' || lower == L'i' ||
            lower == L'o' || lower == L'u') {
            has_vowel = true;
            break;
        }
    }
    if (subdomain.size() > 8 && !has_vowel) {
        return true;
    }

    return false;
}

}  // namespace exeray::etw::dns

#endif  // _WIN32
