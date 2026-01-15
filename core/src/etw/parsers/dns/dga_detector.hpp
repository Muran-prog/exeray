/// @file dga_detector.hpp
/// @brief DGA (Domain Generation Algorithm) detection interface.
///
/// Provides Shannon entropy analysis and heuristic pattern matching
/// to identify potentially malicious auto-generated domains.

#pragma once

#include <string_view>

namespace exeray::etw::dns {

/// @brief Calculate Shannon entropy of a domain name.
///
/// Higher entropy indicates more randomness, typical of DGA domains.
/// Normal domains: 2.5-3.5, DGA domains: 3.8+
///
/// @param domain The domain name to analyze.
/// @return Entropy value (0.0 to ~4.7 for lowercase alphanumeric).
float calculate_entropy(std::wstring_view domain);

/// @brief Check if domain appears to be a DGA-generated domain.
///
/// DGA detection heuristics:
/// - Domain length > 20 chars (excluding TLD)
/// - High Shannon entropy (> 3.8)
/// - High digit ratio in subdomain (> 30%)
/// - Absence of vowels in long subdomains
///
/// @param domain The domain name to check.
/// @return true if domain appears suspicious.
bool is_dga_suspicious(std::wstring_view domain);

}  // namespace exeray::etw::dns
