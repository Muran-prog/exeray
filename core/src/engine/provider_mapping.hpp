/// @file engine/provider_mapping.hpp
/// @brief Internal header for provider mapping utilities.
#pragma once

#include <optional>
#include <string_view>

#ifdef _WIN32
#include <windows.h>

namespace exeray::internal {

/// @brief Map provider name to GUID (Windows implementation).
/// @param name Provider name (e.g., "Process", "File").
/// @return GUID if known, nullopt otherwise.
std::optional<GUID> get_provider_guid(std::string_view name);

}  // namespace exeray::internal
#endif
