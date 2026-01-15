/// @file exeray/etw/provider_mapping.hpp
/// @brief Provider name to GUID mapping utility.
#pragma once

#include <optional>
#include <string_view>
#include "exeray/platform/guid.hpp"

namespace exeray::etw {

/// @brief Map provider name to GUID.
/// @param name Provider name (e.g., "Process", "File", "Registry").
/// @return GUID if known, nullopt otherwise.
std::optional<GUID> get_provider_guid(std::string_view name);

}  // namespace exeray::etw
