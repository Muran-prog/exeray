/// @file constants.hpp
/// @brief CLR Runtime event constants.

#pragma once

#ifdef _WIN32

#include "exeray/etw/event_ids.hpp"

namespace exeray::etw::clr {

/// Alias for centralized CLR event IDs.
namespace event_ids = exeray::etw::ids::clr;

}  // namespace exeray::etw::clr

#endif  // _WIN32
