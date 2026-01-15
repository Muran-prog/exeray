#pragma once

/// @file tdh_parser.hpp
/// @brief TDH (Trace Data Helper) fallback parser for unknown ETW event versions.
/// @note This header provides backward compatibility by including modular headers.

// Include all modular headers for backward compatibility
#include "exeray/etw/tdh/schema_cache.hpp"
#include "exeray/etw/tdh/parser.hpp"
#include "exeray/etw/tdh/converters.hpp"

#ifdef _WIN32
#include "exeray/etw/tdh/internal.hpp"
#endif
