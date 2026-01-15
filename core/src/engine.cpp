/// @file engine.cpp
/// @brief Engine implementation forward declaration.
///
/// All actual implementation is in engine/*.cpp files,
/// which are compiled as separate translation units.

#include "exeray/engine.hpp"

exeray::EngineConfig exeray::EngineConfig::with_defaults(std::size_t arena_size,
                                                  std::size_t num_threads) {
    EngineConfig cfg;
    cfg.arena_size = arena_size;
    cfg.num_threads = num_threads;
    cfg.providers = {
        {"Process", {true, 4, 0}},
        {"File", {true, 4, 0}},
        {"Registry", {true, 4, 0}},
        {"Network", {true, 4, 0}},
        {"Image", {true, 4, 0}},
        {"Thread", {true, 4, 0}},
        {"Memory", {true, 5, 0}},       // VERBOSE for detailed info
        {"PowerShell", {true, 5, 0}},
        {"AMSI", {true, 4, 0}},
        {"DNS", {false, 4, 0}},         // Disabled by default
        {"WMI", {false, 4, 0}},
        {"CLR", {false, 4, 0}},
        {"Security", {false, 4, 0}},
    };
    return cfg;
}
