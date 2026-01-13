#pragma once

#include <cstdint>

namespace exeray {

struct StatusFlags {
    static constexpr std::uint64_t IDLE     = 0;
    static constexpr std::uint64_t PENDING  = 1 << 0;
    static constexpr std::uint64_t COMPLETE = 1 << 1;
    static constexpr std::uint64_t READY    = 1 << 2;
    static constexpr std::uint64_t ERROR    = 1 << 3;
};

}
