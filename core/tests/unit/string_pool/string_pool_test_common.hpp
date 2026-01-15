#pragma once

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "exeray/arena.hpp"
#include "exeray/event/string_pool.hpp"

namespace exeray::event {

class StringPoolTest : public ::testing::Test {
protected:
    static constexpr std::size_t kDefaultArenaSize = 1024 * 1024;  // 1MB

    Arena arena_{kDefaultArenaSize};
    StringPool pool_{arena_};
};

}  // namespace exeray::event

