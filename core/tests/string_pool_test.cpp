#include <gtest/gtest.h>

#include <string>
#include <thread>
#include <vector>

#include "exeray/arena.hpp"
#include "exeray/event/string_pool.hpp"

namespace exeray::event {
namespace {

class StringPoolTest : public ::testing::Test {
protected:
    static constexpr std::size_t kArenaSize = 64 * 1024;  // 64KB

    Arena arena_{kArenaSize};
    StringPool pool_{arena_};
};

// ---------------------------------------------------------------------------
// Basic Functionality Tests
// ---------------------------------------------------------------------------

TEST_F(StringPoolTest, InternAndGetRoundtrip) {
    const std::string_view input = "hello";
    StringId id = pool_.intern(input);

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), input);
}

TEST_F(StringPoolTest, RepeatedInternReturnsSameId) {
    const std::string_view input = "hello";

    StringId id1 = pool_.intern(input);
    StringId id2 = pool_.intern(input);

    EXPECT_NE(id1, INVALID_STRING);
    EXPECT_EQ(id1, id2);
}

TEST_F(StringPoolTest, DifferentStringsGetDifferentIds) {
    StringId id1 = pool_.intern("hello");
    StringId id2 = pool_.intern("world");

    EXPECT_NE(id1, INVALID_STRING);
    EXPECT_NE(id2, INVALID_STRING);
    EXPECT_NE(id1, id2);
}

TEST_F(StringPoolTest, EmptyStringWorks) {
    StringId id = pool_.intern("");

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), "");
}

TEST_F(StringPoolTest, GetInvalidStringReturnsEmptyView) {
    std::string_view result = pool_.get(INVALID_STRING);
    EXPECT_TRUE(result.empty());
}

// ---------------------------------------------------------------------------
// Stats Tests
// ---------------------------------------------------------------------------

TEST_F(StringPoolTest, CountIncrementsForNewStrings) {
    EXPECT_EQ(pool_.count(), 0U);

    pool_.intern("one");
    EXPECT_EQ(pool_.count(), 1U);

    pool_.intern("two");
    EXPECT_EQ(pool_.count(), 2U);

    // Duplicate should not increment count
    pool_.intern("one");
    EXPECT_EQ(pool_.count(), 2U);
}

TEST_F(StringPoolTest, BytesUsedTracksStorage) {
    EXPECT_EQ(pool_.bytes_used(), 0U);

    pool_.intern("hello");  // 4 bytes len + 5 bytes data = 9 bytes
    EXPECT_EQ(pool_.bytes_used(), 4U + 5U);

    pool_.intern("world");  // Another 9 bytes
    EXPECT_EQ(pool_.bytes_used(), 2 * (4U + 5U));
}

// ---------------------------------------------------------------------------
// Edge Cases
// ---------------------------------------------------------------------------

TEST_F(StringPoolTest, LongStringWorks) {
    std::string long_str(1000, 'x');
    StringId id = pool_.intern(long_str);

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), long_str);
}

TEST_F(StringPoolTest, ManyStringsWork) {
    constexpr int kNumStrings = 1000;

    std::vector<StringId> ids;
    ids.reserve(kNumStrings);

    for (int i = 0; i < kNumStrings; ++i) {
        ids.push_back(pool_.intern("str" + std::to_string(i)));
    }

    // Verify all can be retrieved
    for (int i = 0; i < kNumStrings; ++i) {
        EXPECT_EQ(pool_.get(ids[i]), "str" + std::to_string(i));
    }

    EXPECT_EQ(pool_.count(), kNumStrings);
}

// ---------------------------------------------------------------------------
// Thread Safety Tests
// ---------------------------------------------------------------------------

TEST_F(StringPoolTest, ConcurrentInternsSameString) {
    constexpr int kNumThreads = 4;
    constexpr int kItersPerThread = 100;

    std::vector<StringId> results(kNumThreads * kItersPerThread);
    std::vector<std::thread> threads;

    for (int t = 0; t < kNumThreads; ++t) {
        threads.emplace_back([this, t, &results]() {
            for (int i = 0; i < kItersPerThread; ++i) {
                results[t * kItersPerThread + i] = pool_.intern("shared");
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    // All should be the same ID
    StringId expected = results[0];
    for (auto id : results) {
        EXPECT_EQ(id, expected);
    }

    EXPECT_EQ(pool_.count(), 1U);
}

TEST_F(StringPoolTest, ConcurrentInternsDifferentStrings) {
    constexpr int kNumThreads = 4;
    constexpr int kItersPerThread = 50;

    std::vector<std::thread> threads;

    for (int t = 0; t < kNumThreads; ++t) {
        threads.emplace_back([this, t]() {
            for (int i = 0; i < kItersPerThread; ++i) {
                std::string str = "thread" + std::to_string(t) +
                                  "_iter" + std::to_string(i);
                StringId id = pool_.intern(str);
                EXPECT_NE(id, INVALID_STRING);
                EXPECT_EQ(pool_.get(id), str);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    EXPECT_EQ(pool_.count(), kNumThreads * kItersPerThread);
}

}  // namespace
}  // namespace exeray::event
