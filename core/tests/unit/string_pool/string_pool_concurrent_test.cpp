#include "string_pool_test_common.hpp"

namespace exeray::event {
namespace {

// ============================================================================
// 7. Concurrent Operations Tests
// ============================================================================

TEST_F(StringPoolTest, Intern_ConcurrentSameString_AllGetSameId) {
    constexpr int kNumThreads = 8;
    constexpr int kItersPerThread = 1000;

    std::vector<StringId> results(kNumThreads * kItersPerThread);
    std::vector<std::thread> threads;

    for (int t = 0; t < kNumThreads; ++t) {
        threads.emplace_back([this, t, &results]() {
            for (int i = 0; i < kItersPerThread; ++i) {
                results[t * kItersPerThread + i] = pool_.intern("shared_string");
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    // All results should be the same ID
    StringId expected = results[0];
    EXPECT_NE(expected, INVALID_STRING);
    
    for (const auto& id : results) {
        EXPECT_EQ(id, expected);
    }

    // Only one string should be interned
    EXPECT_EQ(pool_.count(), 1U);
}

TEST_F(StringPoolTest, Intern_ConcurrentDifferentStrings_AllUnique) {
    constexpr int kNumThreads = 10;
    constexpr int kStringsPerThread = 1000;

    std::vector<std::vector<StringId>> thread_ids(kNumThreads);
    std::vector<std::thread> threads;

    for (int t = 0; t < kNumThreads; ++t) {
        thread_ids[t].reserve(kStringsPerThread);
        threads.emplace_back([this, t, &thread_ids]() {
            for (int i = 0; i < kStringsPerThread; ++i) {
                std::string str = "t" + std::to_string(t) + "_s" + std::to_string(i);
                StringId id = pool_.intern(str);
                EXPECT_NE(id, INVALID_STRING);
                thread_ids[t].push_back(id);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    // Collect all IDs and verify uniqueness
    std::set<StringId> unique_ids;
    for (const auto& ids : thread_ids) {
        for (StringId id : ids) {
            auto [_, inserted] = unique_ids.insert(id);
            EXPECT_TRUE(inserted) << "Duplicate ID detected!";
        }
    }

    EXPECT_EQ(unique_ids.size(), kNumThreads * kStringsPerThread);
    EXPECT_EQ(pool_.count(), kNumThreads * kStringsPerThread);
}

TEST_F(StringPoolTest, Intern_ConcurrentWithGet_NoRace) {
    // Pre-intern some strings
    constexpr int kPreIntern = 100;
    std::vector<StringId> pre_ids;
    pre_ids.reserve(kPreIntern);

    for (int i = 0; i < kPreIntern; ++i) {
        pre_ids.push_back(pool_.intern("pre_" + std::to_string(i)));
    }

    constexpr int kNumInternThreads = 4;
    constexpr int kNumGetThreads = 4;
    constexpr int kItersPerThread = 1000;

    std::atomic<bool> found_mismatch{false};
    std::vector<std::thread> threads;

    // Intern threads
    for (int t = 0; t < kNumInternThreads; ++t) {
        threads.emplace_back([this, t]() {
            for (int i = 0; i < kItersPerThread; ++i) {
                pool_.intern("intern_t" + std::to_string(t) + "_i" + std::to_string(i));
            }
        });
    }

    // Get threads - read pre-interned strings
    for (int t = 0; t < kNumGetThreads; ++t) {
        threads.emplace_back([this, &pre_ids, &found_mismatch]() {
            for (int i = 0; i < kItersPerThread; ++i) {
                int idx = i % kPreIntern;
                std::string_view result = pool_.get(pre_ids[idx]);
                std::string expected = "pre_" + std::to_string(idx);
                if (result != expected) {
                    found_mismatch.store(true, std::memory_order_relaxed);
                }
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    EXPECT_FALSE(found_mismatch.load()) << "Data race detected: get() returned wrong value";
}

TEST_F(StringPoolTest, Intern_HighContention_StressTest) {
    // 100 threads, 100 unique strings, 1000 repeats each
    // All threads intern the same 100 strings repeatedly
    constexpr int kNumThreads = 100;
    constexpr int kNumStrings = 100;
    constexpr int kRepeatsPerString = 100;

    // Pre-generate expected strings
    std::vector<std::string> strings;
    strings.reserve(kNumStrings);
    for (int i = 0; i < kNumStrings; ++i) {
        strings.push_back("common_" + std::to_string(i));
    }

    std::vector<std::vector<StringId>> thread_results(kNumThreads);
    std::vector<std::thread> threads;

    for (int t = 0; t < kNumThreads; ++t) {
        thread_results[t].reserve(kNumStrings * kRepeatsPerString);
        threads.emplace_back([this, t, &strings, &thread_results]() {
            for (int r = 0; r < kRepeatsPerString; ++r) {
                for (int s = 0; s < kNumStrings; ++s) {
                    thread_results[t].push_back(pool_.intern(strings[s]));
                }
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    // Verify: all interns of same string should return same ID
    // Build map from string index to expected ID (from first thread's first iteration)
    std::vector<StringId> expected_ids(kNumStrings);
    for (int s = 0; s < kNumStrings; ++s) {
        expected_ids[s] = thread_results[0][s];
        EXPECT_NE(expected_ids[s], INVALID_STRING);
    }

    // Verify all threads got same IDs for same strings
    for (int t = 0; t < kNumThreads; ++t) {
        for (int r = 0; r < kRepeatsPerString; ++r) {
            for (int s = 0; s < kNumStrings; ++s) {
                int idx = r * kNumStrings + s;
                EXPECT_EQ(thread_results[t][idx], expected_ids[s])
                    << "Thread " << t << " repeat " << r << " string " << s;
            }
        }
    }

    // Only 100 unique strings should exist
    EXPECT_EQ(pool_.count(), kNumStrings);
}

}  // namespace
}  // namespace exeray::event
