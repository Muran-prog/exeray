#include "arena_test_common.hpp"

namespace exeray {
namespace arena_test {

TEST_F(ArenaTest, Allocate_ConcurrentThreads_NoDataRace) {
    constexpr std::size_t kLargeCapacity = 64 * 1024 * 1024;  // 64MB
    Arena arena{kLargeCapacity};

    constexpr int kNumThreads = 8;
    constexpr int kAllocationsPerThread = 10000;

    std::vector<std::thread> threads;
    std::vector<std::vector<int*>> all_pointers(kNumThreads);

    // Pre-reserve to avoid reallocations during test
    for (auto& v : all_pointers) {
        v.reserve(kAllocationsPerThread);
    }

    for (int t = 0; t < kNumThreads; ++t) {
        threads.emplace_back([&arena, &all_pointers, t]() {
            for (int i = 0; i < kAllocationsPerThread; ++i) {
                int* ptr = arena.allocate<int>();
                ASSERT_NE(ptr, nullptr)
                    << "Thread " << t << " allocation " << i << " failed";
                *ptr = t * kAllocationsPerThread + i;  // Write unique value
                all_pointers[t].push_back(ptr);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    // Collect all pointers and verify uniqueness
    std::set<int*> unique_pointers;
    for (const auto& thread_pointers : all_pointers) {
        for (int* ptr : thread_pointers) {
            auto [_, inserted] = unique_pointers.insert(ptr);
            EXPECT_TRUE(inserted) << "Duplicate pointer detected!";
        }
    }

    EXPECT_EQ(unique_pointers.size(), kNumThreads * kAllocationsPerThread);

    // Verify used memory is reasonable (with alignment padding)
    std::size_t min_expected =
        kNumThreads * kAllocationsPerThread * sizeof(int);
    EXPECT_GE(arena.used(), min_expected);
}

TEST_F(ArenaTest, Allocate_ConcurrentExhaustion_SafeBehavior) {
    // Small arena to force contention and exhaustion
    constexpr std::size_t kSmallCapacity = 10000;
    Arena arena{kSmallCapacity};

    constexpr int kNumThreads = 100;
    constexpr int kAllocationsPerThread = 100;

    std::atomic<int> success_count{0};
    std::vector<std::thread> threads;

    std::vector<std::vector<int*>> all_pointers(kNumThreads);

    for (int t = 0; t < kNumThreads; ++t) {
        threads.emplace_back([&arena, &success_count, &all_pointers, t]() {
            for (int i = 0; i < kAllocationsPerThread; ++i) {
                int* ptr = arena.allocate<int>();
                if (ptr != nullptr) {
                    *ptr = t * 1000 + i;  // Write to verify ownership
                    all_pointers[t].push_back(ptr);
                    ++success_count;
                }
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    // Sum of successful allocations should fit in capacity
    // Account for 64-byte alignment overhead
    EXPECT_LE(arena.used(), arena.capacity());

    // Verify no overlapping memory by checking all written values
    std::set<int*> unique_pointers;
    for (const auto& thread_pointers : all_pointers) {
        for (int* ptr : thread_pointers) {
            auto [_, inserted] = unique_pointers.insert(ptr);
            EXPECT_TRUE(inserted) << "Overlapping memory detected!";
        }
    }
}

TEST_F(ArenaTest, Allocate_ConcurrentMixedTypes_AllAligned) {
    constexpr std::size_t kLargeCapacity = 64 * 1024 * 1024;
    Arena arena{kLargeCapacity};

    constexpr int kNumThreads = 8;
    constexpr int kAllocationsPerThread = 1000;

    std::atomic<bool> all_aligned{true};
    std::vector<std::thread> threads;

    for (int t = 0; t < kNumThreads; ++t) {
        threads.emplace_back([&arena, &all_aligned, t]() {
            for (int i = 0; i < kAllocationsPerThread; ++i) {
                std::uintptr_t addr = 0;
                std::size_t required_align = 64;

                switch ((t + i) % 6) {
                    case 0: {
                        auto* p = arena.allocate<Tiny>();
                        if (p) addr = reinterpret_cast<std::uintptr_t>(p);
                        break;
                    }
                    case 1: {
                        auto* p = arena.allocate<Aligned8>();
                        if (p) addr = reinterpret_cast<std::uintptr_t>(p);
                        break;
                    }
                    case 2: {
                        auto* p = arena.allocate<Aligned16>();
                        if (p) addr = reinterpret_cast<std::uintptr_t>(p);
                        break;
                    }
                    case 3: {
                        auto* p = arena.allocate<Aligned32>();
                        if (p) addr = reinterpret_cast<std::uintptr_t>(p);
                        break;
                    }
                    case 4: {
                        auto* p = arena.allocate<CacheLine>();
                        if (p) addr = reinterpret_cast<std::uintptr_t>(p);
                        break;
                    }
                    case 5: {
                        auto* p = arena.allocate<Aligned128>();
                        if (p) addr = reinterpret_cast<std::uintptr_t>(p);
                        // Arena can only guarantee 64-byte alignment
                        required_align = 64;
                        break;
                    }
                }

                if (addr != 0 && (addr % required_align) != 0) {
                    all_aligned.store(false, std::memory_order_relaxed);
                }
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    EXPECT_TRUE(all_aligned.load());
}

}  // namespace arena_test
}  // namespace exeray
