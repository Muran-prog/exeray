#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <limits>
#include <set>
#include <thread>
#include <vector>

#include "exeray/arena.hpp"

namespace exeray {
namespace {

// ============================================================================
// Test Fixture
// ============================================================================

class ArenaTest : public ::testing::Test {
protected:
    static constexpr std::size_t kDefaultCapacity = 64 * 1024;  // 64KB
};

// ============================================================================
// Helper Structs for Alignment Tests
// ============================================================================

struct alignas(1) Tiny {
    char c;
};

struct alignas(8) Aligned8 {
    std::uint64_t value;
};

struct alignas(16) Aligned16 {
    char data[16];
};

struct alignas(32) Aligned32 {
    char data[32];
};

struct alignas(64) CacheLine {
    char data[64];
};

struct alignas(128) Aligned128 {
    char data[128];
};

struct Huge {
    char data[1024 * 1024];  // 1MB
};

// ============================================================================
// 1. Basic Allocation Tests
// ============================================================================

TEST_F(ArenaTest, Allocate_SingleObject_ReturnsValidPointer) {
    Arena arena{kDefaultCapacity};

    // Allocate a single int
    int* int_ptr = arena.allocate<int>();
    ASSERT_NE(int_ptr, nullptr);

    // Write and read back
    *int_ptr = 42;
    EXPECT_EQ(*int_ptr, 42);

    // Allocate a struct
    struct TestStruct {
        int a;
        double b;
        char c;
    };

    TestStruct* struct_ptr = arena.allocate<TestStruct>();
    ASSERT_NE(struct_ptr, nullptr);

    struct_ptr->a = 100;
    struct_ptr->b = 3.14159;
    struct_ptr->c = 'X';

    EXPECT_EQ(struct_ptr->a, 100);
    EXPECT_DOUBLE_EQ(struct_ptr->b, 3.14159);
    EXPECT_EQ(struct_ptr->c, 'X');
}

TEST_F(ArenaTest, Allocate_MultipleObjects_PointersNonOverlapping) {
    Arena arena{kDefaultCapacity};
    constexpr int kNumAllocations = 100;

    struct Allocation {
        std::uintptr_t start;
        std::size_t size;
    };

    std::vector<Allocation> allocations;
    allocations.reserve(kNumAllocations);

    // Allocate objects of varying sizes
    for (int i = 0; i < kNumAllocations; ++i) {
        void* ptr = nullptr;
        std::size_t size = 0;

        switch (i % 5) {
            case 0:
                ptr = arena.allocate<char>();
                size = sizeof(char);
                break;
            case 1:
                ptr = arena.allocate<int>();
                size = sizeof(int);
                break;
            case 2:
                ptr = arena.allocate<double>();
                size = sizeof(double);
                break;
            case 3:
                ptr = arena.allocate<CacheLine>();
                size = sizeof(CacheLine);
                break;
            case 4:
                ptr = arena.allocate<char>(16);
                size = 16;
                break;
        }

        ASSERT_NE(ptr, nullptr) << "Allocation " << i << " failed";
        allocations.push_back({reinterpret_cast<std::uintptr_t>(ptr), size});
    }

    // Verify non-overlapping: ptr[i] + size[i] <= ptr[i+1]
    // Sort by start address first
    std::sort(allocations.begin(), allocations.end(),
              [](const Allocation& a, const Allocation& b) {
                  return a.start < b.start;
              });

    for (std::size_t i = 0; i + 1 < allocations.size(); ++i) {
        std::uintptr_t end_i = allocations[i].start + allocations[i].size;
        std::uintptr_t start_next = allocations[i + 1].start;

        EXPECT_LE(end_i, start_next)
            << "Allocation " << i << " [" << std::hex << allocations[i].start
            << ", " << end_i << ") overlaps with allocation " << (i + 1)
            << " starting at " << start_next;
    }
}

TEST_F(ArenaTest, Allocate_Array_ContiguousMemory) {
    Arena arena{kDefaultCapacity};
    constexpr int kArraySize = 1000;

    int* arr = arena.allocate<int>(kArraySize);
    ASSERT_NE(arr, nullptr);

    // Write to all elements including the last one
    for (int i = 0; i < kArraySize; ++i) {
        arr[i] = i * 2;
    }

    // Verify last element is accessible and correct
    EXPECT_EQ(arr[kArraySize - 1], (kArraySize - 1) * 2);

    // Verify contiguity by checking pointer arithmetic
    EXPECT_EQ(&arr[kArraySize - 1], arr + (kArraySize - 1));
}

// ============================================================================
// 2. Alignment Torture Tests
// ============================================================================

TEST_F(ArenaTest, Allocate_Alignment1_WorksCorrectly) {
    Arena arena{kDefaultCapacity};
    constexpr int kNumAllocations = 1000;

    for (int i = 0; i < kNumAllocations; ++i) {
        Tiny* ptr = arena.allocate<Tiny>();
        ASSERT_NE(ptr, nullptr) << "Allocation " << i << " failed";

        // Arena enforces minimum 64-byte alignment
        auto addr = reinterpret_cast<std::uintptr_t>(ptr);
        EXPECT_EQ(addr % 64, 0U)
            << "Allocation " << i << " at " << std::hex << addr
            << " is not 64-byte aligned";
    }
}

TEST_F(ArenaTest, Allocate_Alignment64_ProperlyAligned) {
    Arena arena{kDefaultCapacity};
    constexpr int kNumAllocations = 100;

    for (int i = 0; i < kNumAllocations; ++i) {
        CacheLine* ptr = arena.allocate<CacheLine>();
        ASSERT_NE(ptr, nullptr) << "Allocation " << i << " failed";

        auto addr = reinterpret_cast<std::uintptr_t>(ptr);
        EXPECT_EQ(addr % 64, 0U)
            << "Allocation " << i << " at " << std::hex << addr
            << " is not 64-byte aligned";
    }
}

TEST_F(ArenaTest, Allocate_Alignment128_LimitedTo64Bytes) {
    // NOTE: Arena base memory is allocated with 64-byte alignment,
    // so it cannot guarantee alignment > 64 bytes. This test documents
    // that 128-byte aligned types will get at least 64-byte alignment.
    Arena arena{kDefaultCapacity};
    constexpr int kNumAllocations = 50;

    for (int i = 0; i < kNumAllocations; ++i) {
        Aligned128* ptr = arena.allocate<Aligned128>();
        ASSERT_NE(ptr, nullptr) << "Allocation " << i << " failed";

        auto addr = reinterpret_cast<std::uintptr_t>(ptr);
        // Arena can only guarantee 64-byte alignment (base memory constraint)
        EXPECT_EQ(addr % 64, 0U)
            << "Allocation " << i << " at " << std::hex << addr
            << " is not 64-byte aligned";
    }
}

TEST_F(ArenaTest, Allocate_MixedAlignments_AllCorrect) {
    Arena arena{kDefaultCapacity};

    // Interleave different alignment requirements
    // All get at least 64-byte alignment (Arena's minimum)
    for (int i = 0; i < 50; ++i) {
        Tiny* t = arena.allocate<Tiny>();
        ASSERT_NE(t, nullptr);
        EXPECT_EQ(reinterpret_cast<std::uintptr_t>(t) % 64, 0U);

        Aligned8* a8 = arena.allocate<Aligned8>();
        ASSERT_NE(a8, nullptr);
        EXPECT_EQ(reinterpret_cast<std::uintptr_t>(a8) % 64, 0U);

        Aligned16* a16 = arena.allocate<Aligned16>();
        ASSERT_NE(a16, nullptr);
        EXPECT_EQ(reinterpret_cast<std::uintptr_t>(a16) % 64, 0U);

        Aligned32* a32 = arena.allocate<Aligned32>();
        ASSERT_NE(a32, nullptr);
        EXPECT_EQ(reinterpret_cast<std::uintptr_t>(a32) % 64, 0U);

        CacheLine* cl = arena.allocate<CacheLine>();
        ASSERT_NE(cl, nullptr);
        EXPECT_EQ(reinterpret_cast<std::uintptr_t>(cl) % 64, 0U);

        // Aligned128 gets at least 64-byte alignment (Arena limitation)
        Aligned128* a128 = arena.allocate<Aligned128>();
        ASSERT_NE(a128, nullptr);
        EXPECT_EQ(reinterpret_cast<std::uintptr_t>(a128) % 64, 0U);
    }
}

// ============================================================================
// 3. Capacity Limits Tests
// ============================================================================

TEST_F(ArenaTest, Allocate_ExactCapacity_Succeeds) {
    constexpr std::size_t kCapacity = 1024;
    Arena arena{kCapacity};

    // Due to 64-byte alignment, we can allocate up to capacity
    // Note: First allocation may start at offset 0 (already aligned)
    char* ptr = arena.allocate<char>(kCapacity);

    // Should succeed since arena is 64-byte aligned from start
    ASSERT_NE(ptr, nullptr);
    EXPECT_GE(arena.used(), kCapacity);
    EXPECT_LE(arena.used(), arena.capacity());
}

TEST_F(ArenaTest, Allocate_ExceedsCapacity_ReturnsNullptr) {
    constexpr std::size_t kCapacity = 1024;
    Arena arena{kCapacity};

    std::size_t used_before = arena.used();

    // Try to allocate more than capacity
    char* ptr = arena.allocate<char>(2048);
    EXPECT_EQ(ptr, nullptr);

    // State should not have changed
    EXPECT_EQ(arena.used(), used_before);
}

TEST_F(ArenaTest, Allocate_CapacityExhaustion_GracefulFailure) {
    constexpr std::size_t kCapacity = 1000;
    Arena arena{kCapacity};

    int success_count = 0;
    while (true) {
        char* ptr = arena.allocate<char>(100);
        if (ptr == nullptr) {
            break;
        }
        ++success_count;
    }

    // Should have allocated some but not infinite
    EXPECT_GT(success_count, 0);
    EXPECT_LE(arena.used(), arena.capacity());
}

TEST_F(ArenaTest, Allocate_AfterExhaustion_StillNullptr) {
    constexpr std::size_t kCapacity = 512;
    Arena arena{kCapacity};

    // Exhaust the arena
    while (arena.allocate<CacheLine>() != nullptr) {
        // Keep allocating until exhausted
    }

    std::size_t used_after_exhaustion = arena.used();

    // Multiple attempts after exhaustion should all fail
    for (int i = 0; i < 10; ++i) {
        EXPECT_EQ(arena.allocate<int>(), nullptr);
        EXPECT_EQ(arena.allocate<char>(), nullptr);
        EXPECT_EQ(arena.allocate<CacheLine>(), nullptr);
    }

    // No side effects - used should not change
    EXPECT_EQ(arena.used(), used_after_exhaustion);
}

// ============================================================================
// 4. Overflow Protection Tests
// ============================================================================

TEST_F(ArenaTest, Allocate_CountOverflow_ReturnsNullptr) {
    Arena arena{kDefaultCapacity};

    // sizeof(int) * SIZE_MAX will overflow
    int* ptr = arena.allocate<int>(std::numeric_limits<std::size_t>::max());
    EXPECT_EQ(ptr, nullptr);

    // Arena should still be usable
    int* valid_ptr = arena.allocate<int>();
    EXPECT_NE(valid_ptr, nullptr);
}

TEST_F(ArenaTest, Allocate_SizeOverflow_ReturnsNullptr) {
    Arena arena{kDefaultCapacity};

    // SIZE_MAX / 2 + 1 for a 2-byte type will overflow when multiplied
    std::size_t dangerous_count =
        std::numeric_limits<std::size_t>::max() / sizeof(std::uint16_t) + 1;
    std::uint16_t* ptr = arena.allocate<std::uint16_t>(dangerous_count);
    EXPECT_EQ(ptr, nullptr);
}

TEST_F(ArenaTest, Allocate_BoundaryCount_HandlesCorrectly) {
    // Very large arena for this test
    constexpr std::size_t kHugeCapacity = 16 * 1024 * 1024;  // 16MB
    Arena arena{kHugeCapacity};

    // Boundary case: exactly max / sizeof(T) - should not overflow
    std::size_t max_count =
        std::numeric_limits<std::size_t>::max() / sizeof(int);
    int* ptr = arena.allocate<int>(max_count);

    // Should return nullptr because capacity is too small, not because of
    // overflow
    EXPECT_EQ(ptr, nullptr);

    // But smaller allocations should work
    int* valid = arena.allocate<int>(1000);
    EXPECT_NE(valid, nullptr);
}

// ============================================================================
// 5. Concurrent Access Tests (CRITICAL)
// ============================================================================

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

// ============================================================================
// 6. Reset Behavior Tests
// ============================================================================

TEST_F(ArenaTest, Reset_AfterAllocations_ZeroesOffset) {
    Arena arena{kDefaultCapacity};

    // Allocate some objects
    for (int i = 0; i < 100; ++i) {
        ASSERT_NE(arena.allocate<int>(), nullptr);
    }

    EXPECT_GT(arena.used(), 0U);

    // Reset
    arena.reset();

    EXPECT_EQ(arena.used(), 0U);
}

TEST_F(ArenaTest, Reset_NewAllocationsStartFromBase) {
    Arena arena{kDefaultCapacity};

    // First allocation
    int* first = arena.allocate<int>();
    ASSERT_NE(first, nullptr);

    // More allocations
    for (int i = 0; i < 50; ++i) {
        arena.allocate<CacheLine>();
    }

    // Reset
    arena.reset();

    // New allocation should start from the same base address
    int* after_reset = arena.allocate<int>();
    ASSERT_NE(after_reset, nullptr);

    // Should be at the same position as first allocation
    EXPECT_EQ(first, after_reset);
}

// ============================================================================
// 7. Edge Cases Tests
// ============================================================================

TEST_F(ArenaTest, Allocate_ZeroCount_Behavior) {
    Arena arena{kDefaultCapacity};

    // Document the expected behavior for zero-count allocation
    // The implementation returns a valid pointer (current offset) for count=0
    int* ptr = arena.allocate<int>(0);

    // Based on implementation: size = sizeof(int) * 0 = 0
    // This should succeed and return a valid aligned pointer
    // (the pointer is valid but shouldn't be dereferenced for 0 elements)
    EXPECT_NE(ptr, nullptr);
}

TEST_F(ArenaTest, Allocate_HugeStruct_SingleObject) {
    constexpr std::size_t kHugeCapacity = 4 * 1024 * 1024;  // 4MB
    Arena arena{kHugeCapacity};

    // Allocate a 1MB struct
    Huge* ptr = arena.allocate<Huge>();
    ASSERT_NE(ptr, nullptr);

    // Verify it's writable
    ptr->data[0] = 'A';
    ptr->data[sizeof(Huge) - 1] = 'Z';

    EXPECT_EQ(ptr->data[0], 'A');
    EXPECT_EQ(ptr->data[sizeof(Huge) - 1], 'Z');
}

TEST_F(ArenaTest, Allocate_MinimalCapacity_Behavior) {
    // The arena can allocate a single byte even with small capacity
    // because the base is already 64-byte aligned and first allocation
    // starts at offset 0 (already aligned). The allocation succeeds
    // as long as sizeof(T) <= capacity.
    constexpr std::size_t kTinyCapacity = 32;
    Arena arena{kTinyCapacity};

    // Single char allocation succeeds - only needs 1 byte
    char* ptr = arena.allocate<char>();
    EXPECT_NE(ptr, nullptr);

    // But 64-byte aligned struct that's 64 bytes won't fit
    // because used() now > 0 and needs padding to next 64-byte boundary
    CacheLine* cl = arena.allocate<CacheLine>();
    EXPECT_EQ(cl, nullptr);
}

// ============================================================================
// 8. Memory Correctness Tests
// ============================================================================

TEST_F(ArenaTest, Allocate_WriteRead_DataIntegrity) {
    Arena arena{kDefaultCapacity};
    constexpr int kNumInts = 1000;

    std::vector<int*> pointers;
    pointers.reserve(kNumInts);

    // Allocate and write unique values
    for (int i = 0; i < kNumInts; ++i) {
        int* ptr = arena.allocate<int>();
        ASSERT_NE(ptr, nullptr);
        *ptr = i * 7 + 13;  // Unique pattern
        pointers.push_back(ptr);
    }

    // Read all values and verify
    for (int i = 0; i < kNumInts; ++i) {
        EXPECT_EQ(*pointers[i], i * 7 + 13)
            << "Data corruption at index " << i;
    }
}

TEST_F(ArenaTest, Allocate_PatternFill_NoCorruption) {
    Arena arena{kDefaultCapacity};

    // Allocate and fill with pattern
    constexpr std::size_t kBlockSize = 256;
    std::uint32_t* block1 = arena.allocate<std::uint32_t>(kBlockSize);
    ASSERT_NE(block1, nullptr);

    for (std::size_t i = 0; i < kBlockSize; ++i) {
        block1[i] = 0xDEADBEEF;
    }

    // Allocate more memory
    std::uint32_t* block2 = arena.allocate<std::uint32_t>(kBlockSize);
    ASSERT_NE(block2, nullptr);

    for (std::size_t i = 0; i < kBlockSize; ++i) {
        block2[i] = 0xCAFEBABE;
    }

    // Verify first block is not corrupted
    for (std::size_t i = 0; i < kBlockSize; ++i) {
        EXPECT_EQ(block1[i], 0xDEADBEEF)
            << "Corruption in block1 at index " << i;
    }

    // Verify second block
    for (std::size_t i = 0; i < kBlockSize; ++i) {
        EXPECT_EQ(block2[i], 0xCAFEBABE)
            << "Corruption in block2 at index " << i;
    }
}

}  // namespace
}  // namespace exeray
