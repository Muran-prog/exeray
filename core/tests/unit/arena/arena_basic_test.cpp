#include "arena_test_common.hpp"

namespace exeray {
namespace arena_test {

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

}  // namespace arena_test
}  // namespace exeray
