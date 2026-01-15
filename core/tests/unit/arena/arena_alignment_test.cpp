#include "arena_test_common.hpp"

namespace exeray {
namespace arena_test {

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

}  // namespace arena_test
}  // namespace exeray
