#include "string_pool_test_common.hpp"

namespace exeray::event {
namespace {

// ============================================================================
// 9. Arena Exhaustion Tests
// ============================================================================

class SmallArenaStringPoolTest : public ::testing::Test {
protected:
    // Small arena: 1KB - will exhaust quickly
    // Due to 64-byte alignment in Arena, each allocation uses at least 64 bytes
    static constexpr std::size_t kSmallArenaSize = 1024;

    Arena arena_{kSmallArenaSize};
    StringPool pool_{arena_};
};

TEST_F(SmallArenaStringPoolTest, Intern_ArenaFull_GracefulFailure) {
    // Keep interning until we get INVALID_STRING
    std::vector<StringId> valid_ids;
    bool exhausted = false;

    for (int i = 0; i < 1000; ++i) {
        // Create a moderately sized string to exhaust arena faster
        std::string str(100, 'x');
        str += std::to_string(i);
        
        StringId id = pool_.intern(str);
        if (id == INVALID_STRING) {
            exhausted = true;
            break;
        }
        valid_ids.push_back(id);
    }

    EXPECT_TRUE(exhausted) << "Arena should have been exhausted";
    EXPECT_GT(valid_ids.size(), 0U) << "Should have interned at least one string";
}

TEST_F(SmallArenaStringPoolTest, Intern_AfterExhaustion_ConsistentState) {
    // Intern strings and track their IDs
    std::vector<std::pair<std::string, StringId>> interned;

    for (int i = 0; i < 1000; ++i) {
        std::string str = "str_" + std::to_string(i);
        StringId id = pool_.intern(str);
        if (id == INVALID_STRING) {
            break;
        }
        interned.emplace_back(str, id);
    }

    ASSERT_GT(interned.size(), 0U) << "Should have interned at least one string";

    // Try to intern more (should fail)
    StringId fail_id = pool_.intern("this_should_fail_due_to_exhaustion");
    (void)fail_id;  // May or may not fail depending on remaining space

    // All previously interned strings should still be accessible
    for (const auto& [str, id] : interned) {
        EXPECT_EQ(pool_.get(id), str) 
            << "String '" << str << "' corrupted after exhaustion attempt";
    }

    // Count should match number of successful interns
    EXPECT_GE(pool_.count(), interned.size());
}

}  // namespace
}  // namespace exeray::event
