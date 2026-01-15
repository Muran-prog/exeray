#include "correlator_test_common.hpp"

using namespace exeray::event;
using exeray::event::testing::CorrelatorTest;

// ============================================================================
// Edge Cases
// ============================================================================

TEST_F(CorrelatorTest, GetCorrelationId_PidZero_ReturnsZero) {
    // PID=0 is handled specially - returns 0
    // (System Idle Process scenario - per implementation line 51-53)
    uint32_t id = correlator_.get_correlation_id(0);

    EXPECT_EQ(id, 0U);
}

TEST_F(CorrelatorTest, FindProcessParent_PidZero_ReturnsInvalid) {
    // PID=0 lookups return INVALID_EVENT per implementation
    correlator_.register_process(0, 42);  // Should be ignored

    EXPECT_EQ(correlator_.find_process_parent(0), INVALID_EVENT);
}

TEST_F(CorrelatorTest, FindThreadParent_PidZero_ReturnsInvalid) {
    EXPECT_EQ(correlator_.find_thread_parent(0), INVALID_EVENT);
}

TEST_F(CorrelatorTest, GetCorrelationId_MaxUint32_Works) {
    constexpr uint32_t kMaxPid = std::numeric_limits<uint32_t>::max();

    uint32_t id = correlator_.get_correlation_id(kMaxPid);

    EXPECT_GT(id, 0U);

    // Verify it's correctly stored and retrievable
    uint32_t id2 = correlator_.get_correlation_id(kMaxPid);
    EXPECT_EQ(id, id2);
}

TEST_F(CorrelatorTest, CorrelationIdCounter_GeneratesManyIds_AllUnique) {
    constexpr int kNumIds = 10000;

    std::set<uint32_t> ids;
    for (int i = 1; i <= kNumIds; ++i) {
        uint32_t pid = static_cast<uint32_t>(i);
        uint32_t corr_id = correlator_.get_correlation_id(pid);
        auto [_, inserted] = ids.insert(corr_id);
        EXPECT_TRUE(inserted) << "Duplicate ID at iteration " << i;
    }

    EXPECT_EQ(ids.size(), kNumIds);
}

TEST_F(CorrelatorTest, GetCorrelationId_SequentialGeneration) {
    // First three PIDs without parents should get sequential IDs
    uint32_t id1 = correlator_.get_correlation_id(100);
    uint32_t id2 = correlator_.get_correlation_id(200);
    uint32_t id3 = correlator_.get_correlation_id(300);

    // Should be sequential (1, 2, 3) based on atomic counter starting at 1
    EXPECT_EQ(id1, 1U);
    EXPECT_EQ(id2, 2U);
    EXPECT_EQ(id3, 3U);
}

TEST_F(CorrelatorTest, RegisterMultiplePids_IndependentMappings) {
    constexpr int kNumPids = 100;

    for (int i = 1; i <= kNumPids; ++i) {
        uint32_t pid = static_cast<uint32_t>(i);
        EventId event_id = static_cast<EventId>(i * 100);
        correlator_.register_process(pid, event_id);
    }

    // Verify all mappings are correct
    for (int i = 1; i <= kNumPids; ++i) {
        uint32_t pid = static_cast<uint32_t>(i);
        EventId expected = static_cast<EventId>(i * 100);
        EXPECT_EQ(correlator_.find_process_parent(pid), expected);
    }
}

TEST_F(CorrelatorTest, InheritanceChain_GrandchildInheritsRoot) {
    // Create a chain: Root -> Parent -> Child
    // All should share the same correlation ID

    uint32_t root_id = correlator_.get_correlation_id(100, 0);       // Root
    uint32_t parent_id = correlator_.get_correlation_id(200, 100);   // Parent (child of 100)
    uint32_t child_id = correlator_.get_correlation_id(300, 200);    // Child (child of 200)

    EXPECT_EQ(parent_id, root_id);
    EXPECT_EQ(child_id, root_id);
}

TEST_F(CorrelatorTest, InheritanceChain_BrokenChain_NewRoot) {
    // Create: Root -> Parent, then orphan child
    correlator_.get_correlation_id(100, 0);      // Root = ID 1
    correlator_.get_correlation_id(200, 100);    // Parent inherits from 100

    // Child references non-existent parent (PID 9999)
    uint32_t orphan_id = correlator_.get_correlation_id(300, 9999);

    // Should get new ID, not inherit anything
    EXPECT_GT(orphan_id, 0U);
    EXPECT_NE(orphan_id, correlator_.get_correlation_id(100, 0));
}


