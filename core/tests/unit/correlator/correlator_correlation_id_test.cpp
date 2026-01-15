#include "correlator_test_common.hpp"

using namespace exeray::event;
using exeray::event::testing::CorrelatorTest;

// ============================================================================
// Correlation ID Generation
// ============================================================================

TEST_F(CorrelatorTest, GetCorrelationId_NewProcess_GeneratesNew) {
    uint32_t id = correlator_.get_correlation_id(1234);

    EXPECT_GT(id, 0U);
}

TEST_F(CorrelatorTest, GetCorrelationId_SameProcess_ReturnsSame) {
    uint32_t id1 = correlator_.get_correlation_id(1234);
    uint32_t id2 = correlator_.get_correlation_id(1234);

    EXPECT_EQ(id1, id2);
}

TEST_F(CorrelatorTest, GetCorrelationId_DifferentProcesses_DifferentIds) {
    uint32_t id1 = correlator_.get_correlation_id(1000);
    uint32_t id2 = correlator_.get_correlation_id(2000);

    EXPECT_NE(id1, id2);
}

TEST_F(CorrelatorTest, GetCorrelationId_ChildInheritsParent_SameId) {
    // First, assign correlation ID to parent process
    uint32_t parent_id = correlator_.get_correlation_id(1000, 0);  // no parent
    EXPECT_GT(parent_id, 0U);

    // Child should inherit parent's correlation ID
    uint32_t child_id = correlator_.get_correlation_id(2000, 1000);  // parent_pid=1000
    EXPECT_EQ(child_id, parent_id);
}

TEST_F(CorrelatorTest, GetCorrelationId_OrphanChild_GeneratesNew) {
    // Parent PID 9999 is not registered
    uint32_t orphan_id = correlator_.get_correlation_id(5000, 9999);

    EXPECT_GT(orphan_id, 0U);

    // Verify it's a new unique ID (doesn't inherit anything)
    uint32_t another_id = correlator_.get_correlation_id(6000, 9999);
    EXPECT_NE(orphan_id, another_id);
}


