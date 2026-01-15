#include "correlator_test_common.hpp"

using namespace exeray::event;
using exeray::event::testing::CorrelatorTest;

// ============================================================================
// 1. Process Parent Lookup
// ============================================================================

TEST_F(CorrelatorTest, FindProcessParent_RegisteredProcess_ReturnsEventId) {
    constexpr uint32_t kPid = 1234;
    constexpr EventId kEventId = 42;

    correlator_.register_process(kPid, kEventId);

    EXPECT_EQ(correlator_.find_process_parent(kPid), kEventId);
}

TEST_F(CorrelatorTest, FindProcessParent_NotRegistered_ReturnsInvalid) {
    EXPECT_EQ(correlator_.find_process_parent(99999), INVALID_EVENT);
}

TEST_F(CorrelatorTest, FindProcessParent_AfterMultipleRegistrations_LastWins) {
    constexpr uint32_t kPid = 1234;
    constexpr EventId kId1 = 10;
    constexpr EventId kId2 = 20;

    correlator_.register_process(kPid, kId1);
    EXPECT_EQ(correlator_.find_process_parent(kPid), kId1);

    // Simulate PID reuse - second registration wins
    correlator_.register_process(kPid, kId2);
    EXPECT_EQ(correlator_.find_process_parent(kPid), kId2);
}

// ============================================================================
// 2. Thread Parent Lookup
// ============================================================================

TEST_F(CorrelatorTest, FindThreadParent_ProcessRegistered_ReturnsEventId) {
    constexpr uint32_t kPid = 1234;
    constexpr EventId kEventId = 42;

    correlator_.register_process(kPid, kEventId);

    EXPECT_EQ(correlator_.find_thread_parent(kPid), kEventId);
}

TEST_F(CorrelatorTest, FindThreadParent_ProcessNotFound_ReturnsInvalid) {
    EXPECT_EQ(correlator_.find_thread_parent(99999), INVALID_EVENT);
}

// ============================================================================
// 3. Operation Parent Lookup
// ============================================================================

TEST_F(CorrelatorTest, FindOperationParent_ProcessExists_ReturnsEventId) {
    constexpr uint32_t kPid = 1234;
    constexpr EventId kEventId = 42;

    correlator_.register_process(kPid, kEventId);

    // find_operation_parent delegates to find_thread_parent
    EXPECT_EQ(correlator_.find_operation_parent(kPid), kEventId);
}

TEST_F(CorrelatorTest, FindOperationParent_ProcessNotFound_ReturnsInvalid) {
    EXPECT_EQ(correlator_.find_operation_parent(99999), INVALID_EVENT);
}


