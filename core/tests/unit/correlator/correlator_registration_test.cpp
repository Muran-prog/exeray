#include "correlator_test_common.hpp"

using namespace exeray::event;
using exeray::event::testing::CorrelatorTest;

// ============================================================================
// Event Registration
// ============================================================================

TEST_F(CorrelatorTest, RegisterEvent_ProcessCreate_UpdatesMapping) {
    constexpr uint32_t kPid = 1234;
    constexpr EventId kEventId = 42;

    EventNode node = make_process_node(kPid, kEventId, ProcessOp::Create);
    correlator_.register_event(node);

    EXPECT_EQ(correlator_.find_process_parent(kPid), kEventId);
}

TEST_F(CorrelatorTest, RegisterEvent_NonProcessCreate_NoEffect) {
    constexpr uint32_t kPid = 1234;
    constexpr EventId kEventId = 42;

    // ProcessOp::Terminate should NOT register parent
    EventNode node = make_process_node(kPid, kEventId, ProcessOp::Terminate);
    correlator_.register_event(node);

    EXPECT_EQ(correlator_.find_process_parent(kPid), INVALID_EVENT);
}

TEST_F(CorrelatorTest, RegisterEvent_NonProcessCategory_NoEffect) {
    constexpr EventId kEventId = 42;

    EventNode node = make_file_node(kEventId);
    correlator_.register_event(node);

    // Verify process_events_ is unchanged
    // (no way to directly check, but no parent lookup should succeed)
    EXPECT_EQ(correlator_.find_process_parent(0), INVALID_EVENT);
}

TEST_F(CorrelatorTest, RegisterProcess_Explicit_Works) {
    constexpr uint32_t kPid = 1234;
    constexpr EventId kEventId = 42;

    correlator_.register_process(kPid, kEventId);

    EXPECT_EQ(correlator_.find_process_parent(kPid), kEventId);
}

TEST_F(CorrelatorTest, RegisterProcess_ZeroPid_Ignored) {
    correlator_.register_process(0, 42);

    EXPECT_EQ(correlator_.find_process_parent(0), INVALID_EVENT);
}

TEST_F(CorrelatorTest, RegisterProcess_InvalidEventId_Ignored) {
    correlator_.register_process(1234, INVALID_EVENT);

    EXPECT_EQ(correlator_.find_process_parent(1234), INVALID_EVENT);
}


