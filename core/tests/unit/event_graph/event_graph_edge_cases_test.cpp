#include "event_graph_test_common.hpp"

namespace exeray::event::test {

using namespace exeray::event;

// ============================================================================
// 10. Edge Cases
// ============================================================================

TEST_F(EventGraphTest, Exists_InvalidEvent_ReturnsFalse) {
    EXPECT_FALSE(graph_.exists(INVALID_EVENT));
}

TEST_F(EventGraphTest, Exists_FutureId_ReturnsFalse) {
    // Push a few events
    EventPayload p = make_process_payload();
    graph_.push(Category::Process, 0, Status::Success, INVALID_EVENT, 0, p);
    graph_.push(Category::Process, 0, Status::Success, INVALID_EVENT, 0, p);

    // Check a future ID that hasn't been assigned
    EventId future_id = graph_.count() + 100;
    EXPECT_FALSE(graph_.exists(future_id));
}

TEST_F(EventGraphTest, Push_AllFieldsPopulated_NoDefaultsLeaked) {
    EventPayload payload = make_process_payload(1234);

    EventId id = graph_.push(Category::Process,
                              static_cast<uint8_t>(ProcessOp::Create),
                              Status::Denied,
                              INVALID_EVENT,
                              999,  // correlation_id
                              payload);

    EventView view = graph_.get(id);

    // Verify all fields are properly set
    EXPECT_NE(view.id(), INVALID_EVENT);
    EXPECT_EQ(view.parent_id(), INVALID_EVENT);
    EXPECT_GT(view.timestamp(), 0U);  // Should have valid timestamp
    EXPECT_EQ(view.category(), Category::Process);
    EXPECT_EQ(view.status(), Status::Denied);
    EXPECT_EQ(view.operation(), static_cast<uint8_t>(ProcessOp::Create));
    EXPECT_EQ(view.correlation_id(), 999U);
    EXPECT_EQ(view.as_process().pid, 1234U);
}

TEST_F(EventGraphTest, Push_DifferentStatuses_AllPreserved) {
    EventPayload p = make_process_payload();

    EventId s1 = graph_.push(Category::Process, 0, Status::Success,
                              INVALID_EVENT, 0, p);
    EventId s2 = graph_.push(Category::Process, 0, Status::Denied,
                              INVALID_EVENT, 0, p);
    EventId s3 = graph_.push(Category::Process, 0, Status::Pending,
                              INVALID_EVENT, 0, p);
    EventId s4 = graph_.push(Category::Process, 0, Status::Error,
                              INVALID_EVENT, 0, p);
    EventId s5 = graph_.push(Category::Process, 0, Status::Suspicious,
                              INVALID_EVENT, 0, p);

    EXPECT_EQ(graph_.get(s1).status(), Status::Success);
    EXPECT_EQ(graph_.get(s2).status(), Status::Denied);
    EXPECT_EQ(graph_.get(s3).status(), Status::Pending);
    EXPECT_EQ(graph_.get(s4).status(), Status::Error);
    EXPECT_EQ(graph_.get(s5).status(), Status::Suspicious);
}

}  // namespace exeray::event::test
