#include "event_graph_test_common.hpp"

namespace exeray::event::test {

using namespace exeray::event;

// ============================================================================
// 2. Capacity Management
// ============================================================================

TEST_F(EventGraphTest, Push_AtCapacity_ReturnsInvalidEvent) {
    constexpr std::size_t kSmallCapacity = 100;
    Arena small_arena{1024 * 1024};
    StringPool small_strings{small_arena};
    EventGraph small_graph{small_arena, small_strings, kSmallCapacity};

    EventPayload payload = make_process_payload();

    // Push exactly capacity events
    for (std::size_t i = 0; i < kSmallCapacity; ++i) {
        EventId id = small_graph.push(Category::Process,
                                       static_cast<uint8_t>(ProcessOp::Create),
                                       Status::Success, INVALID_EVENT, 0, payload);
        ASSERT_NE(id, INVALID_EVENT) << "Push " << i << " failed prematurely";
    }

    // 101st push should fail
    EventId overflow_id = small_graph.push(Category::Process,
                                            static_cast<uint8_t>(ProcessOp::Create),
                                            Status::Success, INVALID_EVENT, 0, payload);
    EXPECT_EQ(overflow_id, INVALID_EVENT);
}

TEST_F(EventGraphTest, Push_AfterCapacityReached_NoSideEffects) {
    constexpr std::size_t kSmallCapacity = 50;
    Arena small_arena{1024 * 1024};
    StringPool small_strings{small_arena};
    EventGraph small_graph{small_arena, small_strings, kSmallCapacity};

    EventPayload payload = make_process_payload();

    // Fill to capacity
    std::vector<EventId> ids;
    for (std::size_t i = 0; i < kSmallCapacity; ++i) {
        ids.push_back(small_graph.push(Category::Process, 0,
                                        Status::Success, INVALID_EVENT, 0, payload));
    }

    // Attempt overflow
    for (int i = 0; i < 10; ++i) {
        small_graph.push(Category::Process, 0, Status::Success,
                         INVALID_EVENT, 0, payload);
    }

    // Count should remain at capacity
    EXPECT_EQ(small_graph.count(), kSmallCapacity);

    // Previous events should still be valid and uncorrupted
    for (std::size_t i = 0; i < ids.size(); ++i) {
        EXPECT_TRUE(small_graph.exists(ids[i])) << "Event " << i << " corrupted";
        EXPECT_EQ(small_graph.get(ids[i]).category(), Category::Process);
    }
}

TEST_F(EventGraphTest, Exists_OverCapacity_ReturnsFalse) {
    constexpr std::size_t kSmallCapacity = 10;
    Arena small_arena{1024 * 1024};
    StringPool small_strings{small_arena};
    EventGraph small_graph{small_arena, small_strings, kSmallCapacity};

    EventPayload payload = make_process_payload();

    // Fill to capacity
    for (std::size_t i = 0; i < kSmallCapacity; ++i) {
        small_graph.push(Category::Process, 0, Status::Success,
                         INVALID_EVENT, 0, payload);
    }

    // Try to push over capacity
    EventId failed_id = small_graph.push(Category::Process, 0, Status::Success,
                                          INVALID_EVENT, 0, payload);

    EXPECT_EQ(failed_id, INVALID_EVENT);
    EXPECT_FALSE(small_graph.exists(failed_id));
}

}  // namespace exeray::event::test
