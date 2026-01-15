#include "event_graph_test_common.hpp"

namespace exeray::event::test {

using namespace exeray::event;

// ============================================================================
// 6. ForEach All Events
// ============================================================================

TEST_F(EventGraphTest, ForEach_AllEvents_CorrectCount) {
    constexpr int kNumEvents = 100;

    for (int i = 0; i < kNumEvents; ++i) {
        EventPayload p = make_process_payload();
        graph_.push(Category::Process, 0, Status::Success, INVALID_EVENT, 0, p);
    }

    int count = 0;
    graph_.for_each([&count](EventView) { ++count; });

    EXPECT_EQ(count, kNumEvents);
}

TEST_F(EventGraphTest, ForEach_EventOrder_Preserved) {
    constexpr int kNumEvents = 50;

    std::vector<EventId> pushed_ids;
    for (int i = 0; i < kNumEvents; ++i) {
        EventPayload p = make_process_payload(static_cast<uint32_t>(i));
        EventId id = graph_.push(Category::Process, 0, Status::Success,
                                  INVALID_EVENT, 0, p);
        pushed_ids.push_back(id);
    }

    std::vector<EventId> iterated_ids;
    graph_.for_each([&iterated_ids](EventView view) {
        iterated_ids.push_back(view.id());
    });

    ASSERT_EQ(iterated_ids.size(), pushed_ids.size());
    for (std::size_t i = 0; i < pushed_ids.size(); ++i) {
        EXPECT_EQ(iterated_ids[i], pushed_ids[i]) << "Order mismatch at " << i;
    }
}

}  // namespace exeray::event::test
