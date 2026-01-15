#include "event_graph_test_common.hpp"

namespace exeray::event::test {

using namespace exeray::event;

// ============================================================================
// 4. Correlation ID Grouping
// ============================================================================

TEST_F(EventGraphTest, Push_WithCorrelation_IndexUpdated) {
    EventPayload payload = make_network_payload();
    constexpr uint32_t kCorrelationId = 42;

    EventId id = graph_.push(Category::Network, 0, Status::Success,
                              INVALID_EVENT, kCorrelationId, payload);

    std::vector<EventId> correlated;
    graph_.for_each_correlation(kCorrelationId, [&correlated](EventView view) {
        correlated.push_back(view.id());
    });

    ASSERT_EQ(correlated.size(), 1U);
    EXPECT_EQ(correlated[0], id);
}

TEST_F(EventGraphTest, ForEachCorrelation_MultipleEvents_AllFound) {
    EventPayload payload = make_network_payload();
    constexpr uint32_t kCorrelationId = 123;
    constexpr int kNumEvents = 10;

    std::set<EventId> expected;
    for (int i = 0; i < kNumEvents; ++i) {
        EventId id = graph_.push(Category::Network, 0, Status::Success,
                                  INVALID_EVENT, kCorrelationId, payload);
        expected.insert(id);
    }

    std::set<EventId> found;
    graph_.for_each_correlation(kCorrelationId, [&found](EventView view) {
        found.insert(view.id());
    });

    EXPECT_EQ(found.size(), kNumEvents);
    EXPECT_EQ(found, expected);
}

TEST_F(EventGraphTest, ForEachCorrelation_DifferentIds_Isolated) {
    EventPayload payload = make_network_payload();
    constexpr uint32_t kCorr1 = 1;
    constexpr uint32_t kCorr2 = 2;
    constexpr int kEventsPerCorr = 5;

    for (int i = 0; i < kEventsPerCorr; ++i) {
        graph_.push(Category::Network, 0, Status::Success,
                    INVALID_EVENT, kCorr1, payload);
        graph_.push(Category::Network, 0, Status::Success,
                    INVALID_EVENT, kCorr2, payload);
    }

    int corr1_count = 0;
    graph_.for_each_correlation(kCorr1, [&corr1_count](EventView) {
        ++corr1_count;
    });

    int corr2_count = 0;
    graph_.for_each_correlation(kCorr2, [&corr2_count](EventView) {
        ++corr2_count;
    });

    EXPECT_EQ(corr1_count, kEventsPerCorr);
    EXPECT_EQ(corr2_count, kEventsPerCorr);
}

TEST_F(EventGraphTest, ForEachCorrelation_ZeroId_Works) {
    // correlation_id=0 should NOT be indexed (based on implementation)
    EventPayload payload = make_network_payload();

    graph_.push(Category::Network, 0, Status::Success,
                INVALID_EVENT, 0, payload);

    int count = 0;
    graph_.for_each_correlation(0, [&count](EventView) {
        ++count;
    });

    // correlation_id=0 is not indexed per graph.cpp:63
    EXPECT_EQ(count, 0);
}

}  // namespace exeray::event::test
