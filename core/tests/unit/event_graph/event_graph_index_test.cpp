#include "event_graph_test_common.hpp"

namespace exeray::event::test {

using namespace exeray::event;

// ============================================================================
// 8. Index Consistency
// ============================================================================

TEST_F(EventGraphTest, ParentIndex_AfterPush_Consistent) {
    EventPayload payload = make_file_payload();

    EventId parent = graph_.push(Category::FileSystem, 0, Status::Success,
                                  INVALID_EVENT, 0, payload);

    // Add children one by one and verify index consistency
    for (int i = 0; i < 5; ++i) {
        graph_.push(Category::FileSystem, 0, Status::Success, parent, 0, payload);

        int child_count = 0;
        graph_.for_each_child(parent, [&child_count](EventView) {
            ++child_count;
        });

        EXPECT_EQ(child_count, i + 1) << "Parent index inconsistent after push " << i;
    }
}

TEST_F(EventGraphTest, CorrelationIndex_AfterPush_Consistent) {
    EventPayload payload = make_network_payload();
    constexpr uint32_t kCorrId = 999;

    // Add events one by one and verify index consistency
    for (int i = 0; i < 5; ++i) {
        graph_.push(Category::Network, 0, Status::Success,
                    INVALID_EVENT, kCorrId, payload);

        int corr_count = 0;
        graph_.for_each_correlation(kCorrId, [&corr_count](EventView) {
            ++corr_count;
        });

        EXPECT_EQ(corr_count, i + 1) << "Correlation index inconsistent after push " << i;
    }
}

TEST_F(EventGraphTest, Indexes_ConcurrentPush_NoCorruption) {
    constexpr int kNumThreads = 4;
    constexpr int kEventsPerThread = 500;
    constexpr uint32_t kCorrId = 42;

    EventPayload parent_payload = make_file_payload();
    EventId parent = graph_.push(Category::FileSystem, 0, Status::Success,
                                  INVALID_EVENT, 0, parent_payload);

    std::vector<std::thread> threads;

    for (int t = 0; t < kNumThreads; ++t) {
        threads.emplace_back([this, parent]() {
            for (int i = 0; i < kEventsPerThread; ++i) {
                EventPayload p = make_file_payload();
                graph_.push(Category::FileSystem, 0, Status::Success,
                            parent, kCorrId, p);
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // Verify parent index
    int child_count = 0;
    graph_.for_each_child(parent, [&child_count](EventView) {
        ++child_count;
    });
    EXPECT_EQ(child_count, kNumThreads * kEventsPerThread);

    // Verify correlation index
    int corr_count = 0;
    graph_.for_each_correlation(kCorrId, [&corr_count](EventView) {
        ++corr_count;
    });
    EXPECT_EQ(corr_count, kNumThreads * kEventsPerThread);
}

}  // namespace exeray::event::test
