#include "event_graph_test_common.hpp"

namespace exeray::event::test {

using namespace exeray::event;

// ============================================================================
// 7. Concurrent Push (CRITICAL)
// ============================================================================

TEST_F(EventGraphTest, Push_ConcurrentThreads_AllUniqueIds) {
    constexpr int kNumThreads = 8;
    constexpr int kEventsPerThread = 10000;
    constexpr std::size_t kLargeCapacity = 100000;  // Enough for 80000 events

    Arena large_arena{128 * 1024 * 1024};  // 128MB
    StringPool large_strings{large_arena};
    EventGraph large_graph{large_arena, large_strings, kLargeCapacity};

    std::vector<std::thread> threads;
    std::vector<std::vector<EventId>> thread_ids(kNumThreads);

    for (int t = 0; t < kNumThreads; ++t) {
        threads.emplace_back([&large_graph, &thread_ids, t]() {
            thread_ids[t].reserve(kEventsPerThread);
            for (int i = 0; i < kEventsPerThread; ++i) {
                EventPayload p{};
                p.category = Category::Process;
                EventId id = large_graph.push(Category::Process, 0, Status::Success,
                                               INVALID_EVENT, 0, p);
                ASSERT_NE(id, INVALID_EVENT);
                thread_ids[t].push_back(id);
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // Verify all IDs are unique
    std::set<EventId> all_ids;
    for (const auto& ids : thread_ids) {
        for (EventId id : ids) {
            auto [_, inserted] = all_ids.insert(id);
            EXPECT_TRUE(inserted) << "Duplicate ID: " << id;
        }
    }

    EXPECT_EQ(all_ids.size(), kNumThreads * kEventsPerThread);
    EXPECT_EQ(large_graph.count(), kNumThreads * kEventsPerThread);
}

TEST_F(EventGraphTest, Push_ConcurrentNearCapacity_NoOverflow) {
    constexpr std::size_t kCapacity = 1000;
    constexpr int kNumThreads = 10;
    constexpr int kEventsPerThread = 150;  // 1500 total attempts for 1000 capacity

    Arena small_arena{16 * 1024 * 1024};
    StringPool small_strings{small_arena};
    EventGraph small_graph{small_arena, small_strings, kCapacity};

    std::atomic<int> success_count{0};
    std::atomic<int> failure_count{0};
    std::vector<std::thread> threads;

    for (int t = 0; t < kNumThreads; ++t) {
        threads.emplace_back([&small_graph, &success_count, &failure_count]() {
            for (int i = 0; i < kEventsPerThread; ++i) {
                EventPayload p{};
                p.category = Category::Process;
                EventId id = small_graph.push(Category::Process, 0, Status::Success,
                                               INVALID_EVENT, 0, p);
                if (id != INVALID_EVENT) {
                    ++success_count;
                } else {
                    ++failure_count;
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // Exactly capacity should succeed
    EXPECT_EQ(success_count.load(), static_cast<int>(kCapacity));
    EXPECT_EQ(failure_count.load(), kNumThreads * kEventsPerThread - kCapacity);
    EXPECT_EQ(small_graph.count(), kCapacity);
}

TEST_F(EventGraphTest, Push_ConcurrentWithIteration_NoRace) {
    constexpr int kNumPushers = 4;
    constexpr int kNumReaders = 4;
    constexpr int kEventsPerPusher = 1000;

    std::atomic<bool> stop{false};
    std::vector<std::thread> threads;

    // Pusher threads
    for (int t = 0; t < kNumPushers; ++t) {
        threads.emplace_back([this]() {
            for (int i = 0; i < kEventsPerPusher; ++i) {
                EventPayload p = make_file_payload();
                graph_.push(Category::FileSystem, 0, Status::Success,
                            INVALID_EVENT, 0, p);
            }
        });
    }

    // Reader threads
    for (int r = 0; r < kNumReaders; ++r) {
        threads.emplace_back([this, &stop]() {
            while (!stop.load(std::memory_order_acquire)) {
                std::size_t count = 0;
                graph_.for_each([&count](EventView view) {
                    // Access data to ensure no partial reads
                    (void)view.category();
                    (void)view.id();
                    ++count;
                });
                (void)count;
            }
        });
    }

    // Wait for pushers
    for (int i = 0; i < kNumPushers; ++i) {
        threads[i].join();
    }

    stop.store(true, std::memory_order_release);

    // Wait for readers
    for (int i = kNumPushers; i < kNumPushers + kNumReaders; ++i) {
        threads[i].join();
    }

    EXPECT_EQ(graph_.count(), kNumPushers * kEventsPerPusher);
}

TEST_F(EventGraphTest, Push_ConcurrentWithGet_SafeRead) {
    // This test verifies that get() and exists() are safe to call
    // concurrently with push(). We push events, then have reader
    // threads safely access them.
    constexpr int kPushCount = 1000;

    // First, push all events
    for (int i = 0; i < kPushCount; ++i) {
        EventPayload p = make_process_payload(static_cast<uint32_t>(i));
        graph_.push(Category::Process, 0, Status::Success,
                    INVALID_EVENT, 0, p);
    }

    EXPECT_EQ(graph_.count(), kPushCount);

    // Now have multiple readers concurrently access the events
    constexpr int kNumReaders = 4;
    std::atomic<int> read_count{0};
    std::vector<std::thread> threads;

    for (int r = 0; r < kNumReaders; ++r) {
        threads.emplace_back([this, &read_count]() {
            for (int i = 1; i <= 100; ++i) {
                EventId id = static_cast<EventId>(i);
                EXPECT_TRUE(graph_.exists(id));
                EventView view = graph_.get(id);
                EXPECT_EQ(view.category(), Category::Process);
                EXPECT_NE(view.timestamp(), 0U);
                ++read_count;
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(read_count.load(), kNumReaders * 100);
}

}  // namespace exeray::event::test
