#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <set>
#include <thread>
#include <vector>

#include "exeray/arena.hpp"
#include "exeray/event/graph.hpp"

namespace exeray::event {
namespace {

// ============================================================================
// Test Fixture
// ============================================================================

class EventGraphTest : public ::testing::Test {
protected:
    static constexpr std::size_t kArenaSize = 64 * 1024 * 1024;  // 64MB
    static constexpr std::size_t kDefaultCapacity = 65536;

    Arena arena_{kArenaSize};
    StringPool strings_{arena_};
    EventGraph graph_{arena_, strings_, kDefaultCapacity};

    // -------------------------------------------------------------------------
    // Helper: Create payloads for each category
    // -------------------------------------------------------------------------

    static EventPayload make_process_payload(uint32_t pid = 1234) {
        EventPayload payload{};
        payload.category = Category::Process;
        payload.process.pid = pid;
        payload.process.parent_pid = 1;
        return payload;
    }

    static EventPayload make_file_payload(StringId path = INVALID_STRING) {
        EventPayload payload{};
        payload.category = Category::FileSystem;
        payload.file.path = path;
        payload.file.size = 1024;
        payload.file.attributes = 0;
        return payload;
    }

    static EventPayload make_registry_payload() {
        EventPayload payload{};
        payload.category = Category::Registry;
        payload.registry.key_path = INVALID_STRING;
        payload.registry.value_name = INVALID_STRING;
        return payload;
    }

    static EventPayload make_network_payload(uint16_t port = 8080) {
        EventPayload payload{};
        payload.category = Category::Network;
        payload.network.local_port = port;
        payload.network.remote_port = 443;
        return payload;
    }

    static EventPayload make_scheduler_payload() {
        EventPayload payload{};
        payload.category = Category::Scheduler;
        return payload;
    }

    static EventPayload make_input_payload() {
        EventPayload payload{};
        payload.category = Category::Input;
        return payload;
    }

    static EventPayload make_image_payload() {
        EventPayload payload{};
        payload.category = Category::Image;
        payload.image.base_address = 0x7FF00000;
        payload.image.size = 0x10000;
        return payload;
    }

    static EventPayload make_thread_payload(uint32_t tid = 5678) {
        EventPayload payload{};
        payload.category = Category::Thread;
        payload.thread.thread_id = tid;
        payload.thread.start_address = 0x400000;
        return payload;
    }

    static EventPayload make_memory_payload() {
        EventPayload payload{};
        payload.category = Category::Memory;
        payload.memory.base_address = 0x1000;
        payload.memory.region_size = 4096;
        return payload;
    }

    static EventPayload make_script_payload() {
        EventPayload payload{};
        payload.category = Category::Script;
        payload.script.script_block = INVALID_STRING;
        return payload;
    }

    static EventPayload make_amsi_payload() {
        EventPayload payload{};
        payload.category = Category::Amsi;
        payload.amsi.content = INVALID_STRING;
        return payload;
    }

    static EventPayload make_dns_payload() {
        EventPayload payload{};
        payload.category = Category::Dns;
        payload.dns.domain = INVALID_STRING;
        return payload;
    }

    static EventPayload make_security_payload() {
        EventPayload payload{};
        payload.category = Category::Security;
        payload.security.target_user = INVALID_STRING;
        return payload;
    }

    static EventPayload make_service_payload() {
        EventPayload payload{};
        payload.category = Category::Service;
        payload.service.service_name = INVALID_STRING;
        return payload;
    }

    static EventPayload make_wmi_payload() {
        EventPayload payload{};
        payload.category = Category::Wmi;
        payload.wmi.query = INVALID_STRING;
        return payload;
    }

    static EventPayload make_clr_payload() {
        EventPayload payload{};
        payload.category = Category::Clr;
        payload.clr.assembly_name = INVALID_STRING;
        return payload;
    }

    EventPayload make_payload_for_category(Category cat) {
        switch (cat) {
            case Category::FileSystem: return make_file_payload();
            case Category::Registry: return make_registry_payload();
            case Category::Network: return make_network_payload();
            case Category::Process: return make_process_payload();
            case Category::Scheduler: return make_scheduler_payload();
            case Category::Input: return make_input_payload();
            case Category::Image: return make_image_payload();
            case Category::Thread: return make_thread_payload();
            case Category::Memory: return make_memory_payload();
            case Category::Script: return make_script_payload();
            case Category::Amsi: return make_amsi_payload();
            case Category::Dns: return make_dns_payload();
            case Category::Security: return make_security_payload();
            case Category::Service: return make_service_payload();
            case Category::Wmi: return make_wmi_payload();
            case Category::Clr: return make_clr_payload();
            case Category::Count: break;
        }
        return make_file_payload();  // Fallback
    }
};

// ============================================================================
// 1. Basic Push/Get
// ============================================================================

TEST_F(EventGraphTest, Push_SingleEvent_ReturnsValidId) {
    EventPayload payload = make_process_payload(1234);

    EventId id = graph_.push(Category::Process,
                              static_cast<uint8_t>(ProcessOp::Create),
                              Status::Success, INVALID_EVENT, 0, payload);

    EXPECT_NE(id, INVALID_EVENT);
    EXPECT_TRUE(graph_.exists(id));
    EXPECT_EQ(graph_.get(id).id(), id);
}

TEST_F(EventGraphTest, Push_MultipleEvents_IncrementalIds) {
    EventPayload payload = make_process_payload();

    EventId id1 = graph_.push(Category::Process,
                               static_cast<uint8_t>(ProcessOp::Create),
                               Status::Success, INVALID_EVENT, 0, payload);
    EventId id2 = graph_.push(Category::Process,
                               static_cast<uint8_t>(ProcessOp::Create),
                               Status::Success, INVALID_EVENT, 0, payload);
    EventId id3 = graph_.push(Category::Process,
                               static_cast<uint8_t>(ProcessOp::Create),
                               Status::Success, INVALID_EVENT, 0, payload);

    EXPECT_EQ(id2, id1 + 1);
    EXPECT_EQ(id3, id2 + 1);
}

TEST_F(EventGraphTest, Get_ValidEvent_CorrectPayload) {
    constexpr uint32_t kTestPid = 9999;
    EventPayload payload = make_process_payload(kTestPid);

    EventId id = graph_.push(Category::Process,
                              static_cast<uint8_t>(ProcessOp::Create),
                              Status::Success, INVALID_EVENT, 0, payload);

    EventView view = graph_.get(id);
    EXPECT_EQ(view.category(), Category::Process);
    EXPECT_EQ(view.as_process().pid, kTestPid);
}

TEST_F(EventGraphTest, Get_AllCategories_PayloadsCorrect) {
    // Test each category to ensure payloads are correctly stored
    constexpr int kCategoryCount = static_cast<int>(Category::Count);

    for (int i = 0; i < kCategoryCount; ++i) {
        Category cat = static_cast<Category>(i);
        EventPayload payload = make_payload_for_category(cat);

        EventId id = graph_.push(cat, 0, Status::Success,
                                  INVALID_EVENT, 0, payload);

        ASSERT_NE(id, INVALID_EVENT) << "Failed to push category " << i;
        EXPECT_EQ(graph_.get(id).category(), cat)
            << "Category mismatch for " << i;
    }

    EXPECT_EQ(graph_.count(), static_cast<std::size_t>(kCategoryCount));
}

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

// ============================================================================
// 3. Parent-Child Relationships
// ============================================================================

TEST_F(EventGraphTest, Push_WithParent_ParentIndexUpdated) {
    EventPayload payload = make_file_payload();

    EventId parent_id = graph_.push(Category::FileSystem,
                                     static_cast<uint8_t>(FileOp::Create),
                                     Status::Success, INVALID_EVENT, 0, payload);
    EventId child_id = graph_.push(Category::FileSystem,
                                    static_cast<uint8_t>(FileOp::Write),
                                    Status::Success, parent_id, 0, payload);

    std::vector<EventId> children;
    graph_.for_each_child(parent_id, [&children](EventView view) {
        children.push_back(view.id());
    });

    ASSERT_EQ(children.size(), 1U);
    EXPECT_EQ(children[0], child_id);
}

TEST_F(EventGraphTest, ForEachChild_MultipleChildren_AllFound) {
    EventPayload payload = make_file_payload();
    constexpr int kNumChildren = 10;

    EventId parent_id = graph_.push(Category::FileSystem, 0,
                                     Status::Success, INVALID_EVENT, 0, payload);

    std::set<EventId> expected_children;
    for (int i = 0; i < kNumChildren; ++i) {
        EventId child = graph_.push(Category::FileSystem, 0,
                                     Status::Success, parent_id, 0, payload);
        expected_children.insert(child);
    }

    std::set<EventId> found_children;
    graph_.for_each_child(parent_id, [&found_children](EventView view) {
        found_children.insert(view.id());
    });

    EXPECT_EQ(found_children.size(), kNumChildren);
    EXPECT_EQ(found_children, expected_children);
}

TEST_F(EventGraphTest, ForEachChild_NestedHierarchy_DirectOnly) {
    // Create hierarchy: A -> B -> C
    EventPayload payload = make_file_payload();

    EventId a = graph_.push(Category::FileSystem, 0, Status::Success,
                            INVALID_EVENT, 0, payload);
    EventId b = graph_.push(Category::FileSystem, 0, Status::Success,
                            a, 0, payload);
    EventId c = graph_.push(Category::FileSystem, 0, Status::Success,
                            b, 0, payload);

    // for_each_child(A) should only return B, not C
    std::vector<EventId> a_children;
    graph_.for_each_child(a, [&a_children](EventView view) {
        a_children.push_back(view.id());
    });

    ASSERT_EQ(a_children.size(), 1U);
    EXPECT_EQ(a_children[0], b);
    EXPECT_NE(a_children[0], c);

    // for_each_child(B) should only return C
    std::vector<EventId> b_children;
    graph_.for_each_child(b, [&b_children](EventView view) {
        b_children.push_back(view.id());
    });

    ASSERT_EQ(b_children.size(), 1U);
    EXPECT_EQ(b_children[0], c);
}

TEST_F(EventGraphTest, ForEachChild_NoChildren_EmptyIteration) {
    EventPayload payload = make_file_payload();

    EventId parent_id = graph_.push(Category::FileSystem, 0,
                                     Status::Success, INVALID_EVENT, 0, payload);

    int callback_count = 0;
    graph_.for_each_child(parent_id, [&callback_count](EventView) {
        ++callback_count;
    });

    EXPECT_EQ(callback_count, 0);
}

TEST_F(EventGraphTest, ForEachChild_InvalidParent_EmptyIteration) {
    int callback_count = 0;
    graph_.for_each_child(INVALID_EVENT, [&callback_count](EventView) {
        ++callback_count;
    });

    EXPECT_EQ(callback_count, 0);
}

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

// ============================================================================
// 5. Category Filtering
// ============================================================================

TEST_F(EventGraphTest, ForEachCategory_SingleCategory_AllMatching) {
    constexpr int kProcessCount = 30;
    constexpr int kFileCount = 40;
    constexpr int kThreadCount = 30;

    for (int i = 0; i < kProcessCount; ++i) {
        EventPayload p = make_process_payload();
        graph_.push(Category::Process, 0, Status::Success, INVALID_EVENT, 0, p);
    }
    for (int i = 0; i < kFileCount; ++i) {
        EventPayload p = make_file_payload();
        graph_.push(Category::FileSystem, 0, Status::Success, INVALID_EVENT, 0, p);
    }
    for (int i = 0; i < kThreadCount; ++i) {
        EventPayload p = make_thread_payload();
        graph_.push(Category::Thread, 0, Status::Success, INVALID_EVENT, 0, p);
    }

    int process_count = 0;
    graph_.for_each_category(Category::Process, [&process_count](EventView) {
        ++process_count;
    });

    EXPECT_EQ(process_count, kProcessCount);
}

TEST_F(EventGraphTest, ForEachCategory_AllCategories_Exhaustive) {
    // Push one event per category
    constexpr int kCategoryCount = static_cast<int>(Category::Count);

    for (int i = 0; i < kCategoryCount; ++i) {
        Category cat = static_cast<Category>(i);
        EventPayload payload = make_payload_for_category(cat);
        graph_.push(cat, 0, Status::Success, INVALID_EVENT, 0, payload);
    }

    // Verify each category has exactly 1 event
    for (int i = 0; i < kCategoryCount; ++i) {
        Category cat = static_cast<Category>(i);
        int count = 0;
        graph_.for_each_category(cat, [&count](EventView) { ++count; });
        EXPECT_EQ(count, 1) << "Category " << i << " has wrong count";
    }
}

TEST_F(EventGraphTest, ForEachCategory_Empty_NoCallbacks) {
    // Don't push any Network events
    EventPayload payload = make_file_payload();
    graph_.push(Category::FileSystem, 0, Status::Success, INVALID_EVENT, 0, payload);

    int net_count = 0;
    graph_.for_each_category(Category::Network, [&net_count](EventView) {
        ++net_count;
    });

    EXPECT_EQ(net_count, 0);
}

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

// ============================================================================
// 9. String Resolution
// ============================================================================

TEST_F(EventGraphTest, ResolveString_ValidId_ReturnsString) {
    StringId id = graph_.intern_string("test_path.txt");
    std::string_view resolved = graph_.resolve_string(id);

    EXPECT_EQ(resolved, "test_path.txt");
}

TEST_F(EventGraphTest, ResolveString_InvalidId_EmptyView) {
    std::string_view resolved = graph_.resolve_string(INVALID_STRING);

    EXPECT_TRUE(resolved.empty());
}

TEST_F(EventGraphTest, InternString_ViaGraph_WorksCorrectly) {
    StringId id1 = graph_.intern_string("hello");
    StringId id2 = graph_.intern_string("world");
    StringId id3 = graph_.intern_string("hello");  // Duplicate

    EXPECT_NE(id1, INVALID_STRING);
    EXPECT_NE(id2, INVALID_STRING);
    EXPECT_EQ(id1, id3);  // Deduplication

    EXPECT_EQ(graph_.resolve_string(id1), "hello");
    EXPECT_EQ(graph_.resolve_string(id2), "world");
}

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

}  // namespace
}  // namespace exeray::event
