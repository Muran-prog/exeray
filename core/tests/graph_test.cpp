#include <gtest/gtest.h>

#include <atomic>
#include <thread>
#include <vector>

#include "exeray/arena.hpp"
#include "exeray/event/graph.hpp"

namespace exeray::event {
namespace {

class EventGraphTest : public ::testing::Test {
protected:
    static constexpr std::size_t kArenaSize = 16 * 1024 * 1024;  // 16MB
    static constexpr std::size_t kGraphCapacity = 1024;

    Arena arena_{kArenaSize};
    StringPool strings_{arena_};
    EventGraph graph_{arena_, strings_, kGraphCapacity};

    EventPayload make_file_payload(StringId path) {
        EventPayload payload{};
        payload.category = Category::FileSystem;
        payload.file.path = path;
        payload.file.size = 1024;
        payload.file.attributes = 0;
        return payload;
    }
};

TEST_F(EventGraphTest, PushAndGetRoundtrip) {
    StringId path = strings_.intern("C:\\test.txt");
    EventPayload payload = make_file_payload(path);
    EventId id = graph_.push(Category::FileSystem,
                              static_cast<uint8_t>(FileOp::Create),
                              Status::Success, INVALID_EVENT, 0, payload);

    EXPECT_NE(id, INVALID_EVENT);
    EXPECT_TRUE(graph_.exists(id));

    EventView view = graph_.get(id);
    EXPECT_EQ(view.id(), id);
    EXPECT_EQ(view.category(), Category::FileSystem);
    EXPECT_EQ(view.status(), Status::Success);
    EXPECT_EQ(view.file_op(), FileOp::Create);
    EXPECT_TRUE(view.is_root());
}

TEST_F(EventGraphTest, MultipleEventsGetUniqueIds) {
    StringId path1 = strings_.intern("file1.txt");
    StringId path2 = strings_.intern("file2.txt");
    EventPayload p1 = make_file_payload(path1);
    EventPayload p2 = make_file_payload(path2);

    EventId id1 = graph_.push(Category::FileSystem,
                               static_cast<uint8_t>(FileOp::Read),
                               Status::Success, INVALID_EVENT, 0, p1);
    EventId id2 = graph_.push(Category::FileSystem,
                               static_cast<uint8_t>(FileOp::Write),
                               Status::Success, INVALID_EVENT, 0, p2);

    EXPECT_NE(id1, INVALID_EVENT);
    EXPECT_NE(id2, INVALID_EVENT);
    EXPECT_NE(id1, id2);

    EXPECT_EQ(graph_.get(id1).as_file().path, path1);
    EXPECT_EQ(graph_.get(id2).as_file().path, path2);
}

TEST_F(EventGraphTest, ParentChildRelationship) {
    EventPayload payload = make_file_payload(strings_.intern("parent.txt"));

    EventId parent = graph_.push(Category::FileSystem,
                                  static_cast<uint8_t>(FileOp::Create),
                                  Status::Success, INVALID_EVENT, 0, payload);

    EventId child = graph_.push(Category::FileSystem,
                                 static_cast<uint8_t>(FileOp::Write),
                                 Status::Success, parent, 0, payload);

    EventView parent_view = graph_.get(parent);
    EventView child_view = graph_.get(child);

    EXPECT_TRUE(parent_view.is_root());
    EXPECT_FALSE(child_view.is_root());
    EXPECT_EQ(child_view.parent_id(), parent);
}

TEST_F(EventGraphTest, CountTracksEvents) {
    EXPECT_EQ(graph_.count(), 0U);
    EventPayload payload = make_file_payload(strings_.intern("test.txt"));

    graph_.push(Category::FileSystem, static_cast<uint8_t>(FileOp::Create),
                Status::Success, INVALID_EVENT, 0, payload);
    EXPECT_EQ(graph_.count(), 1U);

    graph_.push(Category::FileSystem, static_cast<uint8_t>(FileOp::Delete),
                Status::Success, INVALID_EVENT, 0, payload);
    EXPECT_EQ(graph_.count(), 2U);
}

TEST_F(EventGraphTest, ExistsReturnsFalseForInvalidId) {
    EXPECT_FALSE(graph_.exists(INVALID_EVENT));
    EXPECT_FALSE(graph_.exists(999));  // Non-existent ID
}

TEST_F(EventGraphTest, StringConvenienceMethods) {
    StringId id = graph_.intern_string("test_string");
    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(graph_.resolve_string(id), "test_string");
}

TEST_F(EventGraphTest, ForEachIteratesAllEvents) {
    EventPayload payload = make_file_payload(strings_.intern("test.txt"));

    graph_.push(Category::FileSystem, static_cast<uint8_t>(FileOp::Create),
                Status::Success, INVALID_EVENT, 0, payload);
    graph_.push(Category::FileSystem, static_cast<uint8_t>(FileOp::Read),
                Status::Success, INVALID_EVENT, 0, payload);

    std::size_t count = 0;
    graph_.for_each([&count](EventView) { ++count; });

    EXPECT_EQ(count, 2U);
}

TEST_F(EventGraphTest, ForEachCategoryFiltersCorrectly) {
    EventPayload file_payload{};
    file_payload.category = Category::FileSystem;
    file_payload.file.path = strings_.intern("test.txt");

    EventPayload net_payload{};
    net_payload.category = Category::Network;
    net_payload.network.local_port = 8080;

    graph_.push(Category::FileSystem, static_cast<uint8_t>(FileOp::Create),
                Status::Success, INVALID_EVENT, 0, file_payload);
    graph_.push(Category::Network, static_cast<uint8_t>(NetworkOp::Connect),
                Status::Success, INVALID_EVENT, 0, net_payload);
    graph_.push(Category::FileSystem, static_cast<uint8_t>(FileOp::Read),
                Status::Success, INVALID_EVENT, 0, file_payload);

    std::size_t file_count = 0;
    graph_.for_each_category(Category::FileSystem,
                              [&file_count](EventView) { ++file_count; });
    EXPECT_EQ(file_count, 2U);

    std::size_t net_count = 0;
    graph_.for_each_category(Category::Network,
                              [&net_count](EventView) { ++net_count; });
    EXPECT_EQ(net_count, 1U);
}

TEST_F(EventGraphTest, ForEachChildFindsChildren) {
    EventPayload payload = make_file_payload(strings_.intern("test.txt"));

    EventId parent = graph_.push(Category::FileSystem,
                                  static_cast<uint8_t>(FileOp::Create),
                                  Status::Success, INVALID_EVENT, 0, payload);

    graph_.push(Category::FileSystem, static_cast<uint8_t>(FileOp::Write),
                Status::Success, parent, 0, payload);
    graph_.push(Category::FileSystem, static_cast<uint8_t>(FileOp::Read),
                Status::Success, parent, 0, payload);
    // This one is a root, not a child
    graph_.push(Category::FileSystem, static_cast<uint8_t>(FileOp::Delete),
                Status::Success, INVALID_EVENT, 0, payload);

    std::size_t child_count = 0;
    graph_.for_each_child(parent, [&child_count](EventView) { ++child_count; });

    EXPECT_EQ(child_count, 2U);
}

TEST_F(EventGraphTest, CapacityLimitReturnsInvalidEvent) {
    // Create a small graph for this test
    Arena small_arena{1024 * 1024};
    StringPool small_strings{small_arena};
    EventGraph small_graph{small_arena, small_strings, 2};

    EventPayload payload = make_file_payload(small_strings.intern("test.txt"));

    EventId id1 = small_graph.push(Category::FileSystem,
                                    static_cast<uint8_t>(FileOp::Create),
                                    Status::Success, INVALID_EVENT, 0, payload);
    EventId id2 = small_graph.push(Category::FileSystem,
                                    static_cast<uint8_t>(FileOp::Read),
                                    Status::Success, INVALID_EVENT, 0, payload);
    EventId id3 = small_graph.push(Category::FileSystem,
                                    static_cast<uint8_t>(FileOp::Write),
                                    Status::Success, INVALID_EVENT, 0, payload);

    EXPECT_NE(id1, INVALID_EVENT);
    EXPECT_NE(id2, INVALID_EVENT);
    EXPECT_EQ(id3, INVALID_EVENT);  // Capacity exceeded
    EXPECT_EQ(small_graph.count(), 2U);
}

TEST_F(EventGraphTest, ConcurrentPush) {
    constexpr int kNumThreads = 4;
    constexpr int kEventsPerThread = 100;

    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};

    for (int t = 0; t < kNumThreads; ++t) {
        threads.emplace_back([this, &success_count]() {
            for (int i = 0; i < kEventsPerThread; ++i) {
                EventPayload payload{};
                payload.category = Category::FileSystem;
                payload.file.size = 100;

                EventId id = graph_.push(Category::FileSystem,
                                          static_cast<uint8_t>(FileOp::Write),
                                          Status::Success, INVALID_EVENT,
                                          0, payload);
                if (id != INVALID_EVENT) {
                    ++success_count;
                }
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    EXPECT_EQ(success_count.load(), kNumThreads * kEventsPerThread);
    EXPECT_EQ(graph_.count(), kNumThreads * kEventsPerThread);
}

TEST_F(EventGraphTest, ConcurrentPushAndRead) {
    constexpr int kNumWriters = 2;
    constexpr int kNumReaders = 2;
    constexpr int kEventsPerWriter = 50;

    std::atomic<bool> stop{false};
    std::vector<std::thread> threads;

    // Writers
    for (int w = 0; w < kNumWriters; ++w) {
        threads.emplace_back([this]() {
            for (int i = 0; i < kEventsPerWriter; ++i) {
                EventPayload payload{};
                payload.category = Category::FileSystem;
                graph_.push(Category::FileSystem,
                            static_cast<uint8_t>(FileOp::Create),
                            Status::Success, INVALID_EVENT, 0, payload);
            }
        });
    }

    // Readers
    for (int r = 0; r < kNumReaders; ++r) {
        threads.emplace_back([this, &stop]() {
            while (!stop.load(std::memory_order_acquire)) {
                std::size_t total = 0;
                graph_.for_each([&total](EventView) { ++total; });
                // Just make sure we don't crash
                (void)total;
            }
        });
    }

    // Wait for writers to finish
    for (int i = 0; i < kNumWriters; ++i) {
        threads[i].join();
    }

    stop.store(true, std::memory_order_release);

    // Wait for readers to finish
    for (int i = kNumWriters; i < kNumWriters + kNumReaders; ++i) {
        threads[i].join();
    }

    EXPECT_EQ(graph_.count(), kNumWriters * kEventsPerWriter);
}

TEST_F(EventGraphTest, TimestampIsMonotonicallyIncreasing) {
    EventPayload payload = make_file_payload(strings_.intern("test.txt"));

    EventId id1 = graph_.push(Category::FileSystem,
                               static_cast<uint8_t>(FileOp::Create),
                               Status::Success, INVALID_EVENT, 0, payload);
    EventId id2 = graph_.push(Category::FileSystem,
                               static_cast<uint8_t>(FileOp::Write),
                               Status::Success, INVALID_EVENT, 0, payload);

    EventView v1 = graph_.get(id1);
    EventView v2 = graph_.get(id2);

    // Timestamps should be non-zero and in order (or equal on fast machines)
    EXPECT_GT(v1.timestamp(), 0U);
    EXPECT_GE(v2.timestamp(), v1.timestamp());
}

}  // namespace
}  // namespace exeray::event
