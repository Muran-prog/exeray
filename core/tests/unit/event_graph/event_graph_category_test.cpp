#include "event_graph_test_common.hpp"

namespace exeray::event::test {

using namespace exeray::event;

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

}  // namespace exeray::event::test
