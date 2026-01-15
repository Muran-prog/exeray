#include "event_graph_test_common.hpp"

namespace exeray::event::test {

using namespace exeray::event;

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

}  // namespace exeray::event::test
