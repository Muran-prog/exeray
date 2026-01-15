#include "event_graph_test_common.hpp"

namespace exeray::event::test {

using namespace exeray::event;

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

}  // namespace exeray::event::test
