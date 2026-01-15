#include "event_graph_test_common.hpp"

namespace exeray::event::test {

using namespace exeray::event;

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

}  // namespace exeray::event::test
