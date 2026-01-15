#pragma once

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <limits>
#include <set>
#include <thread>
#include <vector>

#include "exeray/event/correlator.hpp"
#include "exeray/event/node.hpp"
#include "exeray/event/types.hpp"

namespace exeray::event::testing {

// ============================================================================
// Test Fixture
// ============================================================================

class CorrelatorTest : public ::testing::Test {
protected:
    Correlator correlator_;

    /// @brief Create an EventNode for testing register_event()
    static EventNode make_process_node(uint32_t pid, EventId id,
                                        ProcessOp op = ProcessOp::Create) {
        EventNode node{};
        node.id = id;
        node.operation = static_cast<uint8_t>(op);
        node.payload.category = Category::Process;
        node.payload.process.pid = pid;
        node.payload.process.parent_pid = 1;
        return node;
    }

    static EventNode make_file_node(EventId id) {
        EventNode node{};
        node.id = id;
        node.operation = 0;
        node.payload.category = Category::FileSystem;
        return node;
    }
};

}  // namespace exeray::event::testing
