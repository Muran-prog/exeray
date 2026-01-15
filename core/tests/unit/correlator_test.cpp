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

namespace exeray::event {
namespace {

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

// ============================================================================
// 1. Process Parent Lookup
// ============================================================================

TEST_F(CorrelatorTest, FindProcessParent_RegisteredProcess_ReturnsEventId) {
    constexpr uint32_t kPid = 1234;
    constexpr EventId kEventId = 42;

    correlator_.register_process(kPid, kEventId);

    EXPECT_EQ(correlator_.find_process_parent(kPid), kEventId);
}

TEST_F(CorrelatorTest, FindProcessParent_NotRegistered_ReturnsInvalid) {
    EXPECT_EQ(correlator_.find_process_parent(99999), INVALID_EVENT);
}

TEST_F(CorrelatorTest, FindProcessParent_AfterMultipleRegistrations_LastWins) {
    constexpr uint32_t kPid = 1234;
    constexpr EventId kId1 = 10;
    constexpr EventId kId2 = 20;

    correlator_.register_process(kPid, kId1);
    EXPECT_EQ(correlator_.find_process_parent(kPid), kId1);

    // Simulate PID reuse - second registration wins
    correlator_.register_process(kPid, kId2);
    EXPECT_EQ(correlator_.find_process_parent(kPid), kId2);
}

// ============================================================================
// 2. Thread Parent Lookup
// ============================================================================

TEST_F(CorrelatorTest, FindThreadParent_ProcessRegistered_ReturnsEventId) {
    constexpr uint32_t kPid = 1234;
    constexpr EventId kEventId = 42;

    correlator_.register_process(kPid, kEventId);

    EXPECT_EQ(correlator_.find_thread_parent(kPid), kEventId);
}

TEST_F(CorrelatorTest, FindThreadParent_ProcessNotFound_ReturnsInvalid) {
    EXPECT_EQ(correlator_.find_thread_parent(99999), INVALID_EVENT);
}

// ============================================================================
// 3. Operation Parent Lookup
// ============================================================================

TEST_F(CorrelatorTest, FindOperationParent_ProcessExists_ReturnsEventId) {
    constexpr uint32_t kPid = 1234;
    constexpr EventId kEventId = 42;

    correlator_.register_process(kPid, kEventId);

    // find_operation_parent delegates to find_thread_parent
    EXPECT_EQ(correlator_.find_operation_parent(kPid), kEventId);
}

TEST_F(CorrelatorTest, FindOperationParent_ProcessNotFound_ReturnsInvalid) {
    EXPECT_EQ(correlator_.find_operation_parent(99999), INVALID_EVENT);
}

// ============================================================================
// 4. Correlation ID Generation
// ============================================================================

TEST_F(CorrelatorTest, GetCorrelationId_NewProcess_GeneratesNew) {
    uint32_t id = correlator_.get_correlation_id(1234);

    EXPECT_GT(id, 0U);
}

TEST_F(CorrelatorTest, GetCorrelationId_SameProcess_ReturnsSame) {
    uint32_t id1 = correlator_.get_correlation_id(1234);
    uint32_t id2 = correlator_.get_correlation_id(1234);

    EXPECT_EQ(id1, id2);
}

TEST_F(CorrelatorTest, GetCorrelationId_DifferentProcesses_DifferentIds) {
    uint32_t id1 = correlator_.get_correlation_id(1000);
    uint32_t id2 = correlator_.get_correlation_id(2000);

    EXPECT_NE(id1, id2);
}

TEST_F(CorrelatorTest, GetCorrelationId_ChildInheritsParent_SameId) {
    // First, assign correlation ID to parent process
    uint32_t parent_id = correlator_.get_correlation_id(1000, 0);  // no parent
    EXPECT_GT(parent_id, 0U);

    // Child should inherit parent's correlation ID
    uint32_t child_id = correlator_.get_correlation_id(2000, 1000);  // parent_pid=1000
    EXPECT_EQ(child_id, parent_id);
}

TEST_F(CorrelatorTest, GetCorrelationId_OrphanChild_GeneratesNew) {
    // Parent PID 9999 is not registered
    uint32_t orphan_id = correlator_.get_correlation_id(5000, 9999);

    EXPECT_GT(orphan_id, 0U);

    // Verify it's a new unique ID (doesn't inherit anything)
    uint32_t another_id = correlator_.get_correlation_id(6000, 9999);
    EXPECT_NE(orphan_id, another_id);
}

// ============================================================================
// 5. Event Registration
// ============================================================================

TEST_F(CorrelatorTest, RegisterEvent_ProcessCreate_UpdatesMapping) {
    constexpr uint32_t kPid = 1234;
    constexpr EventId kEventId = 42;

    EventNode node = make_process_node(kPid, kEventId, ProcessOp::Create);
    correlator_.register_event(node);

    EXPECT_EQ(correlator_.find_process_parent(kPid), kEventId);
}

TEST_F(CorrelatorTest, RegisterEvent_NonProcessCreate_NoEffect) {
    constexpr uint32_t kPid = 1234;
    constexpr EventId kEventId = 42;

    // ProcessOp::Terminate should NOT register parent
    EventNode node = make_process_node(kPid, kEventId, ProcessOp::Terminate);
    correlator_.register_event(node);

    EXPECT_EQ(correlator_.find_process_parent(kPid), INVALID_EVENT);
}

TEST_F(CorrelatorTest, RegisterEvent_NonProcessCategory_NoEffect) {
    constexpr EventId kEventId = 42;

    EventNode node = make_file_node(kEventId);
    correlator_.register_event(node);

    // Verify process_events_ is unchanged
    // (no way to directly check, but no parent lookup should succeed)
    EXPECT_EQ(correlator_.find_process_parent(0), INVALID_EVENT);
}

TEST_F(CorrelatorTest, RegisterProcess_Explicit_Works) {
    constexpr uint32_t kPid = 1234;
    constexpr EventId kEventId = 42;

    correlator_.register_process(kPid, kEventId);

    EXPECT_EQ(correlator_.find_process_parent(kPid), kEventId);
}

TEST_F(CorrelatorTest, RegisterProcess_ZeroPid_Ignored) {
    correlator_.register_process(0, 42);

    EXPECT_EQ(correlator_.find_process_parent(0), INVALID_EVENT);
}

TEST_F(CorrelatorTest, RegisterProcess_InvalidEventId_Ignored) {
    correlator_.register_process(1234, INVALID_EVENT);

    EXPECT_EQ(correlator_.find_process_parent(1234), INVALID_EVENT);
}

// ============================================================================
// 6. Concurrent Access
// ============================================================================

TEST_F(CorrelatorTest, GetCorrelationId_ConcurrentSamePid_SameId) {
    constexpr int kNumThreads = 10;
    constexpr uint32_t kPid = 1234;

    std::vector<std::thread> threads;
    std::vector<uint32_t> results(kNumThreads);

    for (int i = 0; i < kNumThreads; ++i) {
        threads.emplace_back([this, &results, i]() {
            results[i] = correlator_.get_correlation_id(kPid);
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // All threads should get the same correlation ID
    uint32_t expected = results[0];
    for (int i = 1; i < kNumThreads; ++i) {
        EXPECT_EQ(results[i], expected) << "Thread " << i << " got different ID";
    }
}

TEST_F(CorrelatorTest, RegisterProcess_ConcurrentDifferentPids_NoRace) {
    constexpr int kNumThreads = 10;
    constexpr int kEventsPerThread = 1000;

    std::vector<std::thread> threads;

    for (int t = 0; t < kNumThreads; ++t) {
        threads.emplace_back([this, t]() {
            for (int i = 0; i < kEventsPerThread; ++i) {
                uint32_t pid = static_cast<uint32_t>(t * kEventsPerThread + i + 1);
                EventId event_id = static_cast<EventId>(pid);
                correlator_.register_process(pid, event_id);
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // Verify all registrations succeeded
    for (int t = 0; t < kNumThreads; ++t) {
        for (int i = 0; i < kEventsPerThread; ++i) {
            uint32_t pid = static_cast<uint32_t>(t * kEventsPerThread + i + 1);
            EventId expected = static_cast<EventId>(pid);
            EXPECT_EQ(correlator_.find_process_parent(pid), expected)
                << "PID " << pid << " not found";
        }
    }
}

TEST_F(CorrelatorTest, FindParent_ConcurrentWithRegister_ConsistentResults) {
    constexpr int kNumRegisters = 5;
    constexpr int kNumFinders = 5;
    constexpr int kOperationsPerThread = 500;

    std::atomic<bool> start{false};
    std::atomic<int> valid_finds{0};
    std::atomic<int> invalid_finds{0};
    std::vector<std::thread> threads;

    // Register threads
    for (int t = 0; t < kNumRegisters; ++t) {
        threads.emplace_back([this, &start, t]() {
            while (!start.load(std::memory_order_acquire)) {}
            for (int i = 0; i < kOperationsPerThread; ++i) {
                uint32_t pid = static_cast<uint32_t>(t * kOperationsPerThread + i + 1);
                EventId event_id = static_cast<EventId>(pid * 10);
                correlator_.register_process(pid, event_id);
            }
        });
    }

    // Finder threads
    for (int f = 0; f < kNumFinders; ++f) {
        threads.emplace_back([this, &start, &valid_finds, &invalid_finds]() {
            while (!start.load(std::memory_order_acquire)) {}
            for (int i = 0; i < kOperationsPerThread; ++i) {
                // Search for random PIDs in range
                uint32_t pid = static_cast<uint32_t>((i % 1000) + 1);
                EventId result = correlator_.find_process_parent(pid);
                if (result != INVALID_EVENT) {
                    // If found, must be valid (PID * 10)
                    EXPECT_EQ(result, static_cast<EventId>(pid * 10))
                        << "Invalid result for PID " << pid;
                    ++valid_finds;
                } else {
                    ++invalid_finds;
                }
            }
        });
    }

    start.store(true, std::memory_order_release);

    for (auto& t : threads) {
        t.join();
    }

    // Just verify we completed without crashes
    EXPECT_GE(valid_finds.load() + invalid_finds.load(),
              kNumFinders * kOperationsPerThread);
}

TEST_F(CorrelatorTest, GetCorrelationId_ConcurrentDifferentPids_AllUnique) {
    constexpr int kNumThreads = 4;
    constexpr int kIdsPerThread = 1000;

    std::vector<std::thread> threads;
    std::vector<std::set<uint32_t>> thread_ids(kNumThreads);

    for (int t = 0; t < kNumThreads; ++t) {
        threads.emplace_back([this, &thread_ids, t]() {
            for (int i = 0; i < kIdsPerThread; ++i) {
                uint32_t pid = static_cast<uint32_t>(t * kIdsPerThread + i + 1);
                uint32_t corr_id = correlator_.get_correlation_id(pid);
                thread_ids[t].insert(corr_id);
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // Collect all IDs and verify uniqueness
    std::set<uint32_t> all_ids;
    for (const auto& ids : thread_ids) {
        for (uint32_t id : ids) {
            auto [_, inserted] = all_ids.insert(id);
            EXPECT_TRUE(inserted) << "Duplicate correlation ID: " << id;
        }
    }

    EXPECT_EQ(all_ids.size(), kNumThreads * kIdsPerThread);
}

// ============================================================================
// 7. Edge Cases
// ============================================================================

TEST_F(CorrelatorTest, GetCorrelationId_PidZero_ReturnsZero) {
    // PID=0 is handled specially - returns 0
    // (System Idle Process scenario - per implementation line 51-53)
    uint32_t id = correlator_.get_correlation_id(0);

    EXPECT_EQ(id, 0U);
}

TEST_F(CorrelatorTest, FindProcessParent_PidZero_ReturnsInvalid) {
    // PID=0 lookups return INVALID_EVENT per implementation
    correlator_.register_process(0, 42);  // Should be ignored

    EXPECT_EQ(correlator_.find_process_parent(0), INVALID_EVENT);
}

TEST_F(CorrelatorTest, FindThreadParent_PidZero_ReturnsInvalid) {
    EXPECT_EQ(correlator_.find_thread_parent(0), INVALID_EVENT);
}

TEST_F(CorrelatorTest, GetCorrelationId_MaxUint32_Works) {
    constexpr uint32_t kMaxPid = std::numeric_limits<uint32_t>::max();

    uint32_t id = correlator_.get_correlation_id(kMaxPid);

    EXPECT_GT(id, 0U);

    // Verify it's correctly stored and retrievable
    uint32_t id2 = correlator_.get_correlation_id(kMaxPid);
    EXPECT_EQ(id, id2);
}

TEST_F(CorrelatorTest, CorrelationIdCounter_GeneratesManyIds_AllUnique) {
    constexpr int kNumIds = 10000;

    std::set<uint32_t> ids;
    for (int i = 1; i <= kNumIds; ++i) {
        uint32_t pid = static_cast<uint32_t>(i);
        uint32_t corr_id = correlator_.get_correlation_id(pid);
        auto [_, inserted] = ids.insert(corr_id);
        EXPECT_TRUE(inserted) << "Duplicate ID at iteration " << i;
    }

    EXPECT_EQ(ids.size(), kNumIds);
}

TEST_F(CorrelatorTest, GetCorrelationId_SequentialGeneration) {
    // First three PIDs without parents should get sequential IDs
    uint32_t id1 = correlator_.get_correlation_id(100);
    uint32_t id2 = correlator_.get_correlation_id(200);
    uint32_t id3 = correlator_.get_correlation_id(300);

    // Should be sequential (1, 2, 3) based on atomic counter starting at 1
    EXPECT_EQ(id1, 1U);
    EXPECT_EQ(id2, 2U);
    EXPECT_EQ(id3, 3U);
}

TEST_F(CorrelatorTest, RegisterMultiplePids_IndependentMappings) {
    constexpr int kNumPids = 100;

    for (int i = 1; i <= kNumPids; ++i) {
        uint32_t pid = static_cast<uint32_t>(i);
        EventId event_id = static_cast<EventId>(i * 100);
        correlator_.register_process(pid, event_id);
    }

    // Verify all mappings are correct
    for (int i = 1; i <= kNumPids; ++i) {
        uint32_t pid = static_cast<uint32_t>(i);
        EventId expected = static_cast<EventId>(i * 100);
        EXPECT_EQ(correlator_.find_process_parent(pid), expected);
    }
}

TEST_F(CorrelatorTest, InheritanceChain_GrandchildInheritsRoot) {
    // Create a chain: Root -> Parent -> Child
    // All should share the same correlation ID

    uint32_t root_id = correlator_.get_correlation_id(100, 0);       // Root
    uint32_t parent_id = correlator_.get_correlation_id(200, 100);   // Parent (child of 100)
    uint32_t child_id = correlator_.get_correlation_id(300, 200);    // Child (child of 200)

    EXPECT_EQ(parent_id, root_id);
    EXPECT_EQ(child_id, root_id);
}

TEST_F(CorrelatorTest, InheritanceChain_BrokenChain_NewRoot) {
    // Create: Root -> Parent, then orphan child
    correlator_.get_correlation_id(100, 0);      // Root = ID 1
    correlator_.get_correlation_id(200, 100);    // Parent inherits from 100

    // Child references non-existent parent (PID 9999)
    uint32_t orphan_id = correlator_.get_correlation_id(300, 9999);

    // Should get new ID, not inherit anything
    EXPECT_GT(orphan_id, 0U);
    EXPECT_NE(orphan_id, correlator_.get_correlation_id(100, 0));
}

}  // namespace
}  // namespace exeray::event
