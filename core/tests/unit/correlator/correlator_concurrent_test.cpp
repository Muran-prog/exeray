#include "correlator_test_common.hpp"

using namespace exeray::event;
using exeray::event::testing::CorrelatorTest;

// ============================================================================
// Concurrent Access
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


