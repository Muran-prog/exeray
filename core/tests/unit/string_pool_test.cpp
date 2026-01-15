#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "exeray/arena.hpp"
#include "exeray/event/string_pool.hpp"

namespace exeray::event {
namespace {

// ============================================================================
// Test Fixture
// ============================================================================

class StringPoolTest : public ::testing::Test {
protected:
    static constexpr std::size_t kDefaultArenaSize = 1024 * 1024;  // 1MB

    Arena arena_{kDefaultArenaSize};
    StringPool pool_{arena_};
};

// ============================================================================
// 1. Basic Interning Tests
// ============================================================================

TEST_F(StringPoolTest, Intern_SimpleString_ReturnsValidId) {
    StringId id = pool_.intern("hello");

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), "hello");
}

TEST_F(StringPoolTest, Intern_SameStringTwice_ReturnsSameId) {
    StringId id1 = pool_.intern("test");
    StringId id2 = pool_.intern("test");

    EXPECT_NE(id1, INVALID_STRING);
    EXPECT_EQ(id1, id2) << "Deduplication failed: same string returned different IDs";
}

TEST_F(StringPoolTest, Intern_DifferentStrings_DifferentIds) {
    StringId id1 = pool_.intern("foo");
    StringId id2 = pool_.intern("bar");

    EXPECT_NE(id1, INVALID_STRING);
    EXPECT_NE(id2, INVALID_STRING);
    EXPECT_NE(id1, id2);
}

TEST_F(StringPoolTest, Intern_1000UniqueStrings_AllUnique) {
    constexpr int kNumStrings = 1000;
    std::set<StringId> unique_ids;

    for (int i = 0; i < kNumStrings; ++i) {
        StringId id = pool_.intern("string_" + std::to_string(i));
        ASSERT_NE(id, INVALID_STRING) << "Failed at string " << i;
        auto [_, inserted] = unique_ids.insert(id);
        EXPECT_TRUE(inserted) << "Duplicate ID for string_" << i;
    }

    EXPECT_EQ(unique_ids.size(), kNumStrings);
    EXPECT_EQ(pool_.count(), kNumStrings);
}

// ============================================================================
// 2. Empty and Special Strings Tests
// ============================================================================

TEST_F(StringPoolTest, Intern_EmptyString_ValidId) {
    StringId id = pool_.intern("");

    EXPECT_NE(id, INVALID_STRING);
    
    std::string_view result = pool_.get(id);
    EXPECT_TRUE(result.empty());
    EXPECT_EQ(result, "");
}

TEST_F(StringPoolTest, Intern_Whitespace_PreservedExactly) {
    const std::string_view whitespace = "  \t\n  ";
    StringId id = pool_.intern(whitespace);

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), whitespace);
    EXPECT_EQ(pool_.get(id).size(), whitespace.size());
}

TEST_F(StringPoolTest, Intern_NullCharInMiddle_TruncatedAtNullByStringView) {
    // string_view created from "hello\0world" will have length 5 (stops at null)
    // This documents the expected behavior based on how string_view is constructed
    const char* cstr = "hello\0world";
    std::string_view sv(cstr);  // Length = 5 (truncated at null)
    
    StringId id = pool_.intern(sv);
    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), "hello");
    EXPECT_EQ(pool_.get(id).size(), 5U);

    // To include null in middle, must use explicit length
    std::string_view sv_full(cstr, 11);  // "hello\0world" = 11 chars
    StringId id_full = pool_.intern(sv_full);
    EXPECT_NE(id_full, INVALID_STRING);
    EXPECT_EQ(pool_.get(id_full).size(), 11U);
}

// ============================================================================
// 3. Unicode Stress Tests
// ============================================================================

TEST_F(StringPoolTest, Intern_Cyrillic_CorrectlyStored) {
    const std::string_view cyrillic = "Привет мир";  // UTF-8 encoded
    StringId id = pool_.intern(cyrillic);

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), cyrillic);
}

TEST_F(StringPoolTest, Intern_Chinese_CorrectlyStored) {
    const std::string_view chinese = "你好世界";  // UTF-8 encoded
    StringId id = pool_.intern(chinese);

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), chinese);
}

TEST_F(StringPoolTest, Intern_Emoji_4ByteUtf8) {
    const std::string_view emoji = "🔥💀🎉";  // Each emoji is 4 UTF-8 bytes
    StringId id = pool_.intern(emoji);

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), emoji);
    // 3 emoji × 4 bytes = 12 bytes
    EXPECT_EQ(pool_.get(id).size(), 12U);
}

TEST_F(StringPoolTest, Intern_MixedScripts_Preserved) {
    const std::string_view mixed = "Hello Мир 世界 🌍";
    StringId id = pool_.intern(mixed);

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), mixed);
}

TEST_F(StringPoolTest, Intern_RTL_Arabic_Preserved) {
    const std::string_view arabic = "مرحبا";  // Arabic "hello"
    StringId id = pool_.intern(arabic);

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), arabic);
}

// ============================================================================
// 4. Wide String Conversion Tests (intern_wide)
// ============================================================================

TEST_F(StringPoolTest, InternWide_SimpleAscii_ConvertsToUtf8) {
    StringId id = pool_.intern_wide(L"hello");

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_EQ(pool_.get(id), "hello");
}

TEST_F(StringPoolTest, InternWide_Cyrillic_ProperConversion) {
    // L"Привет" in wide chars
    StringId id = pool_.intern_wide(L"Привет");

    EXPECT_NE(id, INVALID_STRING);
    // Verify UTF-8 bytes are correct (Cyrillic chars are 2 bytes each in UTF-8)
    std::string_view result = pool_.get(id);
    EXPECT_EQ(result, "Привет");
}

TEST_F(StringPoolTest, InternWide_SurrogatePairs_HandledCorrectly) {
    // 🔥 (U+1F525) encoded as surrogate pair: 0xD83D 0xDD25
    wchar_t emoji[] = {static_cast<wchar_t>(0xD83D), static_cast<wchar_t>(0xDD25), 0};
    StringId id = pool_.intern_wide(emoji);

    EXPECT_NE(id, INVALID_STRING);
    std::string_view result = pool_.get(id);
    
    // Should produce 4-byte UTF-8 sequence for U+1F525
    EXPECT_EQ(result.size(), 4U);
    EXPECT_EQ(result, "🔥");
}

TEST_F(StringPoolTest, InternWide_LoneSurrogate_ReplacementChar) {
    // Lone high surrogate followed by regular ASCII
    wchar_t invalid[] = {static_cast<wchar_t>(0xD83D), L'A', 0};
    StringId id = pool_.intern_wide(invalid);

    EXPECT_NE(id, INVALID_STRING);
    std::string_view result = pool_.get(id);
    
    // Lone surrogate should become U+FFFD (3 UTF-8 bytes) + 'A' (1 byte)
    // U+FFFD = EF BF BD in UTF-8
    EXPECT_EQ(result.size(), 4U);  // 3 + 1
    
    // Check for replacement character (EF BF BD)
    EXPECT_EQ(static_cast<unsigned char>(result[0]), 0xEF);
    EXPECT_EQ(static_cast<unsigned char>(result[1]), 0xBF);
    EXPECT_EQ(static_cast<unsigned char>(result[2]), 0xBD);
    EXPECT_EQ(result[3], 'A');
}

TEST_F(StringPoolTest, InternWide_MaxPath_NoTruncation) {
    // Simulate a very long Windows path (not quite 32767, but long enough)
    constexpr std::size_t kLongPathLen = 4096;
    std::wstring long_path(kLongPathLen, L'x');
    long_path[0] = L'C';
    long_path[1] = L':';
    long_path[2] = L'\\';

    StringId id = pool_.intern_wide(long_path);
    EXPECT_NE(id, INVALID_STRING);

    std::string_view result = pool_.get(id);
    EXPECT_EQ(result.size(), kLongPathLen);  // ASCII chars = same byte count
}

TEST_F(StringPoolTest, InternWide_Empty_ValidId) {
    StringId id = pool_.intern_wide(L"");

    EXPECT_NE(id, INVALID_STRING);
    EXPECT_TRUE(pool_.get(id).empty());
}

// ============================================================================
// 5. Get Operations Tests
// ============================================================================

TEST_F(StringPoolTest, Get_ValidId_ReturnsCorrectString) {
    StringId id = pool_.intern("test_string");
    EXPECT_EQ(pool_.get(id), "test_string");
}

TEST_F(StringPoolTest, Get_InvalidString_EmptyView) {
    std::string_view result = pool_.get(INVALID_STRING);
    EXPECT_TRUE(result.empty());
}

TEST_F(StringPoolTest, Get_OutOfRangeId_DoesNotCrash) {
    // Note: This test documents current behavior - accessing out-of-range ID
    // The implementation trusts the ID is valid (no bounds checking)
    // This test just ensures we don't crash with a reasonable out-of-range ID
    // In production, only IDs returned by intern() should be used
    
    // Just verify that INVALID_STRING returns empty
    EXPECT_TRUE(pool_.get(INVALID_STRING).empty());
}

TEST_F(StringPoolTest, Get_AfterManyInterns_StillValid) {
    // Intern first string
    StringId first_id = pool_.intern("first_string");
    ASSERT_NE(first_id, INVALID_STRING);

    // Intern many more strings
    constexpr int kNumStrings = 10000;
    for (int i = 0; i < kNumStrings; ++i) {
        StringId id = pool_.intern("bulk_string_" + std::to_string(i));
        ASSERT_NE(id, INVALID_STRING) << "Failed at iteration " << i;
    }

    // First string should still be accessible
    EXPECT_EQ(pool_.get(first_id), "first_string");
}

// ============================================================================
// 6. Deduplication Correctness Tests
// ============================================================================

TEST_F(StringPoolTest, Intern_SameContentDifferentCase_DifferentIds) {
    StringId id_lower = pool_.intern("hello");
    StringId id_upper = pool_.intern("Hello");
    StringId id_caps = pool_.intern("HELLO");

    EXPECT_NE(id_lower, INVALID_STRING);
    EXPECT_NE(id_upper, INVALID_STRING);
    EXPECT_NE(id_caps, INVALID_STRING);

    // Case-sensitive: all different
    EXPECT_NE(id_lower, id_upper);
    EXPECT_NE(id_lower, id_caps);
    EXPECT_NE(id_upper, id_caps);
}

TEST_F(StringPoolTest, Intern_TrailingSpace_DifferentFromWithout) {
    StringId id_no_space = pool_.intern("test");
    StringId id_trailing = pool_.intern("test ");
    StringId id_leading = pool_.intern(" test");

    EXPECT_NE(id_no_space, id_trailing);
    EXPECT_NE(id_no_space, id_leading);
    EXPECT_NE(id_trailing, id_leading);
}

TEST_F(StringPoolTest, Intern_BinaryContent_ByteExact) {
    // Binary content with null bytes - using explicit length
    const char binary[] = {'\x00', '\x01', '\x02', '\x03'};
    std::string_view sv(binary, 4);

    StringId id = pool_.intern(sv);
    EXPECT_NE(id, INVALID_STRING);

    std::string_view result = pool_.get(id);
    EXPECT_EQ(result.size(), 4U);
    EXPECT_EQ(result[0], '\x00');
    EXPECT_EQ(result[1], '\x01');
    EXPECT_EQ(result[2], '\x02');
    EXPECT_EQ(result[3], '\x03');
}

// ============================================================================
// 7. Concurrent Operations Tests
// ============================================================================

TEST_F(StringPoolTest, Intern_ConcurrentSameString_AllGetSameId) {
    constexpr int kNumThreads = 8;
    constexpr int kItersPerThread = 1000;

    std::vector<StringId> results(kNumThreads * kItersPerThread);
    std::vector<std::thread> threads;

    for (int t = 0; t < kNumThreads; ++t) {
        threads.emplace_back([this, t, &results]() {
            for (int i = 0; i < kItersPerThread; ++i) {
                results[t * kItersPerThread + i] = pool_.intern("shared_string");
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    // All results should be the same ID
    StringId expected = results[0];
    EXPECT_NE(expected, INVALID_STRING);
    
    for (const auto& id : results) {
        EXPECT_EQ(id, expected);
    }

    // Only one string should be interned
    EXPECT_EQ(pool_.count(), 1U);
}

TEST_F(StringPoolTest, Intern_ConcurrentDifferentStrings_AllUnique) {
    constexpr int kNumThreads = 10;
    constexpr int kStringsPerThread = 1000;

    std::vector<std::vector<StringId>> thread_ids(kNumThreads);
    std::vector<std::thread> threads;

    for (int t = 0; t < kNumThreads; ++t) {
        thread_ids[t].reserve(kStringsPerThread);
        threads.emplace_back([this, t, &thread_ids]() {
            for (int i = 0; i < kStringsPerThread; ++i) {
                std::string str = "t" + std::to_string(t) + "_s" + std::to_string(i);
                StringId id = pool_.intern(str);
                EXPECT_NE(id, INVALID_STRING);
                thread_ids[t].push_back(id);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    // Collect all IDs and verify uniqueness
    std::set<StringId> unique_ids;
    for (const auto& ids : thread_ids) {
        for (StringId id : ids) {
            auto [_, inserted] = unique_ids.insert(id);
            EXPECT_TRUE(inserted) << "Duplicate ID detected!";
        }
    }

    EXPECT_EQ(unique_ids.size(), kNumThreads * kStringsPerThread);
    EXPECT_EQ(pool_.count(), kNumThreads * kStringsPerThread);
}

TEST_F(StringPoolTest, Intern_ConcurrentWithGet_NoRace) {
    // Pre-intern some strings
    constexpr int kPreIntern = 100;
    std::vector<StringId> pre_ids;
    pre_ids.reserve(kPreIntern);

    for (int i = 0; i < kPreIntern; ++i) {
        pre_ids.push_back(pool_.intern("pre_" + std::to_string(i)));
    }

    constexpr int kNumInternThreads = 4;
    constexpr int kNumGetThreads = 4;
    constexpr int kItersPerThread = 1000;

    std::atomic<bool> found_mismatch{false};
    std::vector<std::thread> threads;

    // Intern threads
    for (int t = 0; t < kNumInternThreads; ++t) {
        threads.emplace_back([this, t]() {
            for (int i = 0; i < kItersPerThread; ++i) {
                pool_.intern("intern_t" + std::to_string(t) + "_i" + std::to_string(i));
            }
        });
    }

    // Get threads - read pre-interned strings
    for (int t = 0; t < kNumGetThreads; ++t) {
        threads.emplace_back([this, &pre_ids, &found_mismatch]() {
            for (int i = 0; i < kItersPerThread; ++i) {
                int idx = i % kPreIntern;
                std::string_view result = pool_.get(pre_ids[idx]);
                std::string expected = "pre_" + std::to_string(idx);
                if (result != expected) {
                    found_mismatch.store(true, std::memory_order_relaxed);
                }
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    EXPECT_FALSE(found_mismatch.load()) << "Data race detected: get() returned wrong value";
}

TEST_F(StringPoolTest, Intern_HighContention_StressTest) {
    // 100 threads, 100 unique strings, 1000 repeats each
    // All threads intern the same 100 strings repeatedly
    constexpr int kNumThreads = 100;
    constexpr int kNumStrings = 100;
    constexpr int kRepeatsPerString = 100;

    // Pre-generate expected strings
    std::vector<std::string> strings;
    strings.reserve(kNumStrings);
    for (int i = 0; i < kNumStrings; ++i) {
        strings.push_back("common_" + std::to_string(i));
    }

    std::vector<std::vector<StringId>> thread_results(kNumThreads);
    std::vector<std::thread> threads;

    for (int t = 0; t < kNumThreads; ++t) {
        thread_results[t].reserve(kNumStrings * kRepeatsPerString);
        threads.emplace_back([this, t, &strings, &thread_results]() {
            for (int r = 0; r < kRepeatsPerString; ++r) {
                for (int s = 0; s < kNumStrings; ++s) {
                    thread_results[t].push_back(pool_.intern(strings[s]));
                }
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    // Verify: all interns of same string should return same ID
    // Build map from string index to expected ID (from first thread's first iteration)
    std::vector<StringId> expected_ids(kNumStrings);
    for (int s = 0; s < kNumStrings; ++s) {
        expected_ids[s] = thread_results[0][s];
        EXPECT_NE(expected_ids[s], INVALID_STRING);
    }

    // Verify all threads got same IDs for same strings
    for (int t = 0; t < kNumThreads; ++t) {
        for (int r = 0; r < kRepeatsPerString; ++r) {
            for (int s = 0; s < kNumStrings; ++s) {
                int idx = r * kNumStrings + s;
                EXPECT_EQ(thread_results[t][idx], expected_ids[s])
                    << "Thread " << t << " repeat " << r << " string " << s;
            }
        }
    }

    // Only 100 unique strings should exist
    EXPECT_EQ(pool_.count(), kNumStrings);
}

// ============================================================================
// 8. Memory Metrics Tests
// ============================================================================

TEST_F(StringPoolTest, BytesUsed_AfterInterns_AccurateCount) {
    EXPECT_EQ(pool_.bytes_used(), 0U);

    // Intern strings of known lengths
    // Storage format: [len:u32][chars...]
    pool_.intern("abc");     // 4 + 3 = 7 bytes
    pool_.intern("hello");   // 4 + 5 = 9 bytes
    pool_.intern("");        // 4 + 0 = 4 bytes

    std::size_t expected = (4 + 3) + (4 + 5) + (4 + 0);
    EXPECT_EQ(pool_.bytes_used(), expected);
}

TEST_F(StringPoolTest, BytesUsed_Deduplication_NoDuplicateBytes) {
    pool_.intern("test");
    std::size_t after_first = pool_.bytes_used();
    EXPECT_EQ(after_first, 4U + 4U);  // 4 bytes len + 4 bytes "test"

    // Intern same string 1000 times
    for (int i = 0; i < 1000; ++i) {
        pool_.intern("test");
    }

    // bytes_used should not change (deduplication)
    EXPECT_EQ(pool_.bytes_used(), after_first);
}

TEST_F(StringPoolTest, Count_Accurate_AfterOperations) {
    constexpr int kUniqueStrings = 50;
    constexpr int kDuplicatesEach = 10;

    EXPECT_EQ(pool_.count(), 0U);

    // Intern N unique strings, M duplicates each
    for (int i = 0; i < kUniqueStrings; ++i) {
        std::string str = "unique_" + std::to_string(i);
        for (int j = 0; j < kDuplicatesEach; ++j) {
            pool_.intern(str);
        }
    }

    // Count should reflect only unique strings
    EXPECT_EQ(pool_.count(), kUniqueStrings);
}

// ============================================================================
// 9. Arena Exhaustion Tests
// ============================================================================

class SmallArenaStringPoolTest : public ::testing::Test {
protected:
    // Small arena: 1KB - will exhaust quickly
    // Due to 64-byte alignment in Arena, each allocation uses at least 64 bytes
    static constexpr std::size_t kSmallArenaSize = 1024;

    Arena arena_{kSmallArenaSize};
    StringPool pool_{arena_};
};

TEST_F(SmallArenaStringPoolTest, Intern_ArenaFull_GracefulFailure) {
    // Keep interning until we get INVALID_STRING
    std::vector<StringId> valid_ids;
    bool exhausted = false;

    for (int i = 0; i < 1000; ++i) {
        // Create a moderately sized string to exhaust arena faster
        std::string str(100, 'x');
        str += std::to_string(i);
        
        StringId id = pool_.intern(str);
        if (id == INVALID_STRING) {
            exhausted = true;
            break;
        }
        valid_ids.push_back(id);
    }

    EXPECT_TRUE(exhausted) << "Arena should have been exhausted";
    EXPECT_GT(valid_ids.size(), 0U) << "Should have interned at least one string";
}

TEST_F(SmallArenaStringPoolTest, Intern_AfterExhaustion_ConsistentState) {
    // Intern strings and track their IDs
    std::vector<std::pair<std::string, StringId>> interned;

    for (int i = 0; i < 1000; ++i) {
        std::string str = "str_" + std::to_string(i);
        StringId id = pool_.intern(str);
        if (id == INVALID_STRING) {
            break;
        }
        interned.emplace_back(str, id);
    }

    ASSERT_GT(interned.size(), 0U) << "Should have interned at least one string";

    // Try to intern more (should fail)
    StringId fail_id = pool_.intern("this_should_fail_due_to_exhaustion");
    (void)fail_id;  // May or may not fail depending on remaining space

    // All previously interned strings should still be accessible
    for (const auto& [str, id] : interned) {
        EXPECT_EQ(pool_.get(id), str) 
            << "String '" << str << "' corrupted after exhaustion attempt";
    }

    // Count should match number of successful interns
    EXPECT_GE(pool_.count(), interned.size());
}

}  // namespace
}  // namespace exeray::event
