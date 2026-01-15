#pragma once

/**
 * @file static_asserts.hpp
 * @brief Static assertions for type validation.
 */

#include <type_traits>
#include "category.hpp"
#include "status.hpp"
#include "operations/all.hpp"

namespace exeray::event {

// ---------------------------------------------------------------------------
// Static Assertions - Size Validation
// ---------------------------------------------------------------------------

// Verify all enums are 1 byte as required for compact storage
static_assert(sizeof(Category) == 1, "Category must be 1 byte");
static_assert(sizeof(FileOp) == 1, "FileOp must be 1 byte");
static_assert(sizeof(RegistryOp) == 1, "RegistryOp must be 1 byte");
static_assert(sizeof(NetworkOp) == 1, "NetworkOp must be 1 byte");
static_assert(sizeof(ProcessOp) == 1, "ProcessOp must be 1 byte");
static_assert(sizeof(SchedulerOp) == 1, "SchedulerOp must be 1 byte");
static_assert(sizeof(InputOp) == 1, "InputOp must be 1 byte");
static_assert(sizeof(ImageOp) == 1, "ImageOp must be 1 byte");
static_assert(sizeof(ThreadOp) == 1, "ThreadOp must be 1 byte");
static_assert(sizeof(MemoryOp) == 1, "MemoryOp must be 1 byte");
static_assert(sizeof(ScriptOp) == 1, "ScriptOp must be 1 byte");
static_assert(sizeof(AmsiOp) == 1, "AmsiOp must be 1 byte");
static_assert(sizeof(DnsOp) == 1, "DnsOp must be 1 byte");
static_assert(sizeof(SecurityOp) == 1, "SecurityOp must be 1 byte");
static_assert(sizeof(ServiceOp) == 1, "ServiceOp must be 1 byte");
static_assert(sizeof(WmiOp) == 1, "WmiOp must be 1 byte");
static_assert(sizeof(ClrOp) == 1, "ClrOp must be 1 byte");
static_assert(sizeof(Status) == 1, "Status must be 1 byte");

// ---------------------------------------------------------------------------
// Static Assertions - Trivial Copyability
// ---------------------------------------------------------------------------

// Verify enums are trivially copyable for zero-copy semantics
static_assert(std::is_trivially_copyable_v<Category>,
              "Category must be trivially copyable");
static_assert(std::is_trivially_copyable_v<FileOp>,
              "FileOp must be trivially copyable");
static_assert(std::is_trivially_copyable_v<RegistryOp>,
              "RegistryOp must be trivially copyable");
static_assert(std::is_trivially_copyable_v<NetworkOp>,
              "NetworkOp must be trivially copyable");
static_assert(std::is_trivially_copyable_v<ProcessOp>,
              "ProcessOp must be trivially copyable");
static_assert(std::is_trivially_copyable_v<SchedulerOp>,
              "SchedulerOp must be trivially copyable");
static_assert(std::is_trivially_copyable_v<InputOp>,
              "InputOp must be trivially copyable");
static_assert(std::is_trivially_copyable_v<ImageOp>,
              "ImageOp must be trivially copyable");
static_assert(std::is_trivially_copyable_v<ThreadOp>,
              "ThreadOp must be trivially copyable");
static_assert(std::is_trivially_copyable_v<MemoryOp>,
              "MemoryOp must be trivially copyable");
static_assert(std::is_trivially_copyable_v<ScriptOp>,
              "ScriptOp must be trivially copyable");
static_assert(std::is_trivially_copyable_v<AmsiOp>,
              "AmsiOp must be trivially copyable");
static_assert(std::is_trivially_copyable_v<DnsOp>,
              "DnsOp must be trivially copyable");
static_assert(std::is_trivially_copyable_v<SecurityOp>,
              "SecurityOp must be trivially copyable");
static_assert(std::is_trivially_copyable_v<ServiceOp>,
              "ServiceOp must be trivially copyable");
static_assert(std::is_trivially_copyable_v<WmiOp>,
              "WmiOp must be trivially copyable");
static_assert(std::is_trivially_copyable_v<ClrOp>,
              "ClrOp must be trivially copyable");
static_assert(std::is_trivially_copyable_v<Status>,
              "Status must be trivially copyable");

}  // namespace exeray::event
