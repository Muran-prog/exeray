#pragma once

/**
 * @file payload.hpp
 * @brief Event payload structures for the Event Graph system.
 *
 * Defines category-specific payload structures and a tagged union
 * for efficient, type-safe event data storage.
 */

#include <cstdint>
#include <type_traits>

#include "types.hpp"
#include "payloads/all.hpp"

namespace exeray::event {

// ---------------------------------------------------------------------------
// Tagged Union
// ---------------------------------------------------------------------------

/**
 * @brief Tagged union for all event payloads.
 *
 * Uses Category as the discriminator tag. Total size is fixed at 32 bytes
 * for cache efficiency and predictable memory layout.
 *
 * Usage example:
 * @code
 * EventPayload payload;
 * payload.category = Category::FileSystem;
 * payload.file.path = some_string_id;
 * payload.file.size = 1024;
 * @endcode
 */
struct EventPayload {
    Category category;     ///< Discriminator tag indicating active union member
    uint8_t _pad[7];       ///< Explicit padding to align union at 8 bytes

    union {
        FilePayload file;           ///< Active when category == FileSystem
        RegistryPayload registry;   ///< Active when category == Registry
        NetworkPayload network;     ///< Active when category == Network
        ProcessPayload process;     ///< Active when category == Process
        SchedulerPayload scheduler; ///< Active when category == Scheduler
        InputPayload input;         ///< Active when category == Input
        ImagePayload image;         ///< Active when category == Image
        ThreadPayload thread;       ///< Active when category == Thread
        MemoryPayload memory;       ///< Active when category == Memory
        ScriptPayload script;       ///< Active when category == Script
        AmsiPayload amsi;           ///< Active when category == Amsi
        DnsPayload dns;             ///< Active when category == Dns
        SecurityPayload security;   ///< Active when category == Security
        ServicePayload service;     ///< Active when category == Service
        WmiPayload wmi;             ///< Active when category == Wmi
        ClrPayload clr;             ///< Active when category == Clr
    };
};

// ---------------------------------------------------------------------------
// Static Assertions - Size Validation
// ---------------------------------------------------------------------------

static_assert(sizeof(FilePayload) == 24,
              "FilePayload must be 24 bytes");
static_assert(sizeof(RegistryPayload) == 16,
              "RegistryPayload must be 16 bytes");
static_assert(sizeof(NetworkPayload) == 20,
              "NetworkPayload must be 20 bytes");
static_assert(sizeof(ProcessPayload) == 16,
              "ProcessPayload must be 16 bytes");
static_assert(sizeof(SchedulerPayload) == 16,
              "SchedulerPayload must be 16 bytes");
static_assert(sizeof(InputPayload) == 16,
              "InputPayload must be 16 bytes");
static_assert(sizeof(ImagePayload) == 24,
              "ImagePayload must be 24 bytes");
static_assert(sizeof(ThreadPayload) == 24,
              "ThreadPayload must be 24 bytes");
static_assert(sizeof(MemoryPayload) == 24,
              "MemoryPayload must be 24 bytes");
static_assert(sizeof(ScriptPayload) == 16,
              "ScriptPayload must be 16 bytes");
static_assert(sizeof(AmsiPayload) == 16,
              "AmsiPayload must be 16 bytes");
static_assert(sizeof(DnsPayload) == 20,
              "DnsPayload must be 20 bytes");
static_assert(sizeof(SecurityPayload) == 24,
              "SecurityPayload must be 24 bytes");
static_assert(sizeof(ServicePayload) == 20,
              "ServicePayload must be 20 bytes");
static_assert(sizeof(WmiPayload) == 16,
              "WmiPayload must be 16 bytes");
static_assert(sizeof(ClrPayload) == 24,
              "ClrPayload must be 24 bytes");

static_assert(sizeof(EventPayload) == 32,
              "EventPayload must be exactly 32 bytes");

// ---------------------------------------------------------------------------
// Static Assertions - Trivially Copyable
// ---------------------------------------------------------------------------

static_assert(std::is_trivially_copyable_v<FilePayload>,
              "FilePayload must be trivially copyable");
static_assert(std::is_trivially_copyable_v<RegistryPayload>,
              "RegistryPayload must be trivially copyable");
static_assert(std::is_trivially_copyable_v<NetworkPayload>,
              "NetworkPayload must be trivially copyable");
static_assert(std::is_trivially_copyable_v<ProcessPayload>,
              "ProcessPayload must be trivially copyable");
static_assert(std::is_trivially_copyable_v<SchedulerPayload>,
              "SchedulerPayload must be trivially copyable");
static_assert(std::is_trivially_copyable_v<InputPayload>,
              "InputPayload must be trivially copyable");
static_assert(std::is_trivially_copyable_v<ImagePayload>,
              "ImagePayload must be trivially copyable");
static_assert(std::is_trivially_copyable_v<ThreadPayload>,
              "ThreadPayload must be trivially copyable");
static_assert(std::is_trivially_copyable_v<MemoryPayload>,
              "MemoryPayload must be trivially copyable");
static_assert(std::is_trivially_copyable_v<ScriptPayload>,
              "ScriptPayload must be trivially copyable");
static_assert(std::is_trivially_copyable_v<AmsiPayload>,
              "AmsiPayload must be trivially copyable");
static_assert(std::is_trivially_copyable_v<DnsPayload>,
              "DnsPayload must be trivially copyable");
static_assert(std::is_trivially_copyable_v<SecurityPayload>,
              "SecurityPayload must be trivially copyable");
static_assert(std::is_trivially_copyable_v<ServicePayload>,
              "ServicePayload must be trivially copyable");
static_assert(std::is_trivially_copyable_v<WmiPayload>,
              "WmiPayload must be trivially copyable");
static_assert(std::is_trivially_copyable_v<ClrPayload>,
              "ClrPayload must be trivially copyable");
static_assert(std::is_trivially_copyable_v<EventPayload>,
              "EventPayload must be trivially copyable");

}  // namespace exeray::event
