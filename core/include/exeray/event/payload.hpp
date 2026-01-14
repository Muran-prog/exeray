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

namespace exeray::event {

// ---------------------------------------------------------------------------
// Individual Payload Structures
// ---------------------------------------------------------------------------

/**
 * @brief Payload for file system operations.
 *
 * Contains file path, size, and attributes for file/directory events.
 */
struct FilePayload {
    StringId path;         ///< Interned file/directory path
    uint64_t size;         ///< File size in bytes
    uint32_t attributes;   ///< File attributes (platform-specific)
    uint32_t _pad;         ///< Explicit padding for 8-byte alignment
};

/**
 * @brief Payload for Windows registry operations.
 *
 * Contains registry key path, value name, type, and data size.
 */
struct RegistryPayload {
    StringId key_path;     ///< Interned registry key path
    StringId value_name;   ///< Interned value name
    uint32_t value_type;   ///< Registry value type (REG_SZ, REG_DWORD, etc.)
    uint32_t data_size;    ///< Size of value data in bytes
};

/**
 * @brief Payload for network operations.
 *
 * Contains local/remote addresses, ports, byte count, and protocol.
 */
struct NetworkPayload {
    uint32_t local_addr;   ///< Local IPv4 address
    uint32_t remote_addr;  ///< Remote IPv4 address
    uint16_t local_port;   ///< Local port number
    uint16_t remote_port;  ///< Remote port number
    uint32_t bytes;        ///< Number of bytes transferred
    uint8_t protocol;      ///< Protocol type (TCP=6, UDP=17)
    uint8_t _pad[3];       ///< Explicit padding for 4-byte alignment
};

/**
 * @brief Payload for process operations.
 *
 * Contains process IDs and executable information.
 */
struct ProcessPayload {
    uint32_t pid;          ///< Process ID
    uint32_t parent_pid;   ///< Parent process ID
    StringId image_path;   ///< Interned executable path
    StringId command_line; ///< Interned command line arguments
};

/**
 * @brief Payload for task scheduler operations.
 *
 * Contains scheduled task name, action, and trigger type.
 */
struct SchedulerPayload {
    StringId task_name;    ///< Interned task name
    StringId action;       ///< Interned action description
    uint32_t trigger_type; ///< Task trigger type
    uint32_t _pad;         ///< Explicit padding for alignment
};

/**
 * @brief Payload for input device hook operations.
 *
 * Contains hook type and target thread information.
 */
struct InputPayload {
    uint32_t hook_type;    ///< Type of input hook
    uint32_t target_tid;   ///< Target thread ID
    uint64_t _pad;         ///< Explicit padding for alignment
};

/**
 * @brief Payload for image load/unload operations.
 *
 * Contains image path, load address, size, and suspicious flag.
 * Used for detecting process injection via LoadLibrary/LdrLoadDll.
 */
struct ImagePayload {
    StringId image_path;     ///< Interned DLL/EXE path
    uint32_t process_id;     ///< Target process ID
    uint64_t base_address;   ///< Load address in target process
    uint32_t size;           ///< Image size in bytes (max 4GB)
    uint8_t is_suspicious;   ///< 1 if loaded from temp/appdata
    uint8_t _pad[3];         ///< Explicit padding for alignment
};

/**
 * @brief Payload for thread operations.
 *
 * Contains thread ID, process IDs, and start address for injection detection.
 * Used for detecting remote thread injection (CreateRemoteThread).
 */
struct ThreadPayload {
    uint32_t thread_id;      ///< Thread ID
    uint32_t process_id;     ///< Target process ID (thread owner)
    uint64_t start_address;  ///< Thread entry point address
    uint32_t creator_pid;    ///< Creator process ID (who created the thread)
    uint8_t is_remote;       ///< 1 if remote thread injection detected
    uint8_t _pad[3];         ///< Explicit padding for alignment
};

/**
 * @brief Payload for virtual memory operations.
 *
 * Contains allocation details for VirtualAlloc/VirtualFree detection.
 * Used for detecting RWX shellcode allocations (fileless malware).
 */
struct MemoryPayload {
    uint64_t base_address;   ///< Allocated memory base address
    uint32_t region_size;    ///< Size of allocation in bytes (max 4GB)
    uint32_t process_id;     ///< Target process ID
    uint32_t protection;     ///< PAGE_* protection flags
    uint8_t is_suspicious;   ///< 1 if RWX allocation detected
    uint8_t _pad[3];         ///< Explicit padding for alignment
};

/**
 * @brief Payload for PowerShell script operations.
 *
 * Contains script content and context for fileless malware detection.
 * Used for Script Block Logging (Event 4104) and Module Logging (Event 4103).
 */
struct ScriptPayload {
    StringId script_block;   ///< Interned script content
    StringId context;        ///< Host application, RunspaceId
    uint32_t sequence;       ///< Sequence number for multi-part scripts
    uint8_t is_suspicious;   ///< 1 if dangerous patterns detected
    uint8_t _pad[3];         ///< Explicit padding for alignment
};

/**
 * @brief Payload for AMSI scan operations.
 *
 * Contains scanned content info for bypass/malware detection.
 * Used for detecting AMSI bypass attempts (empty content after PowerShell).
 */
struct AmsiPayload {
    StringId content;        ///< Interned scanned content (truncated)
    StringId app_name;       ///< Interned requesting application name
    uint32_t scan_result;    ///< AMSI_RESULT_* value
    uint32_t content_size;   ///< Original content size in bytes
};

/**
 * @brief Payload for DNS operations.
 *
 * Contains DNS query info for C2/DGA domain detection.
 * Used for Event ID 3006 (Query Completed) and 3008 (Query Failed).
 */
struct DnsPayload {
    StringId domain;        ///< Requested domain name (interned)
    uint32_t query_type;    ///< A=1, AAAA=28, TXT=16, MX=15, CNAME=5
    uint32_t result_code;   ///< DNS response code (0=success)
    uint32_t resolved_ip;   ///< IPv4 address if type A
    uint8_t is_suspicious;  ///< 1 if DGA-like domain detected
    uint8_t _pad[3];        ///< Explicit padding for alignment
};

/**
 * @brief Payload for security auditing events.
 *
 * Contains logon/privilege event details for forensics and privilege
 * escalation detection. Used for Events 4624, 4625, 4688, 4689, 4703.
 */
struct SecurityPayload {
    StringId subject_user;   ///< Account performing the action
    StringId target_user;    ///< Target account (if different)
    StringId command_line;   ///< Full command line (Event 4688)
    uint32_t logon_type;     ///< Logon type (2=Interactive, 3=Network, 10=Remote)
    uint32_t process_id;     ///< New/target process ID
    uint8_t is_suspicious;   ///< 1 if suspicious (SeDebugPrivilege, brute force)
    uint8_t _pad[3];         ///< Explicit padding
};

/**
 * @brief Payload for Windows service operations.
 *
 * Contains service installation details for persistence detection.
 * Used for Event 4697 (Service Installation).
 */
struct ServicePayload {
    StringId service_name;   ///< Service display name
    StringId service_path;   ///< Service executable path
    uint32_t service_type;   ///< Service type (0x10=Own, 0x20=Share)
    uint32_t start_type;     ///< Start type (0x2=AUTO, 0x3=DEMAND)
    uint8_t is_suspicious;   ///< 1 if AUTO_START (persistence)
    uint8_t _pad[3];         ///< Explicit padding
};

/**
 * @brief Payload for WMI operations.
 *
 * Contains WMI activity details for attack detection including
 * lateral movement, persistence via Event Subscriptions, and
 * fileless execution via Win32_Process.Create.
 */
struct WmiPayload {
    StringId wmi_namespace;  ///< root\cimv2, etc.
    StringId query;          ///< WQL query or method name
    StringId target_host;    ///< Remote host if any
    uint8_t is_remote;       ///< 1 if not localhost
    uint8_t is_suspicious;   ///< 1 if dangerous pattern
    uint8_t _pad[2];         ///< Explicit padding
};

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
static_assert(std::is_trivially_copyable_v<EventPayload>,
              "EventPayload must be trivially copyable");

}  // namespace exeray::event
