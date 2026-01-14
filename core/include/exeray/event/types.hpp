#pragma once

/**
 * @file types.hpp
 * @brief Base types for Event Graph system.
 *
 * Defines event categories, operation types, and fundamental type aliases
 * used throughout the event monitoring subsystem.
 */

#include <cstdint>
#include <type_traits>

namespace exeray::event {

// ---------------------------------------------------------------------------
// Type Aliases
// ---------------------------------------------------------------------------

/// Unique identifier for events in the graph.
using EventId = std::uint64_t;

/// Interned string identifier for zero-copy string storage.
using StringId = std::uint32_t;

/// High-resolution timestamp in nanoseconds since epoch.
using Timestamp = std::uint64_t;

/// Invalid event identifier sentinel.
constexpr EventId INVALID_EVENT = 0;

/// Invalid string identifier sentinel.
constexpr StringId INVALID_STRING = 0;

// ---------------------------------------------------------------------------
// Category Enum
// ---------------------------------------------------------------------------

/**
 * @brief Top-level event category classification.
 *
 * Each monitored operation belongs to exactly one category.
 * Categories are used for filtering, routing, and visualization.
 */
enum class Category : std::uint8_t {
    FileSystem,   ///< File and directory operations
    Registry,     ///< Windows registry operations
    Network,      ///< Network socket and DNS operations
    Process,      ///< Process and module operations
    Scheduler,    ///< Task scheduler operations
    Input,        ///< Input device hooks and blocks
    Image,        ///< DLL/EXE image load/unload operations
    Thread,       ///< Thread creation/termination operations
    Memory,       ///< Virtual memory allocation operations

    Count         ///< Sentinel for iteration (not a valid category)
};

// ---------------------------------------------------------------------------
// Operation Enums
// ---------------------------------------------------------------------------

/**
 * @brief File system operation types.
 */
enum class FileOp : std::uint8_t {
    Create,        ///< Create file or directory
    Delete,        ///< Delete file or directory
    Read,          ///< Read from file
    Write,         ///< Write to file
    Rename,        ///< Rename file or directory
    SetAttributes  ///< Modify file attributes
};

/**
 * @brief Windows registry operation types.
 */
enum class RegistryOp : std::uint8_t {
    CreateKey,   ///< Create registry key
    DeleteKey,   ///< Delete registry key
    SetValue,    ///< Set registry value
    DeleteValue, ///< Delete registry value
    QueryValue   ///< Query registry value
};

/**
 * @brief Network operation types.
 */
enum class NetworkOp : std::uint8_t {
    Connect,   ///< Outbound connection
    Listen,    ///< Start listening on port
    Send,      ///< Send data
    Receive,   ///< Receive data
    DnsQuery   ///< DNS resolution query
};

/**
 * @brief Process operation types.
 */
enum class ProcessOp : std::uint8_t {
    Create,      ///< Create child process
    Terminate,   ///< Terminate process
    Inject,      ///< Inject code/memory into process
    LoadLibrary  ///< Load DLL/module
};

/**
 * @brief Task scheduler operation types.
 */
enum class SchedulerOp : std::uint8_t {
    CreateTask, ///< Create scheduled task
    DeleteTask, ///< Delete scheduled task
    ModifyTask, ///< Modify existing task
    RunTask     ///< Manually trigger task execution
};

/**
 * @brief Input device operation types.
 *
 * These operations are often associated with malicious activity.
 */
enum class InputOp : std::uint8_t {
    BlockKeyboard, ///< Block keyboard input
    BlockMouse,    ///< Block mouse input
    InstallHook    ///< Install input hook
};

/**
 * @brief Image load/unload operation types.
 *
 * Tracks DLL and EXE loading for process injection detection.
 */
enum class ImageOp : std::uint8_t {
    Load,   ///< Image loaded into process
    Unload  ///< Image unloaded from process
};

/**
 * @brief Thread operation types.
 *
 * Tracks thread creation/termination for remote injection detection.
 */
enum class ThreadOp : std::uint8_t {
    Start,    ///< Thread started
    End,      ///< Thread terminated
    DCStart,  ///< Running thread enumeration (session start)
    DCEnd     ///< Running thread enumeration (session end)
};

/**
 * @brief Virtual memory operation types.
 *
 * Tracks VirtualAlloc/VirtualProtect for RWX shellcode detection.
 */
enum class MemoryOp : std::uint8_t {
    Alloc,    ///< VirtualAlloc
    Free      ///< VirtualFree
};

// ---------------------------------------------------------------------------
// Status Enum
// ---------------------------------------------------------------------------

/**
 * @brief Operation result status.
 */
enum class Status : std::uint8_t {
    Success,    ///< Operation completed successfully
    Denied,     ///< Operation was denied (access/permission)
    Pending,    ///< Operation is in progress
    Error,      ///< Operation failed with error
    Suspicious  ///< Operation flagged as potentially malicious
};

// ---------------------------------------------------------------------------
// Static Assertions
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
static_assert(sizeof(Status) == 1, "Status must be 1 byte");

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
static_assert(std::is_trivially_copyable_v<Status>,
              "Status must be trivially copyable");

}  // namespace exeray::event
