#pragma once

/**
 * @file static_asserts.hpp
 * @brief Static assertions for type validation.
 *
 * This file ensures:
 * 1. All enums are 1-byte for compact storage
 * 2. All enums are trivially copyable for zero-copy semantics
 * 3. All enum values are sequential starting from 0 (no gaps)
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

// ---------------------------------------------------------------------------
// Static Assertions - Category enum values are sequential (0..N-1)
// ---------------------------------------------------------------------------

static_assert(static_cast<int>(Category::FileSystem) == 0, "Category::FileSystem must be 0");
static_assert(static_cast<int>(Category::Registry) == 1, "Category::Registry must be 1");
static_assert(static_cast<int>(Category::Network) == 2, "Category::Network must be 2");
static_assert(static_cast<int>(Category::Process) == 3, "Category::Process must be 3");
static_assert(static_cast<int>(Category::Scheduler) == 4, "Category::Scheduler must be 4");
static_assert(static_cast<int>(Category::Input) == 5, "Category::Input must be 5");
static_assert(static_cast<int>(Category::Image) == 6, "Category::Image must be 6");
static_assert(static_cast<int>(Category::Thread) == 7, "Category::Thread must be 7");
static_assert(static_cast<int>(Category::Memory) == 8, "Category::Memory must be 8");
static_assert(static_cast<int>(Category::Script) == 9, "Category::Script must be 9");
static_assert(static_cast<int>(Category::Amsi) == 10, "Category::Amsi must be 10");
static_assert(static_cast<int>(Category::Dns) == 11, "Category::Dns must be 11");
static_assert(static_cast<int>(Category::Security) == 12, "Category::Security must be 12");
static_assert(static_cast<int>(Category::Service) == 13, "Category::Service must be 13");
static_assert(static_cast<int>(Category::Wmi) == 14, "Category::Wmi must be 14");
static_assert(static_cast<int>(Category::Clr) == 15, "Category::Clr must be 15");
static_assert(static_cast<int>(Category::Count) == 16, "Category::Count must be 16 (total categories)");

// ---------------------------------------------------------------------------
// Static Assertions - Status enum values are sequential (0..N-1)
// ---------------------------------------------------------------------------

static_assert(static_cast<int>(Status::Success) == 0, "Status::Success must be 0");
static_assert(static_cast<int>(Status::Denied) == 1, "Status::Denied must be 1");
static_assert(static_cast<int>(Status::Pending) == 2, "Status::Pending must be 2");
static_assert(static_cast<int>(Status::Error) == 3, "Status::Error must be 3");
static_assert(static_cast<int>(Status::Suspicious) == 4, "Status::Suspicious must be 4");

// ---------------------------------------------------------------------------
// Static Assertions - FileOp enum values are sequential (0..N-1)
// ---------------------------------------------------------------------------

static_assert(static_cast<int>(FileOp::Create) == 0, "FileOp::Create must be 0");
static_assert(static_cast<int>(FileOp::Delete) == 1, "FileOp::Delete must be 1");
static_assert(static_cast<int>(FileOp::Read) == 2, "FileOp::Read must be 2");
static_assert(static_cast<int>(FileOp::Write) == 3, "FileOp::Write must be 3");
static_assert(static_cast<int>(FileOp::Rename) == 4, "FileOp::Rename must be 4");
static_assert(static_cast<int>(FileOp::SetAttributes) == 5, "FileOp::SetAttributes must be 5");

// ---------------------------------------------------------------------------
// Static Assertions - RegistryOp enum values are sequential (0..N-1)
// ---------------------------------------------------------------------------

static_assert(static_cast<int>(RegistryOp::CreateKey) == 0, "RegistryOp::CreateKey must be 0");
static_assert(static_cast<int>(RegistryOp::DeleteKey) == 1, "RegistryOp::DeleteKey must be 1");
static_assert(static_cast<int>(RegistryOp::SetValue) == 2, "RegistryOp::SetValue must be 2");
static_assert(static_cast<int>(RegistryOp::DeleteValue) == 3, "RegistryOp::DeleteValue must be 3");
static_assert(static_cast<int>(RegistryOp::QueryValue) == 4, "RegistryOp::QueryValue must be 4");

// ---------------------------------------------------------------------------
// Static Assertions - NetworkOp enum values are sequential (0..N-1)
// ---------------------------------------------------------------------------

static_assert(static_cast<int>(NetworkOp::Connect) == 0, "NetworkOp::Connect must be 0");
static_assert(static_cast<int>(NetworkOp::Listen) == 1, "NetworkOp::Listen must be 1");
static_assert(static_cast<int>(NetworkOp::Send) == 2, "NetworkOp::Send must be 2");
static_assert(static_cast<int>(NetworkOp::Receive) == 3, "NetworkOp::Receive must be 3");
static_assert(static_cast<int>(NetworkOp::DnsQuery) == 4, "NetworkOp::DnsQuery must be 4");

// ---------------------------------------------------------------------------
// Static Assertions - ProcessOp enum values are sequential (0..N-1)
// ---------------------------------------------------------------------------

static_assert(static_cast<int>(ProcessOp::Create) == 0, "ProcessOp::Create must be 0");
static_assert(static_cast<int>(ProcessOp::Terminate) == 1, "ProcessOp::Terminate must be 1");
static_assert(static_cast<int>(ProcessOp::Inject) == 2, "ProcessOp::Inject must be 2");
static_assert(static_cast<int>(ProcessOp::LoadLibrary) == 3, "ProcessOp::LoadLibrary must be 3");

// ---------------------------------------------------------------------------
// Static Assertions - SchedulerOp enum values are sequential (0..N-1)
// ---------------------------------------------------------------------------

static_assert(static_cast<int>(SchedulerOp::CreateTask) == 0, "SchedulerOp::CreateTask must be 0");
static_assert(static_cast<int>(SchedulerOp::DeleteTask) == 1, "SchedulerOp::DeleteTask must be 1");
static_assert(static_cast<int>(SchedulerOp::ModifyTask) == 2, "SchedulerOp::ModifyTask must be 2");
static_assert(static_cast<int>(SchedulerOp::RunTask) == 3, "SchedulerOp::RunTask must be 3");

// ---------------------------------------------------------------------------
// Static Assertions - InputOp enum values are sequential (0..N-1)
// ---------------------------------------------------------------------------

static_assert(static_cast<int>(InputOp::BlockKeyboard) == 0, "InputOp::BlockKeyboard must be 0");
static_assert(static_cast<int>(InputOp::BlockMouse) == 1, "InputOp::BlockMouse must be 1");
static_assert(static_cast<int>(InputOp::InstallHook) == 2, "InputOp::InstallHook must be 2");

// ---------------------------------------------------------------------------
// Static Assertions - ImageOp enum values are sequential (0..N-1)
// ---------------------------------------------------------------------------

static_assert(static_cast<int>(ImageOp::Load) == 0, "ImageOp::Load must be 0");
static_assert(static_cast<int>(ImageOp::Unload) == 1, "ImageOp::Unload must be 1");

// ---------------------------------------------------------------------------
// Static Assertions - ThreadOp enum values are sequential (0..N-1)
// ---------------------------------------------------------------------------

static_assert(static_cast<int>(ThreadOp::Start) == 0, "ThreadOp::Start must be 0");
static_assert(static_cast<int>(ThreadOp::End) == 1, "ThreadOp::End must be 1");
static_assert(static_cast<int>(ThreadOp::DCStart) == 2, "ThreadOp::DCStart must be 2");
static_assert(static_cast<int>(ThreadOp::DCEnd) == 3, "ThreadOp::DCEnd must be 3");

// ---------------------------------------------------------------------------
// Static Assertions - MemoryOp enum values are sequential (0..N-1)
// ---------------------------------------------------------------------------

static_assert(static_cast<int>(MemoryOp::Alloc) == 0, "MemoryOp::Alloc must be 0");
static_assert(static_cast<int>(MemoryOp::Free) == 1, "MemoryOp::Free must be 1");

// ---------------------------------------------------------------------------
// Static Assertions - ScriptOp enum values are sequential (0..N-1)
// ---------------------------------------------------------------------------

static_assert(static_cast<int>(ScriptOp::Execute) == 0, "ScriptOp::Execute must be 0");
static_assert(static_cast<int>(ScriptOp::Module) == 1, "ScriptOp::Module must be 1");

// ---------------------------------------------------------------------------
// Static Assertions - AmsiOp enum values are sequential (0..N-1)
// ---------------------------------------------------------------------------

static_assert(static_cast<int>(AmsiOp::Scan) == 0, "AmsiOp::Scan must be 0");
static_assert(static_cast<int>(AmsiOp::Session) == 1, "AmsiOp::Session must be 1");

// ---------------------------------------------------------------------------
// Static Assertions - DnsOp enum values are sequential (0..N-1)
// ---------------------------------------------------------------------------

static_assert(static_cast<int>(DnsOp::Query) == 0, "DnsOp::Query must be 0");
static_assert(static_cast<int>(DnsOp::Response) == 1, "DnsOp::Response must be 1");
static_assert(static_cast<int>(DnsOp::Failure) == 2, "DnsOp::Failure must be 2");

// ---------------------------------------------------------------------------
// Static Assertions - SecurityOp enum values are sequential (0..N-1)
// ---------------------------------------------------------------------------

static_assert(static_cast<int>(SecurityOp::Logon) == 0, "SecurityOp::Logon must be 0");
static_assert(static_cast<int>(SecurityOp::LogonFailed) == 1, "SecurityOp::LogonFailed must be 1");
static_assert(static_cast<int>(SecurityOp::PrivilegeAdjust) == 2, "SecurityOp::PrivilegeAdjust must be 2");
static_assert(static_cast<int>(SecurityOp::ProcessCreate) == 3, "SecurityOp::ProcessCreate must be 3");
static_assert(static_cast<int>(SecurityOp::ProcessTerminate) == 4, "SecurityOp::ProcessTerminate must be 4");

// ---------------------------------------------------------------------------
// Static Assertions - ServiceOp enum values are sequential (0..N-1)
// ---------------------------------------------------------------------------

static_assert(static_cast<int>(ServiceOp::Install) == 0, "ServiceOp::Install must be 0");
static_assert(static_cast<int>(ServiceOp::Start) == 1, "ServiceOp::Start must be 1");
static_assert(static_cast<int>(ServiceOp::Stop) == 2, "ServiceOp::Stop must be 2");
static_assert(static_cast<int>(ServiceOp::Delete) == 3, "ServiceOp::Delete must be 3");

// ---------------------------------------------------------------------------
// Static Assertions - WmiOp enum values are sequential (0..N-1)
// ---------------------------------------------------------------------------

static_assert(static_cast<int>(WmiOp::Query) == 0, "WmiOp::Query must be 0");
static_assert(static_cast<int>(WmiOp::ExecMethod) == 1, "WmiOp::ExecMethod must be 1");
static_assert(static_cast<int>(WmiOp::Subscribe) == 2, "WmiOp::Subscribe must be 2");
static_assert(static_cast<int>(WmiOp::Connect) == 3, "WmiOp::Connect must be 3");

// ---------------------------------------------------------------------------
// Static Assertions - ClrOp enum values are sequential (0..N-1)
// ---------------------------------------------------------------------------

static_assert(static_cast<int>(ClrOp::AssemblyLoad) == 0, "ClrOp::AssemblyLoad must be 0");
static_assert(static_cast<int>(ClrOp::AssemblyUnload) == 1, "ClrOp::AssemblyUnload must be 1");
static_assert(static_cast<int>(ClrOp::MethodJit) == 2, "ClrOp::MethodJit must be 2");

}  // namespace exeray::event
