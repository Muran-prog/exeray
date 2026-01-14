/// @file controller.cpp
/// @brief Implementation of Process Controller using Windows APIs.

#include "exeray/process/controller.hpp"

#include <cstdio>
#include <string>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace exeray::process {

namespace {

#ifdef _WIN32
/// @brief Log Windows error with function context.
void log_error(const char* function) {
    DWORD error = GetLastError();
    std::fprintf(stderr, "[exeray::process] %s failed with error %lu\n",
                 function, error);
}
#endif

}  // namespace

// -----------------------------------------------------------------------------
// Factory
// -----------------------------------------------------------------------------

std::unique_ptr<Controller> Controller::launch(
    [[maybe_unused]] std::wstring_view exe_path,
    [[maybe_unused]] std::wstring_view args,
    [[maybe_unused]] std::wstring_view working_dir
) {
#ifdef _WIN32
    // Create Job Object for process isolation
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job == nullptr) {
        log_error("CreateJobObjectW");
        return nullptr;
    }

    // Build command line: "exe_path" args
    // CreateProcessW may modify the command line buffer, so we need writable storage
    std::wstring cmd_line;
    cmd_line.reserve(exe_path.size() + args.size() + 4);
    cmd_line += L'"';
    cmd_line += exe_path;
    cmd_line += L'"';
    if (!args.empty()) {
        cmd_line += L' ';
        cmd_line += args;
    }

    // Prepare startup info
    STARTUPINFOW si{};
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi{};

    // Prepare working directory
    const wchar_t* work_dir_ptr = nullptr;
    std::wstring work_dir_str;
    if (!working_dir.empty()) {
        work_dir_str = std::wstring(working_dir);
        work_dir_ptr = work_dir_str.c_str();
    }

    // Create process in suspended state
    BOOL success = CreateProcessW(
        nullptr,                          // lpApplicationName (use command line)
        cmd_line.data(),                  // lpCommandLine (writable)
        nullptr,                          // lpProcessAttributes
        nullptr,                          // lpThreadAttributes
        FALSE,                            // bInheritHandles
        CREATE_SUSPENDED,                 // dwCreationFlags
        nullptr,                          // lpEnvironment
        work_dir_ptr,                     // lpCurrentDirectory
        &si,                              // lpStartupInfo
        &pi                               // lpProcessInformation
    );

    if (!success) {
        log_error("CreateProcessW");
        CloseHandle(job);
        return nullptr;
    }

    // Assign process to job object
    if (!AssignProcessToJobObject(job, pi.hProcess)) {
        log_error("AssignProcessToJobObject");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(job);
        return nullptr;
    }

    // Create Controller instance
    auto controller = std::unique_ptr<Controller>(new Controller());
    controller->process_handle_ = pi.hProcess;
    controller->thread_handle_ = pi.hThread;
    controller->job_handle_ = job;
    controller->pid_ = pi.dwProcessId;

    return controller;
#else
    // Non-Windows: not supported
    std::fprintf(stderr, "[exeray::process] Controller::launch() not supported on this platform\n");
    return nullptr;
#endif
}

// -----------------------------------------------------------------------------
// Destructor
// -----------------------------------------------------------------------------

Controller::~Controller() {
#ifdef _WIN32
    if (is_running()) {
        terminate(1);
    }
    if (thread_handle_ != nullptr) {
        CloseHandle(static_cast<HANDLE>(thread_handle_));
    }
    if (process_handle_ != nullptr) {
        CloseHandle(static_cast<HANDLE>(process_handle_));
    }
    if (job_handle_ != nullptr) {
        CloseHandle(static_cast<HANDLE>(job_handle_));
    }
#endif
}

// -----------------------------------------------------------------------------
// Process Control
// -----------------------------------------------------------------------------

void Controller::resume() {
#ifdef _WIN32
    if (thread_handle_ != nullptr) {
        DWORD result = ResumeThread(static_cast<HANDLE>(thread_handle_));
        if (result == static_cast<DWORD>(-1)) {
            log_error("ResumeThread");
        }
    }
#endif
}

void Controller::suspend() {
#ifdef _WIN32
    if (thread_handle_ != nullptr) {
        DWORD result = SuspendThread(static_cast<HANDLE>(thread_handle_));
        if (result == static_cast<DWORD>(-1)) {
            log_error("SuspendThread");
        }
    }
#endif
}

void Controller::terminate(std::uint32_t exit_code) {
#ifdef _WIN32
    if (process_handle_ != nullptr) {
        if (!TerminateProcess(static_cast<HANDLE>(process_handle_), exit_code)) {
            log_error("TerminateProcess");
        }
    }
#else
    (void)exit_code;
#endif
}

// -----------------------------------------------------------------------------
// State Queries
// -----------------------------------------------------------------------------

bool Controller::is_running() const {
#ifdef _WIN32
    if (process_handle_ == nullptr) {
        return false;
    }
    DWORD code = 0;
    if (!GetExitCodeProcess(static_cast<HANDLE>(process_handle_), &code)) {
        return false;
    }
    return code == STILL_ACTIVE;
#else
    return false;
#endif
}

std::uint32_t Controller::exit_code() const {
#ifdef _WIN32
    if (process_handle_ == nullptr) {
        return 0;
    }
    DWORD code = 0;
    if (!GetExitCodeProcess(static_cast<HANDLE>(process_handle_), &code)) {
        return 0;
    }
    return code;
#else
    return 0;
#endif
}

// -----------------------------------------------------------------------------
// Job Object Control
// -----------------------------------------------------------------------------

void Controller::set_memory_limit([[maybe_unused]] std::size_t bytes) {
#ifdef _WIN32
    if (job_handle_ == nullptr) {
        return;
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    info.ProcessMemoryLimit = bytes;

    if (!SetInformationJobObject(
            static_cast<HANDLE>(job_handle_),
            JobObjectExtendedLimitInformation,
            &info,
            sizeof(info))) {
        log_error("SetInformationJobObject (memory limit)");
    }
#endif
}

void Controller::set_cpu_limit([[maybe_unused]] std::uint32_t percent) {
#ifdef _WIN32
    if (job_handle_ == nullptr) {
        return;
    }

    // Clamp to valid range
    if (percent == 0) percent = 1;
    if (percent > 100) percent = 100;

    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION info{};
    info.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE |
                        JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
    // CpuRate is in units of 1/100th of a percent (0-10000)
    info.CpuRate = percent * 100;

    if (!SetInformationJobObject(
            static_cast<HANDLE>(job_handle_),
            JobObjectCpuRateControlInformation,
            &info,
            sizeof(info))) {
        log_error("SetInformationJobObject (CPU limit)");
    }
#endif
}

void Controller::deny_child_processes() {
#ifdef _WIN32
    if (job_handle_ == nullptr) {
        return;
    }

    JOBOBJECT_BASIC_LIMIT_INFORMATION info{};
    info.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    info.ActiveProcessLimit = 1;

    if (!SetInformationJobObject(
            static_cast<HANDLE>(job_handle_),
            JobObjectBasicLimitInformation,
            &info,
            sizeof(info))) {
        log_error("SetInformationJobObject (deny child processes)");
    }
#endif
}

}  // namespace exeray::process
